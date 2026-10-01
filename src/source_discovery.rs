//! Autonomous GitHub source discovery for ProxyRift.
//!
//! Discovery is deliberately separate from proxy validation. This module finds candidate
//! subscription files; the existing collector remains the authority that decides whether a
//! source is safe to fetch and whether its configs are usable.
//!
//! State is persisted in subscriptions/source-registry.json. A source is retired only after
//! repeated collection failures, so temporary GitHub search-rank changes do not cause churn.

use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use url::Url;

const REGISTRY_VERSION: u64 = 1;
const SEARCH_PER_PAGE: usize = 50;
const MAX_DISCOVERY_REPOS: usize = 300;
const MAX_TREE_SCANS: usize = 60;
const MAX_TREE_FILES_PER_REPO: usize = 25;
const MAX_ACTIVE_SOURCES: usize = 1200;
const MAX_NEW_SOURCES: usize = 800;
const MAX_FAILURE_STREAK: u64 = 5;
const USER_AGENT: &str = "ProxyRift-source-discovery/1.0";
const README_MAX_BYTES: usize = 256 * 1024;

const DEFAULT_QUERIES: [&str; 10] = [
    "v2ray subscription",
    "vless subscription",
    "vmess subscription",
    "xray subscription",
    "free v2ray configs",
    "v2ray configs",
    "sing-box subscription",
    "hysteria2 subscription",
    "reality configs",
    "v2ray collector",
];

const PATH_HINTS: [&str; 16] = [
    "sub",
    "config",
    "v2ray",
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria",
    "hysteria2",
    "tuic",
    "reality",
    "clash",
    "sing",
    "nodes",
    "servers",
    "proxy",
];

const NOISE_HINTS: [&str; 12] = [
    ".github/",
    "readme",
    "license",
    "changelog",
    "contributing",
    "issue",
    "pull/",
    "/actions/",
    ".git/",
    "package-lock",
    "cargo.lock",
    "go.sum",
];

const SOURCE_EXTENSIONS: [&str; 8] = [
    ".txt", ".yaml", ".yml", ".json", ".conf", ".list", ".sub", ".ini",
];

#[derive(Clone, Debug)]
struct Candidate {
    url: String,
    repo: String,
    priority: u8,
}

struct Registry {
    root: Map<String, Value>,
}

impl Registry {
    fn new(now: u64) -> Self {
        let mut root = Map::new();
        root.insert("schema_version".into(), Value::from(REGISTRY_VERSION));
        root.insert("updated_at".into(), Value::from(now));
        root.insert("sources".into(), Value::Object(Map::new()));
        Self { root }
    }

    fn from_value(value: Value, now: u64) -> Self {
        let Value::Object(mut root) = value else {
            return Self::new(now);
        };

        if root
            .get("schema_version")
            .and_then(Value::as_u64)
            != Some(REGISTRY_VERSION)
        {
            return Self::new(now);
        }

        if !matches!(root.get("sources"), Some(Value::Object(_))) {
            root.insert("sources".into(), Value::Object(Map::new()));
        }

        root.insert("updated_at".into(), Value::from(now));
        Self { root }
    }

    fn sources(&self) -> &Map<String, Value> {
        self.root
            .get("sources")
            .and_then(Value::as_object)
            .expect("registry always contains sources")
    }

    fn sources_mut(&mut self) -> &mut Map<String, Value> {
        self.root
            .get_mut("sources")
            .and_then(Value::as_object_mut)
            .expect("registry always contains sources")
    }

    fn active_urls(&self) -> Vec<String> {
        self.sources()
            .iter()
            .filter_map(|(url, record)| {
                let failures = record
                    .get("failure_streak")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();

                (failures < MAX_FAILURE_STREAK).then(|| url.clone())
            })
            .collect()
    }

    fn add_candidate(&mut self, candidate: &Candidate, now: u64) {
        let sources = self.sources_mut();
        let record = sources
            .entry(candidate.url.clone())
            .or_insert_with(|| {
                let mut object = Map::new();
                object.insert("url".into(), Value::String(candidate.url.clone()));
                object.insert("repo".into(), Value::String(candidate.repo.clone()));
                object.insert("first_seen".into(), Value::from(now));
                object.insert("last_discovered".into(), Value::from(now));
                object.insert("last_checked".into(), Value::Null);
                object.insert("successes".into(), Value::from(0u64));
                object.insert("failures".into(), Value::from(0u64));
                object.insert("failure_streak".into(), Value::from(0u64));
                object.insert("configs_total".into(), Value::from(0u64));
                Value::Object(object)
            });

        if let Some(object) = record.as_object_mut() {
            object.insert("last_discovered".into(), Value::from(now));
            if object.get("repo").and_then(Value::as_str).is_none_or(str::is_empty) {
                object.insert("repo".into(), Value::String(candidate.repo.clone()));
            }
        }
    }

    fn record_result(&mut self, url: &str, produced_configs: usize, now: u64) {
        let Some(object) = self
            .sources_mut()
            .get_mut(url)
            .and_then(Value::as_object_mut)
        else {
            return;
        };

        let successes = object
            .get("successes")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let failures = object
            .get("failures")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let streak = object
            .get("failure_streak")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let configs_total = object
            .get("configs_total")
            .and_then(Value::as_u64)
            .unwrap_or_default();

        object.insert("last_checked".into(), Value::from(now));
        object.insert(
            "configs_last_run".into(),
            Value::from(produced_configs as u64),
        );
        object.insert(
            "configs_total".into(),
            Value::from(configs_total.saturating_add(produced_configs as u64)),
        );

        if produced_configs > 0 {
            object.insert("successes".into(), Value::from(successes + 1));
            object.insert("failure_streak".into(), Value::from(0u64));
            object.insert("last_success".into(), Value::from(now));
        } else {
            object.insert("failures".into(), Value::from(failures + 1));
            object.insert(
                "failure_streak".into(),
                Value::from(streak.saturating_add(1)),
            );
        }
    }

    fn retire_failed(&mut self) -> usize {
        let before = self.sources().len();
        self.sources_mut().retain(|_, record| {
            record
                .get("failure_streak")
                .and_then(Value::as_u64)
                .unwrap_or_default()
                < MAX_FAILURE_STREAK
        });
        before.saturating_sub(self.sources().len())
    }

    fn json(&self) -> Value {
        Value::Object(self.root.clone())
    }
}

pub async fn discover_and_write() -> Result<(usize, usize), Box<dyn std::error::Error + Send + Sync>> {
    let root = project_root()?;
    let registry_path = root.join("subscriptions").join("source-registry.json");
    let sources_path = root.join("sources.txt");
    let now = unix_now();

    let mut registry = load_registry(&registry_path, now).await;
    let token = env::var("GITHUB_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());

    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let mut repos = search_repositories(&client, token.as_deref()).await?;
    repos.sort();
    repos.dedup();
    repos.truncate(MAX_DISCOVERY_REPOS);

    let mut discovered = discover_from_repos(&client, &repos).await?;
    let mut unique = HashMap::<String, Candidate>::new();

    for candidate in discovered.drain(..) {
        unique
            .entry(candidate.url.clone())
            .and_modify(|existing| {
                if candidate.priority > existing.priority {
                    *existing = candidate.clone();
                }
            })
            .or_insert(candidate);
    }

    let mut discovered = unique.into_values().collect::<Vec<_>>();
    discovered.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.repo.cmp(&b.repo))
            .then_with(|| a.url.cmp(&b.url))
    });
    discovered.truncate(MAX_NEW_SOURCES);

    for candidate in &discovered {
        registry.add_candidate(candidate, now);
    }

    let mut new_urls = discovered
        .iter()
        .map(|candidate| candidate.url.clone())
        .collect::<Vec<_>>();
    new_urls.sort();
    new_urls.dedup();

    let mut active = registry.active_urls();
    active.sort();

    let mut ordered = new_urls;
    let seen = ordered.iter().cloned().collect::<HashSet<_>>();
    ordered.extend(active.into_iter().filter(|url| !seen.contains(url)));
    ordered.truncate(MAX_ACTIVE_SOURCES);

    if ordered.is_empty() {
        return Err("GitHub discovery produced no usable subscription sources".into());
    }

    write_registry(&registry_path, &registry).await?;
    write_sources(&sources_path, &ordered).await?;

    println!(
        "[INFO] 🔭 [DISCOVERY] {} repositories searched | {} newly discovered | {} active sources",
        repos.len(),
        discovered.len(),
        ordered.len()
    );

    Ok((discovered.len(), ordered.len()))
}

pub async fn record_collection_results(
    results: &[(String, usize)],
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    if results.is_empty() {
        return Ok(0);
    }

    let root = project_root()?;
    let registry_path = root.join("subscriptions").join("source-registry.json");
    let now = unix_now();
    let mut registry = load_registry(&registry_path, now).await;

    for (url, configs) in results {
        registry.record_result(url, *configs, now);
    }

    let retired = registry.retire_failed();
    write_registry(&registry_path, &registry).await?;

    println!(
        "[INFO] 🔭 [DISCOVERY] source health updated | checked {} | retired {}",
        results.len(),
        retired
    );

    Ok(retired)
}

async fn discover_from_repos(
    client: &Client,
    repos: &[(String, String)],
) -> Result<Vec<Candidate>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = stream::iter(repos.iter().cloned().map(|repo| {
        let client = client.clone();
        async move { discover_repo(&client, &repo).await }
    }))
    .buffer_unordered(24);

    let mut all = Vec::new();
    let mut missing = 0usize;

    while let Some(result) = stream.next().await {
        match result {
            Ok((candidates, needs_tree)) => {
                if candidates.is_empty() && needs_tree {
                    missing += 1;
                }
                all.extend(candidates);
            }
            Err(error) => {
                println!("[WARN] 🔭 [DISCOVERY] repository probe failed: {error}");
            }
        }
    }

    if missing > 0 {
        let tree_targets = repos
            .iter()
            .filter(|(repo, _)| !all.iter().any(|candidate| candidate.repo == *repo))
            .take(MAX_TREE_SCANS)
            .cloned()
            .collect::<Vec<_>>();

        for (index, repo) in tree_targets.into_iter().enumerate() {
            match scan_repo_tree(client, &repo).await {
                Ok(candidates) => all.extend(candidates),
                Err(error) => println!(
                    "[WARN] 🔭 [DISCOVERY] tree probe {}/{} failed: {error}",
                    index + 1,
                    MAX_TREE_SCANS
                ),
            }
        }
    }

    Ok(all)
}

async fn discover_repo(
    client: &Client,
    repo: &(String, String),
) -> Result<(Vec<Candidate>, bool), Box<dyn std::error::Error + Send + Sync>> {
    let (name, branch) = repo;

    for readme in ["README.md", "README", "readme.md"] {
        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}",
            name, branch, readme
        );

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            continue;
        }

        if response
            .content_length()
            .is_some_and(|length| length > README_MAX_BYTES as u64)
        {
            continue;
        }

        let body = response.bytes().await?;
        let body = body.iter().copied().take(README_MAX_BYTES).collect::<Vec<_>>();
        let text = String::from_utf8_lossy(&body);
        let candidates = extract_source_urls(&text, name);

        return Ok((candidates, true));
    }

    Ok((Vec::new(), true))
}

async fn scan_repo_tree(
    client: &Client,
    repo: &(String, String),
) -> Result<Vec<Candidate>, Box<dyn std::error::Error + Send + Sync>> {
    let (name, branch) = repo;
    let url = format!(
        "https://api.github.com/repos/{}/git/trees/{}?recursive=1",
        name,
        percent_encode(branch)
    );

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        return Err(format!("GitHub tree API returned HTTP {}", response.status()).into());
    }

    let text = response.text().await?;
    let payload: Value = serde_json::from_str(&text)?;
    let tree = payload
        .get("tree")
        .and_then(Value::as_array)
        .ok_or("GitHub tree response did not contain a tree")?;

    let mut paths = Vec::new();

    for entry in tree {
        if entry.get("type").and_then(Value::as_str) != Some("blob") {
            continue;
        }

        let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
        if is_source_path(path) {
            paths.push(path.to_string());
        }
    }

    paths.sort_by_key(|path| (path.matches('/').count(), path.len(), path.clone()));
    paths.truncate(MAX_TREE_FILES_PER_REPO);

    Ok(paths
        .into_iter()
        .map(|path| Candidate {
            url: format!(
                "https://raw.githubusercontent.com/{}/{}/{}",
                name,
                branch,
                path.split('/').map(percent_encode).collect::<Vec<_>>().join("/")
            ),
            repo: name.clone(),
            priority: 50,
        })
        .collect())
}

async fn search_repositories(
    client: &Client,
    token: Option<&str>,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error + Send + Sync>> {
    let mut repos = Vec::new();

    for query in DEFAULT_QUERIES {
        let mut request = client
            .get("https://api.github.com/search/repositories")
            .query(&[
                ("q", query),
                ("sort", "updated"),
                ("order", "desc"),
                ("per_page", &SEARCH_PER_PAGE.to_string()),
            ]);

        if let Some(token) = token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(format!(
                "GitHub repository search returned HTTP {}",
                response.status()
            )
            .into());
        }

        let text = response.text().await?;
        let payload: Value = serde_json::from_str(&text)?;

        if let Some(items) = payload.get("items").and_then(Value::as_array) {
            for item in items {
                let Some(name) = item.get("full_name").and_then(Value::as_str) else {
                    continue;
                };

                let branch = item
                    .get("default_branch")
                    .and_then(Value::as_str)
                    .unwrap_or("main");

                repos.push((name.to_string(), branch.to_string()));
            }
        }
    }

    Ok(repos)
}

fn extract_source_urls(text: &str, repo: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut start = 0;

    while let Some(relative) = text[start..].find("http") {
        let absolute = start + relative;
        let end = text[absolute..]
            .find(|character: char| {
                character.is_whitespace()
                    || matches!(character, '<' | '>' | '"' | '\'' | ')' | ']' | '}' | '\u{60}')
            })
            .map(|offset| absolute + offset)
            .unwrap_or(text.len());

        let raw = text[absolute..end]
            .trim()
            .trim_end_matches(&['.', ',', ';', ':', '!', '?'][..]);

        if let Some(url) = normalize_github_source(raw) {
            if likely_source_url(&url) {
                candidates.push(Candidate {
                    url,
                    repo: repo.to_string(),
                    priority: 100,
                });
            }
        }

        start = end;
    }

    candidates.sort_by(|a, b| a.url.cmp(&b.url));
    candidates.dedup_by(|a, b| a.url == b.url);
    candidates
}

fn normalize_github_source(raw: &str) -> Option<String> {
    let mut value = Url::parse(raw).ok()?;

    if !matches!(value.scheme(), "http" | "https") {
        return None;
    }

    if !value.username().is_empty() || value.password().is_some() {
        return None;
    }

    let host = value.host_str()?.to_ascii_lowercase();

    if host == "github.com" {
        let segments = value.path_segments()?.collect::<Vec<_>>();
        if segments.len() < 5 {
            return None;
        }

        let owner = segments[0];
        let repo = segments[1];
        let marker = segments[2];

        if marker != "blob" && marker != "raw" {
            return None;
        }

        let branch = segments[3];
        let path = segments[4..].join("/");
        if path.is_empty() {
            return None;
        }

        value = Url::parse(&format!(
            "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
        ))
        .ok()?;
    } else if host != "raw.githubusercontent.com" {
        return None;
    }

    value.set_query(None);
    value.set_fragment(None);
    Some(value.to_string())
}

fn likely_source_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };

    let path = parsed.path().to_ascii_lowercase();

    if NOISE_HINTS.iter().any(|hint| path.contains(hint)) {
        return false;
    }

    let extension_ok = SOURCE_EXTENSIONS
        .iter()
        .any(|extension| path.ends_with(extension));
    let hint_ok = PATH_HINTS.iter().any(|hint| path.contains(hint));

    extension_ok || hint_ok
}

fn is_source_path(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();

    if NOISE_HINTS.iter().any(|hint| lowered.contains(hint)) {
        return false;
    }

    let extension_ok = SOURCE_EXTENSIONS
        .iter()
        .any(|extension| lowered.ends_with(extension));
    let hint_ok = PATH_HINTS.iter().any(|hint| lowered.contains(hint));

    extension_ok && hint_ok
}

fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(value.len());

    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(*byte as char);
        } else {
            output.push('%');
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0F) as usize] as char);
        }
    }

    output
}

async fn load_registry(path: &Path, now: u64) -> Registry {
    match fs::read_to_string(path).await {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(value) => Registry::from_value(value, now),
            Err(_) => Registry::new(now),
        },
        Err(_) => Registry::new(now),
    }
}

async fn write_registry(
    path: &Path,
    registry: &Registry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let data = serde_json::to_string_pretty(&registry.json())?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, format!("{data}\n")).await?;
    fs::rename(&temporary, path).await?;
    Ok(())
}

async fn write_sources(
    path: &Path,
    urls: &[String],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fs::write(path, format!("{}\n", urls.join("\n"))).await?;
    Ok(())
}

fn project_root() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let cwd = env::current_dir()?;

    if cwd.join("Cargo.toml").is_file() {
        return Ok(cwd);
    }

    let exe = env::current_exe()?;

    for ancestor in exe.ancestors() {
        if ancestor.join("Cargo.toml").is_file() {
            return Ok(ancestor.to_path_buf());
        }
    }

    Err("could not locate ProxyRift project root".into())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{is_source_path, likely_source_url, normalize_github_source};

    #[test]
    fn normalizes_github_blob_to_raw() {
        assert_eq!(
            normalize_github_source(
                "https://github.com/example/project/blob/main/subscriptions/all.txt"
            )
            .as_deref(),
            Some(
                "https://raw.githubusercontent.com/example/project/main/subscriptions/all.txt"
            )
        );
    }

    #[test]
    fn rejects_non_github_sources() {
        assert!(normalize_github_source("https://example.com/sub.txt").is_none());
    }

    #[test]
    fn rejects_github_repository_pages() {
        assert!(normalize_github_source("https://github.com/example/project").is_none());
    }

    #[test]
    fn recognizes_source_paths() {
        assert!(is_source_path("configs/vless.txt"));
        assert!(is_source_path("subscriptions/all.yaml"));
        assert!(!is_source_path("src/main.rs"));
    }

    #[test]
    fn rejects_obvious_noise() {
        assert!(!likely_source_url(
            "https://raw.githubusercontent.com/example/project/main/.github/workflows/sub.txt"
        ));
        assert!(!likely_source_url(
            "https://raw.githubusercontent.com/example/project/main/README.md"
        ));
    }
}
