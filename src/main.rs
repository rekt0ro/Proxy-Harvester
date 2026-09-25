use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt, TryStreamExt};
use percent_encoding::percent_decode_str;
use regex::Regex;
use serde_json::Value;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::{timeout, Duration, Instant};
use url::Url;

const DOWNLOAD_CONCURRENCY: usize = 16;
const TEST_CONCURRENCY: usize = 8;
const TEST_CONNECTION_CONCURRENCY: usize = 64;
const CHUNK_SIZE: usize = 2000;
const LIGHT_LIMIT: usize = 200;
const TCP_TIMEOUT_SECS: u64 = 3;
const PROXY_TEST_LIMIT_PER_PROTOCOL: usize = 500;
const PROXY_TEST_TIMEOUT_SECS: u64 = 3;
const PROXY_TEST_WORKERS: usize = 24;
const PROXY_TEST_BATCH_SIZE: usize = 100;
const PROXY_TEST_PROTOCOL_CONCURRENCY: usize = 1;
const PROXY_TEST_MAX_TCP_LATENCY_MS: u64 = 800;
const LIGHT_CANDIDATE_BUDGET: usize = 6000;
const LIGHT_NON_VMESS_TARGET: usize = 100;
const LIGHT_VMESS_CANDIDATE_BUDGET: usize = 500;
const LIGHT_VMESS_SOFT_LIMIT: usize = 100;
const GEO_PER_PROTOCOL_LIMIT: usize = 1000;
const GEO_BATCH_SIZE: usize = 100;
const GEO_RESOLUTION_CONCURRENCY: usize = 64;
const GEO_TIMEOUT_SECS: u64 = 10;
const MAX_COMPACT_BASE64_BYTES: usize = 4 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("[INFO] Proxy-Harvester starting...");

    let root = project_root()?;
    let sources_path = root.join("sources.txt");
    let output_dir = root.join("subscriptions");
    fs::create_dir_all(&output_dir).await?;

    let sources = load_sources(&sources_path).await?;
    println!("[INFO] Loaded {} sources.", sources.len());

    let client = Client::builder()
        .user_agent("Proxy-Harvester/3.0")
        .timeout(Duration::from_secs(20))
        .build()?;

    let mut unique = HashSet::new();
    let mut source_results = stream::iter(sources.iter().cloned())
        .map(|url| {
            let client = client.clone();
            async move {
                println!("[INFO] Downloading {url}");
                match client.get(&url).send().await {
                    Ok(response) => match response.error_for_status() {
                        Ok(response) => match response.text().await {
                            Ok(text) => {
                                let configs = extract_configs(&text);
                                println!("[INFO] Found {} configs from {url}.", configs.len());
                                configs
                            }
                            Err(error) => {
                                println!("[WARN] Failed to read {url}: {error}");
                                Vec::new()
                            }
                        },
                        Err(error) => {
                            println!("[WARN] Failed to download {url}: {error}");
                            Vec::new()
                        }
                    },
                    Err(error) => {
                        println!("[WARN] Failed to download {url}: {error}");
                        Vec::new()
                    }
                }
            }
        })
        .buffer_unordered(DOWNLOAD_CONCURRENCY);

    while let Some(configs) = source_results.next().await {
        unique.extend(configs);
    }

    let mut configs: Vec<String> = unique.into_iter().collect();
    configs.sort_unstable();
    configs = assign_config_names(configs);

    println!("[INFO] Collected {} unique configs.", configs.len());

    if configs.is_empty() {
        return Err("no proxy configurations were collected".into());
    }

    let mut scheme_counts = HashMap::new();
    for config in &configs {
        *scheme_counts.entry(config_scheme(config)).or_insert(0usize) += 1;
    }

    for (scheme, count) in scheme_counts {
        println!("[INFO] Protocol {scheme}: {count}");
    }

    let working_path = output_dir.join(".working.txt");
    let all_path = output_dir.join("all.txt");
    let light_path = output_dir.join("light.txt");

    let _ = fs::remove_file(&working_path).await;

    let mut endpoint_groups: HashMap<(String, u16), Vec<String>> = HashMap::new();
    let mut endpoint_representatives = Vec::new();

    for config in &configs {
        let Some(endpoint) = endpoint(config) else {
            continue;
        };

        if !endpoint_groups.contains_key(&endpoint) {
            endpoint_representatives.push(config.clone());
        }
        endpoint_groups.entry(endpoint).or_default().push(config.clone());
    }

    let endpoint_config_count: usize = endpoint_groups.values().map(Vec::len).sum();
    if endpoint_config_count < configs.len() || endpoint_config_count > endpoint_representatives.len() {
        println!(
            "[INFO] Global TCP endpoint deduplication: {} testable configs -> {} unique endpoints ({} configs have no testable endpoint).",
            endpoint_config_count,
            endpoint_representatives.len(),
            configs.len().saturating_sub(endpoint_config_count)
        );
    } else {
        println!(
            "[INFO] Global TCP endpoint deduplication: {} testable configs -> {} unique endpoints.",
            endpoint_config_count,
            endpoint_representatives.len()
        );
    }

    let mut chunk_results = stream::iter(endpoint_representatives.chunks(CHUNK_SIZE).enumerate())
        .map(|(index, chunk)| {
            async move { test_chunk(index, format!("{index}"), chunk.to_vec()).await }
        })
        .buffer_unordered(TEST_CONCURRENCY)
        .try_collect::<Vec<(usize, Vec<(String, u64)>)>>()
        .await?;

    chunk_results.sort_by_key(|(index, _)| *index);

    let mut all_output = File::create(&working_path).await?;
    let mut working_count = 0usize;
    let mut latency_by_config = HashMap::new();
    let mut working_configs = Vec::new();

    for (_, working) in chunk_results {
        for (representative, latency_ms) in working {
            let Some(endpoint_key) = endpoint(&representative) else {
                continue;
            };
            let Some(group) = endpoint_groups.get(&endpoint_key) else {
                continue;
            };

            for config in group {
                all_output.write_all(config.as_bytes()).await?;
                all_output.write_all(b"\n").await?;
                latency_by_config.insert(config.clone(), latency_ms);
                working_count += 1;

                let scheme = config_scheme(config);
                if scheme != "http" && scheme != "https" {
                    working_configs.push(config.clone());
                }
            }
        }
    }

    all_output.flush().await?;
    drop(all_output);

    if working_count == 0 {
        let _ = fs::remove_file(&working_path).await;
        println!("[WARN] Zero working configs found. Existing subscriptions were preserved.");
        diagnose_configs(&configs).await;
        return Ok(());
    }

    if working_configs.is_empty() {
        let _ = fs::remove_file(&working_path).await;
        return Err("no compatible proxy configs were found after filtering HTTP(S) endpoints".into());
    }

    let mut by_scheme: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    let mut light_incompatible = 0usize;

    for config in &working_configs {
        if !light_candidate_supported(config) {
            light_incompatible += 1;
            continue;
        }

        if let Some(&latency_ms) = latency_by_config.get(config) {
            if latency_ms <= PROXY_TEST_MAX_TCP_LATENCY_MS {
                by_scheme
                    .entry(config_scheme(config))
                    .or_default()
                    .push((config.clone(), latency_ms));
            }
        }
    }

    for configs in by_scheme.values_mut() {
        configs.sort_by_key(|(_, latency_ms)| *latency_ms);
    }

    let light_candidate_count: usize = by_scheme.values().map(Vec::len).sum();
    if light_incompatible > 0 {
        println!(
            "[INFO] Light candidate compatibility filtering: {} removed, {} remain before latency/budget limits.",
            light_incompatible, light_candidate_count
        );
    }

    let mut schemes: Vec<String> = by_scheme.keys().cloned().collect();
    schemes.sort_unstable();

    let light_configs = match proxy_test_light(&by_scheme, &output_dir, &client).await {
        Some(configs) => configs,
        None => {
            println!("[WARN] Proxy-level testing unavailable or produced no verified configs.");
            Vec::new()
        }
    };

    let all_subscription = format!("{}\n", working_configs.join("\n"));
    let light_subscription = format!("{}\n", light_configs.join("\n"));
    let all_base64 = STANDARD.encode(all_subscription.as_bytes());
    let light_base64 = STANDARD.encode(light_subscription.as_bytes());
    let all_subscription_path = output_dir.join(".all.txt");
    let light_subscription_path = output_dir.join(".light.txt");
    let all_base64_path = output_dir.join(".all-base64.txt");
    let light_base64_path = output_dir.join(".light-base64.txt");

    fs::write(&all_subscription_path, all_subscription).await?;
    fs::write(&light_subscription_path, light_subscription).await?;
    fs::write(&all_base64_path, format!("{}\n", all_base64)).await?;
    fs::write(&light_base64_path, format!("{}\n", light_base64)).await?;
    fs::rename(&all_subscription_path, &all_path).await?;
    fs::rename(&light_subscription_path, &light_path).await?;
    fs::rename(&all_base64_path, output_dir.join("all-base64.txt")).await?;
    fs::rename(&light_base64_path, output_dir.join("light-base64.txt")).await?;
    fs::remove_file(&working_path).await?;

    let light_count = light_configs.len();

    println!("[INFO] Published {} working configs to all.txt and all-base64.txt.", working_configs.len());
    println!("[INFO] Published {} configs to light.txt and light-base64.txt.", light_count);
    println!("[INFO] Done.");

    Ok(())
}

fn project_root() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let exe = env::current_exe()?;
    let root = exe
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or("failed to determine project root")?;
    Ok(root.to_path_buf())
}

async fn load_sources(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let content = fs::read_to_string(path).await?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect())
}

fn config_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:vmess|vless|trojan|ssr?|socks5?|hysteria2?|hy2|tuic|wg|ssh|naive\+https)://[^\s<>"']+|(?:https?)://[^\s<>"']+:\d+[^\s<>"']*"#,
        )
        .expect("config regex must compile")
    })
}

fn extract_configs(text: &str) -> Vec<String> {
    let text = decode_html_entities(text);
    let pattern = config_pattern();

    let mut found = Vec::new();

    for capture in pattern.find_iter(&text) {
        if let Some(config) = normalize_config(capture.as_str()) {
            found.push(config);
        }
    }

    for decoded in decode_base64_variants(&text) {
        for capture in pattern.find_iter(&decoded) {
            if let Some(config) = normalize_config(capture.as_str()) {
                found.push(config);
            }
        }
    }

    found.sort_unstable();
    found.dedup();
    found
}

fn normalize_config(config: &str) -> Option<String> {
    let config = trim_config(config);

    if has_invalid_percent_escapes(&config) || has_bracketed_ipv4_host(&config) {
        return None;
    }

    let scheme = config_scheme(&config);

    if scheme == "vmess" {
        return normalize_vmess(&config);
    }

    let Ok(url) = Url::parse(&config) else {
        return None;
    };

    if scheme == "vless" {
        return normalize_vless(&config, &url);
    }

    if let Some(host) = url.host_str() {
        if host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
    }

    if scheme == "ss" {
        return normalize_shadowsocks(&config, &url);
    }

    if url.query_pairs().any(|(key, value)| {
        (key.eq_ignore_ascii_case("fp") || key.eq_ignore_ascii_case("fingerprint"))
            && value.eq_ignore_ascii_case("unsafe")
    }) {
        return None;
    }

    Some(config)
}

fn has_invalid_percent_escapes(value: &str) -> bool {
    let bytes = value.as_bytes();

    for index in 0..bytes.len() {
        if bytes[index] != b'%' {
            continue;
        }

        if index + 2 >= bytes.len()
            || !bytes[index + 1].is_ascii_hexdigit()
            || !bytes[index + 2].is_ascii_hexdigit()
        {
            return true;
        }
    }

    false
}

fn has_bracketed_ipv4_host(config: &str) -> bool {
    let Some(authority) = config.split_once("://").and_then(|(_, rest)| rest.split(['?', '#']).next()) else {
        return false;
    };

    let Some(host_port) = authority.rsplit_once('@').map(|(_, host)| host) else {
        return false;
    };

    let decoded = percent_decode_str(host_port).decode_utf8_lossy();
    let host = if let Some(stripped) = decoded.strip_prefix('[') {
        stripped.split_once(']').map(|(host, _)| host)
    } else {
        None
    };

    let Some(host) = host else {
        return false;
    };

    host.parse::<std::net::Ipv4Addr>().is_ok()
}

fn normalize_shadowsocks(config: &str, url: &Url) -> Option<String> {
    const METHODS: &[&str] = &[
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "none",
    ];

    let method = if !url.username().is_empty() {
        percent_decode_str(url.username()).decode_utf8().ok()?.into_owned()
    } else {
        let payload = config.split_once("://")?.1.split('#').next()?.split('@').next()?;
        let mut padded = payload.to_string();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }

        let decoded = [STANDARD.decode(payload), STANDARD.decode(&padded), URL_SAFE.decode(payload), URL_SAFE_NO_PAD.decode(payload)]
            .into_iter()
            .find_map(Result::ok)?;

        let decoded = String::from_utf8(decoded).ok()?;
        decoded.split_once(':')?.0.to_string()
    };

    if METHODS.iter().any(|supported| method.eq_ignore_ascii_case(supported)) {
        Some(config.to_string())
    } else {
        None
    }
}

fn normalize_vless(config: &str, url: &Url) -> Option<String> {
    let uuid = percent_decode_str(url.username()).decode_utf8().ok()?;

    if !is_uuid(uuid.as_ref()) {
        return None;
    }

    if url.query_pairs().any(|(key, value)| {
        (key.eq_ignore_ascii_case("fp") || key.eq_ignore_ascii_case("fingerprint"))
            && value.eq_ignore_ascii_case("unsafe")
    }) {
        return None;
    }

    if url.query_pairs().any(|(key, value)| {
        key.eq_ignore_ascii_case("security")
            && !matches!(value.to_ascii_lowercase().as_str(), "none" | "tls" | "reality")
    }) {
        return None;
    }

    if url.query_pairs().any(|(key, value)| {
        key.eq_ignore_ascii_case("encryption") && !value.eq_ignore_ascii_case("none")
    }) {
        return None;
    }

    if url.query_pairs().any(|(key, value)| {
        (key.eq_ignore_ascii_case("packetencoding")
            || key.eq_ignore_ascii_case("packet-encoding"))
            && !matches!(value.to_ascii_lowercase().as_str(), "xudp" | "packetaddr" | "none")
    }) {
        return None;
    }

    if url.query_pairs().any(|(key, _)| key.eq_ignore_ascii_case("fm")) {
        return None;
    }

    if url.query_pairs().any(|(key, value)| {
        key.eq_ignore_ascii_case("path")
            && value.to_ascii_lowercase().contains("security=tls")
    }) {
        return None;
    }

    if is_invalid_vless_reality_public_key(url) {
        return None;
    }

    Some(config.to_string())
}

fn is_invalid_vless_reality_public_key(url: &Url) -> bool {
    let is_reality = url
        .query_pairs()
        .any(|(key, value)| key.eq_ignore_ascii_case("security") && value.eq_ignore_ascii_case("reality"));

    if !is_reality {
        return false;
    }

    let Some(public_key) = url.query_pairs().find_map(|(key, value)| {
        key.eq_ignore_ascii_case("pbk").then(|| value.into_owned())
    }) else {
        return false;
    };

    let public_key = public_key.trim();

    // sing-box Reality public keys are 32-byte X25519 keys encoded as
    // unpadded base64url, which is exactly 43 characters.
    if public_key.len() != 43
        || !public_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return true;
    }

    !matches!(URL_SAFE_NO_PAD.decode(public_key), Ok(bytes) if bytes.len() == 32)
}

fn normalize_vmess(config: &str) -> Option<String> {
    let payload = config.split_once("://")?.1;
    let encoded = payload.split('#').next()?.trim();

    if encoded.is_empty() {
        return None;
    }

    let decoded = decode_vmess_payload(encoded)?;
    let value: Value = serde_json::from_str(&decoded).ok()?;
    let object = value.as_object()?;

    let version_ok = match object.get("v") {
        Some(Value::String(version)) => version == "2",
        Some(Value::Number(version)) => version.as_u64() == Some(2),
        _ => false,
    };
    if !version_ok {
        return None;
    }

    let add = object.get("add")?.as_str()?.trim();
    if add.is_empty() || add.chars().any(|c| c.is_control() || c == ' ' || c == '/' || c == '\\') {
        return None;
    }

    let port = match object.get("port") {
        Some(Value::String(port)) => port.parse::<u16>().ok()?,
        Some(Value::Number(port)) => port.as_u64().and_then(|port| u16::try_from(port).ok())?,
        _ => return None,
    };
    if port == 0 {
        return None;
    }

    let id = object.get("id")?.as_str()?.trim();
    if !is_uuid(id) {
        return None;
    }

    if ["fp", "fingerprint"].iter().any(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("unsafe"))
    }) {
        return None;
    }

    if let Some(path) = object.get("path").and_then(Value::as_str) {
        if has_invalid_percent_escapes(path) {
            return None;
        }
    }

    let canonical = STANDARD.encode(decoded.as_bytes());
    Some(format!("vmess://{canonical}"))
}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }

    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }

    true
}

fn decode_vmess_payload(encoded: &str) -> Option<String> {
    let mut candidates = Vec::with_capacity(4);
    let mut padded = encoded.to_string();

    while padded.len() % 4 != 0 {
        padded.push('=');
    }

    candidates.push(encoded.to_string());
    if padded != encoded {
        candidates.push(padded);
    }

    for candidate in candidates {
        for decoded in [
            STANDARD.decode(&candidate),
            URL_SAFE.decode(&candidate),
            URL_SAFE_NO_PAD.decode(&candidate),
        ] {
            if let Ok(bytes) = decoded {
                if let Ok(text) = String::from_utf8(bytes) {
                    return Some(text);
                }
            }
        }
    }

    None
}

fn decode_html_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn trim_config(config: &str) -> String {
    let config = config
        .trim_end_matches(|c| {
            c == ')' || c == ']' || c == '}' || c == ',' || c == ';' || c == '.'
                || c == '\r' || c == '\n'
        })
        .to_string();

    let Ok(mut url) = Url::parse(&config) else {
        return config;
    };

    url.set_fragment(None);
    url.to_string()
}

fn assign_config_names(configs: Vec<String>) -> Vec<String> {
    let mut counters: HashMap<String, usize> = HashMap::new();
    let mut named = Vec::with_capacity(configs.len());

    for config in configs {
        let scheme = config_scheme(&config);
        let counter = counters.entry(scheme.clone()).or_insert(0);
        *counter += 1;

        let name = format!("{} {:03}", display_protocol(&scheme), *counter);

        if scheme == "vmess" {
            if let Some(named_config) = name_vmess_config(&config, &name) {
                named.push(named_config);
                continue;
            }
        }

        if let Ok(mut url) = Url::parse(&config) {
            url.set_fragment(Some(&name));
            named.push(url.to_string());
        } else {
            named.push(config);
        }
    }

    named
}

fn name_vmess_config(config: &str, name: &str) -> Option<String> {
    let encoded = config.split_once("://")?.1.split('#').next()?.trim();
    let decoded = decode_vmess_payload(encoded)?;
    let mut object: serde_json::Map<String, Value> = serde_json::from_str(&decoded).ok()?;
    object.insert("ps".to_string(), Value::String(name.to_string()));

    let payload = serde_json::to_vec(&Value::Object(object)).ok()?;
    Some(format!("vmess://{}", STANDARD.encode(payload)))
}

fn display_protocol(scheme: &str) -> &str {
    match scheme {
        "vmess" => "VMess",
        "vless" => "VLESS",
        "trojan" => "Trojan",
        "ss" => "Shadowsocks",
        "ssr" => "ShadowsocksR",
        "hysteria" => "Hysteria",
        "hysteria2" | "hy2" => "Hysteria2",
        "tuic" => "TUIC",
        "socks" | "socks4" | "socks5" | "socks5h" => "SOCKS",
        "wg" => "WireGuard",
        "ssh" => "SSH",
        "naive+https" => "NaiveProxy",
        "http" => "HTTP",
        "https" => "HTTPS",
        _ => scheme,
    }
}

fn decode_base64_variants(text: &str) -> Vec<String> {
    let mut inputs = Vec::new();
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();

    if compact.len() >= 16
        && compact.len() <= MAX_COMPACT_BASE64_BYTES
        && !text.contains("://")
    {
        inputs.push(compact);
    }

    for line in text.lines().map(str::trim).filter(|line| line.len() >= 16) {
        if line.len() <= 8192 {
            inputs.push(line.to_string());
        }
    }

    let mut results = Vec::new();

    for input in inputs {
        let mut variants = vec![input.clone()];
        let mut padded = input.clone();

        while padded.len() % 4 != 0 {
            padded.push('=');
        }

        variants.push(padded);

        for candidate in variants {
            for decoded in [
                STANDARD.decode(&candidate),
                URL_SAFE.decode(&candidate),
                URL_SAFE_NO_PAD.decode(&candidate),
            ] {
                if let Ok(bytes) = decoded {
                    let decoded = String::from_utf8_lossy(&bytes).to_string();
                    if decoded.contains("://") {
                        results.push(decoded);
                    }
                }
            }
        }
    }

    results.sort();
    results.dedup();
    results
}

fn config_scheme(config: &str) -> String {
    config
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

fn light_candidate_supported(config: &str) -> bool {
    let scheme = config_scheme(config);

    let Ok(url) = Url::parse(config) else {
        return false;
    };

    match scheme.as_str() {
        "vless" => {
            let valid_flow = !url.query_pairs().any(|(key, value)| {
                key.eq_ignore_ascii_case("flow")
                    && !value.is_empty()
                    && !value.eq_ignore_ascii_case("xtls-rprx-vision")
            });

            let valid_fingerprint = !url.query_pairs().any(|(key, value)| {
                if !key.eq_ignore_ascii_case("fp") {
                    return false;
                }

                !matches!(
                    value.to_ascii_lowercase().as_str(),
                    "chrome"
                        | "firefox"
                        | "edge"
                        | "safari"
                        | "360"
                        | "qq"
                        | "ios"
                        | "android"
                        | "random"
                        | "randomized"
                        | ""
                )
            });

            valid_flow && valid_fingerprint
        },
        "trojan" => {
            // singbox2proxy unquotes the whole Trojan URL before urlparse().
            // Percent-encoded brackets in the password then become IPv6 brackets
            // and are rejected as an invalid IPv6 URL by its parser.
            percent_decode_str(url.username())
                .decode_utf8()
                .map(|password| !password.contains(['[', ']']))
                .unwrap_or(false)
        }
        _ => true,
    }
}

fn endpoint(config: &str) -> Option<(String, u16)> {
    let url = Url::parse(config).ok()?;
    let scheme = url.scheme().to_ascii_lowercase();

    if scheme == "vmess" {
        let encoded = config.split_once("://")?.1.split('#').next()?.trim();
        let decoded = decode_vmess_payload(encoded)?;
        let value: Value = serde_json::from_str(&decoded).ok()?;

        let add = value.get("add")?.as_str()?.trim().to_string();
        let port = match value.get("port") {
            Some(Value::String(port)) => port.parse::<u16>().ok()?,
            Some(Value::Number(port)) => port.as_u64().and_then(|port| u16::try_from(port).ok())?,
            _ => return None,
        };

        if add.is_empty() || port == 0 {
            return None;
        }

        return Some((add, port));
    }

    let host = url.host_str()?.to_string();
    let port = url.port().or_else(|| match scheme.as_str() {
        "http" => Some(80),
        "https" => Some(443),
        "socks" | "socks4" | "socks5" | "socks5h" => Some(1080),
        _ => None,
    })?;

    Some((host, port))
}
async fn tcp_latency_endpoint(host: &str, port: u16) -> Option<u64> {
    let start = Instant::now();

    let mut addresses = timeout(
        Duration::from_secs(TCP_TIMEOUT_SECS),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .ok()?
    .ok()?
    .collect::<Vec<_>>();

    addresses.sort_by_key(|address| !address.is_ipv4());

    if addresses.is_empty() {
        return None;
    }

    match timeout(
        Duration::from_secs(TCP_TIMEOUT_SECS),
        TcpStream::connect(addresses.as_slice()),
    )
    .await
    {
        Ok(Ok(_)) => Some(start.elapsed().as_millis() as u64),
        _ => None,
    }
}

async fn tcp_latency(config: &str) -> Option<u64> {
    let (host, port) = endpoint(config)?;
    tcp_latency_endpoint(&host, port).await
}
async fn tcp_reachable(config: &str) -> bool {
    tcp_latency(config).await.is_some()
}

async fn test_tcp_configs(configs: Vec<String>) -> Vec<(String, u64)> {
    let mut by_endpoint: HashMap<(String, u16), Vec<String>> = HashMap::new();

    for config in configs {
        if let Some(endpoint) = endpoint(&config) {
            by_endpoint.entry(endpoint).or_default().push(config);
        }
    }

    let endpoint_count = by_endpoint.len();
    let config_count: usize = by_endpoint.values().map(Vec::len).sum();
    if endpoint_count < config_count {
        println!(
            "[INFO] TCP endpoint deduplication: {} configs -> {} unique endpoints.",
            config_count, endpoint_count
        );
    }

    let endpoint_results = stream::iter(by_endpoint.keys().cloned())
        .map(|(host, port)| async move {
            tcp_latency_endpoint(&host, port)
                .await
                .map(|latency| ((host, port), latency))
        })
        .buffer_unordered(TEST_CONNECTION_CONCURRENCY)
        .filter_map(async move |result| result)
        .collect::<Vec<_>>()
        .await;

    let mut working = Vec::new();
    for ((host, port), latency_ms) in endpoint_results {
        if let Some(configs) = by_endpoint.get(&(host, port)) {
            working.extend(configs.iter().cloned().map(|config| (config, latency_ms)));
        }
    }

    working
}
async fn test_chunk(
    index: usize,
    label: String,
    configs: Vec<String>,
) -> Result<(usize, Vec<(String, u64)>), Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "[INFO] Testing chunk {}: {} configs with TCP reachability.",
        label,
        configs.len()
    );

    let working = test_tcp_configs(configs.clone()).await;

    println!(
        "[INFO] Chunk {} complete: {}/{} TCP reachable.",
        label,
        working.len(),
        configs.len()
    );

    Ok((index, working))
}

async fn run_proxy_check_batch(
    checker: &Path,
    output_dir: &Path,
    scheme: String,
    candidates: Vec<String>,
    offset: usize,
) -> (String, Vec<String>) {
    let input_path = output_dir.join(format!(".proxy-test-{scheme}.txt"));
    let output_path = output_dir.join(format!(".proxy-working-{scheme}.txt"));
    let input = candidates.join("\n");

    if fs::write(&input_path, format!("{input}\n")).await.is_err() {
        println!("[WARN] Failed to prepare proxy test input for {scheme}.");
        return (scheme, Vec::new());
    }

    let _ = fs::remove_file(&output_path).await;
    println!(
        "[INFO] Proxy-testing {} {} candidates (offset {}..{}) until {} verified configs are reached.",
        scheme,
        candidates.len(),
        offset,
        offset + candidates.len(),
        LIGHT_LIMIT
    );

    let start = Instant::now();
    let result = Command::new("python3")
        .arg(checker)
        .arg("--input").arg(&input_path)
        .arg("--output").arg(&output_path)
        .arg("--workers").arg(PROXY_TEST_WORKERS.to_string())
        .arg("--batch-size").arg(PROXY_TEST_BATCH_SIZE.to_string())
        .arg("--timeout").arg(PROXY_TEST_TIMEOUT_SECS.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    let Ok(result) = result else {
        println!("[WARN] Failed to run Python proxy checker for {scheme}.");
        let _ = fs::remove_file(&input_path).await;
        let _ = fs::remove_file(&output_path).await;
        return (scheme, Vec::new());
    };

    println!(
        "[DIAG] Python proxy test {} exit: success={}, status={}, elapsed={}ms, stdout_bytes={}, stderr_bytes={}",
        scheme,
        result.status.success(),
        result.status,
        start.elapsed().as_millis(),
        result.stdout.len(),
        result.stderr.len()
    );

    let stdout = String::from_utf8_lossy(&result.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&result.stderr).trim().to_string();

    if !stdout.is_empty() {
        println!("[INFO] Python proxy test {scheme}: {stdout}");
    }

    if !result.status.success() {
        if !stderr.is_empty() {
            println!("[WARN] Python proxy test {scheme} stderr: {stderr}");
        }
        let _ = fs::remove_file(&input_path).await;
        let _ = fs::remove_file(&output_path).await;
        return (scheme, Vec::new());
    }

    if !stderr.is_empty() {
        println!("[INFO] Python proxy test {scheme} stderr: {stderr}");
    }

    let verified = fs::read_to_string(&output_path)
        .await
        .ok()
        .map(|content| {
            content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let _ = fs::remove_file(&input_path).await;
    let _ = fs::remove_file(&output_path).await;

    (scheme, verified)
}

async fn proxy_test_light(
    by_scheme: &HashMap<String, Vec<(String, u64)>>,
    output_dir: &Path,
    client: &Client,
) -> Option<Vec<String>> {
    let root = output_dir.parent()?.to_path_buf();
    let checker = root.join("scripts").join("check_proxies.py");

    if fs::metadata(&checker).await.is_err() {
        println!("[WARN] Python proxy checker is unavailable.");
        return None;
    }

    let mut schemes: Vec<String> = by_scheme.keys().cloned().collect();
    schemes.sort_unstable();

    let mut geo_candidates = Vec::new();
    for scheme in &schemes {
        if scheme == "http" || scheme == "https" || scheme == "ssr" {
            continue;
        }

        if let Some(configs) = by_scheme.get(scheme) {
            geo_candidates.extend(
                configs
                    .iter()
                    .take(GEO_PER_PROTOCOL_LIMIT)
                    .map(|(config, _)| config.clone()),
            );
        }
    }

    let eu_by_endpoint = detect_eu_endpoints(client, &geo_candidates).await;

    let mut prioritized_by_scheme = by_scheme.clone();
    for (scheme, configs) in prioritized_by_scheme.iter_mut() {
        configs.sort_by_key(|(config, latency_ms)| {
            let is_eu = endpoint(config)
                .and_then(|key| eu_by_endpoint.get(&key).copied())
                .unwrap_or(false);
            (!is_eu, *latency_ms)
        });

        let eu_count = configs
            .iter()
            .filter(|(config, _)| {
                endpoint(config)
                    .and_then(|key| eu_by_endpoint.get(&key).copied())
                    .unwrap_or(false)
            })
            .count();

        if eu_count > 0 {
            println!(
                "[INFO] EU candidate preference: {scheme} has {eu_count} detected EU endpoints in its Light pool."
            );
        }
    }

    let mut verified_by_scheme: HashMap<String, Vec<String>> = HashMap::new();
    let mut offsets: HashMap<String, usize> = HashMap::new();
    let mut total_verified = 0usize;
    let mut tested_candidates = 0usize;
    let mut tested_vmess_candidates = 0usize;

    while tested_candidates < LIGHT_CANDIDATE_BUDGET {
        let non_vmess_verified: usize = verified_by_scheme
            .iter()
            .filter(|(scheme, _)| scheme.as_str() != "vmess")
            .map(|(_, configs)| configs.len())
            .sum();

        if total_verified >= LIGHT_LIMIT && non_vmess_verified >= LIGHT_NON_VMESS_TARGET {
            break;
        }
        let mut jobs = Vec::new();
        let mut remaining_budget = LIGHT_CANDIDATE_BUDGET - tested_candidates;

        for scheme in &schemes {
            if remaining_budget == 0 {
                break;
            }

            if scheme == "http" || scheme == "https" || scheme == "ssr" {
                continue;
            }

            let Some(configs) = prioritized_by_scheme.get(scheme) else { continue };
            if scheme == "vmess" && tested_vmess_candidates >= LIGHT_VMESS_CANDIDATE_BUDGET {
                continue;
            }
            let offset = *offsets.get(scheme).unwrap_or(&0);

            if offset >= configs.len() {
                continue;
            }

            let scheme_budget = if scheme == "vmess" {
                LIGHT_VMESS_CANDIDATE_BUDGET.saturating_sub(tested_vmess_candidates)
            } else {
                remaining_budget
            };
            let batch_len = PROXY_TEST_LIMIT_PER_PROTOCOL
                .min(remaining_budget)
                .min(scheme_budget);
            let end = (offset + batch_len).min(configs.len());
            let candidates = configs[offset..end]
                .iter()
                .map(|(config, _)| config.clone())
                .collect::<Vec<_>>();

            offsets.insert(scheme.clone(), end);
            remaining_budget = remaining_budget.saturating_sub(candidates.len());
            tested_candidates += candidates.len();
            if scheme == "vmess" {
                tested_vmess_candidates += candidates.len();
            }

            if !candidates.is_empty() {
                jobs.push((scheme.clone(), candidates, offset));
            }
        }

        if jobs.is_empty() {
            break;
        }

        let batches = stream::iter(jobs.into_iter().map(|(scheme, candidates, offset)| {
            run_proxy_check_batch(&checker, output_dir, scheme, candidates, offset)
        }))
        .buffer_unordered(PROXY_TEST_PROTOCOL_CONCURRENCY)
        .collect::<Vec<(String, Vec<String>)>>()
        .await;

        for (scheme, verified) in batches {
            let entry = verified_by_scheme.entry(scheme.clone()).or_default();
            let before = entry.len();
            let mut seen: HashSet<String> = entry.iter().cloned().collect();

            for config in verified {
                if seen.insert(config.clone()) {
                    entry.push(config);
                }
            }

            let added = entry.len() - before;
            total_verified += added;

            println!(
                "[INFO] Proxy-tested {} batch: {} new verified, {} total verified.",
                scheme, added, total_verified
            );
        }
    }

    if verified_by_scheme.is_empty() {
        return None;
    }

    let mut verified_schemes: Vec<String> = verified_by_scheme.keys().cloned().collect();
    verified_schemes.sort_unstable();

    let mut eu_by_scheme: HashMap<String, Vec<String>> = HashMap::new();
    let mut non_eu_by_scheme: HashMap<String, Vec<String>> = HashMap::new();

    for scheme in &verified_schemes {
        let Some(items) = verified_by_scheme.get(scheme) else {
            continue;
        };

        for config in items {
            let is_eu = endpoint(config)
                .and_then(|key| eu_by_endpoint.get(&key).copied())
                .unwrap_or(false);

            if is_eu {
                eu_by_scheme
                    .entry(scheme.clone())
                    .or_default()
                    .push(config.clone());
            } else {
                non_eu_by_scheme
                    .entry(scheme.clone())
                    .or_default()
                    .push(config.clone());
            }
        }
    }

    let mut verified = Vec::with_capacity(total_verified.min(LIGHT_LIMIT));
    let mut vmess_count = 0usize;

    for pools in [&eu_by_scheme, &non_eu_by_scheme] {
        let mut index = 0usize;

        while verified.len() < LIGHT_LIMIT {
            let mut added = false;

            for scheme in &verified_schemes {
                let Some(items) = pools.get(scheme) else {
                    continue;
                };

                if let Some(config) = items.get(index) {
                    if config_scheme(config) == "vmess" && vmess_count >= LIGHT_VMESS_SOFT_LIMIT {
                        continue;
                    }

                    verified.push(config.clone());
                    if config_scheme(config) == "vmess" {
                        vmess_count += 1;
                    }
                    added = true;

                    if verified.len() >= LIGHT_LIMIT {
                        break;
                    }
                }
            }

            if !added {
                break;
            }

            index += 1;
        }
    }

    if verified.len() < LIGHT_LIMIT {
        let mut fallback = Vec::new();
        for scheme in &verified_schemes {
            if let Some(items) = verified_by_scheme.get(scheme) {
                fallback.extend(items.iter().cloned());
            }
        }

        for config in fallback {
            if verified.contains(&config) {
                continue;
            }

            if config_scheme(&config) == "vmess" && vmess_count >= LIGHT_VMESS_SOFT_LIMIT {
                continue;
            }

            verified.push(config);
            if config_scheme(&config) == "vmess" {
                vmess_count += 1;
            }
            if verified.len() >= LIGHT_LIMIT {
                break;
            }
        }
    }

    println!(
        "[INFO] Proxy-level testing completed with {} fully verified configs ({} EU, {} VMess).",
        verified.len(),
        verified
            .iter()
            .filter(|config| {
                endpoint(config)
                    .and_then(|key| eu_by_endpoint.get(&key).copied())
                    .unwrap_or(false)
            })
            .count(),
        verified.iter().filter(|config| config_scheme(config) == "vmess").count()
    );

    Some(verified)
}
fn is_eu_country_code(code: &str) -> bool {
    matches!(
        code,
        "AT"
            | "BE"
            | "BG"
            | "HR"
            | "CY"
            | "CZ"
            | "DK"
            | "EE"
            | "FI"
            | "FR"
            | "DE"
            | "GR"
            | "HU"
            | "IE"
            | "IT"
            | "LV"
            | "LT"
            | "LU"
            | "MT"
            | "NL"
            | "PL"
            | "PT"
            | "RO"
            | "SK"
            | "SI"
            | "ES"
            | "SE"
    )
}

async fn resolve_geo_ip(host: &str, port: u16) -> Option<std::net::IpAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ip);
    }

    let mut addresses = timeout(
        Duration::from_secs(GEO_TIMEOUT_SECS),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .ok()?
    .ok()?
    .collect::<Vec<_>>();

    addresses.sort_by_key(|address| !address.ip().is_ipv4());

    addresses
        .into_iter()
        .map(|address| address.ip())
        .find(|ip| !ip.is_unspecified() && !ip.is_loopback())
}

async fn detect_eu_endpoints(
    client: &Client,
    configs: &[String],
) -> HashMap<(String, u16), bool> {
    let mut endpoints = HashSet::new();
    for config in configs {
        if let Some(key) = endpoint(config) {
            endpoints.insert(key);
        }
    }

    if endpoints.is_empty() {
        return HashMap::new();
    }

    let resolved = stream::iter(endpoints.into_iter().map(|key| async move {
        let ip = resolve_geo_ip(&key.0, key.1).await;
        ip.map(|ip| (key, ip))
    }))
    .buffer_unordered(GEO_RESOLUTION_CONCURRENCY)
    .filter_map(async move |result| result)
    .collect::<Vec<_>>()
    .await;

    let mut endpoint_by_ip: HashMap<std::net::IpAddr, Vec<(String, u16)>> = HashMap::new();
    for (key, ip) in resolved {
        endpoint_by_ip.entry(ip).or_default().push(key);
    }

    let ips: Vec<std::net::IpAddr> = endpoint_by_ip.keys().copied().collect();
    let mut ip_is_eu: HashMap<std::net::IpAddr, bool> = HashMap::new();

    for (batch_index, chunk) in ips.chunks(GEO_BATCH_SIZE).enumerate() {
        if batch_index > 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let payload = match serde_json::to_vec(
            &chunk.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ) {
            Ok(payload) => payload,
            Err(_) => continue,
        };

        let mut response = None;

        for attempt in 0..=2 {
            let result = client
                .post("https://api.country.is/")
                .header("content-type", "application/json")
                .body(payload.clone())
                .send()
                .await;

            match result {
                Ok(candidate) if candidate.status().is_success() => {
                    response = Some(candidate);
                    break;
                }
                Ok(candidate) if candidate.status().as_u16() == 429 || candidate.status().is_server_error() => {
                    if attempt < 2 {
                        let backoff_ms = 250u64.saturating_mul(1u64 << attempt);
                        println!(
                            "[WARN] country.is geo lookup returned HTTP {}; retrying batch in {}ms (attempt {}/3).",
                            candidate.status(),
                            backoff_ms,
                            attempt + 2
                        );
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }
                Ok(candidate) => {
                    println!(
                        "[WARN] country.is geo lookup returned HTTP {}; skipping batch.",
                        candidate.status()
                    );
                    break;
                }
                Err(error) => {
                    if attempt < 2 {
                        let backoff_ms = 250u64.saturating_mul(1u64 << attempt);
                        println!(
                            "[WARN] country.is geo lookup failed: {error}; retrying batch in {}ms (attempt {}/3).",
                            backoff_ms,
                            attempt + 2
                        );
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    } else {
                        println!(
                            "[WARN] country.is geo lookup failed after 3 attempts: {error}"
                        );
                    }
                }
            }
        }

        let Some(response) = response else {
            continue;
        };

        let body = match response.text().await {
            Ok(body) => body,
            Err(error) => {
                println!("[WARN] Failed to read country.is geo response: {error}");
                continue;
            }
        };

        let results: Vec<Value> = match serde_json::from_str(&body) {
            Ok(results) => results,
            Err(error) => {
                println!("[WARN] Failed to parse country.is geo response: {error}");
                continue;
            }
        };

        for result in results {
            let Some(ip) = result
                .get("ip")
                .and_then(Value::as_str)
                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
            else {
                continue;
            };

            let is_eu = result
                .get("country")
                .and_then(Value::as_str)
                .is_some_and(is_eu_country_code);

            ip_is_eu.insert(ip, is_eu);
        }
    }

    let mut eu_by_endpoint = HashMap::new();
    for (ip, keys) in endpoint_by_ip {
        let is_eu = ip_is_eu.get(&ip).copied().unwrap_or(false);
        for key in keys {
            eu_by_endpoint.insert(key, is_eu);
        }
    }

    let eu_count = eu_by_endpoint.values().filter(|&&is_eu| is_eu).count();
    println!(
        "[INFO] EU endpoint detection: classified {} endpoints, {} detected in the EU.",
        eu_by_endpoint.len(),
        eu_count
    );

    eu_by_endpoint
}

async fn diagnose_configs(configs: &[String]) {
    let mut samples = Vec::new();
    let mut seen = HashSet::new();

    for config in configs {
        let scheme = config_scheme(config);
        if seen.insert(scheme) {
            samples.push(config.clone());
        }
        if samples.len() >= 12 {
            break;
        }
    }

    println!("[DIAG] TCP testing {} protocol samples.", samples.len());

    for (index, config) in samples.iter().enumerate() {
        println!(
            "[DIAG] Sample {} [{}]: {}",
            index + 1,
            config_scheme(config),
            config
        );
        println!(
            "[DIAG] TCP result: {}",
            if tcp_reachable(config).await { "PASS" } else { "FAIL" }
        );
    }
}
