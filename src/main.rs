use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt, TryStreamExt};
use percent_encoding::percent_decode_str;
use regex::Regex;
use reqwest::Client;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::fs;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration, Instant};
use url::Url;

const DOWNLOAD_CONCURRENCY: usize = 16;
const TEST_CONCURRENCY: usize = 8;
const TEST_CONNECTION_CONCURRENCY: usize = 64;
const CHUNK_SIZE: usize = 2000;
const TCP_TIMEOUT_SECS: u64 = 3;
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
    let _ = fs::remove_file(&working_path).await;

    let mut endpoint_groups: HashMap<(String, u16), Vec<String>> = HashMap::new();
    let mut endpoint_representatives = Vec::new();
    let mut transport_passthrough = Vec::new();

    for config in &configs {
        let scheme = config_scheme(config);

        if matches!(scheme.as_str(), "hysteria" | "hysteria2" | "hy2" | "tuic" | "wg") {
            transport_passthrough.push(config.clone());
            continue;
        }

        let Some(endpoint) = endpoint(config) else {
            continue;
        };

        if !endpoint_groups.contains_key(&endpoint) {
            endpoint_representatives.push(config.clone());
        }
        endpoint_groups
            .entry(endpoint)
            .or_default()
            .push(config.clone());
    }

    let total_testable_configs: usize = endpoint_groups.values().map(Vec::len).sum();
    println!(
        "[INFO] TCP endpoint deduplication: {} TCP configs -> {} unique TCP endpoints; {} UDP/transport configs passed through.",
        total_testable_configs,
        endpoint_representatives.len(),
        transport_passthrough.len()
    );

    let mut chunk_results = stream::iter(endpoint_representatives.chunks(CHUNK_SIZE).enumerate())
        .map(|(index, chunk)| {
            async move { test_chunk(index, format!("{index}"), chunk.to_vec()).await }
        })
        .buffer_unordered(TEST_CONCURRENCY)
        .try_collect::<Vec<(usize, Vec<(String, u64)>)>>()
        .await?;

    chunk_results.sort_by_key(|(index, _)| *index);

    let mut working_configs = transport_passthrough;
    let mut reachable_endpoints = 0usize;

    for (_, working) in chunk_results {
        reachable_endpoints += working.len();

        for (representative, _) in working {
            let Some(endpoint_key) = endpoint(&representative) else {
                continue;
            };
            if let Some(group) = endpoint_groups.get(&endpoint_key) {
                working_configs.extend(group.iter().cloned());
            }
        }
    }

    if working_configs.is_empty() {
        println!("[WARN] No usable configs remained after transport filtering and TCP reachability screening.");
        diagnose_configs(&configs).await;
        return Ok(());
    }

    working_configs.sort_unstable();
    working_configs.dedup();

    let all_subscription = format!("{}\n", working_configs.join("\n"));
    let temporary_all = output_dir.join(".all.txt");
    fs::write(&temporary_all, all_subscription).await?;
    fs::rename(&temporary_all, &all_path).await?;

    println!(
        "[INFO] Published {} TCP-reachable configs from {} reachable endpoints.",
        working_configs.len(),
        reachable_endpoints
    );
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