use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt, TryStreamExt};
use percent_encoding::percent_decode_str;
use proxyrift::validator::{config_label, endpoint};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::Endpoint;
use regex::Regex;
use reqwest::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration, Instant};
use url::Url;
use wireguard_sans_io::{
    Config as WireGuardConfig, EntropyError, EntropySource, Now as WireGuardNow, PresharedKey,
    PublicKey, Received, StaticSecret, Tunnel,
};

const DOWNLOAD_CONCURRENCY: usize = 16;
const TEST_CONCURRENCY: usize = 8;
const TEST_CONNECTION_CONCURRENCY: usize = 64;
const CHUNK_SIZE: usize = 2000;
const TCP_TIMEOUT_SECS: u64 = 3;
const MAX_COMPACT_BASE64_BYTES: usize = 4 * 1024 * 1024;
const MAX_ALL_CONFIGS: usize = 2000;
const MAX_LIGHT_CANDIDATES: usize = 10000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("[INFO] ProxyRift starting...");

    let root = project_root()?;
    let sources_path = root.join("sources.txt");
    let output_dir = root.join("subscriptions");
    fs::create_dir_all(&output_dir).await?;

    let sources = load_sources(&sources_path).await?;
    println!("[INFO] Loaded {} sources.", sources.len());

    let client = Client::builder()
        .user_agent("ProxyRift/3.0")
        .timeout(Duration::from_secs(20))
        .build()?;

    let mut unique = HashSet::new();
    let mut source_results = stream::iter(sources.iter().cloned())
        .map(|url| {
            let client = client.clone();
            let source_label = source_label(&url);
            async move {
                println!("[INFO] Downloading source {source_label}");
                match client.get(&url).send().await {
                    Ok(response) => match response.error_for_status() {
                        Ok(response) => match response.text().await {
                            Ok(text) => {
                                let configs = extract_configs(&text);
                                println!(
                                    "[INFO] Found {} configs from source {source_label}.",
                                    configs.len()
                                );
                                configs
                            }
                            Err(error) => {
                                println!("[WARN] Failed to read source {source_label}: {error}");
                                Vec::new()
                            }
                        },
                        Err(error) => {
                            println!("[WARN] Failed to download source {source_label}: {error}");
                            Vec::new()
                        }
                    },
                    Err(error) => {
                        println!("[WARN] Failed to download source {source_label}: {error}");
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

    let all_path = output_dir.join("all.txt");

    let mut chunk_results = stream::iter(configs.chunks(CHUNK_SIZE).enumerate())
        .map(|(index, chunk)| async move { test_chunk(index, chunk).await })
        .buffer_unordered(TEST_CONCURRENCY)
        .try_collect::<Vec<(usize, Vec<(String, u64)>)>>()
        .await?;

    chunk_results.sort_by_key(|(index, _)| *index);

    let mut ranked_working_configs = Vec::new();
    let mut reachable_probes = 0usize;

    for (_, working) in chunk_results {
        reachable_probes += working.len();
        ranked_working_configs.extend(working);
    }

    if ranked_working_configs.is_empty() {
        println!("[WARN] No usable configs remained after transport-aware reachability screening.");
        diagnose_configs(&configs).await;
        return Ok(());
    }

    ranked_working_configs.sort_unstable_by(|(config_a, latency_a), (config_b, latency_b)| {
        latency_a
            .cmp(latency_b)
            .then_with(|| config_a.cmp(config_b))
    });

    let light_target = MAX_LIGHT_CANDIDATES.min(ranked_working_configs.len());
    let mut light_candidates = Vec::with_capacity(light_target);
    let mut light_candidate_endpoints = HashSet::new();

    if light_target == ranked_working_configs.len() {
        for (config, _) in &ranked_working_configs {
            if let Some(endpoint) = endpoint(config) {
                if light_candidate_endpoints.insert(endpoint) {
                    light_candidates.push(config.clone());
                }
            }
        }
    } else if light_target > 0 {
        let last_index = ranked_working_configs.len() - 1;
        let last_slot = light_target - 1;

        for slot in 0..light_target {
            let index = if last_slot == 0 {
                0
            } else {
                slot.saturating_mul(last_index) / last_slot
            };

            let (config, _) = &ranked_working_configs[index];
            if let Some(endpoint) = endpoint(config) {
                if light_candidate_endpoints.insert(endpoint) {
                    light_candidates.push(config.clone());
                }
            }
        }

        if light_candidates.len() < light_target {
            for (config, _) in &ranked_working_configs {
                if light_candidates.len() >= light_target {
                    break;
                }

                if let Some(endpoint) = endpoint(config) {
                    if light_candidate_endpoints.insert(endpoint) {
                        light_candidates.push(config.clone());
                    }
                }
            }
        }
    }

    println!(
        "[INFO] Light candidate sampling: selected {} of {} transport-reachable configs across the ranked pool.",
        light_candidates.len(),
        ranked_working_configs.len()
    );
    let light_candidates_path = output_dir.join(".light-candidates.txt");
    let light_candidates_subscription = if light_candidates.is_empty() {
        String::new()
    } else {
        format!("{}\n", light_candidates.join("\n"))
    };
    fs::write(&light_candidates_path, light_candidates_subscription).await?;

    let mut working_configs = Vec::with_capacity(MAX_ALL_CONFIGS.min(ranked_working_configs.len()));
    let mut seen = HashSet::new();

    for (config, _) in ranked_working_configs {
        if seen.insert(config.clone()) {
            working_configs.push(config);
            if working_configs.len() >= MAX_ALL_CONFIGS {
                break;
            }
        }
    }

    let all_subscription = format!("{}\n", working_configs.join("\n"));
    let temporary_all = output_dir.join(".all.txt");
    fs::write(&temporary_all, all_subscription).await?;
    fs::rename(&temporary_all, &all_path).await?;

    println!(
        "[INFO] Published {} configs to All, prioritizing the fastest transport-reachable configs ({} reachable configs; cap {}).",
        working_configs.len(),
        reachable_probes,
        MAX_ALL_CONFIGS
    );
    println!(
        "[INFO] Prepared {} transport-reachable Light candidates (cap {}).",
        light_candidates.len(),
        MAX_LIGHT_CANDIDATES
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

async fn load_sources(
    path: &Path,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let content = fs::read_to_string(path).await?;
    let mut seen = HashSet::new();
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| seen.insert(*line))
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
    let Some(authority) = config
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['?', '#']).next())
    else {
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
        percent_decode_str(url.username())
            .decode_utf8()
            .ok()?
            .into_owned()
    } else {
        let payload = config
            .split_once("://")?
            .1
            .split('#')
            .next()?
            .split('@')
            .next()?;
        let mut padded = payload.to_string();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }

        let decoded = [
            STANDARD.decode(payload),
            STANDARD.decode(&padded),
            URL_SAFE.decode(payload),
            URL_SAFE_NO_PAD.decode(payload),
        ]
        .into_iter()
        .find_map(Result::ok)?;

        let decoded = String::from_utf8(decoded).ok()?;
        decoded.split_once(':')?.0.to_string()
    };

    if METHODS
        .iter()
        .any(|supported| method.eq_ignore_ascii_case(supported))
    {
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
            && !matches!(
                value.to_ascii_lowercase().as_str(),
                "none" | "tls" | "reality"
            )
    }) {
        return None;
    }

    if url.query_pairs().any(|(key, value)| {
        key.eq_ignore_ascii_case("encryption") && !value.eq_ignore_ascii_case("none")
    }) {
        return None;
    }

    if url.query_pairs().any(|(key, value)| {
        (key.eq_ignore_ascii_case("packetencoding") || key.eq_ignore_ascii_case("packet-encoding"))
            && !matches!(
                value.to_ascii_lowercase().as_str(),
                "xudp" | "packetaddr" | "none"
            )
    }) {
        return None;
    }

    if url
        .query_pairs()
        .any(|(key, _)| key.eq_ignore_ascii_case("fm"))
    {
        return None;
    }

    if url.query_pairs().any(|(key, value)| {
        key.eq_ignore_ascii_case("path") && value.to_ascii_lowercase().contains("security=tls")
    }) {
        return None;
    }

    if is_invalid_vless_reality_public_key(url) {
        return None;
    }

    Some(config.to_string())
}

fn is_invalid_vless_reality_public_key(url: &Url) -> bool {
    let is_reality = url.query_pairs().any(|(key, value)| {
        key.eq_ignore_ascii_case("security") && value.eq_ignore_ascii_case("reality")
    });

    if !is_reality {
        return false;
    }

    let Some(public_key) = url
        .query_pairs()
        .find_map(|(key, value)| key.eq_ignore_ascii_case("pbk").then(|| value.into_owned()))
    else {
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
    if add.is_empty()
        || add
            .chars()
            .any(|c| c.is_control() || c == ' ' || c == '/' || c == '\\')
    {
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
    let mut padded = encoded.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }

    let candidates: &[&str] = if padded == encoded {
        &[encoded]
    } else {
        &[encoded, padded.as_str()]
    };

    for candidate in candidates {
        for decoded in [
            STANDARD.decode(candidate),
            URL_SAFE.decode(candidate),
            URL_SAFE_NO_PAD.decode(candidate),
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
            c == ')'
                || c == ']'
                || c == '}'
                || c == ','
                || c == ';'
                || c == '.'
                || c == '\r'
                || c == '\n'
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

fn looks_like_base64(value: &str) -> bool {
    value.len() >= 16
        && value.len() <= 8192
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
        })
}

fn decode_base64_variants(text: &str) -> Vec<String> {
    let mut inputs = Vec::new();

    if !text.contains("://") && text.len() <= MAX_COMPACT_BASE64_BYTES.saturating_mul(2) {
        let compact = text.split_whitespace().collect::<String>();
        if compact.len() <= MAX_COMPACT_BASE64_BYTES && looks_like_base64(&compact) {
            inputs.push(compact);
        }
    }

    inputs.extend(
        text.lines()
            .map(str::trim)
            .filter(|line| looks_like_base64(line))
            .map(ToOwned::to_owned),
    );
    inputs.sort_unstable();
    inputs.dedup();

    let mut results = Vec::new();

    for input in inputs {
        let mut padded = input.clone();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }

        let candidates: &[&str] = if padded == input {
            &[input.as_str()]
        } else {
            &[input.as_str(), padded.as_str()]
        };

        for candidate in candidates {
            for decoded in [
                STANDARD.decode(candidate),
                URL_SAFE.decode(candidate),
                URL_SAFE_NO_PAD.decode(candidate),
            ] {
                if let Ok(bytes) = decoded {
                    if bytes
                        .iter()
                        .filter(|byte| **byte < 0x20 && !matches!(**byte, b'\n' | b'\r' | b'\t'))
                        .count()
                        > 8
                    {
                        continue;
                    }

                    let decoded = String::from_utf8_lossy(&bytes);
                    if decoded.contains("://") {
                        results.push(decoded.into_owned());
                    }
                }
            }
        }
    }

    results.sort_unstable();
    results.dedup();
    results
}

fn config_scheme(config: &str) -> String {
    config
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

fn source_label(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "<invalid source>".to_string())
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

async fn transport_reachable(config: &str) -> bool {
    transport_latency(config).await.is_some()
}

async fn test_transport_configs(configs: &[String]) -> Vec<(String, u64)> {
    let mut tcp_by_endpoint: HashMap<(String, u16), Vec<usize>> = HashMap::new();
    let mut transport_indices = Vec::new();

    for (index, config) in configs.iter().enumerate() {
        let scheme = config_scheme(config);
        if matches!(
            scheme.as_str(),
            "hysteria" | "hysteria2" | "hy2" | "tuic" | "wg"
        ) {
            transport_indices.push(index);
            continue;
        }

        if let Some(endpoint) = endpoint(config) {
            tcp_by_endpoint.entry(endpoint).or_default().push(index);
        }
    }

    let tcp_config_count: usize = tcp_by_endpoint.values().map(Vec::len).sum();
    if tcp_config_count > 0 {
        println!(
            "[INFO] TCP endpoint deduplication: {} configs -> {} unique endpoints.",
            tcp_config_count,
            tcp_by_endpoint.len()
        );
    }

    let tcp_results = stream::iter(tcp_by_endpoint.keys().cloned())
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

    for ((host, port), latency_ms) in tcp_results {
        if let Some(indices) = tcp_by_endpoint.get(&(host, port)) {
            working.extend(
                indices
                    .iter()
                    .map(|&index| (configs[index].clone(), latency_ms)),
            );
        }
    }

    if !transport_indices.is_empty() {
        println!(
            "[INFO] Protocol-aware UDP probing: {} transport configs.",
            transport_indices.len()
        );

        let udp_results = stream::iter(transport_indices)
            .map(|index| async move {
                transport_latency(&configs[index])
                    .await
                    .map(|latency| (index, latency))
            })
            .buffer_unordered(TEST_CONNECTION_CONCURRENCY)
            .filter_map(async move |result| result)
            .collect::<Vec<_>>()
            .await;

        working.extend(
            udp_results
                .into_iter()
                .map(|(index, latency)| (configs[index].clone(), latency)),
        );
    }

    working
}

async fn test_chunk(
    index: usize,
    configs: &[String],
) -> Result<(usize, Vec<(String, u64)>), Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "[INFO] Testing chunk {}: {} configs with transport-aware reachability.",
        index,
        configs.len()
    );

    let working = test_transport_configs(configs).await;

    println!(
        "[INFO] Chunk {} complete: {}/{} transport-reachable.",
        index,
        working.len(),
        configs.len()
    );

    Ok((index, working))
}

// This verifier is only for transport reachability. The actual proxy validation
// later in the pipeline performs normal certificate handling.
#[derive(Debug)]
struct ProbeCertVerifier;

impl ServerCertVerifier for ProbeCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn quic_client_config(alpn: &[String]) -> Option<quinn::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ProbeCertVerifier))
        .with_no_client_auth();

    tls.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();

    let crypto = QuicClientConfig::try_from(tls).ok()?;
    Some(quinn::ClientConfig::new(Arc::new(crypto)))
}

fn query_values(config: &str, key: &str) -> Vec<String> {
    Url::parse(config)
        .ok()
        .map(|url| {
            url.query_pairs()
                .filter(|(name, _)| name.eq_ignore_ascii_case(key))
                .map(|(_, value)| value.into_owned())
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn query_value(config: &str, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| query_values(config, key).into_iter().next())
}

fn quic_params(config: &str) -> Option<(String, u16, String, Vec<String>)> {
    let url = Url::parse(config).ok()?;
    let host = url.host_str()?.to_string();
    let port = url.port()?;

    if query_value(config, &["obfs"]).is_some() {
        return None;
    }

    let sni = query_value(config, &["sni", "server_name"]).unwrap_or_else(|| host.clone());

    let alpn = {
        let values = query_values(config, "alpn");
        if values.is_empty() {
            vec!["h3".to_string()]
        } else {
            values
        }
    };

    Some((host, port, sni, alpn))
}

async fn quic_latency(config: &str) -> Option<u64> {
    let (host, port, sni, alpn) = quic_params(config)?;

    let mut addresses = timeout(
        Duration::from_secs(TCP_TIMEOUT_SECS),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .ok()?
    .ok()?
    .collect::<Vec<_>>();

    addresses.sort_by_key(|address| !address.is_ipv4());

    for address in addresses {
        let local = if address.ip().is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };

        let endpoint = Endpoint::client(local).ok()?;
        let client_config = quic_client_config(&alpn)?;
        let connecting = endpoint.connect_with(client_config, address, &sni).ok()?;
        let start = Instant::now();

        let connected = match timeout(Duration::from_secs(TCP_TIMEOUT_SECS), connecting).await {
            Ok(Ok(connection)) => connection,
            _ => {
                endpoint.close(0u32.into(), b"probe timeout");
                continue;
            }
        };

        let latency = start.elapsed().as_millis() as u64;
        connected.close(0u32.into(), b"probe complete");
        endpoint.close(0u32.into(), b"probe complete");
        return Some(latency);
    }

    None
}

struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(buf).map_err(|_| EntropyError)
    }
}

fn wireguard_key(config: &str, keys: &[&str]) -> Option<[u8; 32]> {
    let encoded = query_value(config, keys)?;
    let decoded = STANDARD
        .decode(encoded.as_bytes())
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded.as_bytes()))
        .ok()?;

    decoded.try_into().ok()
}

fn wireguard_private_key(config: &str) -> Option<[u8; 32]> {
    if let Some(key) = wireguard_key(
        config,
        &[
            "privatekey",
            "private-key",
            "private_key",
            "private_key_base64",
        ],
    ) {
        return Some(key);
    }

    let url = Url::parse(config).ok()?;
    let username = percent_decode_str(url.username()).decode_utf8().ok()?;
    if username.is_empty() {
        return None;
    }

    let decoded = STANDARD
        .decode(username.as_bytes())
        .or_else(|_| URL_SAFE_NO_PAD.decode(username.as_bytes()))
        .ok()?;

    decoded.try_into().ok()
}

async fn wireguard_latency(config: &str) -> Option<u64> {
    let (host, port) = endpoint(config)?;
    let private_key = wireguard_private_key(config)?;
    let public_key = wireguard_key(
        config,
        &[
            "publickey",
            "public-key",
            "public_key",
            "peer-public-key",
            "peer_public_key",
            "pubkey",
        ],
    )?;

    let psk = wireguard_key(
        config,
        &["presharedkey", "preshared-key", "preshared_key", "psk"],
    );

    let mut addresses = timeout(
        Duration::from_secs(TCP_TIMEOUT_SECS),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .ok()?
    .ok()?
    .collect::<Vec<_>>();

    addresses.sort_by_key(|address| !address.is_ipv4());

    for address in addresses {
        let mut wg_config = WireGuardConfig::new(
            StaticSecret::from_bytes(private_key),
            PublicKey::from_bytes(public_key),
        );
        if let Some(psk) = psk {
            wg_config.psk = PresharedKey::from_bytes(psk);
        }

        let mut tunnel = Tunnel::new(wg_config).ok()?;

        let local = if address.ip().is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };

        let socket = UdpSocket::bind(local).await.ok()?;
        socket.connect(address).await.ok()?;

        let start = std::time::Instant::now();
        let mut rng = OsEntropy;
        let mut send_buf = [0u8; 2048];
        let init = tunnel
            .initiate_handshake(wireguard_now(start), &mut send_buf, &mut rng)
            .ok()?
            .to_vec();

        socket.send(&init).await.ok()?;

        let deadline = start + std::time::Duration::from_secs(TCP_TIMEOUT_SECS);
        let remote = address.to_string().into_bytes();
        let mut recv_buf = [0u8; 2048];

        loop {
            let now = std::time::Instant::now();
            if now >= deadline {
                break;
            }

            let remaining = deadline.duration_since(now);
            let received = match timeout(remaining, socket.recv(&mut recv_buf)).await {
                Ok(Ok(size)) => size,
                _ => break,
            };

            match tunnel.decapsulate(
                wireguard_now(start),
                &remote,
                false,
                &recv_buf[..received],
                &mut send_buf,
                &mut rng,
            ) {
                Ok(Received::HandshakeComplete) => {
                    return Some(start.elapsed().as_millis() as u64);
                }
                Ok(Received::CookieStored) => {
                    let retry = tunnel
                        .initiate_handshake(wireguard_now(start), &mut send_buf, &mut rng)
                        .ok()?
                        .to_vec();
                    socket.send(&retry).await.ok()?;
                }
                Ok(Received::Reply(reply)) => {
                    socket.send(reply).await.ok()?;
                }
                Ok(Received::Keepalive) | Ok(Received::Data(_)) => {}
                Err(_) => {}
            }
        }
    }

    None
}

async fn transport_latency(config: &str) -> Option<u64> {
    match config_scheme(config).as_str() {
        "hysteria" | "hysteria2" | "hy2" | "tuic" => quic_latency(config).await,
        "wg" => wireguard_latency(config).await,
        _ => {
            let (host, port) = endpoint(config)?;
            tcp_latency_endpoint(&host, port).await
        }
    }
}

fn wireguard_now(start: std::time::Instant) -> WireGuardNow {
    let elapsed = start.elapsed();
    let ticks = elapsed
        .as_secs()
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(elapsed.subsec_nanos()));
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    WireGuardNow::new(ticks, wall.as_secs(), wall.subsec_nanos())
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

    println!(
        "[DIAG] Transport testing {} protocol samples.",
        samples.len()
    );

    for (index, config) in samples.iter().enumerate() {
        println!(
            "[DIAG] Sample {} [{}]: {}",
            index + 1,
            config_scheme(config),
            config_label(config)
        );
        println!(
            "[DIAG] Transport result: {}",
            if transport_reachable(config).await {
                "PASS"
            } else {
                "FAIL"
            }
        );
    }
}
