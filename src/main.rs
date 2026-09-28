use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt, TryStreamExt};
use percent_encoding::percent_decode_str;
use proxyrift::validator::{config_label, endpoint};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use regex::Regex;
use reqwest::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
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

// Keep total endpoint probes bounded. The previous 8 x 64 nesting could create
// roughly 512 simultaneous probes before address fan-out was even considered.
const TEST_CONCURRENCY: usize = 2;
const TEST_CONNECTION_CONCURRENCY: usize = 32;

const MAX_TCP_ADDRESS_CONCURRENCY: usize = 8;
const MAX_QUIC_TARGET_CONCURRENCY: usize = 8;
const MAX_WIREGUARD_ADDRESS_CONCURRENCY: usize = 4;

const CHUNK_SIZE: usize = 2000;
const TCP_TIMEOUT_SECS: u64 = 3;
const MAX_BASE64_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;

// Bound total discovery work before transport probing. The final published pool
// is capped separately by MAX_ALL_CONFIGS.
const MAX_DISCOVERED_CONFIGS: usize = 20_000;

const MAX_ALL_CONFIGS: usize = 2000;
const MAX_LIGHT_CANDIDATES: usize = 10000;

#[derive(Debug)]
enum SourceBodyError {
    TooLarge,
    Read,
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

    let mut source_results = stream::iter(sources.iter().cloned().enumerate())
        .map(|(source_index, url)| {
            let client = client.clone();

            async move {
                let source_number = source_index + 1;
                println!("[INFO] Downloading source #{source_number}");

                match client.get(&url).send().await {
                    Ok(response) => {
                        let status = response.status();

                        if !status.is_success() {
                            println!(
                                "[WARN] Source #{source_number} returned HTTP status {status}"
                            );
                            return Vec::new();
                        }

                        if response
                            .content_length()
                            .is_some_and(|length| length > MAX_SOURCE_BYTES as u64)
                        {
                            println!(
                                "[WARN] Skipping source #{source_number}: response exceeds {} bytes",
                                MAX_SOURCE_BYTES
                            );
                            return Vec::new();
                        }

                        match read_source_body(response).await {
                            Ok(bytes) => match String::from_utf8(bytes) {
                                Ok(text) => {
                                    let configs = extract_configs(&text);

                                    println!(
                                        "[INFO] Found {} configs from source #{source_number}.",
                                        configs.len()
                                    );

                                    configs
                                }

                                Err(error) => {
                                    println!(
                                        "[WARN] Failed to decode source #{source_number} as UTF-8: {error}"
                                    );
                                    Vec::new()
                                }
                            },

                            Err(SourceBodyError::TooLarge) => {
                                println!(
                                    "[WARN] Skipping source #{source_number}: response exceeds {} bytes",
                                    MAX_SOURCE_BYTES
                                );
                                Vec::new()
                            }

                            Err(SourceBodyError::Read) => {
                                println!("[WARN] Failed to read source #{source_number}.");
                                Vec::new()
                            }
                        }
                    }

                    Err(error) => {
                        println!(
                            "[WARN] Failed to download source #{source_number}: {error}"
                        );
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

    if configs.len() > MAX_DISCOVERED_CONFIGS {
        println!(
            "[WARN] Discovery produced {} configs; sampling down to {} before transport testing.",
            configs.len(),
            MAX_DISCOVERED_CONFIGS
        );

        configs = sample_evenly(&configs, MAX_DISCOVERED_CONFIGS);
    }

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

    let hysteria_candidates = configs
        .iter()
        .filter(|config| config_scheme(config) == "hysteria")
        .cloned()
        .collect::<Vec<_>>();

    let hysteria2_candidates = configs
        .iter()
        .filter(|config| matches!(config_scheme(config).as_str(), "hysteria2" | "hy2"))
        .cloned()
        .collect::<Vec<_>>();

    let mut special_hysteria_candidates = hysteria_candidates.clone();
    special_hysteria_candidates.extend(hysteria2_candidates.iter().cloned());

    if ranked_working_configs.is_empty() && special_hysteria_candidates.is_empty() {
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
                slot.saturating_mul(last_index)
                    .checked_div(last_slot)
                    .unwrap_or_default()
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

    let sampled_transport_count = light_candidates.len();

    for config in &special_hysteria_candidates {
        if light_candidates.len() >= MAX_LIGHT_CANDIDATES {
            break;
        }

        if let Some(ep) = endpoint(config) {
            if light_candidate_endpoints.insert(ep) {
                light_candidates.push(config.clone());
            }
        }
    }

    let special_count = light_candidates
        .len()
        .saturating_sub(sampled_transport_count);

    println!(
        "[INFO] Light candidate sampling: selected {} transport-reachable configs and retained {} Hysteria/Hysteria2 candidates for core validation.",
        sampled_transport_count,
        special_count
    );

    let light_candidates_path = output_dir.join(".light-candidates.txt");

    let light_candidates_subscription = if light_candidates.is_empty() {
        String::new()
    } else {
        format!("{}\n", light_candidates.join("\n"))
    };

    fs::write(&light_candidates_path, light_candidates_subscription).await?;

    let working_configs =
        select_all_candidates(&ranked_working_configs, &special_hysteria_candidates);

    let all_subscription = if working_configs.is_empty() {
        String::new()
    } else {
        format!("{}\n", working_configs.join("\n"))
    };

    let temporary_all = output_dir.join(".all.txt");

    fs::write(&temporary_all, all_subscription).await?;
    fs::rename(&temporary_all, &all_path).await?;

    println!(
        "[INFO] Prepared {} core-validation candidates for All ({} transport-reachable; cap {}).",
        working_configs.len(),
        reachable_probes,
        MAX_ALL_CONFIGS
    );

    println!(
        "[INFO] Prepared {} Light candidates (cap {}).",
        light_candidates.len(),
        MAX_LIGHT_CANDIDATES
    );

    println!("[INFO] Done.");

    Ok(())
}

fn append_limited_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> bool {
    if chunk.len() > MAX_SOURCE_BYTES.saturating_sub(body.len()) {
        return false;
    }

    body.extend_from_slice(chunk);
    true
}

async fn read_source_body(mut response: reqwest::Response) -> Result<Vec<u8>, SourceBodyError> {
    let mut body = Vec::new();

    while let Some(chunk) = response.chunk().await.map_err(|_| SourceBodyError::Read)? {
        if !append_limited_chunk(&mut body, &chunk) {
            return Err(SourceBodyError::TooLarge);
        }
    }

    Ok(body)
}

fn project_root() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let cwd = env::current_dir()?;

    if cwd.join("sources.txt").is_file() {
        return Ok(cwd);
    }

    let exe = env::current_exe()?;

    for ancestor in exe.ancestors() {
        if ancestor.join("sources.txt").is_file() {
            return Ok(ancestor.to_path_buf());
        }
    }

    for ancestor in exe.ancestors() {
        if ancestor.join("Cargo.toml").is_file() {
            return Ok(ancestor.to_path_buf());
        }
    }

    Err("failed to determine project root".into())
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

fn sample_evenly(configs: &[String], target: usize) -> Vec<String> {
    if target == 0 || configs.is_empty() {
        return Vec::new();
    }

    if target >= configs.len() {
        return configs.to_vec();
    }

    if target == 1 {
        return vec![configs[0].clone()];
    }

    let last = configs.len() - 1;
    let last_slot = target - 1;

    let mut sampled = Vec::with_capacity(target);

    for slot in 0..target {
        let index = slot
            .saturating_mul(last)
            .checked_div(last_slot)
            .unwrap_or_default();

        sampled.push(configs[index].clone());
    }

    sampled
}

fn config_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();

    PATTERN.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:vmess|vless|trojan|ss|socks(?:4a?|5h?)?|hysteria|hysteria2|hy2|wg|http)://[^\s<>"']+"#,
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
    if config
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return None;
    }

    if has_invalid_percent_escapes(&config) || has_bracketed_ipv4_host(&config) {
        return None;
    }

    let scheme = config_scheme(&config);

    if !matches!(
        scheme.as_str(),
        "vless"
            | "vmess"
            | "trojan"
            | "ss"
            | "hysteria"
            | "hysteria2"
            | "hy2"
            | "wg"
            | "socks"
            | "socks4"
            | "socks4a"
            | "socks5"
            | "socks5h"
            | "http"
    ) {
        return None;
    }

    if scheme == "vmess" {
        return normalize_vmess(&config);
    }

    // Hysteria2 supports port-hopping syntax such as:
    // host:1234,5000-5002
    // which Url::parse rejects because the authority is not a single u16 port.
    if matches!(scheme.as_str(), "hysteria2" | "hy2") {
        return normalize_hysteria2(&config);
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

    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);

    let decoded = percent_decode_str(host_port).decode_utf8_lossy();

    let host = if let Some(stripped) = decoded.strip_prefix('[') {
        stripped.split_once(']').map(|(host, _)| host)
    } else {
        None
    };

    let Some(host) = host else {
        return false;
    };

    host.parse::<Ipv4Addr>().is_ok()
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

    fn supported(method: &str, methods: &[&str]) -> bool {
        methods
            .iter()
            .any(|candidate| method.eq_ignore_ascii_case(candidate))
    }

    if !url.username().is_empty() {
        let userinfo = percent_decode_str(url.username()).decode_utf8().ok()?;

        let method = if url.password().is_some() {
            userinfo.to_string()
        } else if let Some((method, _)) = userinfo.split_once(':') {
            method.to_string()
        } else {
            let decoded = decode_base64_string(&userinfo)?;
            decoded.split_once(':')?.0.to_string()
        };

        return supported(&method, METHODS).then(|| config.to_string());
    }

    let payload = config.split_once("://")?.1.split('#').next()?;

    if let Some((credentials, _remote)) = payload.rsplit_once('@') {
        let decoded = decode_base64_string(credentials)?;
        let method = decoded.split_once(':')?.0;

        return supported(method, METHODS).then(|| config.to_string());
    }

    let decoded = decode_base64_string(payload)?;
    let (credentials, _remote) = decoded.rsplit_once('@')?;
    let method = credentials.split_once(':')?.0;

    supported(method, METHODS).then(|| config.to_string())
}

fn valid_vless_encryption(value: &str) -> bool {
    let blocks = value.split('.').collect::<Vec<_>>();

    if blocks.len() < 4 || blocks[0] != "mlkem768x25519plus" {
        return false;
    }

    if !matches!(blocks[1], "native" | "xorpub" | "random") || !matches!(blocks[2], "1rtt" | "0rtt")
    {
        return false;
    }

    let mut has_key = false;

    if !blocks[3..].iter().all(|block| {
        if block.len() < 20 {
            return true;
        }

        let valid = matches!(
            URL_SAFE_NO_PAD.decode(block),
            Ok(bytes) if bytes.len() == 32 || bytes.len() == 1184
        );

        has_key |= valid;
        valid
    }) {
        return false;
    }

    has_key
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
            && !value.trim().is_empty()
            && !matches!(
                value.to_ascii_lowercase().as_str(),
                "none" | "tls" | "reality"
            )
    }) {
        return None;
    }

    if url.query_pairs().any(|(key, value)| {
        key.eq_ignore_ascii_case("encryption")
            && !value.trim().is_empty()
            && !value.eq_ignore_ascii_case("none")
            && !valid_vless_encryption(value.as_ref())
    }) {
        return None;
    }

    if url.query_pairs().any(|(key, value)| {
        (key.eq_ignore_ascii_case("packetencoding") || key.eq_ignore_ascii_case("packet-encoding"))
            && !value.trim().is_empty()
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

    // Do not reject a valid path merely because its literal path text happens
    // to contain "security=tls". The path is not re-parsed as a query.
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

    if public_key.len() != 43
        || !public_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return true;
    }

    !matches!(URL_SAFE_NO_PAD.decode(public_key), Ok(bytes) if bytes.len() == 32)
}

fn normalize_hysteria2(config: &str) -> Option<String> {
    let (_, port_spec, _) = hysteria2_parts(config)?;

    if !port_spec.is_empty() {
        hysteria2_probe_ports(config)?;
    }

    for key in ["fp", "fingerprint"] {
        if hysteria2_query_values(config, key)
            .into_iter()
            .any(|value| value.eq_ignore_ascii_case("unsafe"))
        {
            return None;
        }
    }

    Some(config.to_string())
}

fn hysteria2_parts(config: &str) -> Option<(String, String, String)> {
    let rest = config.split_once("://")?.1;
    let authority = rest.split(['?', '#']).next()?;

    let (auth_raw, host_port) = authority.rsplit_once('@')?;

    if auth_raw.is_empty() || host_port.is_empty() {
        return None;
    }

    let password = percent_decode_str(auth_raw).decode_utf8().ok()?;

    if password.is_empty() {
        return None;
    }

    let (host, port_spec) = if let Some(stripped) = host_port.strip_prefix('[') {
        let (host, remainder) = stripped.split_once(']')?;

        if host.is_empty()
            || host.chars().any(|c| c.is_whitespace() || c.is_control())
            || host.parse::<Ipv6Addr>().is_err()
        {
            return None;
        }

        if !remainder.is_empty() && !remainder.starts_with(':') {
            return None;
        }

        (
            host.to_string(),
            remainder.strip_prefix(':').unwrap_or("").to_string(),
        )
    } else if let Some((host, port_spec)) = host_port.rsplit_once(':') {
        if host.is_empty()
            || host.contains(':')
            || host.contains('[')
            || host.contains(']')
            || host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\'))
        {
            return None;
        }

        (host.to_string(), port_spec.to_string())
    } else {
        if host_port
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '[' | ']' | '/' | '\\'))
        {
            return None;
        }

        (host_port.to_string(), String::new())
    };

    if host.is_empty() {
        return None;
    }

    Some((host, port_spec, auth_raw.to_string()))
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

fn decode_base64_string(encoded: &str) -> Option<String> {
    let mut padded = encoded.to_string();

    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }

    let candidates: &[&str] = if padded == encoded {
        &[encoded]
    } else {
        &[encoded, padded.as_str()]
    };

    for candidate in candidates {
        for bytes in [
            STANDARD.decode(candidate),
            URL_SAFE.decode(candidate),
            URL_SAFE_NO_PAD.decode(candidate),
        ]
        .into_iter()
        .flatten()
        {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
    }

    None
}

fn decode_vmess_payload(encoded: &str) -> Option<String> {
    decode_base64_string(encoded)
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
    let config = config.trim();

    // Preserve meaningful fragments for standard URL schemes.
    // Hysteria2 port-hopping syntax cannot be parsed by Url::parse when the port
    // list is present, so we strip the fragment only for that scheme before parse.
    if let Ok(url) = Url::parse(config) {
        let scheme = url.scheme().to_ascii_lowercase();
        if matches!(scheme.as_str(), "hysteria2" | "hy2") {
            let mut sanitized = url;
            sanitized.set_fragment(None);
            return sanitized.to_string();
        }

        return config.to_string();
    }

    if let Some((base, _)) = config.split_once('#') {
        let candidate = base.trim();
        if !candidate.is_empty() {
            let parsed = Url::parse(candidate);
            if let Ok(url) = parsed {
                let scheme = url.scheme().to_ascii_lowercase();
                if matches!(scheme.as_str(), "hysteria2" | "hy2") {
                    let mut sanitized = url;
                    sanitized.set_fragment(None);
                    return sanitized.to_string();
                }
            }
        }
    }

    config.to_string()
}

fn percent_encode_fragment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());

    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }

            _ => {
                encoded.push('%');
                encoded.push(HEX[(byte >> 4) as usize] as char);
                encoded.push(HEX[(byte & 0x0F) as usize] as char);
            }
        }
    }

    encoded
}

fn set_config_fragment(config: &str, name: &str) -> String {
    let base = config.split('#').next().unwrap_or(config);

    format!("{}#{}", base, percent_encode_fragment(name))
}

fn assign_config_names(configs: Vec<String>) -> Vec<String> {
    let mut counters: HashMap<String, usize> = HashMap::new();
    let mut named = Vec::with_capacity(configs.len());

    for config in configs {
        let scheme = config_scheme(&config);
        let display = display_protocol(&scheme).to_string();

        let counter = counters.entry(display.clone()).or_insert(0);
        *counter += 1;

        let name = format!("{} {:03}", display, *counter);

        if scheme == "vmess" {
            if let Some(named_config) = name_vmess_config(&config, &name) {
                named.push(named_config);
                continue;
            }
        }

        if matches!(scheme.as_str(), "hysteria2" | "hy2") {
            named.push(set_config_fragment(&config, &name));
            continue;
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
        "socks" | "socks4" | "socks4a" | "socks5" | "socks5h" => "SOCKS",
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
        && value.len() <= MAX_BASE64_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
        })
}

fn decode_base64_variants(text: &str) -> Vec<String> {
    let mut inputs = Vec::new();

    if !text.contains("://") && text.len() <= MAX_BASE64_BYTES.saturating_mul(2) {
        let compact = text.split_whitespace().collect::<String>();

        if compact.len() <= MAX_BASE64_BYTES && looks_like_base64(&compact) {
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

        while !padded.len().is_multiple_of(4) {
            padded.push('=');
        }

        let candidates: &[&str] = if padded == input {
            &[input.as_str()]
        } else {
            &[input.as_str(), padded.as_str()]
        };

        for candidate in candidates {
            for bytes in [
                STANDARD.decode(candidate),
                URL_SAFE.decode(candidate),
                URL_SAFE_NO_PAD.decode(candidate),
            ]
            .into_iter()
            .flatten()
            {
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

    results.sort_unstable();
    results.dedup();
    results
}

#[cfg(test)]
mod tests {
    use super::{
        append_limited_chunk, assign_config_names, decode_base64_variants, extract_configs,
        normalize_config, trim_config, MAX_SOURCE_BYTES,
    };
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    #[test]
    fn bounded_source_chunk_stops_at_limit() {
        let mut body = Vec::new();

        assert!(append_limited_chunk(&mut body, &[1, 2, 3]));
        assert_eq!(body.len(), 3);

        let remaining = MAX_SOURCE_BYTES - body.len();

        assert!(append_limited_chunk(&mut body, &vec![0u8; remaining]));

        assert_eq!(body.len(), MAX_SOURCE_BYTES);

        assert!(!append_limited_chunk(&mut body, &[0]));
        assert_eq!(body.len(), MAX_SOURCE_BYTES);
    }

    #[test]
    fn decodes_large_single_line_base64_sources() {
        let payload = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls\n"
            .repeat(300);

        let encoded = STANDARD.encode(payload.as_bytes());

        assert!(encoded.len() > 8192);
        assert_eq!(decode_base64_variants(&encoded), vec![payload]);
    }

    #[test]
    fn rejects_protocols_without_a_proxy_validator() {
        for config in [
            "https://127.0.0.1:443",
            "ssr://encoded",
            "ssh://user@127.0.0.1:22",
            "tuic://token@127.0.0.1:443",
            "naive+https://user:pass@example.com:443",
        ] {
            assert!(normalize_config(config).is_none(), "{config}");
        }
    }

    #[test]
    fn accepts_vless_mlkem_encryption() {
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=reality&flow=xtls-rprx-vision&encryption=mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        assert!(normalize_config(config).is_some());
    }

    #[test]
    fn rejects_invalid_vless_mlkem_encryption() {
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=reality&flow=xtls-rprx-vision&encryption=mlkem768x25519plus.invalid.1rtt.seed";

        assert!(normalize_config(config).is_none());
    }

    #[test]
    fn accepts_shadowsocks_plain_and_base64_userinfo() {
        assert!(normalize_config("ss://aes-256-gcm:secret@example.com:8388").is_some());

        assert!(normalize_config("ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388").is_some());
    }

    #[test]
    fn accepts_legacy_base64_shadowsocks_urls() {
        let legacy = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZEBleGFtcGxlLmNvbTo4Mzg4";

        assert!(normalize_config(legacy).is_some());
    }

    #[test]
    fn retains_supported_proxy_schemes() {
        assert!(normalize_config("http://127.0.0.1:8080").is_some(), "http");

        assert!(
            normalize_config("socks4://127.0.0.1:1080").is_some(),
            "socks4"
        );

        assert!(
            normalize_config("socks5://127.0.0.1:1080").is_some(),
            "socks5"
        );

        assert!(
            normalize_config("socks5h://127.0.0.1:1080").is_some(),
            "socks5h"
        );

        assert!(
            normalize_config("socks4a://127.0.0.1:1080").is_some(),
            "socks4a"
        );
    }

    #[test]
    fn extracts_socks_variants_from_sources() {
        let configs = extract_configs(
            "socks4://127.0.0.1:1080 socks4a://127.0.0.1:1081 socks5://127.0.0.1:1082 socks5h://127.0.0.1:1083",
        );

        assert_eq!(
            configs,
            vec![
                "socks4://127.0.0.1:1080".to_string(),
                "socks4a://127.0.0.1:1081".to_string(),
                "socks5://127.0.0.1:1082".to_string(),
                "socks5h://127.0.0.1:1083".to_string(),
            ]
        );
    }

    #[test]
    fn preserves_punctuation_in_uri_credentials_and_queries() {
        assert_eq!(
            normalize_config("trojan://secret.@example.com:443?security=tls&path=/foo,;#label."),
            Some("trojan://secret.@example.com:443?security=tls&path=/foo,;".to_string())
        );
    }

    #[test]
    fn preserves_non_hysteria_fragments() {
        let config = "trojan://secret.@example.com:443?security=tls&path=/foo,;#label";
        assert_eq!(normalize_config(config), Some(config.to_string()));
    }

    #[test]
    fn strips_hysteria2_fragment_for_parsing() {
        let config = "hy2://password@example.com:443#Hysteria2%20001";

        assert_eq!(
            normalize_config(config),
            Some("hy2://password@example.com:443".to_string())
        );

        assert_eq!(trim_config(config), "hy2://password@example.com:443");
    }

    #[test]
    fn all_candidates_include_hysteria_v1_after_transport_screening() {
        let working = Vec::<(String, u64)>::new();

        let hysteria = vec!["hysteria://example.com:443?upmbps=100&downmbps=100".to_string()];

        let selected = super::select_all_candidates(&working, &hysteria);

        assert_eq!(
            selected,
            vec!["hysteria://example.com:443?upmbps=100&downmbps=100".to_string()]
        );
    }

    #[test]
    fn all_candidates_include_hysteria2_after_transport_screening() {
        let working = vec![("vless://uuid@example.com:443".to_string(), 20)];

        let hysteria2 = vec![
            "hysteria2://password@example.com:443?obfs=salamander&obfs-password=secret".to_string(),
        ];

        let selected = super::select_all_candidates(&working, &hysteria2);

        assert_eq!(
            selected,
            vec![
                "vless://uuid@example.com:443".to_string(),
                "hysteria2://password@example.com:443?obfs=salamander&obfs-password=secret"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn retains_vless_with_empty_packet_encoding_value() {
        let config =
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&packetEncoding=";

        assert_eq!(normalize_config(config), Some(config.to_string()));
    }

    #[test]
    fn retains_vless_with_empty_encryption_value() {
        let config =
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&encryption=";

        assert_eq!(normalize_config(config), Some(config.to_string()));
    }

    #[test]
    fn rejects_vless_encryption_without_public_key() {
        let config =
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&encryption=mlkem768x25519plus.native.1rtt.padding";

        assert!(super::normalize_config(config).is_none());
    }

    #[test]
    fn retains_vless_with_empty_security_value() {
        let config =
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=&type=tcp";

        assert_eq!(super::normalize_config(config), Some(config.to_string()));
    }

    #[test]
    fn retains_legacy_hysteria_links() {
        let config = "hysteria://example.com:443?upmbps=100&downmbps=100&peer=edge.example.com";

        assert_eq!(super::normalize_config(config), Some(config.to_string()));
    }

    #[test]
    fn accepts_hysteria2_port_hopping() {
        let config = "hy2://password@example.com:1234,5000-5002";

        assert_eq!(normalize_config(config), Some(config.to_string()));
    }

    #[test]
    fn rejects_invalid_hysteria2_port_hopping() {
        assert!(normalize_config("hy2://password@example.com:5000-4000").is_none());

        assert!(normalize_config("hy2://password@example.com:not-a-port").is_none());

        assert!(normalize_config("hy2://password@example.com:0").is_none());
    }

    #[test]
    fn hysteria2_probe_ports_supports_port_hopping() {
        assert_eq!(
            super::hysteria2_probe_ports("hy2://password@example.com"),
            Some(vec![443])
        );

        assert_eq!(
            super::hysteria2_probe_ports("hy2://password@example.com:1234,5000-5002"),
            Some(vec![1234, 5000, 5001, 5002])
        );
    }

    #[test]
    fn hysteria2_probe_ports_rejects_invalid_explicit_ports() {
        assert!(super::hysteria2_probe_ports("hy2://password@example.com:not-a-port").is_none());

        assert!(super::hysteria2_probe_ports("hy2://password@example.com:0").is_none());

        assert!(super::hysteria2_probe_ports("hy2://password@example.com:5000-4000").is_none());
    }

    #[test]
    fn hysteria2_probe_ports_bounds_large_ranges() {
        let ports = super::hysteria2_probe_ports("hy2://password@example.com:1000-65000")
            .expect("large range should produce bounded probe ports");

        assert!(ports.len() <= super::MAX_HYSTERIA2_PROBE_PORTS);

        assert!(ports.contains(&1000));
        assert!(ports.contains(&65000));
    }

    #[test]
    fn preserves_vless_path_that_contains_security_text() {
        let config =
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&type=ws&path=%2Ffoo%3Fsecurity%3Dtls";

        assert!(normalize_config(config).is_some());
    }

    #[test]
    fn alias_protocols_share_display_counter() {
        let configs = vec![
            "hy2://password@example.com:443".to_string(),
            "hysteria2://password@example.net:443".to_string(),
            "socks4://127.0.0.1:1080".to_string(),
            "socks5://127.0.0.1:1081".to_string(),
        ];

        let named = assign_config_names(configs);

        assert!(named[0].contains("#Hysteria2%20001"));
        assert!(named[1].contains("#Hysteria2%20002"));
        assert!(named[2].contains("#SOCKS%20001"));
        assert!(named[3].contains("#SOCKS%20002"));
    }
}

fn select_all_candidates(
    ranked_working_configs: &[(String, u64)],
    special_candidates: &[String],
) -> Vec<String> {
    let mut selected = Vec::with_capacity(MAX_ALL_CONFIGS);
    let mut seen = HashSet::new();

    for (config, _) in ranked_working_configs {
        if selected.len() >= MAX_ALL_CONFIGS {
            break;
        }

        if seen.insert(config.clone()) {
            selected.push(config.clone());
        }
    }

    for config in special_candidates {
        if selected.len() >= MAX_ALL_CONFIGS {
            break;
        }

        if seen.insert(config.clone()) {
            selected.push(config.clone());
        }
    }

    selected
}

fn config_scheme(config: &str) -> String {
    config
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn resolve_host_addresses(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    let addresses = timeout(
        Duration::from_secs(TCP_TIMEOUT_SECS),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .ok()?
    .ok()?
    .collect::<Vec<_>>();

    if addresses.is_empty() {
        return None;
    }

    let mut seen = HashSet::new();
    let mut unique = Vec::with_capacity(addresses.len());

    for address in addresses {
        if seen.insert(address) {
            unique.push(address);
        }
    }

    Some(unique)
}

async fn resolve_host_ips(host: &str, port: u16) -> Option<Vec<IpAddr>> {
    let addresses = resolve_host_addresses(host, port).await?;

    let mut seen = HashSet::new();
    let mut ips = Vec::with_capacity(addresses.len());

    for address in addresses {
        if seen.insert(address.ip()) {
            ips.push(address.ip());
        }
    }

    Some(ips)
}

async fn tcp_latency_endpoint(host: &str, port: u16) -> Option<u64> {
    let addresses = resolve_host_addresses(host, port).await?;

    let start = Instant::now();

    let probe = stream::iter(addresses)
        .map(|address| async move {
            match TcpStream::connect(address).await {
                Ok(stream) => {
                    drop(stream);
                    Some(start.elapsed().as_millis() as u64)
                }

                Err(_) => None,
            }
        })
        .buffer_unordered(MAX_TCP_ADDRESS_CONCURRENCY)
        .filter_map(|result| async move { result });

    futures::pin_mut!(probe);

    timeout(Duration::from_secs(TCP_TIMEOUT_SECS), probe.next())
        .await
        .ok()
        .flatten()
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
        .filter_map(|result| async move { result })
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
            .filter_map(|result| async move { result })
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

fn quic_client_config(alpn: &[String]) -> Option<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ProbeCertVerifier))
        .with_no_client_auth();

    tls.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();

    let crypto = QuicClientConfig::try_from(tls).ok()?;

    Some(ClientConfig::new(Arc::new(crypto)))
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

fn query_csv_values(config: &str, key: &str) -> Vec<String> {
    query_values(config, key)
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
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
        let values = query_csv_values(config, "alpn");

        if values.is_empty() {
            vec!["h3".to_string()]
        } else {
            values
        }
    };

    Some((host, port, sni, alpn))
}

const MAX_HYSTERIA2_PROBE_PORTS: usize = 8;

fn hysteria2_port_spec(config: &str) -> Option<String> {
    let (_, port_spec, _) = hysteria2_parts(config)?;

    Some(port_spec)
}

fn hysteria2_probe_ports(config: &str) -> Option<Vec<u16>> {
    let spec = hysteria2_port_spec(config)?;

    if spec.is_empty() {
        return Some(vec![443]);
    }

    let mut candidates = Vec::new();

    for entry in spec
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        if let Some((start, end)) = entry.split_once('-') {
            let start = start.parse::<u16>().ok()?;
            let end = end.parse::<u16>().ok()?;

            if start == 0 || end == 0 || start > end {
                return None;
            }

            candidates.push(start);

            if end != start {
                candidates.push(start + (end - start) / 2);
                candidates.push(end);
            }
        } else {
            let port = entry.parse::<u16>().ok().filter(|port| *port != 0)?;
            candidates.push(port);
        }
    }

    candidates.sort_unstable();
    candidates.dedup();

    if candidates.is_empty() {
        return None;
    }

    if candidates.len() <= MAX_HYSTERIA2_PROBE_PORTS {
        return Some(candidates);
    }

    let mut sampled = Vec::with_capacity(MAX_HYSTERIA2_PROBE_PORTS);

    let last = candidates.len() - 1;

    for slot in 0..MAX_HYSTERIA2_PROBE_PORTS {
        let index = slot
            .saturating_mul(last)
            .checked_div(MAX_HYSTERIA2_PROBE_PORTS - 1)
            .unwrap_or_default();

        sampled.push(candidates[index]);
    }

    sampled.sort_unstable();
    sampled.dedup();

    Some(sampled)
}

fn hysteria2_query_values(config: &str, key: &str) -> Vec<String> {
    let Some((_, query)) = config.split_once('?') else {
        return Vec::new();
    };

    let query = query.split('#').next().unwrap_or(query);

    url::form_urlencoded::parse(query.as_bytes())
        .filter(|(name, value)| name.eq_ignore_ascii_case(key) && !value.is_empty())
        .map(|(_, value)| value.into_owned())
        .collect()
}

fn hysteria2_query_csv_values(config: &str, key: &str) -> Vec<String> {
    hysteria2_query_values(config, key)
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

async fn quic_probe_target(
    address: SocketAddr,
    sni: &str,
    client_config: ClientConfig,
) -> Option<u64> {
    let local = if address.ip().is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };

    let endpoint = Endpoint::client(local).ok()?;

    let connecting = endpoint.connect_with(client_config, address, sni).ok()?;

    let start = Instant::now();

    let connected = match timeout(Duration::from_secs(TCP_TIMEOUT_SECS), connecting).await {
        Ok(Ok(connection)) => connection,

        _ => {
            endpoint.close(0u32.into(), b"probe timeout");
            return None;
        }
    };

    let latency = start.elapsed().as_millis() as u64;

    connected.close(0u32.into(), b"probe complete");

    endpoint.close(0u32.into(), b"probe complete");

    Some(latency)
}

async fn quic_latency_for_targets(
    host: &str,
    ports: &[u16],
    sni: &str,
    alpn: &[String],
) -> Option<u64> {
    let first_port = *ports.first()?;

    let ips = resolve_host_ips(host, first_port).await?;

    let client_config = quic_client_config(alpn)?;

    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    for port in ports {
        for ip in &ips {
            let address = SocketAddr::new(*ip, *port);

            if seen.insert(address) {
                targets.push(address);
            }
        }
    }

    if targets.is_empty() {
        return None;
    }

    let sni = sni.to_string();

    let probe = stream::iter(targets)
        .map(|address| {
            let sni = sni.clone();
            let client_config = client_config.clone();

            async move { quic_probe_target(address, &sni, client_config).await }
        })
        .buffer_unordered(MAX_QUIC_TARGET_CONCURRENCY)
        .filter_map(|result| async move { result });

    futures::pin_mut!(probe);

    timeout(Duration::from_secs(TCP_TIMEOUT_SECS), probe.next())
        .await
        .ok()
        .flatten()
}
