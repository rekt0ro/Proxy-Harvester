use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt};
use futures::FutureExt;
use percent_encoding::percent_decode_str;
use proxyrift::validator::{
    config_label, endpoint, is_cheaply_supported_config, is_locally_supported_config, is_public_ip,
    resolve_public_host,
};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use regex::Regex;
use reqwest::{header::LOCATION, Client};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
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

const TEST_CONCURRENCY: usize = 2;
const TEST_CONNECTION_CONCURRENCY: usize = 64;

const MAX_TCP_ADDRESS_CONCURRENCY: usize = 8;
const MAX_QUIC_TARGET_CONCURRENCY: usize = 8;
const MAX_WIREGUARD_ADDRESS_CONCURRENCY: usize = 4;

const CHUNK_SIZE: usize = 2000;
const TCP_TIMEOUT_SECS: u64 = 3;
const MAX_BASE64_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCE_REDIRECTS: usize = 2;

const MAX_COLLECTED_CONFIGS: usize = 25_000;
const MAX_ALL_CONFIGS: usize = 2000;
const MAX_ALL_PER_ENDPOINT: usize = 3;
const MAX_LIGHT_CANDIDATES: usize = 10000;
const SOURCE_RETRIES: usize = 2;
const SOURCE_RETRY_BASE_MS: u64 = 250;

type TcpProbe = futures::future::Shared<futures::future::BoxFuture<'static, Option<u64>>>;
type TcpProbeCache = Arc<HashMap<(String, u16), TcpProbe>>;

#[derive(Debug)]
enum SourceBodyError {
    TooLarge,
    Read,
}

fn parse_source_redirect(current_url: &Url, location: &str) -> Result<Url, &'static str> {
    let target_url = current_url
        .join(location)
        .map_err(|_| "redirect location is not a valid URL")?;

    if target_url.scheme() != "https" {
        return Err("redirect destination must use HTTPS");
    }

    if target_url.host().is_none() {
        return Err("redirect destination must have a host");
    }

    if !target_url.username().is_empty() || target_url.password().is_some() {
        return Err("redirect destination must not contain credentials");
    }

    let current_port = current_url.port_or_known_default();
    let target_port = target_url.port_or_known_default();

    let http_to_https_default_ports =
        current_url.scheme() == "http" && current_port == Some(80) && target_port == Some(443);

    if current_port != target_port && !http_to_https_default_ports {
        return Err("redirect destination must keep the same port");
    }

    Ok(target_url)
}

async fn safe_source_client(current_url: &Url) -> Result<Client, &'static str> {
    if !matches!(current_url.scheme(), "http" | "https") {
        return Err("source URL must use HTTP or HTTPS");
    }

    let host = current_url
        .host_str()
        .ok_or("source URL must have a host")?;

    let port = current_url
        .port_or_known_default()
        .ok_or("source URL must have a known port")?;

    let mut builder = Client::builder()
        .user_agent("ProxyRift/3.0")
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none());

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_ip(&ip) {
            return Err("source URL must resolve to a public address");
        }
    } else {
        let ip = resolve_public_host(host, port)
            .await
            .ok_or("source URL must resolve to a public address")?;

        builder = builder.resolve(host, SocketAddr::new(ip, port));
    }

    builder
        .build()
        .map_err(|_| "failed to build source HTTP client")
}

async fn safe_source_redirect(current_url: &Url, location: &str) -> Result<Url, &'static str> {
    let target_url = parse_source_redirect(current_url, location)?;
    let host = target_url
        .host_str()
        .ok_or("redirect destination must have a host")?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_ip(&ip) {
            return Err("redirect destination must resolve to a public address");
        }
        return Ok(target_url);
    }

    let port = target_url
        .port_or_known_default()
        .ok_or("redirect destination must have a known port")?;

    if resolve_public_host(host, port).await.is_none() {
        return Err("redirect destination must resolve to a public address");
    }

    Ok(target_url)
}

async fn test_chunk(
    index: usize,
    configs: &[String],
    tcp_probe_cache: TcpProbeCache,
) -> Result<(usize, Vec<(String, u64)>), Box<dyn std::error::Error + Send + Sync>> {
    let working = test_transport_configs(configs, tcp_probe_cache).await;
    Ok((index, working))
}

async fn write_atomic(
    path: &Path,
    contents: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("output");

    let temporary = path.with_file_name(format!(".{file_name}.tmp"));

    fs::write(&temporary, contents).await?;
    if let Err(error) = fs::rename(&temporary, path).await {
        let _ = fs::remove_file(&temporary).await;
        return Err(error.into());
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("[INFO] 🚀 ProxyRift starting...");

    let root = project_root()?;
    let sources_path = root.join("sources.txt");
    let output_dir = root.join("subscriptions");
    fs::create_dir_all(&output_dir).await?;

    let sources = load_sources(&sources_path).await?;
    println!("[INFO] 📡 Loaded {} sources", sources.len());

    let mut unique = HashSet::new();
    let source_http_warnings = Arc::new(Mutex::new(Vec::<(usize, u16)>::new()));

    let mut source_results = stream::iter(sources.iter().cloned().enumerate())
        .map(|(source_index, url)| {
            let source_http_warnings = Arc::clone(&source_http_warnings);

            async move {
                let source_number = source_index + 1;
                let mut current_url = match Url::parse(&url) {
                    Ok(url) if matches!(url.scheme(), "http" | "https") => url,

                    _ => {
                        println!(
                            "[WARN] ⚠️ Source #{source_number} has an invalid or unsupported URL."
                        );
                        return Vec::new();
                    }
                };

                let mut client = match safe_source_client(&current_url).await {
                    Ok(client) => client,

                    Err(reason) => {
                        println!(
                            "[WARN] ⚠️ Source #{source_number} rejected by safety policy: {reason}."
                        );
                        return Vec::new();
                    }
                };

                let mut redirect_count = 0usize;
                let mut attempt = 0usize;
                loop {
                    match client.get(current_url.clone()).send().await {
                        Ok(response) => {
                            let status = response.status();

                            if status.is_redirection() {
                                if redirect_count == MAX_SOURCE_REDIRECTS {
                                    println!(
                                        "[WARN] ⚠️ Source #{source_number} exceeded the {}-redirect limit.",
                                        MAX_SOURCE_REDIRECTS
                                    );
                                    return Vec::new();
                                }

                                let Some(location) = response.headers().get(LOCATION) else {
                                    println!(
                                        "[WARN] ⚠️ Source #{source_number} returned HTTP status {status} without a Location header."
                                    );
                                    return Vec::new();
                                };

                                let location = match location.to_str() {
                                    Ok(location) => location,

                                    Err(_) => {
                                        println!(
                                            "[WARN] ⚠️ Source #{source_number} returned an invalid redirect Location header."
                                        );
                                        return Vec::new();
                                    }
                                };

                                match safe_source_redirect(&current_url, location).await {
                                    Ok(next_url) => {
                                        current_url = next_url;

                                        client = match safe_source_client(&current_url).await {
                                            Ok(client) => client,

                                            Err(reason) => {
                                                println!(
                                                    "[WARN] ⚠️ Source #{source_number} redirect rejected by safety policy: {reason}."
                                                );
                                                return Vec::new();
                                            }
                                        };

                                        redirect_count += 1;
                                        attempt = 0;
                                        continue;
                                    }

                                    Err(reason) => {
                                        println!(
                                            "[WARN] ⚠️ Source #{source_number} redirect rejected by safety policy: {reason}."
                                        );
                                        return Vec::new();
                                    }
                                }
                            }

                            if !status.is_success() {
                                let retryable = status.as_u16() == 408
                                    || status.as_u16() == 425
                                    || status.as_u16() == 429
                                    || status.is_server_error();

                                if retryable && attempt < SOURCE_RETRIES {
                                    let delay = Duration::from_millis(
                                        SOURCE_RETRY_BASE_MS
                                            .saturating_mul(1u64 << attempt.min(4)),
                                    );
                                    tokio::time::sleep(delay).await;
                                    attempt += 1;
                                    continue;
                                }

                                if let Ok(mut warnings) = source_http_warnings.lock() {
                                    warnings.push((source_number, status.as_u16()));
                                }
                                return Vec::new();
                            }

                            if response
                                .content_length()
                                .is_some_and(|length| length > MAX_SOURCE_BYTES as u64)
                            {
                                println!(
                                    "[WARN] ⚠️ Skipping source #{source_number}: response exceeds {} bytes",
                                    MAX_SOURCE_BYTES
                                );
                                return Vec::new();
                            }

                            match read_source_body(response).await {
                                Ok(bytes) => {
                                    let text = String::from_utf8_lossy(&bytes);
                                    let configs = extract_configs(&text);


                                    return configs;
                                }

                                Err(SourceBodyError::TooLarge) => {
                                    println!(
                                        "[WARN] ⚠️ Skipping source #{source_number}: response exceeds {} bytes",
                                        MAX_SOURCE_BYTES
                                    );
                                    return Vec::new();
                                }

                                Err(SourceBodyError::Read) => {
                                    println!("[WARN] ⚠️ Failed to read source #{source_number}.");
                                    return Vec::new();
                                }
                            }
                        }

                        Err(error) => {
                            if attempt < SOURCE_RETRIES {
                                let delay = Duration::from_millis(
                                    SOURCE_RETRY_BASE_MS
                                        .saturating_mul(1u64 << attempt.min(4)),
                                );
                                tokio::time::sleep(delay).await;
                                attempt += 1;
                                continue;
                            }

                            println!(
                                "[WARN] ⚠️ Failed to download source #{source_number}: {error}"
                            );
                            return Vec::new();
                        }
                    }
                }

            }
        })
        .buffer_unordered(DOWNLOAD_CONCURRENCY.min(sources.len()).max(1));

    while let Some(configs) = source_results.next().await {
        unique.extend(configs);
    }

    let mut warnings = source_http_warnings
        .lock()
        .map(|warnings| warnings.clone())
        .unwrap_or_default();

    if !warnings.is_empty() {
        warnings.sort_unstable();

        let mut grouped = HashMap::<u16, Vec<usize>>::new();
        for (source_number, status_code) in warnings {
            grouped.entry(status_code).or_default().push(source_number);
        }

        let mut groups = grouped.into_iter().collect::<Vec<_>>();
        groups.sort_unstable_by_key(|(status_code, _)| *status_code);

        for (status_code, mut source_numbers) in groups {
            source_numbers.sort_unstable();
            let reason = reqwest::StatusCode::from_u16(status_code)
                .ok()
                .and_then(|status| status.canonical_reason())
                .unwrap_or("UNKNOWN")
                .to_ascii_uppercase();
            let sources = source_numbers
                .iter()
                .map(|number| format!("#{number}"))
                .collect::<Vec<_>>()
                .join(", ");

            println!("[WARN] ⚠️ [SOURCES] HTTP {status_code} {reason} | SOURCES: {sources}");
        }
    }

    let mut configs: Vec<String> = unique.into_iter().collect();
    configs.sort_unstable();

    let mut seen_keys = HashSet::new();
    configs.retain(|config| seen_keys.insert(dedup_key(config)));

    let before_cheap_compatibility = configs.len();
    configs.retain(|config| is_cheaply_supported_config(config));
    let cheaply_rejected = before_cheap_compatibility.saturating_sub(configs.len());
    if cheaply_rejected > 0 {
        println!(
            "[INFO] 🧹 [COMPATIBILITY] REJECTED {} COLLECTED CONFIGS BY CHEAP COMPATIBILITY SCREENING",
            cheaply_rejected
        );
    }

    configs = assign_config_names(configs);

    let special_hysteria_candidates = configs
        .iter()
        .filter(|config| needs_core_validation_only(config))
        .filter(|config| is_locally_supported_config(config))
        .cloned()
        .collect::<Vec<_>>();

    configs = cap_configs_by_protocol(configs, MAX_COLLECTED_CONFIGS);

    println!("[INFO] 📦 Collected {} unique configs", configs.len());

    if configs.is_empty() {
        return Err("no proxy configurations were collected".into());
    }

    let mut scheme_counts: HashMap<String, usize> = HashMap::new();

    for config in &configs {
        *scheme_counts.entry(config_scheme(config)).or_insert(0usize) += 1;
    }

    let mut scheme_counts = scheme_counts.into_iter().collect::<Vec<_>>();
    scheme_counts.sort();

    for chunk in scheme_counts.chunks(4) {
        let summary = chunk
            .iter()
            .map(|(scheme, count)| format!("{} {count}", scheme.to_ascii_uppercase()))
            .collect::<Vec<_>>()
            .join(" | ");
        println!("[INFO] 📊 [PROTOCOLS] {summary}");
    }

    let all_path = output_dir.join("all.txt");

    let (tcp_probe_cache, tcp_config_count, unique_tcp_endpoints) = build_tcp_probe_cache(&configs);
    let non_tcp_transport_count = configs
        .iter()
        .filter(|config| {
            matches!(
                config_scheme(config).as_str(),
                "hysteria" | "hysteria2" | "hy2" | "tuic" | "wg"
            )
        })
        .count();

    println!(
        "[INFO] 🔎 [TRANSPORT] PLAN | {} CONFIGS | TCP {} CONFIGS → {} UNIQUE | NON-TCP {}",
        configs.len(),
        tcp_config_count,
        unique_tcp_endpoints,
        non_tcp_transport_count
    );

    let transport_chunk_count = configs.len().div_ceil(CHUNK_SIZE);
    let test_concurrency = TEST_CONCURRENCY.min(transport_chunk_count).max(1);

    let mut chunk_stream = stream::iter(configs.chunks(CHUNK_SIZE).enumerate())
        .map(|(index, chunk)| {
            let tcp_probe_cache = Arc::clone(&tcp_probe_cache);
            async move { test_chunk(index, chunk, tcp_probe_cache).await }
        })
        .buffered(test_concurrency);

    let mut chunk_results = Vec::with_capacity(transport_chunk_count);

    while let Some(result) = chunk_stream.next().await {
        let (index, working) = result?;

        let tested = configs
            .chunks(CHUNK_SIZE)
            .nth(index)
            .map_or(0, |chunk| chunk.len());

        println!(
            "[INFO] ✅ [TRANSPORT] CHUNK {}/{} | {} TESTED | {} REACHABLE",
            index + 1,
            transport_chunk_count,
            tested,
            working.len()
        );

        chunk_results.push((index, working));
    }

    let reachable_probes = chunk_results
        .iter()
        .map(|(_, working)| working.len())
        .sum::<usize>();

    println!(
        "[INFO] ✅ [TRANSPORT] COMPLETE | {} CONFIGS | {} REACHABLE",
        configs.len(),
        reachable_probes
    );

    let mut ranked_working_configs = Vec::new();

    for (_, working) in chunk_results {
        ranked_working_configs.extend(working);
    }

    if ranked_working_configs.is_empty() && special_hysteria_candidates.is_empty() {
        println!(
            "[WARN] ⚠️ No usable configs remained after transport-aware reachability and compatibility screening."
        );

        diagnose_configs(&configs).await;
        return Err("no usable configs remained after transport-aware screening".into());
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
        "[INFO] 🧠 [LIGHT INTELLIGENCE] PRIORITIZING {} CANDIDATES | {} HYSTERIA/HYSTERIA2 RETAINED",
        sampled_transport_count,
        special_count
    );

    let light_candidates_path = output_dir.join(".light-candidates.txt");

    let light_candidates_subscription = if light_candidates.is_empty() {
        String::new()
    } else {
        format!("{}\n", light_candidates.join("\n"))
    };

    write_atomic(&light_candidates_path, light_candidates_subscription).await?;

    let working_configs = select_all_candidates(&ranked_working_configs, &[]);

    let all_subscription = if working_configs.is_empty() {
        String::new()
    } else {
        format!("{}\n", working_configs.join("\n"))
    };

    write_atomic(&all_path, all_subscription).await?;

    let all_unique_endpoints = working_configs
        .iter()
        .filter_map(|config| endpoint(config))
        .collect::<HashSet<_>>()
        .len();

    println!(
        "[INFO] 📦 [ALL] {} CONFIGS READY | UNIQUE ENDPOINTS: {}",
        working_configs.len(),
        all_unique_endpoints
    );

    println!(
        "[INFO] 🎯 [LIGHT] {} CANDIDATES READY | CAP: {}",
        light_candidates.len(),
        MAX_LIGHT_CANDIDATES
    );

    println!("[INFO] ✅ [COLLECTION] COMPLETE");

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

fn cap_configs_by_protocol(configs: Vec<String>, cap: usize) -> Vec<String> {
    if configs.len() <= cap {
        return configs;
    }

    let mut by_protocol = HashMap::<String, Vec<String>>::new();
    for config in configs {
        by_protocol
            .entry(config_scheme(&config))
            .or_default()
            .push(config);
    }

    let mut protocols = by_protocol.keys().cloned().collect::<Vec<_>>();
    protocols.sort_unstable();

    let mut selected = Vec::with_capacity(cap);
    let mut index = 0usize;

    while selected.len() < cap {
        let mut added = false;
        for protocol in &protocols {
            if selected.len() >= cap {
                break;
            }
            if let Some(values) = by_protocol.get(protocol) {
                if index < values.len() {
                    selected.push(values[index].clone());
                    added = true;
                }
            }
        }
        if !added {
            break;
        }
        index += 1;
    }

    selected.sort_unstable();
    selected
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
            r#"(?i)(?:vmess|vless|trojan|ss|socks(?:4a?|5h?)?|hysteria|hysteria2|hy2|wg|http)://[^\s<>"']+"#,
        )
        .expect("config regex must compile")
    })
}

fn split_concatenated_configs(config: &str) -> Vec<&str> {
    if normalize_config(config).is_some() {
        return vec![config];
    }

    const SCHEMES: &[&str] = &[
        "vmess://",
        "vless://",
        "trojan://",
        "ss://",
        "socks://",
        "socks4://",
        "socks4a://",
        "socks5://",
        "socks5h://",
        "hysteria://",
        "hysteria2://",
        "hy2://",
        "wg://",
        "http://",
    ];

    let mut matches = Vec::new();

    for index in 1..config.len() {
        if !config.is_char_boundary(index) {
            continue;
        }

        for scheme in SCHEMES {
            if config[index..].len() >= scheme.len()
                && config.is_char_boundary(index + scheme.len())
                && config[index..index + scheme.len()].eq_ignore_ascii_case(scheme)
            {
                matches.push((index, scheme.len()));
            }
        }
    }

    matches.sort_unstable_by_key(|(index, length)| (*index, std::cmp::Reverse(*length)));

    let mut starts = vec![0];
    let mut previous_end = SCHEMES
        .iter()
        .find(|scheme| {
            config.len() >= scheme.len() && config[..scheme.len()].eq_ignore_ascii_case(scheme)
        })
        .map(|scheme| scheme.len())
        .unwrap_or_default();

    for (index, length) in matches {
        if index >= previous_end {
            starts.push(index);
            previous_end = index + length;
        }
    }

    starts
        .windows(2)
        .map(|pair| &config[pair[0]..pair[1]])
        .chain(starts.last().map(|&start| &config[start..]))
        .collect()
}
fn extract_configs(text: &str) -> Vec<String> {
    let text = decode_html_entities(text);
    let pattern = config_pattern();

    let mut found = Vec::new();

    for capture in pattern.find_iter(&text) {
        for candidate in split_concatenated_configs(capture.as_str()) {
            if let Some(config) = normalize_config(candidate) {
                found.push(config);
            }
        }
    }

    for decoded in decode_base64_variants(&text) {
        for capture in pattern.find_iter(&decoded) {
            for candidate in split_concatenated_configs(capture.as_str()) {
                if let Some(config) = normalize_config(candidate) {
                    found.push(config);
                }
            }
        }
    }

    found.sort_unstable();
    found.dedup();
    found
}

fn lowercase_scheme(config: &str) -> String {
    match config.split_once("://") {
        Some((scheme, rest)) => format!("{}://{}", scheme.to_ascii_lowercase(), rest),
        None => config.to_string(),
    }
}

fn has_explicit_port(config: &str) -> bool {
    let Some(rest) = config.split_once("://").map(|(_, rest)| rest) else {
        return false;
    };

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");

    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);

    let port = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped
            .split_once(']')
            .and_then(|(_, remainder)| remainder.strip_prefix(':'))
    } else {
        host_port.rsplit_once(':').map(|(_, port)| port)
    };

    matches!(port, Some(port) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn normalize_config(config: &str) -> Option<String> {
    let config = lowercase_scheme(&trim_config(config));
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

    if matches!(scheme.as_str(), "hysteria2" | "hy2") {
        return normalize_hysteria2(&config);
    }

    let Ok(url) = Url::parse(&config) else {
        return None;
    };

    let needs_port = scheme != "ss" || !url.username().is_empty();

    if needs_port && !has_explicit_port(&config) {
        return None;
    }

    if scheme == "vless" {
        return normalize_vless(&config, &url);
    }

    if let Some(host) = url.host_str() {
        let bare = host.trim_start_matches('[').trim_end_matches(']');

        if bare.contains(':') && bare.parse::<Ipv6Addr>().is_err() {
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

fn dedup_key(config: &str) -> String {
    if config_scheme(config) == "vmess" {
        let encoded = config
            .split_once("://")
            .map(|(_, rest)| rest.split('#').next().unwrap_or(rest).trim());

        if let Some(decoded) = encoded.and_then(decode_vmess_payload) {
            if let Ok(Value::Object(mut object)) = serde_json::from_str::<Value>(&decoded) {
                object.remove("ps");
                return format!("vmess://{}", Value::Object(object));
            }
        }
    }

    config.split('#').next().unwrap_or(config).to_string()
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
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
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
        return true;
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

    let authority = rest.split(['/', '?', '#']).next()?;

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
        Some(Value::String(port)) => port.trim().parse::<u16>().ok()?,
        Some(Value::Number(port)) => port.as_u64().and_then(|port| u16::try_from(port).ok())?,
        _ => return None,
    };

    if port == 0 {
        return None;
    }

    let id = object.get("id")?.as_str()?.trim();

    if !is_valid_vmess_id(id) {
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

fn is_valid_vmess_id(value: &str) -> bool {
    is_uuid(value)
        || (!value.is_empty() && value.len() <= 30 && !value.chars().any(|c| c.is_control()))
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
    text.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn trim_config(config: &str) -> String {
    let config = config.trim();

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

        named.push(set_config_fragment(&config, &name));
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
        normalize_config, parse_source_redirect, safe_source_client, safe_source_redirect,
        select_all_candidates, split_concatenated_configs, tcp_endpoint_groups, trim_config,
        MAX_SOURCE_BYTES,
    };
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use url::Url;

    #[test]
    fn tcp_endpoint_groups_share_identical_endpoints() {
        let configs = vec![
            "http://example.com:443".to_string(),
            "socks5://example.com:443".to_string(),
            "http://example.net:443".to_string(),
            "hysteria://example.com:443?upmbps=1&downmbps=1".to_string(),
        ];

        let groups = tcp_endpoint_groups(&configs);

        assert_eq!(
            groups.get(&("example.com".to_string(), 443)),
            Some(&vec![0, 1])
        );
        assert_eq!(
            groups.get(&("example.net".to_string(), 443)),
            Some(&vec![2])
        );
        assert_eq!(groups.len(), 2);
    }

    #[tokio::test]
    async fn rejects_private_initial_source_addresses() {
        let url = Url::parse("https://127.0.0.1/source").unwrap();
        assert!(safe_source_client(&url).await.is_err());
        let url = Url::parse("https://169.254.169.254/source").unwrap();
        assert!(safe_source_client(&url).await.is_err());
    }

    #[tokio::test]
    async fn accepts_public_initial_source_addresses() {
        let url = Url::parse("https://93.184.216.34/source").unwrap();
        assert!(safe_source_client(&url).await.is_ok());
    }

    #[test]
    fn accepts_cross_host_https_source_redirect() {
        let current = Url::parse("https://example.com/source").unwrap();

        assert_eq!(
            parse_source_redirect(&current, "https://cdn.example.net/source"),
            Ok(Url::parse("https://cdn.example.net/source").unwrap())
        );
    }

    #[test]
    fn accepts_http_to_https_source_redirect_on_different_host() {
        let current = Url::parse("http://example.com/source").unwrap();

        assert_eq!(
            parse_source_redirect(&current, "https://cdn.example.net/source"),
            Ok(Url::parse("https://cdn.example.net/source").unwrap())
        );
    }

    #[test]
    fn accepts_relative_https_source_redirect() {
        let current = Url::parse("https://example.com/old").unwrap();

        assert_eq!(
            parse_source_redirect(&current, "/new"),
            Ok(Url::parse("https://example.com/new").unwrap())
        );
    }

    #[test]
    fn rejects_source_redirect_to_non_https() {
        let current = Url::parse("https://example.com/source").unwrap();

        assert!(parse_source_redirect(&current, "http://cdn.example.net/source").is_err());
    }

    #[test]
    fn rejects_source_redirect_with_changed_port() {
        let current = Url::parse("https://example.com/source").unwrap();

        assert!(parse_source_redirect(&current, "https://cdn.example.net:8443/source").is_err());
    }

    #[test]
    fn rejects_source_redirect_with_credentials() {
        let current = Url::parse("https://example.com/source").unwrap();

        assert!(
            parse_source_redirect(&current, "https://user:pass@cdn.example.net/source").is_err()
        );
    }

    #[tokio::test]
    async fn rejects_private_ip_source_redirect() {
        let current = Url::parse("https://example.com/source").unwrap();

        assert_eq!(
            safe_source_redirect(&current, "https://127.0.0.1/source").await,
            Err("redirect destination must resolve to a public address")
        );
    }

    #[tokio::test]
    async fn accepts_public_ip_source_redirect() {
        let current = Url::parse("https://example.com/source").unwrap();

        assert_eq!(
            safe_source_redirect(&current, "https://1.1.1.1/source")
                .await
                .unwrap(),
            Url::parse("https://1.1.1.1/source").unwrap()
        );
    }

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
    fn extracts_concatenated_urls_without_whitespace() {
        let concatenated =
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=nonevless://00000000-0000-0000-0000-000000000002@example.com:443?security=none";
        let parts = split_concatenated_configs(concatenated);

        assert_eq!(
            parts,
            vec![
                "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=none",
                "vless://00000000-0000-0000-0000-000000000002@example.com:443?security=none",
            ]
        );

        let configs = extract_configs(concatenated);
        assert_eq!(configs, parts);
    }

    #[test]
    fn preserves_embedded_scheme_in_query_value() {
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?url=vless://00000000-0000-0000-0000-000000000002@example.com:443";

        assert_eq!(split_concatenated_configs(config), vec![config]);
        assert_eq!(extract_configs(config), vec![config.to_string()]);
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
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=reality&flow=xtls-rprx-vision&encryption=mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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
            Some("trojan://secret.@example.com:443?security=tls&path=/foo,;#label.".to_string())
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
    fn all_candidates_enforce_per_endpoint_limit() {
        let working = vec![
            ("vless://uuid1@example.com:443".to_string(), 10),
            ("vless://uuid2@example.com:443".to_string(), 20),
            ("vless://uuid3@example.com:443".to_string(), 30),
            ("vless://uuid4@example.com:443".to_string(), 40),
            ("vless://uuid5@other.example.com:443".to_string(), 50),
        ];

        let selected = select_all_candidates(&working, &[]);

        assert_eq!(
            selected,
            vec![
                "vless://uuid1@example.com:443",
                "vless://uuid2@example.com:443",
                "vless://uuid3@example.com:443",
                "vless://uuid5@other.example.com:443",
            ]
        );
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
    fn accepts_hysteria2_with_slash_before_query() {
        let config = "hy2://password@example.com:443/?sni=example.com&insecure=1";

        assert!(normalize_config(config).is_some());

        assert_eq!(
            super::hysteria2_probe_ports(config),
            Some(vec![443]),
            "the trailing slash must not leak into the port spec"
        );
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

    #[test]
    fn rejects_plain_web_links_without_explicit_port() {
        assert!(normalize_config("http://example.com/some/page").is_none());
        assert!(normalize_config("http://example.com").is_none());

        assert!(normalize_config("http://203.0.113.10:80").is_some());
    }

    #[test]
    fn accepts_ipv6_hosts() {
        assert!(normalize_config("trojan://secret@[2001:4860:4860::8888]:443").is_some());
        assert!(normalize_config("socks5://[2001:4860:4860::8888]:1080").is_some());
    }

    #[test]
    fn lowercases_scheme_only() {
        assert_eq!(
            normalize_config("SOCKS5://User:Pass@127.0.0.1:1080"),
            Some("socks5://User:Pass@127.0.0.1:1080".to_string())
        );
    }

    #[test]
    fn html_entities_are_not_double_decoded() {
        assert_eq!(super::decode_html_entities("&amp;quot;"), "&quot;");
        assert_eq!(super::decode_html_entities("a=1&amp;b=2"), "a=1&b=2");
    }

    #[test]
    fn dedup_key_ignores_labels() {
        assert_eq!(
            super::dedup_key("trojan://secret@example.com:443#one"),
            super::dedup_key("trojan://secret@example.com:443#two")
        );

        let a = STANDARD.encode(r#"{"v":"2","ps":"a","add":"h.com","port":"443","id":"00000000-0000-0000-0000-000000000001"}"#);
        let b = STANDARD.encode(r#"{"v":"2","ps":"b","add":"h.com","port":"443","id":"00000000-0000-0000-0000-000000000001"}"#);

        assert_eq!(
            super::dedup_key(&format!("vmess://{a}")),
            super::dedup_key(&format!("vmess://{b}"))
        );
    }

    #[test]
    fn reality_requires_a_public_key() {
        let base = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=reality";

        assert!(normalize_config(base).is_none());

        assert!(normalize_config(&format!(
            "{base}&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ))
        .is_some());
    }

    #[test]
    fn vmess_accepts_custom_string_ids() {
        let make = |id: &str| {
            let json = format!(r#"{{"v":"2","add":"h.com","port":"443","id":"{id}"}}"#);
            format!("vmess://{}", STANDARD.encode(json))
        };

        assert!(normalize_config(&make("my-custom-id")).is_some());
        assert!(normalize_config(&make(&"x".repeat(31))).is_none());
    }

    #[test]
    fn obfuscated_hysteria_needs_core_validation_only() {
        assert!(super::needs_core_validation_only(
            "hy2://pw@example.com:443/?obfs=salamander&obfs-password=x"
        ));
        assert!(super::needs_core_validation_only(
            "hysteria://example.com:443?obfs=xplus&obfsParam=x"
        ));
        assert!(!super::needs_core_validation_only(
            "hy2://pw@example.com:443/?sni=example.com"
        ));
        assert!(!super::needs_core_validation_only(
            "hysteria://example.com:443?upmbps=100"
        ));
        assert!(!super::needs_core_validation_only(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
        ));
    }

    #[test]
    fn only_public_addresses_are_probed() {
        use std::net::IpAddr;

        for private in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            let ip: IpAddr = private.parse().unwrap();
            assert!(!super::is_public_ip(&ip), "{private}");
        }

        for public in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            let ip: IpAddr = public.parse().unwrap();
            assert!(super::is_public_ip(&ip), "{public}");
        }
    }
}

fn needs_core_validation_only(config: &str) -> bool {
    match config_scheme(config).as_str() {
        "hysteria2" | "hy2" => !hysteria2_query_values(config, "obfs").is_empty(),
        "hysteria" => !query_values(config, "obfs").is_empty(),
        _ => false,
    }
}

fn select_all_candidates(
    ranked_working_configs: &[(String, u64)],
    special_candidates: &[String],
) -> Vec<String> {
    let mut selected = Vec::with_capacity(MAX_ALL_CONFIGS);
    let mut seen = HashSet::new();
    let mut endpoint_counts = HashMap::<(String, u16), usize>::new();
    let mut deferred = Vec::new();

    for config in ranked_working_configs
        .iter()
        .map(|(config, _)| config)
        .chain(special_candidates.iter())
    {
        if selected.len() >= MAX_ALL_CONFIGS {
            break;
        }

        if seen.contains(config) {
            continue;
        }

        let endpoint_allowed = endpoint(config)
            .map(|ep| endpoint_counts.get(&ep).copied().unwrap_or(0) < MAX_ALL_PER_ENDPOINT)
            .unwrap_or(true);

        if endpoint_allowed {
            seen.insert(config.clone());
            if let Some(ep) = endpoint(config) {
                *endpoint_counts.entry(ep).or_default() += 1;
            }
            selected.push(config.clone());
        } else {
            deferred.push(config.clone());
        }
    }

    for config in deferred {
        if selected.len() >= MAX_ALL_CONFIGS {
            break;
        }

        if seen.contains(&config) {
            continue;
        }

        let Some(ep) = endpoint(&config) else {
            if seen.insert(config.clone()) {
                selected.push(config);
            }
            continue;
        };

        if endpoint_counts.get(&ep).copied().unwrap_or(0) >= MAX_ALL_PER_ENDPOINT {
            continue;
        }

        seen.insert(config.clone());
        *endpoint_counts.entry(ep).or_default() += 1;
        selected.push(config);
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
        if is_public_ip(&address.ip()) && seen.insert(address) {
            unique.push(address);
        }
    }

    if unique.is_empty() {
        return None;
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

fn tcp_endpoint_groups(configs: &[String]) -> HashMap<(String, u16), Vec<usize>> {
    let mut tcp_by_endpoint: HashMap<(String, u16), Vec<usize>> = HashMap::new();

    for (index, config) in configs.iter().enumerate() {
        if matches!(
            config_scheme(config).as_str(),
            "hysteria" | "hysteria2" | "hy2" | "tuic" | "wg"
        ) {
            continue;
        }

        if let Some(endpoint) = endpoint(config) {
            tcp_by_endpoint.entry(endpoint).or_default().push(index);
        }
    }

    tcp_by_endpoint
}

fn build_tcp_probe_cache(configs: &[String]) -> (TcpProbeCache, usize, usize) {
    let tcp_by_endpoint = tcp_endpoint_groups(configs);
    let tcp_config_count = tcp_by_endpoint.values().map(Vec::len).sum();
    let unique_tcp_endpoints = tcp_by_endpoint.len();

    let cache = tcp_by_endpoint
        .into_keys()
        .map(|(host, port)| {
            let probe_host = host.clone();
            let probe = async move { tcp_latency_endpoint(&probe_host, port).await }
                .boxed()
                .shared();
            ((host, port), probe)
        })
        .collect();

    (Arc::new(cache), tcp_config_count, unique_tcp_endpoints)
}

async fn test_transport_configs(
    configs: &[String],
    tcp_probe_cache: TcpProbeCache,
) -> Vec<(String, u64)> {
    let tcp_by_endpoint = tcp_endpoint_groups(configs);

    let tcp_results = stream::iter(tcp_by_endpoint.keys().cloned())
        .map(|(host, port)| {
            let probe = tcp_probe_cache.get(&(host.clone(), port)).cloned();

            async move {
                let latency = probe?.await;
                latency.map(|latency| ((host, port), latency))
            }
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

    let transport_indices = configs
        .iter()
        .enumerate()
        .filter_map(|(index, config)| {
            matches!(
                config_scheme(config).as_str(),
                "hysteria" | "hysteria2" | "hy2" | "tuic" | "wg"
            )
            .then_some(index)
        })
        .collect::<Vec<_>>();

    if !transport_indices.is_empty() {
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

    let sni = query_value(config, &["sni", "peer", "server_name"]).unwrap_or_else(|| host.clone());

    let default_alpn = if config_scheme(config) == "hysteria" {
        "hysteria"
    } else {
        "h3"
    };

    let alpn = {
        let values = query_csv_values(config, "alpn");

        if values.is_empty() {
            vec![default_alpn.to_string()]
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

async fn hysteria2_quic_latency(config: &str) -> Option<u64> {
    let (host, _) = endpoint(config)?;

    if hysteria2_query_values(config, "obfs")
        .into_iter()
        .any(|value| !value.is_empty())
    {
        return None;
    }

    let ports = hysteria2_probe_ports(config)?;

    let sni = ["sni", "peer", "server_name"]
        .iter()
        .find_map(|key| hysteria2_query_values(config, key).into_iter().next())
        .unwrap_or_else(|| host.clone());

    let alpn = {
        let values = hysteria2_query_csv_values(config, "alpn");

        if values.is_empty() {
            vec!["h3".to_string()]
        } else {
            values
        }
    };

    quic_latency_for_targets(&host, &ports, &sni, &alpn).await
}

async fn quic_latency(config: &str) -> Option<u64> {
    if matches!(config_scheme(config).as_str(), "hysteria2" | "hy2") {
        return hysteria2_quic_latency(config).await;
    }

    let (host, port, sni, alpn) = quic_params(config)?;

    quic_latency_for_targets(&host, &[port], &sni, &alpn).await
}

struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(buf).map_err(|_| EntropyError)
    }
}

fn decode_key_32(encoded: &str) -> Option<[u8; 32]> {
    let encoded = encoded.trim();

    if encoded.is_empty() {
        return None;
    }

    let mut padded = encoded.to_string();

    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }

    for candidate in [encoded, padded.as_str()] {
        for decoded in [
            STANDARD.decode(candidate),
            URL_SAFE.decode(candidate),
            URL_SAFE_NO_PAD.decode(candidate),
        ]
        .into_iter()
        .flatten()
        {
            if decoded.len() == 32 {
                return decoded.try_into().ok();
            }
        }
    }

    None
}

fn wireguard_key(config: &str, keys: &[&str]) -> Option<[u8; 32]> {
    let encoded = query_value(config, keys)?;

    decode_key_32(&encoded)
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

    decode_key_32(username.as_ref())
}

async fn wireguard_latency_on_address(
    address: SocketAddr,
    private_key: [u8; 32],
    public_key: [u8; 32],
    psk: Option<[u8; 32]>,
) -> Option<u64> {
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
            return None;
        }

        let remaining = deadline.duration_since(now);

        let received = match timeout(remaining, socket.recv(&mut recv_buf)).await {
            Ok(Ok(size)) => size,
            _ => return None,
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

    let addresses = resolve_host_addresses(&host, port).await?;

    let probe = stream::iter(addresses)
        .map(|address| async move {
            wireguard_latency_on_address(address, private_key, public_key, psk).await
        })
        .buffer_unordered(MAX_WIREGUARD_ADDRESS_CONCURRENCY)
        .filter_map(|result| async move { result });

    futures::pin_mut!(probe);

    timeout(Duration::from_secs(TCP_TIMEOUT_SECS), probe.next())
        .await
        .ok()
        .flatten()
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
