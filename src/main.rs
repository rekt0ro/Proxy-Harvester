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
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::{timeout, Duration, Instant};
use url::Url;

const DOWNLOAD_CONCURRENCY: usize = 16;
const TEST_CONCURRENCY: usize = 4;
const CHUNK_SIZE: usize = 500;
const LIGHT_LIMIT: usize = 200;
const TCP_TIMEOUT_SECS: u64 = 3;
const PROXY_TEST_LIMIT_PER_PROTOCOL: usize = 100;
const PROXY_TEST_TIMEOUT_SECS: u64 = 8;
const PROXY_TEST_WORKERS: usize = 20;
const PROXY_TEST_BATCH_SIZE: usize = 50;

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

    let source_results = stream::iter(sources.iter().cloned())
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
        .buffer_unordered(DOWNLOAD_CONCURRENCY)
        .collect::<Vec<Vec<String>>>()
        .await;

    let mut unique = HashSet::new();
    for configs in source_results {
        for config in configs {
            unique.insert(config);
        }
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

    let chunks: Vec<Vec<String>> = configs
        .chunks(CHUNK_SIZE)
        .map(|chunk| chunk.to_vec())
        .collect();

    let mut chunk_results = stream::iter(chunks.into_iter().enumerate())
        .map(|(index, chunk)| {
            async move { test_chunk(index, format!("{index}"), chunk).await }
        })
        .buffer_unordered(TEST_CONCURRENCY)
        .try_collect::<Vec<(usize, Vec<(String, u64)>)>>()
        .await?;

    chunk_results.sort_by_key(|(index, _)| *index);

    let mut all_output = File::create(&working_path).await?;
    let mut working_count = 0usize;
    let mut latency_by_config = HashMap::new();

    for (_, working) in chunk_results {
        for (config, latency_ms) in working {
            all_output.write_all(config.as_bytes()).await?;
            all_output.write_all(b"\n").await?;
            latency_by_config.insert(config, latency_ms);
            working_count += 1;
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

    let all_contents = fs::read_to_string(&working_path).await?;

    let working_configs: Vec<String> = all_contents
        .lines()
        .filter(|line| {
            let scheme = config_scheme(line);
            scheme != "http" && scheme != "https"
        })
        .map(ToOwned::to_owned)
        .collect();

    if working_configs.is_empty() {
        let _ = fs::remove_file(&working_path).await;
        return Err("no compatible proxy configs were found after filtering HTTP(S) endpoints".into());
    }

    let mut by_scheme: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    for config in &working_configs {
        if let Some(&latency_ms) = latency_by_config.get(config) {
            by_scheme
                .entry(config_scheme(config))
                .or_default()
                .push((config.clone(), latency_ms));
        }
    }

    for configs in by_scheme.values_mut() {
        configs.sort_by_key(|(_, latency_ms)| *latency_ms);
    }

    let mut schemes: Vec<String> = by_scheme.keys().cloned().collect();
    schemes.sort_unstable();

    let light_configs = match proxy_test_light(&by_scheme, &output_dir).await {
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

fn extract_configs(text: &str) -> Vec<String> {
    let text = decode_html_entities(text);

    let pattern = Regex::new(
        r#"(?i)(?:vmess|vless|trojan|ssr?|socks5?|hysteria2?|hy2|tuic|wg|ssh|naive\+https)://[^\s<>"']+|(?:https?)://[^\s<>"']+:\d+[^\s<>"']*"#,
    )
    .unwrap();

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

    if url.query_pairs().any(|(key, value)| {
        key.eq_ignore_ascii_case("fp") && value.eq_ignore_ascii_case("unsafe")
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

fn normalize_vless(config: &str, url: &Url) -> Option<String> {
    let uuid = percent_decode_str(url.username()).decode_utf8().ok()?;

    if !is_uuid(uuid.as_ref()) {
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

    if object
        .get("fp")
        .and_then(Value::as_str)
        .is_some_and(|fp| fp.trim().eq_ignore_ascii_case("unsafe"))
    {
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

        if let Ok(mut url) = Url::parse(&config) {
            url.set_fragment(Some(&name));
            named.push(url.to_string());
        } else {
            named.push(config);
        }
    }

    named
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

    if compact.len() >= 16 {
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

        let add = Regex::new(r#""add"\s*:\s*"([^"]+)""#)
            .ok()?
            .captures(&decoded)?
            .get(1)?
            .as_str()
            .to_string();
        let port = Regex::new(r#""port"\s*:\s*"?([0-9]+)"?"#)
            .ok()?
            .captures(&decoded)?
            .get(1)?
            .as_str()
            .parse::<u16>()
            .ok()?;

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

async fn tcp_latency(config: &str) -> Option<u64> {
    let (host, port) = endpoint(config)?;
    let start = Instant::now();

    let mut addresses = timeout(
        Duration::from_secs(TCP_TIMEOUT_SECS),
        tokio::net::lookup_host((host.as_str(), port)),
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

async fn tcp_reachable(config: &str) -> bool {
    tcp_latency(config).await.is_some()
}

async fn test_tcp_configs(configs: Vec<String>) -> Vec<(String, u64)> {
    stream::iter(configs)
        .map(|config| async move {
            tcp_latency(&config).await.map(|latency| (config, latency))
        })
        .buffer_unordered(TEST_CONCURRENCY * 16)
        .filter_map(async move |result| result)
        .collect()
        .await
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

async fn proxy_test_light(
    by_scheme: &HashMap<String, Vec<(String, u64)>>,
    output_dir: &Path,
) -> Option<Vec<String>> {
    let root = output_dir.parent()?.to_path_buf();
    let checker = root.join("scripts").join("check_proxies.py");

    if fs::metadata(&checker).await.is_err() {
        println!("[WARN] Python proxy checker is unavailable.");
        return None;
    }

    let mut schemes: Vec<String> = by_scheme.keys().cloned().collect();
    schemes.sort_unstable();

    let mut verified_by_scheme: HashMap<String, Vec<String>> = HashMap::new();
    let mut offsets: HashMap<String, usize> = HashMap::new();
    let mut total_verified = 0usize;

    while total_verified < LIGHT_LIMIT {
        let mut progress = false;

        for scheme in &schemes {
            if total_verified >= LIGHT_LIMIT {
                break;
            }
            if scheme == "http" || scheme == "https" || scheme == "ssr" {
                continue;
            }

            let Some(configs) = by_scheme.get(scheme) else { continue };
            let offset = *offsets.get(scheme).unwrap_or(&0);
            if offset >= configs.len() { continue }

            let end = (offset + PROXY_TEST_LIMIT_PER_PROTOCOL).min(configs.len());
            let candidates: Vec<&String> = configs[offset..end].iter().map(|(config, _)| config).collect();
            offsets.insert(scheme.clone(), end);

            if candidates.is_empty() { continue }
            progress = true;

            let input_path = output_dir.join(format!(".proxy-test-{scheme}.txt"));
            let output_path = output_dir.join(format!(".proxy-working-{scheme}.txt"));
            let input = candidates.iter().map(|config| config.as_str()).collect::<Vec<_>>().join("\n");

            if fs::write(&input_path, format!("{input}\n")).await.is_err() {
                println!("[WARN] Failed to prepare proxy test input for {scheme}.");
                continue;
            }

            let _ = fs::remove_file(&output_path).await;
            println!(
                "[INFO] Proxy-testing {} {} candidates (offset {}..{}) until {} verified configs are reached.",
                scheme, candidates.len(), offset, end, LIGHT_LIMIT
            );

            let start = Instant::now();
            let result = Command::new("python3")
                .arg(&checker)
                .arg("--input").arg(&input_path)
                .arg("--output").arg(&output_path)
                .arg("--workers").arg(PROXY_TEST_WORKERS.to_string())
                .arg("--batch-size").arg(PROXY_TEST_BATCH_SIZE.to_string())
                .arg("--timeout").arg(PROXY_TEST_TIMEOUT_SECS.to_string())
                .stdout(Stdio::piped()).stderr(Stdio::piped()).output().await;

            let Ok(result) = result else {
                println!("[WARN] Failed to run Python proxy checker for {scheme}.");
                let _ = fs::remove_file(&input_path).await;
                continue;
            };

            let stdout = String::from_utf8_lossy(&result.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&result.stderr).trim().to_string();
            println!(
                "[DIAG] Python proxy test {} exit: success={}, status={}, elapsed={}ms, stdout_bytes={}, stderr_bytes={}",
                scheme, result.status.success(), result.status, start.elapsed().as_millis(),
                result.stdout.len(), result.stderr.len()
            );
            if !stdout.is_empty() { println!("[INFO] Python proxy test {scheme}: {stdout}"); }

            if !result.status.success() {
                if !stderr.is_empty() { println!("[WARN] Python proxy test {scheme} stderr: {stderr}"); }
                let _ = fs::remove_file(&input_path).await;
                let _ = fs::remove_file(&output_path).await;
                continue;
            }
            if !stderr.is_empty() { println!("[INFO] Python proxy test {scheme} stderr: {stderr}"); }

            if let Ok(content) = fs::read_to_string(&output_path).await {
                let verified: Vec<String> = content.lines().map(str::trim).filter(|line| !line.is_empty()).map(ToOwned::to_owned).collect();
                let entry = verified_by_scheme.entry(scheme.clone()).or_default();
                let before = entry.len();
                let mut seen: HashSet<String> = entry.iter().cloned().collect();

                for config in verified {
                    if seen.insert(config.clone()) { entry.push(config); }
                }

                let added = entry.len() - before;
                total_verified += added;
                println!(
                    "[INFO] Proxy-tested {} batch: {} new verified, {} total verified.",
                    scheme, added, total_verified
                );
            } else {
                println!("[INFO] Proxy-tested {} batch: 0/{} passed.", scheme, candidates.len());
            }

            let _ = fs::remove_file(&input_path).await;
            let _ = fs::remove_file(&output_path).await;
        }

        if !progress { break; }
    }

    if verified_by_scheme.is_empty() {
        return None;
    }

    let mut verified = Vec::with_capacity(total_verified.min(LIGHT_LIMIT));
    let mut verified_schemes: Vec<String> = verified_by_scheme.keys().cloned().collect();
    verified_schemes.sort_unstable();

    let mut index = 0usize;
    while verified.len() < LIGHT_LIMIT {
        let mut added = false;
        for scheme in &verified_schemes {
            if let Some(config) = verified_by_scheme.get(scheme).and_then(|items| items.get(index)) {
                verified.push(config.clone());
                added = true;
                if verified.len() >= LIGHT_LIMIT { break; }
            }
        }
        if !added { break; }
        index += 1;
    }

    println!("[INFO] Proxy-level testing completed with {} fully verified configs.", verified.len());
    Some(verified)
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
