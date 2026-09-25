use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt, TryStreamExt};
use percent_encoding::percent_decode_str;
use regex::Regex;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration, Instant};
use url::Url;

const DOWNLOAD_CONCURRENCY: usize = 16;
const TEST_CONCURRENCY: usize = 4;
const CHUNK_SIZE: usize = 500;
const LIGHT_LIMIT: usize = 200;
const TCP_TIMEOUT_SECS: u64 = 3;

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

    let mut light_configs = Vec::with_capacity(LIGHT_LIMIT);
    let mut index = 0usize;

    while light_configs.len() < LIGHT_LIMIT {
        let mut added = false;

        for scheme in &schemes {
            if let Some((config, _)) = by_scheme.get(scheme).and_then(|items| items.get(index)) {
                light_configs.push(config.clone());
                added = true;

                if light_configs.len() >= LIGHT_LIMIT {
                    break;
                }
            }
        }

        if !added {
            break;
        }

        index += 1;
    }

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
    let pattern = Regex::new(
        r#"(?i)(?:vmess|vless|trojan|ssr?|socks5?|hysteria2?|hy2|tuic|wg|ssh|naive\+https)://[^\s<>"']+|(?:https?)://[^\s<>"']+:\d+[^\s<>"']*"#,
    )
    .unwrap();

    let mut found = Vec::new();

    for capture in pattern.find_iter(text) {
        found.push(trim_config(capture.as_str()));
    }

    for decoded in decode_base64_variants(text) {
        for capture in pattern.find_iter(&decoded) {
            found.push(trim_config(capture.as_str()));
        }
    }

    found.sort_unstable();
    found.dedup();
    found
}

fn trim_config(config: &str) -> String {
    let config = config
        .trim_end_matches(|c| c == ')' || c == ']' || c == '}' || c == ',' || c == '\r' || c == '\n')
        .to_string();

    let Ok(mut url) = Url::parse(&config) else {
        return config;
    };

    if let Some(fragment) = url.fragment().map(str::to_string) {
        let decoded_fragment = percent_decode_str(&fragment)
            .decode_utf8_lossy()
            .to_string();

        let name: String = decoded_fragment
            .chars()
            .filter(|c| !is_emoji(*c))
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .trim_matches(|c| c == '-' || c == '_' || c == '|')
            .trim()
            .to_string();

        url.set_fragment(if name.is_empty() { None } else { Some(&name) });
    }

    url.to_string()
}

fn is_emoji(c: char) -> bool {
    matches!(
        c as u32,
        0x1F000..=0x1FAFF
            | 0x1FC00..=0x1FFFF
            | 0x2600..=0x27BF
            | 0x2300..=0x23FF
            | 0x2B00..=0x2BFF
            | 0x2190..=0x21FF
            | 0x3030..=0x303D
            | 0x3297..=0x3299
            | 0xFE00..=0xFE0F
            | 0xE0020..=0xE007F
    ) || matches!(
        c,
        '\u{00A9}'
            | '\u{00AE}'
            | '\u{203C}'
            | '\u{2049}'
            | '\u{2122}'
            | '\u{2139}'
            | '\u{200D}'
            | '\u{20E3}'
    )
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
        let mut decoded_texts = Vec::new();
        let mut padded = encoded.to_string();

        while padded.len() % 4 != 0 {
            padded.push('=');
        }

        for candidate in [encoded.to_string(), padded] {
            for decoded in [
                STANDARD.decode(&candidate),
                URL_SAFE.decode(&candidate),
                URL_SAFE_NO_PAD.decode(&candidate),
            ] {
                if let Ok(bytes) = decoded {
                    decoded_texts.push(String::from_utf8_lossy(&bytes).to_string());
                }
            }
        }

        let decoded = decoded_texts.into_iter().find(|text| text.contains("\"add\""))?;
        let add = Regex::new(r#"\"add\"\s*:\s*\"([^\"]+)\""#)
            .ok()?
            .captures(&decoded)?
            .get(1)?
            .as_str()
            .to_string();
        let port = Regex::new(r#"\"port\"\s*:\s*\"?([0-9]+)\"?"#)
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

    match timeout(
        Duration::from_secs(TCP_TIMEOUT_SECS),
        TcpStream::connect((host.as_str(), port))
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
