use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt, TryStreamExt};
use regex::Regex;
use reqwest::{Client, Proxy};
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use url::Url;

const DOWNLOAD_CONCURRENCY: usize = 16;
const TEST_CONCURRENCY: usize = 4;
const PLAIN_WORKERS: usize = 32;
const TEST_WORKERS: usize = 8;
const BATCH_SIZE: usize = 50;
const CHUNK_SIZE: usize = 500;
const LIGHT_LIMIT: usize = 200;
const TEST_TIMEOUT: usize = 6;
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
    let light_working_path = output_dir.join(".light.txt");
    let all_path = output_dir.join("all.txt");
    let light_path = output_dir.join("light.txt");

    let _ = fs::remove_file(&working_path).await;
    let _ = fs::remove_file(&light_working_path).await;

    let chunks: Vec<Vec<String>> = configs
        .chunks(CHUNK_SIZE)
        .map(|chunk| chunk.to_vec())
        .collect();

    let semaphore = Arc::new(Semaphore::new(TEST_CONCURRENCY));
    let mut chunk_results = stream::iter(chunks.into_iter().enumerate())
        .map(|(index, chunk)| {
            let semaphore = semaphore.clone();
            async move {
                let _permit = semaphore.acquire_owned().await?;
                test_chunk(index, format!("{index}"), chunk).await
            }
        })
        .buffer_unordered(TEST_CONCURRENCY)
        .try_collect::<Vec<(usize, Vec<String>)>>()
        .await?;

    chunk_results.sort_by_key(|(index, _)| *index);

    let mut all_output = File::create(&working_path).await?;
    let mut working_count = 0usize;

    for (_, working) in chunk_results {
        for config in working {
            all_output.write_all(config.as_bytes()).await?;
            all_output.write_all(b"\n").await?;
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
    let light_output: String = all_contents
        .lines()
        .take(LIGHT_LIMIT)
        .map(|line| format!("{line}\n"))
        .collect();

    fs::write(&light_working_path, light_output).await?;
    fs::rename(&working_path, &all_path).await?;
    fs::rename(&light_working_path, &light_path).await?;

    let light_count = fs::read_to_string(&light_path)
        .await?
        .lines()
        .count();

    println!("[INFO] Published {} working configs to all.txt.", working_count);
    println!("[INFO] Published {} configs to light.txt.", light_count);
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
    config
        .trim_end_matches(|c| c == ')' || c == ']' || c == '}' || c == ',' || c == '\r' || c == '\n')
        .to_string()
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

fn is_plain_proxy(config: &str) -> bool {
    matches!(
        config_scheme(config).as_str(),
        "http" | "https" | "socks5" | "socks5h"
    )
}

fn endpoint(config: &str) -> Option<(String, u16)> {
    let url = Url::parse(config).ok()?;
    let host = url.host_str()?.to_string();
    let port = url.port().or_else(|| match url.scheme().to_ascii_lowercase().as_str() {
        "http" => Some(80),
        "https" => Some(443),
        "socks" | "socks4" | "socks5" | "socks5h" => Some(1080),
        _ => None,
    })?;
    Some((host, port))
}

async fn tcp_reachable(config: &str) -> bool {
    let Some((host, port)) = endpoint(config) else {
        return true;
    };

    matches!(
        timeout(
            Duration::from_secs(TCP_TIMEOUT_SECS),
            TcpStream::connect((host.as_str(), port))
        )
        .await,
        Ok(Ok(_))
    )
}

async fn test_plain_proxy(config: String, target: &'static str) -> bool {
    let Ok(proxy) = Proxy::all(&config) else {
        return false;
    };

    let Ok(client) = Client::builder()
        .proxy(proxy)
        .connect_timeout(Duration::from_secs(TCP_TIMEOUT_SECS))
        .timeout(Duration::from_secs(TEST_TIMEOUT as u64))
        .user_agent("Proxy-Harvester/3.0")
        .build()
    else {
        return false;
    };

    match client.get(target).send().await {
        Ok(response) => response.status().is_success() || response.status().is_redirection(),
        Err(_) => false,
    }
}

async fn test_plain_configs(configs: Vec<String>) -> Vec<String> {
    if configs.is_empty() {
        return Vec::new();
    }

    let semaphore = Arc::new(Semaphore::new(PLAIN_WORKERS));

    stream::iter(configs)
        .map(|config| {
            let semaphore = semaphore.clone();
            async move {
                let _permit = semaphore.acquire_owned().await.ok();
                if test_plain_proxy(config.clone(), "https://www.gstatic.com/generate_204").await {
                    Some(config)
                } else {
                    None
                }
            }
        })
        .buffer_unordered(PLAIN_WORKERS)
        .filter_map(async move |result| result)
        .collect()
        .await
}

async fn test_advanced_batch(
    index: usize,
    label: &str,
    configs: &[String],
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    if configs.is_empty() {
        return Ok(Vec::new());
    }

    let reachable = stream::iter(configs.iter().cloned())
        .map(|config| async move {
            if tcp_reachable(&config).await {
                Some(config)
            } else {
                None
            }
        })
        .buffer_unordered(64)
        .filter_map(async move |result| result)
        .collect::<Vec<String>>()
        .await;

    println!(
        "[INFO] Chunk {} advanced candidates: {}/{} passed TCP preflight.",
        label,
        reachable.len(),
        configs.len()
    );

    if reachable.is_empty() {
        return Ok(Vec::new());
    }

    let temp = std::env::temp_dir().join(format!(
        "proxy-harvester-{}-{}-{}.txt",
        std::process::id(),
        index,
        label
    ));
    let output = std::env::temp_dir().join(format!(
        "proxy-harvester-{}-{}-{}-working.txt",
        std::process::id(),
        index,
        label
    ));

    fs::write(&temp, reachable.join("\n")).await?;

    let result = Command::new("sb2p")
        .arg("--check")
        .arg(&temp)
        .arg("-o")
        .arg(&output)
        .arg("-q")
        .arg("--workers")
        .arg(TEST_WORKERS.to_string())
        .arg("--batch-size")
        .arg(BATCH_SIZE.to_string())
        .arg("--timeout")
        .arg(TEST_TIMEOUT.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        if !stderr.trim().is_empty() {
            println!("[WARN] sb2p chunk {}: {}", label, stderr.trim());
        }

        let _ = fs::remove_file(&temp).await;
        let _ = fs::remove_file(&output).await;

        if reachable.len() == 1 {
            return Ok(Vec::new());
        }

        let midpoint = reachable.len() / 2;
        let left_future = Box::pin(test_advanced_batch(index, &format!("{label}a"), &reachable[..midpoint]));
        let right_future = Box::pin(test_advanced_batch(index, &format!("{label}b"), &reachable[midpoint..]));
        let (left, right) = tokio::join!(left_future, right_future);

        let mut combined = left?;
        combined.extend(right?);
        return Ok(combined);
    }

    let working = if output.exists() {
        read_working(&output).await?
    } else {
        Vec::new()
    };

    println!(
        "[INFO] Chunk {} advanced complete: {}/{} working.",
        label,
        working.len(),
        reachable.len()
    );

    let _ = fs::remove_file(&temp).await;
    let _ = fs::remove_file(&output).await;

    Ok(working)
}

async fn test_chunk(
    index: usize,
    label: String,
    configs: Vec<String>,
) -> Result<(usize, Vec<String>), Box<dyn std::error::Error + Send + Sync>> {
    let mut plain = Vec::new();
    let mut advanced = Vec::new();

    for config in configs {
        if is_plain_proxy(&config) {
            plain.push(config);
        } else {
            advanced.push(config);
        }
    }

    println!(
        "[INFO] Testing chunk {}: {} plain, {} advanced.",
        label,
        plain.len(),
        advanced.len()
    );

    let plain_future = test_plain_configs(plain);
    let advanced_future = test_advanced_batch(index, &label, &advanced);
    let (plain_working, advanced_working) = tokio::join!(plain_future, advanced_future);

    let mut working = plain_working;
    working.extend(advanced_working?);

    working.sort_unstable();
    working.dedup();

    println!(
        "[INFO] Chunk {} complete: {}/{} working.",
        label,
        working.len(),
        working.len() + advanced.len()
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

    println!("[DIAG] Testing {} protocol samples.", samples.len());

    for (index, config) in samples.iter().enumerate() {
        println!("[DIAG] Sample {} [{}]: {}", index + 1, config_scheme(config), config);

        if is_plain_proxy(config) {
            let working = test_plain_proxy(config.clone(), "https://www.gstatic.com/generate_204").await;
            println!("[DIAG] Plain proxy result: {}", if working { "PASS" } else { "FAIL" });
            continue;
        }

        match Command::new("sb2p")
            .arg(config)
            .arg("--test")
            .arg("--verbose")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
        {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                let stderr = String::from_utf8_lossy(&result.stderr);

                if !stdout.trim().is_empty() {
                    println!("[DIAG] stdout:\n{}", stdout.trim());
                }

                if !stderr.trim().is_empty() {
                    println!("[DIAG] stderr:\n{}", stderr.trim());
                }
            }
            Err(error) => {
                println!("[DIAG] Failed to execute sb2p: {error}");
            }
        }
    }
}

async fn read_working(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(path).await?;
    let mut reader = BufReader::new(file).lines();
    let mut result = Vec::new();

    while let Some(line) = reader.next_line().await? {
        let line = line.trim();
        if !line.is_empty() {
            result.push(line.to_string());
        }
    }

    Ok(result)
}
