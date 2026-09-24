use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures::stream::{self, StreamExt, TryStreamExt};
use regex::Regex;
use reqwest::Client;
use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::Semaphore;

const DOWNLOAD_CONCURRENCY: usize = 16;
const TEST_CONCURRENCY: usize = 4;
const TEST_WORKERS: usize = 20;
const BATCH_SIZE: usize = 50;
const CHUNK_SIZE: usize = 500;
const LIGHT_LIMIT: usize = 200;
const TEST_TIMEOUT: usize = 5;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[INFO] Proxy-Harvester starting...");

    let root = project_root()?;
    let sources_path = root.join("sources.txt");
    let output_dir = root.join("subscriptions");
    fs::create_dir_all(&output_dir).await?;

    let sources = load_sources(&sources_path).await?;
    println!("[INFO] Loaded {} sources.", sources.len());

    let client = Client::builder()
        .user_agent("Proxy-Harvester/2.0")
        .timeout(std::time::Duration::from_secs(20))
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

    let working_path = output_dir.join(".working.txt");
    let all_path = output_dir.join("all.txt");
    let light_path = output_dir.join("light.txt");

    let _ = fs::remove_file(&working_path).await;
    let _ = fs::remove_file(&light_path).await;

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
                test_chunk(index, chunk).await
            }
        })
        .buffer_unordered(TEST_CONCURRENCY)
        .try_collect::<Vec<(usize, Vec<String>)>>()
        .await?;

    chunk_results.sort_by_key(|(index, _)| *index);

    let mut all_output = File::create(&working_path).await?;
    let mut light_count = 0usize;
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

    let all_contents = fs::read_to_string(&working_path).await?;
    let mut light_output = String::new();

    for line in all_contents.lines() {
        if light_count >= LIGHT_LIMIT {
            break;
        }
        light_output.push_str(line);
        light_output.push('\n');
        light_count += 1;
    }

    fs::write(&light_path, light_output).await?;
    fs::rename(&working_path, &all_path).await?;

    println!("[INFO] Published {} working configs to all.txt.", working_count);
    println!("[INFO] Published {} configs to light.txt.", light_count);
    println!("[INFO] Done.");

    Ok(())
}

async fn project_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let exe = env::current_exe()?;
    let root = exe
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or("failed to determine project root")?;
    Ok(root.to_path_buf())
}

async fn load_sources(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
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
        r#"(?i)(?:vmess|vless|trojan|ssr?|socks5?|hysteria2?|hy2)://[^s<>"']+|(?:https?)://[^/s<>"']+:d+[^s<>"']*"#,
    )
    .unwrap();

    let mut found = Vec::new();

    for capture in pattern.find_iter(text) {
        found.push(trim_config(capture.as_str()));
    }

    if found.is_empty() {
        if let Some(decoded) = decode_base64(text) {
            for capture in pattern.find_iter(&decoded) {
                found.push(trim_config(capture.as_str()));
            }
        }
    } else {
        let decoded = decode_base64(text);
        if let Some(decoded) = decoded {
            for capture in pattern.find_iter(&decoded) {
                found.push(trim_config(capture.as_str()));
            }
        }
    }

    found
}

fn trim_config(config: &str) -> String {
    config
        .trim_end_matches(|c| c == ')' || c == ']' || c == '}' || c == ',' || c == '\r' || c == '\n')
        .to_string()
}

fn decode_base64(text: &str) -> Option<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();

    if compact.len() < 16 {
        return None;
    }

    let mut padded = compact.clone();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }

    if let Ok(bytes) = STANDARD.decode(&padded) {
        let decoded = String::from_utf8_lossy(&bytes).to_string();
        if decoded.contains("://") {
            return Some(decoded);
        }
    }

    None
}

async fn test_chunk(
    index: usize,
    configs: Vec<String>,
) -> Result<(usize, Vec<String>), Box<dyn std::error::Error + Send + Sync>> {
    if configs.is_empty() {
        return Ok((index, Vec::new()));
    }

    let temp = std::env::temp_dir().join(format!(
        "proxy-harvester-{}-{}.txt",
        std::process::id(),
        index
    ));

    let output = std::env::temp_dir().join(format!(
        "proxy-harvester-{}-{}-working.txt",
        std::process::id(),
        index
    ));

    fs::write(&temp, configs.join("\n")).await?;

    println!(
        "[INFO] Testing chunk {} ({} configs)...",
        index + 1,
        configs.len()
    );

    let status = Command::new("sb2p")
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
        .status()
        .await?;

    if !status.success() {
        println!(
            "[WARN] Chunk {} returned exit code {}. Retrying invalid entries individually.",
            index + 1,
            status.code().unwrap_or(-1)
        );
        let result = retry_individually(&configs).await?;
        let _ = fs::remove_file(&temp).await;
        let _ = fs::remove_file(&output).await;
        return Ok((index, result));
    }

    let working = if output.exists() {
        read_working(&output).await?
    } else {
        Vec::new()
    };

    println!(
        "[INFO] Chunk {} complete: {}/{} working.",
        index + 1,
        working.len(),
        configs.len()
    );

    let _ = fs::remove_file(&temp).await;
    let _ = fs::remove_file(&output).await;

    Ok((index, working))
}

async fn retry_individually(
    configs: &[String],
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let semaphore = Arc::new(Semaphore::new(TEST_WORKERS));
    let results = stream::iter(configs.iter().cloned())
        .map(|config| {
            let semaphore = semaphore.clone();
            async move {
                let _permit = semaphore.acquire_owned().await?;
                test_one(&config).await
            }
        })
        .buffer_unordered(TEST_WORKERS)
        .try_collect::<Vec<Option<String>>>()
        .await?;

    Ok(results.into_iter().flatten().collect())
}

async fn test_one(
    config: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let temp = std::env::temp_dir().join(format!(
        "proxy-harvester-one-{}.txt",
        uuid_seed(config)
    ));
    let output = std::env::temp_dir().join(format!(
        "proxy-harvester-one-{}-working.txt",
        uuid_seed(config)
    ));

    fs::write(&temp, config).await?;

    let status = Command::new("sb2p")
        .arg("--check")
        .arg(&temp)
        .arg("-o")
        .arg(&output)
        .arg("-q")
        .arg("--workers")
        .arg("1")
        .arg("--batch-size")
        .arg("1")
        .arg("--timeout")
        .arg(TEST_TIMEOUT.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    let working = if status.map(|s| s.success()).unwrap_or(false) && output.exists() {
        let values = read_working(&output).await?;
        values.into_iter().next()
    } else {
        None
    };

    let _ = fs::remove_file(&temp).await;
    let _ = fs::remove_file(&output).await;

    Ok(working)
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

fn uuid_seed(value: &str) -> String {
    let mut hash = 1469598103934665603u64;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    format!("{hash:x}")
}
