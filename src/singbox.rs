use crate::validator::ProxyMetrics;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::Url;

const TARGET: &str = "http://cp.cloudflare.com/";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const STABILITY_ATTEMPTS: usize = 3;
const MIN_SUCCESSFUL_ATTEMPTS: usize = 2;
const MAX_LATENCY_MS: f64 = 3000.0;
const START_TIMEOUT: Duration = Duration::from_secs(5);
const BATCH_SIZE: usize = 250;

fn clean(url: &str) -> &str {
    url.split('#').next().unwrap_or(url)
}

fn decode_component(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

fn b64decode(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    let mut padded = value.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }

    for candidate in [value, padded.as_str()] {
        for decoded in [
            STANDARD.decode(candidate),
            URL_SAFE.decode(candidate),
            URL_SAFE_NO_PAD.decode(candidate),
        ] {
            if let Ok(bytes) = decoded {
                return Some(bytes);
            }
        }
    }

    None
}

fn boolish(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_u64().unwrap_or(0) != 0,
        Some(Value::String(value)) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        _ => false,
    }
}

fn query_bool(url: &Url, names: &[&str]) -> bool {
    url.query_pairs().any(|(key, value)| {
        names.iter().any(|name| key.eq_ignore_ascii_case(name))
            && matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
    })
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;

    for part in path {
        current = match current {
            Value::Object(map) => map.get(*part)?,
            Value::Array(values) => {
                let index = part.parse::<usize>().ok()?;
                values.get(index)?
            }
            _ => return None,
        };
    }

    Some(current)
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str, String> {
    value_at(value, path)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("invalid {}", path.join(".")))
}

fn u16_at(value: &Value, path: &[&str]) -> Result<u16, String> {
    let current = value_at(value, path).ok_or_else(|| format!("missing {}", path.join(".")))?;

    match current {
        Value::Number(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| format!("invalid {}", path.join("."))),
        Value::String(value) => value
            .parse::<u16>()
            .map_err(|_| format!("invalid {}", path.join("."))),
        _ => Err(format!("invalid {}", path.join("."))),
    }
}

fn first_user(value: &Value) -> Result<&Value, String> {
    value["settings"]["vnext"]
        .get(0)
        .and_then(|node| node["users"].get(0))
        .ok_or_else(|| "missing outbound user".to_string())
}

fn tls_settings(stream: &Value, insecure: bool) -> Result<Option<Value>, String> {
    let security = stream
        .get("security")
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_ascii_lowercase();

    if security == "none" {
        return Ok(None);
    }
    if !matches!(security.as_str(), "tls" | "reality") {
        return Err(format!("unsupported sing-box TLS mode {security}"));
    }

    let xray_tls = stream
        .get("tlsSettings")
        .or_else(|| stream.get("realitySettings"))
        .ok_or_else(|| "missing TLS settings".to_string())?;

    let mut tls = json!({
        "enabled": true,
    });

    if let Some(server_name) = xray_tls.get("serverName").and_then(Value::as_str) {
        if !server_name.is_empty() {
            tls["server_name"] = json!(server_name);
        }
    }
    if insecure {
        tls["insecure"] = json!(true);
    }
    if let Some(alpn) = xray_tls.get("alpn").filter(|value| value.is_array()) {
        tls["alpn"] = alpn.clone();
    }
    if security == "reality" {
        let fingerprint = xray_tls
            .get("fingerprint")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("chrome");

        tls["utls"] = json!({
            "enabled": true,
            "fingerprint": fingerprint,
        });
    } else if let Some(fp) = xray_tls
        .get("fingerprint")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        tls["utls"] = json!({
            "enabled": true,
            "fingerprint": fp,
        });
    }

    if security == "reality" {
        let reality = stream
            .get("realitySettings")
            .ok_or_else(|| "missing Reality settings".to_string())?;
        let public_key = reality
            .get("publicKey")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Reality public key missing".to_string())?;
        let short_id = reality.get("shortId").and_then(Value::as_str).unwrap_or("");

        tls["reality"] = json!({
            "enabled": true,
            "public_key": public_key,
            "short_id": short_id,
        });
    }

    Ok(Some(tls))
}

fn transport_settings(stream: &Value) -> Result<Option<Value>, String> {
    let network = stream
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or("raw")
        .to_ascii_lowercase();

    match network.as_str() {
        "raw" => {
            let header = stream
                .get("rawSettings")
                .and_then(|value| value.get("header"))
                .filter(|value| !value.is_null());

            if header
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("http"))
            {
                let request = header
                    .and_then(|value| value.get("request"))
                    .ok_or_else(|| "missing raw HTTP request settings".to_string())?;

                let mut transport = json!({
                    "type": "http",
                });

                if let Some(path) = request
                    .get("path")
                    .and_then(Value::as_array)
                    .and_then(|value| value.first())
                    .and_then(Value::as_str)
                {
                    transport["path"] = json!(path);
                }

                if let Some(host) = request.get("headers").and_then(|value| value.get("Host")) {
                    if host.is_array() {
                        transport["host"] = host.clone();
                    } else if let Some(host) = host.as_str() {
                        transport["host"] = json!([host]);
                    }
                }

                Ok(Some(transport))
            } else {
                Ok(None)
            }
        }
        "ws" => {
            let settings = stream
                .get("wsSettings")
                .ok_or_else(|| "missing WebSocket settings".to_string())?;
            let mut transport = json!({
                "type": "ws",
            });

            if let Some(path) = settings.get("path").and_then(Value::as_str) {
                if !path.is_empty() {
                    transport["path"] = json!(path);
                }
            }
            if let Some(headers) = settings.get("headers").filter(|value| value.is_object()) {
                transport["headers"] = headers.clone();
            }

            Ok(Some(transport))
        }
        "grpc" => {
            let settings = stream
                .get("grpcSettings")
                .ok_or_else(|| "missing gRPC settings".to_string())?;
            if settings
                .get("multiMode")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err("sing-box gRPC multiMode unsupported".to_string());
            }
            if settings
                .get("authority")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            {
                return Err("sing-box gRPC authority unsupported".to_string());
            }

            let mut transport = json!({
                "type": "grpc",
            });
            if let Some(service_name) = settings
                .get("serviceName")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            {
                transport["service_name"] = json!(service_name);
            }

            Ok(Some(transport))
        }
        "httpupgrade" => {
            let settings = stream
                .get("httpupgradeSettings")
                .ok_or_else(|| "missing HTTPUpgrade settings".to_string())?;
            let mut transport = json!({
                "type": "httpupgrade",
            });

            if let Some(path) = settings.get("path").and_then(Value::as_str) {
                if !path.is_empty() {
                    transport["path"] = json!(path);
                }
            }
            if let Some(host) = settings.get("host").and_then(Value::as_str) {
                if !host.is_empty() {
                    transport["host"] = json!(host);
                }
            }

            Ok(Some(transport))
        }
        "xhttp" => Err("sing-box standard build does not support XHTTP".to_string()),
        "hysteria" => Ok(None),
        "tcp" => Ok(None),
        _ => Err(format!("unsupported sing-box transport {network}")),
    }
}

fn vmess_security(value: &str) -> Result<&'static str, String> {
    match value.to_ascii_lowercase().as_str() {
        "auto" => Ok("auto"),
        "none" => Ok("none"),
        "zero" => Ok("zero"),
        "aes-128-gcm" => Ok("aes-128-gcm"),
        "chacha20-poly1305" => Ok("chacha20-poly1305"),
        "aes-128-ctr" => Ok("aes-128-ctr"),
        other => Err(format!("unsupported sing-box VMess security {other}")),
    }
}

fn parse_vmess_raw(config: &str) -> Result<Value, String> {
    let payload = clean(config)
        .split_once("://")
        .ok_or_else(|| "invalid VMess URL".to_string())?
        .1;
    let decoded = b64decode(payload).ok_or_else(|| "invalid VMess base64".to_string())?;
    serde_json::from_slice(&decoded).map_err(|error| error.to_string())
}

fn singbox_outbound(config: &str) -> Result<Value, String> {
    let scheme = Url::parse(clean(config))
        .map_err(|error| error.to_string())?
        .scheme()
        .to_ascii_lowercase();
    let xray = crate::validator::parse_config(config)?;
    let stream = xray
        .get("streamSettings")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let transport = transport_settings(&stream)?;

    match scheme.as_str() {
        "vless" => {
            let user = first_user(&xray)?;
            let mut outbound = json!({
                "type": "vless",
                "server": string_at(&xray, &["settings", "vnext", "0", "address"])?,
                "server_port": u16_at(&xray, &["settings", "vnext", "0", "port"])?,
                "uuid": string_at(user, &["id"])?,
            });

            if let Some(flow) = user.get("flow").and_then(Value::as_str) {
                if flow != "xtls-rprx-vision" {
                    return Err(format!("unsupported sing-box VLESS flow {flow}"));
                }
                outbound["flow"] = json!(flow);
            }

            if let Some(tls) = tls_settings(
                &stream,
                query_bool(
                    &Url::parse(clean(config)).map_err(|error| error.to_string())?,
                    &["insecure"],
                ),
            )? {
                outbound["tls"] = tls;
            }
            if let Some(transport) = transport {
                outbound["transport"] = transport;
            }
            Ok(outbound)
        }
        "vmess" => {
            let source = parse_vmess_raw(config)?;
            let user = first_user(&xray)?;
            let network = stream
                .get("network")
                .and_then(Value::as_str)
                .unwrap_or("raw")
                .to_ascii_lowercase();
            let mut outbound = json!({
                "type": "vmess",
                "server": string_at(&xray, &["settings", "vnext", "0", "address"])?,
                "server_port": u16_at(&xray, &["settings", "vnext", "0", "port"])?,
                "uuid": string_at(user, &["id"])?,
                "security": vmess_security(string_at(user, &["security"] )?)?,
                "alter_id": user.get("alterId").and_then(Value::as_u64).unwrap_or(0),
            });

            if network != "udp" {
                outbound["network"] = json!("tcp");
            }

            if let Some(tls) = tls_settings(&stream, boolish(source.get("allowInsecure")))? {
                outbound["tls"] = tls;
            }
            if let Some(transport) = transport {
                outbound["transport"] = transport;
            }

            Ok(outbound)
        }
        "trojan" => {
            let url = Url::parse(clean(config)).map_err(|error| error.to_string())?;
            let password = xray["settings"]["servers"]
                .get(0)
                .and_then(|server| server["password"].as_str())
                .ok_or_else(|| "missing Trojan password".to_string())?;
            let mut outbound = json!({
                "type": "trojan",
                "server": string_at(&xray, &["settings", "servers", "0", "address"])?,
                "server_port": u16_at(&xray, &["settings", "servers", "0", "port"])?,
                "password": password,
            });

            if let Some(tls) = tls_settings(&stream, query_bool(&url, &["insecure"]))? {
                outbound["tls"] = tls;
            }
            if let Some(transport) = transport {
                outbound["transport"] = transport;
            }

            Ok(outbound)
        }
        "ss" => Ok(json!({
            "type": "shadowsocks",
            "server": string_at(&xray, &["settings", "servers", "0", "address"])?,
            "server_port": u16_at(&xray, &["settings", "servers", "0", "port"])?,
            "method": string_at(&xray, &["settings", "servers", "0", "method"])?,
            "password": string_at(&xray, &["settings", "servers", "0", "password"])?,
        })),
        "hysteria2" | "hy2" => {
            let url = Url::parse(clean(config)).map_err(|error| error.to_string())?;
            let password = string_at(&xray, &["streamSettings", "hysteriaSettings", "auth"])?;
            let mut outbound = json!({
                "type": "hysteria2",
                "server": string_at(&xray, &["settings", "address"])?,
                "server_port": u16_at(&xray, &["settings", "port"])?,
                "password": password,
            });

            if let Some(tls) = tls_settings(&stream, query_bool(&url, &["insecure"]))? {
                outbound["tls"] = tls;
            } else {
                return Err("Hysteria2 TLS settings missing".to_string());
            }
            Ok(outbound)
        }
        _ => Err(format!("scheme {scheme} not supported by sing-box Light")),
    }
}

fn allocated_ports(count: usize) -> Result<Vec<u16>, String> {
    let mut ports = Vec::with_capacity(count);
    let mut listeners = Vec::with_capacity(count);

    for _ in 0..count {
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
        ports.push(
            listener
                .local_addr()
                .map_err(|error| error.to_string())?
                .port(),
        );
        listeners.push(listener);
    }

    drop(listeners);
    Ok(ports)
}

fn singbox_config(entries: &[(String, Value)]) -> Result<(Value, Vec<u16>), String> {
    let ports = allocated_ports(entries.len())?;
    let mut inbounds = Vec::with_capacity(entries.len());
    let mut outbounds = Vec::with_capacity(entries.len());
    let mut rules = Vec::with_capacity(entries.len());

    for (index, (_, outbound)) in entries.iter().enumerate() {
        let in_tag = format!("in-{index}");
        let out_tag = format!("out-{index}");
        let mut outbound = outbound.clone();
        outbound["tag"] = json!(out_tag);

        inbounds.push(json!({
            "type": "socks",
            "tag": in_tag,
            "listen": "127.0.0.1",
            "listen_port": ports[index],
        }));
        outbounds.push(outbound);
        rules.push(json!({
            "inbound": [in_tag],
            "action": "route",
            "outbound": out_tag,
        }));
    }

    Ok((
        json!({
            "log": { "level": "error" },
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {
                "rules": rules,
                "auto_detect_interface": true,
            }
        }),
        ports,
    ))
}

fn make_temp_dir() -> Result<std::path::PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "proxy-harvester-singbox-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).map_err(|error| error.to_string())?;
    Ok(path)
}

fn start_singbox(
    binary: &str,
    config_path: &std::path::Path,
    log_path: &std::path::Path,
) -> Result<Child, String> {
    let log = File::create(log_path).map_err(|error| error.to_string())?;
    let stderr = log.try_clone().map_err(|error| error.to_string())?;

    Command::new(binary)
        .args(["run", "-c"])
        .arg(config_path)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .stdin(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())
}

fn check_singbox_config(binary: &str, config_path: &std::path::Path) -> Result<(), String> {
    let output = Command::new(binary)
        .args(["check", "-c"])
        .arg(config_path)
        .output()
        .map_err(|error| error.to_string())?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(if stderr.trim().is_empty() {
        "sing-box rejected configuration".to_string()
    } else {
        stderr.trim().to_string()
    })
}

async fn ports_ready(child: &mut Child, ports: &[u16]) -> bool {
    let deadline = tokio::time::Instant::now() + START_TIMEOUT;
    let workers = ports.len().clamp(1, 64);
    let mut pending = ports.to_vec();

    while !pending.is_empty() && tokio::time::Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }

        let checks = stream::iter(pending.clone())
            .map(|port| async move {
                let ready = timeout(
                    Duration::from_millis(150),
                    TcpStream::connect(("127.0.0.1", port)),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .is_some();
                (port, ready)
            })
            .buffer_unordered(workers)
            .collect::<Vec<_>>()
            .await;

        pending = checks
            .into_iter()
            .filter_map(|(port, ready)| (!ready).then_some(port))
            .collect();
    }

    pending.is_empty()
}

fn client_for_port(port: u16) -> Result<Client, String> {
    Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
                .map_err(|error| error.to_string())?,
        )
        .timeout(REQUEST_TIMEOUT)
        .user_agent("Proxy-Harvester-Singbox/1.0")
        .build()
        .map_err(|error| error.to_string())
}

async fn request_url(client: &Client, url: &str, head: bool) -> Result<f64, String> {
    let started = std::time::Instant::now();
    let response = if head {
        client.head(url)
    } else {
        client.get(url)
    }
    .send()
    .await
    .map_err(|error| error.to_string())?;

    let _ = response;
    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

async fn check_batch(
    binary: &str,
    entries: &[(String, Value)],
    workers: usize,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    if entries.is_empty() {
        return Ok(HashMap::new());
    }

    let mut pending = vec![entries.to_vec()];
    let mut verified = HashMap::new();

    while let Some(batch_entries) = pending.pop() {
        let work = make_temp_dir()?;
        let config_path = work.join("sing-box.json");
        let log_path = work.join("sing-box.log");
        let (config, local_ports) = singbox_config(&batch_entries)?;

        fs::write(
            &config_path,
            serde_json::to_vec(&config).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;

        if let Err(error) = check_singbox_config(binary, &config_path) {
            let _ = fs::remove_dir_all(&work);

            if batch_entries.len() > 1 {
                let mid = batch_entries.len() / 2;
                pending.push(batch_entries[..mid].to_vec());
                pending.push(batch_entries[mid..].to_vec());
                continue;
            }

            println!("[WARN] sing-box rejected {}: {}", batch_entries[0].0, error);
            continue;
        }

        let mut child = start_singbox(binary, &config_path, &log_path)?;

        if !ports_ready(&mut child, &local_ports).await {
            let _ = child.kill();
            let _ = child.wait();

            if batch_entries.len() > 1 {
                let mid = batch_entries.len() / 2;
                pending.push(batch_entries[..mid].to_vec());
                pending.push(batch_entries[mid..].to_vec());
                let _ = fs::remove_dir_all(&work);
                continue;
            }

            let tail = fs::read_to_string(&log_path)
                .unwrap_or_default()
                .chars()
                .rev()
                .take(700)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>();
            println!("[WARN] sing-box failed to start: {}", batch_entries[0].0);
            if !tail.is_empty() {
                println!("[WARN] sing-box log: {tail}");
            }
            let _ = fs::remove_dir_all(&work);
            continue;
        }

        let mut active = Vec::with_capacity(batch_entries.len());
        let mut client_error = None;

        for (index, (config, _)) in batch_entries.iter().enumerate() {
            match client_for_port(local_ports[index]) {
                Ok(client) => active.push((config.clone(), client)),
                Err(error) => {
                    client_error = Some(error);
                    break;
                }
            }
        }

        if let Some(error) = client_error {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir_all(&work);
            return Err(error);
        }

        let mut successes = HashMap::<String, usize>::new();
        let mut attempts = HashMap::<String, usize>::new();
        let mut latencies = HashMap::<String, Vec<f64>>::new();

        for attempt in 0..STABILITY_ATTEMPTS {
            let results = stream::iter(active.clone())
                .map(|(config, client)| async move {
                    let started = std::time::Instant::now();
                    let result = match request_url(&client, TARGET, false).await {
                        Ok(_) => match request_url(&client, TARGET, true).await {
                            Ok(_) => Ok(started.elapsed().as_secs_f64() * 1000.0),
                            Err(error) => Err(error),
                        },
                        Err(error) => Err(error),
                    };
                    (config, result)
                })
                .buffer_unordered(workers.max(1))
                .collect::<Vec<_>>()
                .await;

            for (config, result) in results {
                *attempts.entry(config.clone()).or_insert(0) += 1;
                if let Ok(latency) = result {
                    *successes.entry(config.clone()).or_insert(0) += 1;
                    latencies.entry(config).or_default().push(latency);
                }
            }

            let remaining_attempts = STABILITY_ATTEMPTS - attempt - 1;
            active.retain(|(config, _)| {
                let wins = successes.get(config).copied().unwrap_or(0);
                wins < MIN_SUCCESSFUL_ATTEMPTS
                    && wins + remaining_attempts >= MIN_SUCCESSFUL_ATTEMPTS
            });
        }

        for (config, _) in &batch_entries {
            let wins = successes.get(config).copied().unwrap_or(0);
            let values = latencies.get(config).cloned().unwrap_or_default();

            if wins >= MIN_SUCCESSFUL_ATTEMPTS
                && !values.is_empty()
                && values.iter().copied().fold(0.0, f64::max) <= MAX_LATENCY_MS
            {
                let mut values = values;
                values.sort_by(f64::total_cmp);
                let median = if values.len() % 2 == 1 {
                    values[values.len() / 2]
                } else {
                    let right = values.len() / 2;
                    (values[right - 1] + values[right]) / 2.0
                };

                verified.insert(
                    config.clone(),
                    ProxyMetrics {
                        successes: wins,
                        attempts: attempts.get(config).copied().unwrap_or(0),
                        median_ms: median,
                        min_ms: values[0],
                    },
                );
            }
        }

        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&work);
    }

    Ok(verified)
}

pub async fn validate_candidates(
    binary: &str,
    candidates: &[String],
    workers: usize,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    let mut parsed = Vec::new();
    let mut rejected = Vec::new();
    let mut seen = HashSet::new();

    for config in candidates {
        let cleaned = clean(config).to_string();
        if !seen.insert(cleaned) {
            continue;
        }

        match singbox_outbound(config) {
            Ok(outbound) => parsed.push((config.clone(), outbound)),
            Err(error) => rejected.push((config.clone(), error)),
        }
    }

    println!(
        "loaded {} input URLs, accepted {} for sing-box, rejected {}",
        candidates.len(),
        parsed.len(),
        rejected.len()
    );

    for (config, reason) in rejected.iter().take(8) {
        println!("sing-box rejected: {config} :: {reason}");
    }

    if parsed.is_empty() {
        return Ok(HashMap::new());
    }

    let batch_size = BATCH_SIZE.min(parsed.len()).max(1);
    let total_batches = (parsed.len() + batch_size - 1) / batch_size;
    let mut metadata = HashMap::new();

    for (index, batch) in parsed.chunks(batch_size).enumerate() {
        println!(
            "target {TARGET}: batch {}/{} testing {} configs with sing-box; requiring {MIN_SUCCESSFUL_ATTEMPTS}/{} attempts",
            index + 1,
            total_batches,
            batch.len(),
            STABILITY_ATTEMPTS
        );
        metadata.extend(check_batch(binary, batch, workers.max(1)).await?);
    }

    println!(
        "{}/{} verified by sing-box against {TARGET} with {MIN_SUCCESSFUL_ATTEMPTS}/{} successful GET+HEAD attempts and every measured latency <= {}ms",
        metadata.len(),
        candidates.len(),
        STABILITY_ATTEMPTS,
        MAX_LATENCY_MS
    );

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_vless_reality_to_singbox_tls() {
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?type=raw&security=reality&sni=example.com&fp=chrome&pbk=test-public-key&sid=01234567";
        let outbound = singbox_outbound(config).expect("VLESS Reality should map");
        assert_eq!(outbound["type"], "vless");
        assert_eq!(outbound["flow"], Value::Null);
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "example.com");
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbound["tls"]["reality"]["enabled"], true);
        assert_eq!(outbound["tls"]["reality"]["short_id"], "01234567");
    }

    #[test]
    fn maps_vmess_websocket_tls() {
        let source = json!({
            "v": "2",
            "ps": "test",
            "add": "example.com",
            "port": "443",
            "id": "00000000-0000-0000-0000-000000000001",
            "aid": 0,
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "cdn.example.com",
            "path": "/proxy",
            "tls": "tls",
        });
        let encoded = STANDARD.encode(source.to_string());
        let config = format!("vmess://{encoded}");
        let outbound = singbox_outbound(&config).expect("VMess WS should map");
        assert_eq!(outbound["type"], "vmess");
        assert_eq!(outbound["network"], "tcp");
        assert_eq!(outbound["transport"]["type"], "ws");
        assert_eq!(outbound["transport"]["path"], "/proxy");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "example.com");
    }

    #[test]
    fn uses_chrome_for_vless_reality_without_fingerprint() {
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?type=raw&security=reality&sni=example.com&pbk=test-public-key&sid=01234567";
        let outbound = singbox_outbound(config).expect("VLESS Reality without fp should map");
        assert_eq!(outbound["tls"]["utls"]["enabled"], true);
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
    }

    #[test]
    fn maps_hysteria2_to_native_singbox_outbound() {
        let config = "hysteria2://password@example.com:443?sni=example.com";
        let outbound = singbox_outbound(config).expect("Hysteria2 should map");
        assert_eq!(outbound["type"], "hysteria2");
        assert_eq!(outbound["server"], "example.com");
        assert_eq!(outbound["server_port"], 443);
        assert_eq!(outbound["password"], "password");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "example.com");
    }

    #[test]
    fn rejects_vless_vision_udp443() {
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?flow=xtls-rprx-vision-udp443&security=none";
        let error = singbox_outbound(config).expect_err("unsupported flow should be rejected");
        assert!(error.contains("unsupported sing-box VLESS flow"));
    }

    #[test]
    fn rejects_xhttp() {
        let config =
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?type=xhttp&security=none";
        let error =
            singbox_outbound(config).expect_err("XHTTP is unsupported by standard sing-box");
        assert!(error.contains("XHTTP"));
    }
}
