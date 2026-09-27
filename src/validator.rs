use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use url::Url;

pub const PRIMARY_TARGET: &str = "https://speed.cloudflare.com";
pub const DOWNLOAD_BYTES: usize = 4096;
pub const UPLOAD_BYTES: usize = 1024;
pub const MAX_RESPONSE_BYTES: usize = 65536;
pub const STABILITY_ATTEMPTS: usize = 3;
pub const MIN_SUCCESSFUL_TARGETS: usize = 2;
pub const MAX_LATENCY_MS: f64 = 800.0;
pub const CORE_START_TIMEOUT: Duration = Duration::from_secs(5);
pub const RATE_LIMIT_RETRIES: usize = 1;
pub const RATE_LIMIT_DEFAULT_WAIT: Duration = Duration::from_secs(5);
pub const RATE_LIMIT_MIN_WAIT: Duration = Duration::from_secs(1);
pub const RATE_LIMIT_MAX_WAIT: Duration = Duration::from_secs(300);

static RATE_LIMIT_UNTIL_MS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct ProxyMetrics {
    pub successes: usize,
    pub attempts: usize,
    pub median_ms: f64,
    pub min_ms: f64,
}

#[derive(Debug)]
enum ProbeError {
    RateLimited,
    Failed(String),
}

fn clean(url: &str) -> &str {
    url.split('#').next().unwrap_or(url)
}

pub fn read_lines(path: &str) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let mut seen = HashSet::new();
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| seen.insert((*line).to_string()))
        .map(ToOwned::to_owned)
        .collect())
}

pub fn write_lines(path: &str, values: &[String]) -> Result<(), String> {
    let mut file = File::create(path).map_err(|error| error.to_string())?;
    if !values.is_empty() {
        file.write_all(values.join("\n").as_bytes())
            .map_err(|error| error.to_string())?;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
    }
    Ok(())
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

fn first_query(url: &Url, names: &[&str], default: Option<&str>) -> String {
    for (key, value) in url.query_pairs() {
        if names.iter().any(|name| key.eq_ignore_ascii_case(name)) && !value.is_empty() {
            return value.into_owned();
        }
    }
    default.unwrap_or_default().to_string()
}
fn decode_component(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

fn json_text(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn json_u64(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Number(value)) => value.as_u64().unwrap_or(0),
        Some(Value::String(value)) => value.parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

fn csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn truthy(url: &Url, names: &[&str]) -> bool {
    matches!(
        first_query(url, names, Some(""))
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn endpoint_from_url(url: &Url, default_port: Option<u16>) -> Result<(String, u16), String> {
    let host = url
        .host_str()
        .ok_or_else(|| "missing host".to_string())?
        .to_string();
    let port = url
        .port()
        .or(default_port)
        .ok_or_else(|| "missing port".to_string())?;
    if port == 0 {
        return Err("invalid port".to_string());
    }
    Ok((host, port))
}

pub fn endpoint(config: &str) -> Option<(String, u16)> {
    let url = Url::parse(clean(config)).ok()?;
    if url.scheme().eq_ignore_ascii_case("vmess") {
        let payload = clean(config).split_once("://")?.1;
        let decoded = b64decode(payload)?;
        let value: Value = serde_json::from_slice(&decoded).ok()?;
        let host = value.get("add")?.as_str()?.trim().to_string();
        let port = match value.get("port")? {
            Value::String(value) => value.parse().ok()?,
            Value::Number(value) => u16::try_from(value.as_u64()?).ok()?,
            _ => return None,
        };
        if host.is_empty() || port == 0 {
            return None;
        }
        return Some((host, port));
    }

    let default = match url.scheme().to_ascii_lowercase().as_str() {
        "http" => Some(8080),
        "https" => Some(443),
        "socks" | "socks4" | "socks5" | "socks5h" => Some(1080),
        _ => None,
    };
    endpoint_from_url(&url, default).ok()
}

fn stream_settings(url: &Url, host: &str) -> Result<Value, String> {
    let mut network = first_query(url, &["type", "network"], Some("tcp")).to_ascii_lowercase();
    if network == "tcp" {
        network = "raw".to_string();
    }

    match network.as_str() {
        "raw" | "ws" | "grpc" | "httpupgrade" | "xhttp" => {}
        _ => return Err(format!("unsupported transport {network}")),
    }

    let security = first_query(url, &["security"], Some("none")).to_ascii_lowercase();
    match security.as_str() {
        "none" | "tls" | "reality" => {}
        _ => return Err(format!("unsupported security {security}")),
    }

    if security == "reality" && !matches!(network.as_str(), "raw" | "xhttp" | "grpc") {
        return Err("reality unsupported with this transport".to_string());
    }

    let sni = first_query(url, &["sni", "server_name", "peer"], Some(host));
    let alpn = csv(&first_query(url, &["alpn"], Some("")));
    let mut out = json!({
        "network": network,
        "security": security,
    });

    if security == "tls" {
        let mut tls = json!({ "serverName": sni });
        if !alpn.is_empty() {
            tls["alpn"] = json!(alpn);
        }
        let fp = first_query(url, &["fp", "fingerprint"], Some(""));
        if !fp.is_empty() {
            tls["fingerprint"] = json!(fp);
        }
        if truthy(url, &["insecure", "allowInsecure"]) {
            tls["allowInsecure"] = json!(true);
        }
        out["tlsSettings"] = tls;
    } else if security == "reality" {
        let pbk = first_query(url, &["pbk", "publicKey"], Some(""));
        if pbk.is_empty() {
            return Err("reality public key missing".to_string());
        }
        let mut reality = json!({
            "show": false,
            "serverName": sni,
            "publicKey": pbk,
        });
        let fp = first_query(url, &["fp", "fingerprint"], Some(""));
        let sid = first_query(url, &["sid", "shortId"], Some(""));
        let spx = first_query(url, &["spx", "spiderX"], Some(""));
        if !fp.is_empty() {
            reality["fingerprint"] = json!(fp);
        }
        if !sid.is_empty() {
            reality["shortId"] = json!(sid);
        }
        if !spx.is_empty() {
            reality["spiderX"] = json!(spx);
        }
        out["realitySettings"] = reality;
    }

    let path = first_query(url, &["path"], Some(""));
    let host_header = first_query(url, &["host"], Some(""));

    match network.as_str() {
        "raw" => {
            if first_query(url, &["headerType", "header_type"], Some(""))
                .eq_ignore_ascii_case("http")
            {
                let mut request = json!({});
                if !path.is_empty() {
                    request["path"] = json!([path]);
                }
                if !host_header.is_empty() {
                    request["headers"] = json!({ "Host": csv(&host_header) });
                }
                out["rawSettings"] = json!({
                    "header": {
                        "type": "http",
                        "request": request,
                    }
                });
            }
        }
        "ws" => {
            let mut settings = json!({});
            if !path.is_empty() {
                settings["path"] = json!(path);
            }
            if !host_header.is_empty() {
                settings["headers"] = json!({ "Host": host_header });
            }
            out["wsSettings"] = settings;
        }
        "httpupgrade" => {
            let mut settings = json!({});
            if !path.is_empty() {
                settings["path"] = json!(path);
            }
            if !host_header.is_empty() {
                settings["host"] = json!(host_header);
            }
            out["httpupgradeSettings"] = settings;
        }
        "grpc" => {
            let mut settings = json!({});
            let authority = first_query(url, &["authority", "host"], Some(""));
            let service = first_query(url, &["serviceName", "service_name"], Some(""));
            if !authority.is_empty() {
                settings["authority"] = json!(authority);
            }
            if !service.is_empty() {
                settings["serviceName"] = json!(service);
            }
            if first_query(url, &["mode"], Some("")).eq_ignore_ascii_case("multi") {
                settings["multiMode"] = json!(true);
            }
            out["grpcSettings"] = settings;
        }
        "xhttp" => {
            let mut settings = json!({
                "mode": first_query(url, &["mode"], Some("auto")),
            });
            if !path.is_empty() {
                settings["path"] = json!(path);
            }
            if !host_header.is_empty() {
                settings["host"] = json!(host_header);
            }
            let extra = first_query(url, &["extra"], Some(""));
            if !extra.is_empty() {
                if let Ok(value) = serde_json::from_str::<Value>(&extra) {
                    if value.is_object() {
                        settings["extra"] = value;
                    }
                }
            }
            out["xhttpSettings"] = settings;
        }
        _ => unreachable!(),
    }

    Ok(out)
}

fn parse_vless(config: &str) -> Result<Value, String> {
    let url = Url::parse(clean(config)).map_err(|error| error.to_string())?;
    let (host, port) = endpoint_from_url(&url, None)?;
    let uuid = decode_component(url.username());
    if uuid.is_empty() {
        return Err("VLESS UUID missing".to_string());
    }
    let mut user = json!({
        "id": uuid,
        "encryption": first_query(&url, &["encryption"], Some("none")),
    });
    let flow = first_query(&url, &["flow"], Some(""));
    if !flow.is_empty() {
        user["flow"] = json!(flow);
    }
    Ok(json!({
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [user],
            }]
        },
        "streamSettings": stream_settings(&url, &host)?,
    }))
}

fn parse_vmess(config: &str) -> Result<Value, String> {
    let payload = clean(config)
        .split_once("://")
        .ok_or_else(|| "invalid VMess URL".to_string())?
        .1;
    let decoded = b64decode(payload).ok_or_else(|| "invalid VMess base64".to_string())?;
    let value: Value = serde_json::from_slice(&decoded).map_err(|error| error.to_string())?;

    let host = value
        .get("add")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "VMess endpoint missing".to_string())?;
    let port = match value.get("port") {
        Some(Value::String(value)) => value
            .parse::<u16>()
            .map_err(|_| "invalid VMess port".to_string())?,
        Some(Value::Number(value)) => u16::try_from(
            value
                .as_u64()
                .ok_or_else(|| "invalid VMess port".to_string())?,
        )
        .map_err(|_| "invalid VMess port".to_string())?,
        _ => return Err("VMess port missing".to_string()),
    };
    if port == 0 {
        return Err("invalid VMess port".to_string());
    }

    let uuid = value
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "VMess UUID missing".to_string())?;

    let network = json_text(value.get("net")).unwrap_or_else(|| "tcp".to_string());
    if network.eq_ignore_ascii_case("h2") {
        return Err("VMess h2 transport unsupported".to_string());
    }

    let mut q = vec![
        ("type".to_string(), network.clone()),
        (
            "security".to_string(),
            json_text(value.get("tls")).unwrap_or_default(),
        ),
    ];
    if value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value| value.eq_ignore_ascii_case("http"))
        && network.eq_ignore_ascii_case("tcp")
    {
        q.push(("headerType".to_string(), "http".to_string()));
    }
    for (source, destination) in [
        ("sni", "sni"),
        ("alpn", "alpn"),
        ("fp", "fp"),
        ("host", "host"),
        ("path", "path"),
        ("allowInsecure", "insecure"),
    ] {
        if let Some(value) = json_text(value.get(source)) {
            if !value.is_empty() {
                q.push((destination.to_string(), value));
            }
        }
    }

    let query = q
        .iter()
        .map(|(key, value)| format!("{}={}", urlencoding(key), urlencoding(value)))
        .collect::<Vec<_>>()
        .join("&");
    let synthetic = Url::parse(&format!("https://example.invalid/?{query}"))
        .map_err(|error| error.to_string())?;

    let user = json!({
        "id": uuid,
        "alterId": json_u64(value.get("aid")),
        "security": json_text(value.get("scy")).unwrap_or_else(|| "auto".to_string()),
    });

    let stream = stream_settings(&synthetic, host)?;

    Ok(json!({
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [user],
            }]
        },
        "streamSettings": stream,
    }))
}

fn urlencoding(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn parse_trojan(config: &str) -> Result<Value, String> {
    let url = Url::parse(clean(config)).map_err(|error| error.to_string())?;
    let (host, port) = endpoint_from_url(&url, None)?;
    let password_source = url
        .password()
        .filter(|value| !value.is_empty())
        .unwrap_or(url.username());
    let password = decode_component(password_source);
    if password.is_empty() {
        return Err("Trojan password missing".to_string());
    }
    Ok(json!({
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "password": password,
            }]
        },
        "streamSettings": stream_settings(&url, &host)?,
    }))
}

fn parse_ss(config: &str) -> Result<Value, String> {
    let url = Url::parse(clean(config)).map_err(|error| error.to_string())?;
    if url
        .query_pairs()
        .any(|(key, _)| key.eq_ignore_ascii_case("plugin"))
    {
        return Err("Shadowsocks plugins unsupported".to_string());
    }

    let (host, port, method, password) = if let Some(password) = url.password() {
        let method = decode_component(url.username());
        let (host, port) = endpoint_from_url(&url, None)?;
        if method.is_empty() {
            return Err("Shadowsocks method missing".to_string());
        }
        (host, port, method, decode_component(password))
    } else {
        let payload = clean(config)
            .split_once("://")
            .ok_or_else(|| "invalid Shadowsocks payload".to_string())?
            .1
            .split('#')
            .next()
            .unwrap_or("");
        let (credentials, remote) = payload
            .rsplit_once('@')
            .ok_or_else(|| "invalid Shadowsocks payload".to_string())?;
        let decoded = String::from_utf8(
            b64decode(credentials).ok_or_else(|| "invalid Shadowsocks base64".to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let (method, password) = decoded
            .split_once(':')
            .ok_or_else(|| "invalid Shadowsocks credentials".to_string())?;
        let remote_url =
            Url::parse(&format!("ss://{remote}")).map_err(|error| error.to_string())?;
        let (host, port) = endpoint_from_url(&remote_url, None)?;
        (host, port, method.to_string(), password.to_string())
    };

    Ok(json!({
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password,
            }]
        }
    }))
}

fn parse_hy2(config: &str) -> Result<Value, String> {
    let url = Url::parse(clean(config)).map_err(|error| error.to_string())?;
    let (host, port) = endpoint_from_url(&url, None)?;
    if url.query_pairs().any(|(key, _)| {
        key.eq_ignore_ascii_case("obfs") || key.eq_ignore_ascii_case("obfs-password")
    }) {
        return Err("Hysteria2 obfs unsupported by Xray".to_string());
    }

    let mut password = decode_component(url.username());
    if let Some(pass) = url.password() {
        if !password.is_empty() {
            password.push(':');
        }
        password.push_str(&decode_component(pass));
    }
    if password.is_empty() {
        return Err("Hysteria2 password missing".to_string());
    }

    let mut tls = json!({
        "serverName": first_query(&url, &["sni", "server_name"], Some(&host)),
    });
    let alpn = csv(&first_query(&url, &["alpn"], Some("")));
    if !alpn.is_empty() {
        tls["alpn"] = json!(alpn);
    }
    let fp = first_query(&url, &["fp", "fingerprint"], Some(""));
    if !fp.is_empty() {
        tls["fingerprint"] = json!(fp);
    }
    if truthy(&url, &["insecure", "allowInsecure"]) {
        tls["allowInsecure"] = json!(true);
    }

    Ok(json!({
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "address": host,
            "port": port,
        },
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": tls,
            "hysteriaSettings": {
                "version": 2,
                "auth": password,
            }
        }
    }))
}

fn decode_key(value: &str) -> Option<String> {
    let bytes = b64decode(value)?;
    if bytes.len() == 32 {
        Some(value.to_string())
    } else {
        None
    }
}

fn parse_wg(config: &str) -> Result<Value, String> {
    let url = Url::parse(clean(config)).map_err(|error| error.to_string())?;
    let (host, port) = endpoint_from_url(&url, None)?;

    let private = if url.username().is_empty() {
        first_query(
            &url,
            &[
                "privatekey",
                "private-key",
                "private_key",
                "private_key_base64",
            ],
            Some(""),
        )
    } else {
        decode_component(url.username())
    };
    let public = first_query(
        &url,
        &[
            "publickey",
            "public-key",
            "public_key",
            "peer-public-key",
            "peer_public_key",
            "pubkey",
        ],
        Some(""),
    );

    if private.is_empty() || public.is_empty() {
        return Err("WireGuard keys missing".to_string());
    }
    decode_key(&private).ok_or_else(|| "invalid WireGuard private key".to_string())?;
    decode_key(&public).ok_or_else(|| "invalid WireGuard public key".to_string())?;

    let address = csv(&first_query(
        &url,
        &["address", "addresses", "local-address"],
        Some("10.0.0.1"),
    ));
    let allowed = csv(&first_query(
        &url,
        &["allowedIPs", "allowed-ips"],
        Some("0.0.0.0/0,::/0"),
    ));

    let mut peer = json!({
        "endpoint": format!("{host}:{port}"),
        "publicKey": public,
        "allowedIPs": allowed,
    });

    let psk = first_query(
        &url,
        &["presharedkey", "preshared-key", "preshared_key", "psk"],
        Some(""),
    );
    if !psk.is_empty() {
        decode_key(&psk).ok_or_else(|| "invalid WireGuard preshared key".to_string())?;
        peer["preSharedKey"] = json!(psk);
    }

    if let Ok(keepalive) = first_query(&url, &["keepalive", "keep-alive"], Some("")).parse::<u64>()
    {
        peer["keepAlive"] = json!(keepalive);
    }

    Ok(json!({
        "protocol": "wireguard",
        "settings": {
            "secretKey": private,
            "address": address,
            "peers": [peer],
            "noKernelTun": true,
            "remoteDNS": ["1.1.1.1", "1.0.0.1"],
        }
    }))
}

fn parse_basic(config: &str) -> Result<Value, String> {
    let url = Url::parse(clean(config)).map_err(|error| error.to_string())?;
    let scheme = url.scheme().to_ascii_lowercase();
    let default = if matches!(scheme.as_str(), "socks" | "socks5" | "socks5h") {
        1080
    } else {
        8080
    };
    let (host, port) = endpoint_from_url(&url, Some(default))?;
    let protocol = if scheme == "http" { "http" } else { "socks" };
    let mut server = json!({
        "address": host,
        "port": port,
    });
    if !url.username().is_empty() {
        server["users"] = json!([{
            "user": decode_component(url.username()),
            "pass": decode_component(url.password().unwrap_or("")),
        }]);
    }
    Ok(json!({
        "protocol": protocol,
        "settings": {
            "servers": [server],
        }
    }))
}

fn parse_config(config: &str) -> Result<Value, String> {
    let scheme = Url::parse(clean(config))
        .map_err(|error| error.to_string())?
        .scheme()
        .to_ascii_lowercase();

    match scheme.as_str() {
        "vless" => parse_vless(config),
        "vmess" => parse_vmess(config),
        "trojan" => parse_trojan(config),
        "ss" => parse_ss(config),
        "hysteria2" | "hy2" => parse_hy2(config),
        "wg" => parse_wg(config),
        "socks" | "socks5" | "socks5h" | "http" => parse_basic(config),
        _ => Err(format!("unsupported scheme {scheme}")),
    }
}

fn unique_parsed(candidates: &[String]) -> (Vec<(String, Value)>, Vec<(String, String)>) {
    let mut originals = Vec::new();
    let mut seen_clean = HashSet::new();

    for original in candidates {
        let cleaned = clean(original).to_string();
        if seen_clean.insert(cleaned.clone()) {
            originals.push((original.clone(), cleaned));
        }
    }

    let mut parsed = Vec::new();
    let mut rejected = Vec::new();

    for (original, cleaned) in originals {
        match parse_config(&cleaned) {
            Ok(value) => parsed.push((original, value)),
            Err(error) => rejected.push((original, error)),
        }
    }

    (parsed, rejected)
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

fn xray_config(entries: &[(String, Value)]) -> Result<(Value, Vec<u16>), String> {
    let ports = allocated_ports(entries.len())?;
    let mut inbounds = Vec::with_capacity(entries.len());
    let mut outbounds = Vec::with_capacity(entries.len());
    let mut rules = Vec::with_capacity(entries.len());

    for (index, (_, outbound)) in entries.iter().enumerate() {
        let in_tag = format!("in-{index}");
        let out_tag = format!("out-{index}");

        inbounds.push(json!({
            "tag": in_tag,
            "listen": "127.0.0.1",
            "port": ports[index],
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": false,
            }
        }));

        let mut outbound = outbound.clone();
        outbound["tag"] = json!(out_tag);
        outbounds.push(outbound);

        rules.push(json!({
            "type": "field",
            "inboundTag": [in_tag],
            "outboundTag": out_tag,
        }));
    }

    Ok((
        json!({
            "log": { "loglevel": "error" },
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {
                "domainStrategy": "AsIs",
                "rules": rules,
            }
        }),
        ports,
    ))
}

fn make_temp_dir() -> Result<std::path::PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "proxy-harvester-xray-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).map_err(|error| error.to_string())?;
    Ok(path)
}

fn start_xray(
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

async fn ports_ready(child: &mut Child, ports: &[u16]) -> bool {
    let deadline = tokio::time::Instant::now() + CORE_START_TIMEOUT;
    let mut pending = ports.to_vec();
    let workers = pending.len().clamp(1, 64);

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

        if !pending.is_empty() {
            sleep(Duration::from_millis(50)).await;
        }
    }

    pending.is_empty()
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn rate_limit_wait(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(RATE_LIMIT_DEFAULT_WAIT)
        .max(RATE_LIMIT_MIN_WAIT)
        .min(RATE_LIMIT_MAX_WAIT)
}

fn extend_rate_limit(wait: Duration) {
    let wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
    let target = unix_now_ms().saturating_add(wait_ms);
    let mut current = RATE_LIMIT_UNTIL_MS.load(Ordering::Acquire);

    while target > current {
        match RATE_LIMIT_UNTIL_MS.compare_exchange_weak(
            current,
            target,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

async fn wait_for_rate_limit() {
    loop {
        let now = unix_now_ms();
        let until = RATE_LIMIT_UNTIL_MS.load(Ordering::Acquire);
        if until <= now {
            return;
        }
        sleep(Duration::from_millis(until - now)).await;
    }
}

fn client_for_port(port: u16, timeout_seconds: f64) -> Result<Client, String> {
    let request_timeout = if timeout_seconds.is_finite() && timeout_seconds > 0.0 {
        Duration::from_secs_f64(timeout_seconds)
    } else {
        Duration::from_secs(1)
    };

    Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
                .map_err(|error| error.to_string())?,
        )
        .timeout(request_timeout)
        .user_agent("Proxy-Harvester/3.0")
        .build()
        .map_err(|error| error.to_string())
}

async fn probe_request(
    client: &Client,
    url: Url,
    body: Option<Vec<u8>>,
) -> Result<(f64, usize), ProbeError> {
    wait_for_rate_limit().await;
    let started = Instant::now();
    let request = match body {
        Some(body) => client
            .post(url)
            .header("Accept-Encoding", "identity")
            .header("Content-Type", "application/octet-stream")
            .body(body),
        None => client.get(url).header("Accept-Encoding", "identity"),
    };

    let response = request
        .send()
        .await
        .map_err(|error| ProbeError::Failed(error.to_string()))?;

    if response.status().as_u16() == 429 {
        let retry = rate_limit_wait(response.headers());
        extend_rate_limit(retry);
        return Err(ProbeError::RateLimited);
    }

    if !response.status().is_success() {
        return Err(ProbeError::Failed(format!(
            "HTTP status {}",
            response.status()
        )));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|error| ProbeError::Failed(error.to_string()))?;

    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ProbeError::Failed("response body too large".to_string()));
    }

    Ok((started.elapsed().as_secs_f64() * 1000.0, bytes.len()))
}

fn target_with(target: &Url, path: &str, query: Option<&str>) -> Url {
    let mut url = target.clone();
    url.set_path(path);
    url.set_query(query);
    url
}

async fn functional_attempt(client: &Client, target: &Url) -> Result<f64, ProbeError> {
    for retry in 0..=RATE_LIMIT_RETRIES {
        let download_url = target_with(target, "/__down", Some(&format!("bytes={DOWNLOAD_BYTES}")));

        let (download_latency, download_len) = match probe_request(client, download_url, None).await
        {
            Ok(value) => value,
            Err(ProbeError::RateLimited) if retry < RATE_LIMIT_RETRIES => {
                wait_for_rate_limit().await;
                continue;
            }
            Err(error) => return Err(error),
        };

        if download_len < DOWNLOAD_BYTES {
            return Err(ProbeError::Failed(format!(
                "download body too small: {download_len} < {DOWNLOAD_BYTES}"
            )));
        }

        let upload_url = target_with(target, "/__up", None);
        let upload_body = vec![0u8; UPLOAD_BYTES];

        let (upload_latency, _) = match probe_request(client, upload_url, Some(upload_body)).await {
            Ok(value) => value,
            Err(ProbeError::RateLimited) if retry < RATE_LIMIT_RETRIES => {
                wait_for_rate_limit().await;
                continue;
            }
            Err(error) => return Err(error),
        };

        return Ok(download_latency.max(upload_latency));
    }

    Err(ProbeError::Failed(
        "Cloudflare test endpoint rate limited after retry".to_string(),
    ))
}

async fn check_batch(
    binary: &str,
    entries: &[(String, Value)],
    target: &Url,
    workers: usize,
    timeout_seconds: f64,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    if entries.is_empty() {
        return Ok(HashMap::new());
    }

    let mut pending_batches = vec![entries.to_vec()];
    let mut combined = HashMap::new();

    while let Some(batch_entries) = pending_batches.pop() {
        let work = make_temp_dir()?;
        let config_path = work.join("xray.json");
        let log_path = work.join("xray.log");
        let (config, local_ports) = xray_config(&batch_entries)?;

        fs::write(
            &config_path,
            serde_json::to_vec(&config).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;

        let mut child = match start_xray(binary, &config_path, &log_path) {
            Ok(child) => child,
            Err(error) => {
                let _ = fs::remove_dir_all(&work);
                return Err(error);
            }
        };

        if !ports_ready(&mut child, &local_ports).await {
            let _ = child.kill();
            let _ = child.wait();

            if batch_entries.len() > 1 {
                let mid = batch_entries.len() / 2;
                pending_batches.push(batch_entries[..mid].to_vec());
                pending_batches.push(batch_entries[mid..].to_vec());
            } else {
                let tail = fs::read_to_string(&log_path)
                    .unwrap_or_default()
                    .chars()
                    .rev()
                    .take(700)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>();

                println!("[WARN] Validation skipped: {}", batch_entries[0].0);
                if !tail.is_empty() {
                    println!("[WARN] Xray core failed to start: {tail}");
                }
            }

            let _ = fs::remove_dir_all(&work);
            continue;
        }

        let mut active = Vec::with_capacity(batch_entries.len());
        for (index, (config, _)) in batch_entries.iter().enumerate() {
            let client = match client_for_port(local_ports[index], timeout_seconds) {
                Ok(client) => client,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = fs::remove_dir_all(&work);
                    return Err(error);
                }
            };

            active.push((config.clone(), local_ports[index], client));
        }

        let mut successes = HashMap::<String, usize>::new();
        let mut attempts = HashMap::<String, usize>::new();
        let mut latencies = HashMap::<String, Vec<f64>>::new();
        let mut errors = HashMap::<String, String>::new();

        for attempt in 0..STABILITY_ATTEMPTS {
            if active.is_empty() {
                break;
            }

            let results = stream::iter(active.clone())
                .map(|(config, port, client)| {
                    let target = target.clone();
                    async move {
                        let result = functional_attempt(&client, &target).await;
                        (config, port, result)
                    }
                })
                .buffer_unordered(workers.max(1))
                .collect::<Vec<_>>()
                .await;

            for (config, _, result) in results {
                *attempts.entry(config.clone()).or_insert(0) += 1;
                match result {
                    Ok(latency) => {
                        *successes.entry(config.clone()).or_insert(0) += 1;
                        latencies.entry(config).or_default().push(latency);
                    }
                    Err(error) => {
                        let message = match error {
                            ProbeError::RateLimited => "target rate limited".to_string(),
                            ProbeError::Failed(message) => message,
                        };
                        errors.insert(config, message);
                    }
                }
            }

            let remaining_attempts = STABILITY_ATTEMPTS - attempt - 1;
            active.retain(|(config, _, _)| {
                let wins = successes.get(config).copied().unwrap_or(0);
                wins < MIN_SUCCESSFUL_TARGETS && wins + remaining_attempts >= MIN_SUCCESSFUL_TARGETS
            });
        }

        for (config, _) in &batch_entries {
            let values = latencies.get(config).cloned().unwrap_or_default();
            let wins = successes.get(config).copied().unwrap_or(0);

            if wins >= MIN_SUCCESSFUL_TARGETS
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

                combined.insert(
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

    Ok(combined)
}

pub async fn validate_candidates(
    binary: &str,
    candidates: &[String],
    target: &str,
    workers: usize,
    batch_size: usize,
    timeout_seconds: f64,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    let (parsed, rejected) = unique_parsed(candidates);

    println!(
        "loaded {} input URLs, accepted {} for Xray, rejected {}",
        candidates.len(),
        parsed.len(),
        rejected.len()
    );

    for (config, reason) in rejected.iter().take(8) {
        println!("rejected: {config} :: {reason}");
    }

    if !rejected.is_empty() {
        let mut counts = HashMap::<String, usize>::new();
        for (config, _) in &rejected {
            let scheme = Url::parse(clean(config))
                .map(|url| url.scheme().to_ascii_lowercase())
                .unwrap_or_else(|_| "unknown".to_string());
            *counts.entry(scheme).or_insert(0) += 1;
        }
        println!("rejected by scheme: {:?}", counts);
    }

    if parsed.is_empty() {
        return Ok(HashMap::new());
    }

    let target = Url::parse(target).map_err(|error| error.to_string())?;
    let batch_size = batch_size.max(1);
    let total_batches = (parsed.len() + batch_size - 1) / batch_size;
    let mut metadata = HashMap::new();

    for (index, batch) in parsed.chunks(batch_size).enumerate() {
        println!(
            "target {target}: batch {}/{} testing {} configs with Xray core; requiring {}/{}",
            index + 1,
            total_batches,
            batch.len(),
            MIN_SUCCESSFUL_TARGETS,
            STABILITY_ATTEMPTS
        );

        let batch_metadata =
            check_batch(binary, batch, &target, workers.max(1), timeout_seconds).await?;
        metadata.extend(batch_metadata);
    }

    println!(
        "{}/{} verified by Xray with {}/{} successful attempts and every measured latency <= {}ms",
        metadata.len(),
        candidates.len(),
        MIN_SUCCESSFUL_TARGETS,
        STABILITY_ATTEMPTS,
        MAX_LATENCY_MS
    );

    Ok(metadata)
}

pub fn write_metadata(path: &str, metadata: &HashMap<String, ProxyMetrics>) -> Result<(), String> {
    let mut output = serde_json::Map::new();
    for (config, metrics) in metadata {
        output.insert(
            config.clone(),
            json!({
                "successes": metrics.successes,
                "attempts": metrics.attempts,
                "median_ms": metrics.median_ms,
                "min_ms": metrics.min_ms,
            }),
        );
    }

    fs::write(
        path,
        serde_json::to_vec(&Value::Object(output)).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn vless_percent_encoded_username_is_decoded() {
        let config = "vless://user%40name@example.com:443?security=tls&sni=edge.example";
        let parsed = parse_config(config).expect("VLESS should parse");
        assert_eq!(
            parsed["settings"]["vnext"][0]["users"][0]["id"],
            "user@name"
        );
        assert_eq!(
            parsed["streamSettings"]["tlsSettings"]["serverName"],
            "edge.example"
        );
    }

    #[test]
    fn vmess_tcp_http_preserves_path_and_host() {
        let payload = json!({
            "add": "example.com",
            "port": 443,
            "id": "00000000-0000-0000-0000-000000000001",
            "aid": 0,
            "scy": "auto",
            "net": "tcp",
            "tls": "tls",
            "type": "http",
            "host": "origin.example",
            "path": "/proxy",
        });
        let config = format!("vmess://{}", STANDARD.encode(payload.to_string()));
        let parsed = parse_config(&config).expect("VMess should parse");

        assert_eq!(
            parsed["streamSettings"]["rawSettings"]["header"]["type"],
            "http"
        );
        assert_eq!(
            parsed["streamSettings"]["rawSettings"]["header"]["request"]["path"][0],
            "/proxy"
        );
        assert_eq!(
            parsed["streamSettings"]["rawSettings"]["header"]["request"]["headers"]["Host"][0],
            "origin.example"
        );
    }

    #[test]
    fn basic_proxy_endpoint_defaults_are_preserved() {
        assert_eq!(
            endpoint("socks5://127.0.0.1").expect("SOCKS endpoint"),
            ("127.0.0.1".to_string(), 1080)
        );
        assert_eq!(
            endpoint("http://127.0.0.1").expect("HTTP endpoint"),
            ("127.0.0.1".to_string(), 8080)
        );
    }

    #[test]
    fn vmess_endpoint_comes_from_decoded_payload() {
        let payload = json!({
            "add": "proxy.example",
            "port": 8443,
            "id": "00000000-0000-0000-0000-000000000001"
        });
        let config = format!("vmess://{}", STANDARD.encode(payload.to_string()));
        assert_eq!(
            endpoint(&config).expect("VMess endpoint"),
            ("proxy.example".to_string(), 8443)
        );
    }

    #[test]
    fn retry_after_is_conservative_and_bounded() {
        let mut headers = HeaderMap::new();

        headers.insert("retry-after", HeaderValue::from_static("30"));
        assert_eq!(rate_limit_wait(&headers), Duration::from_secs(30));

        headers.insert("retry-after", HeaderValue::from_static("0"));
        assert_eq!(rate_limit_wait(&headers), RATE_LIMIT_MIN_WAIT);

        headers.insert("retry-after", HeaderValue::from_static("900"));
        assert_eq!(rate_limit_wait(&headers), RATE_LIMIT_MAX_WAIT);

        headers.insert("retry-after", HeaderValue::from_static("invalid"));
        assert_eq!(rate_limit_wait(&headers), RATE_LIMIT_DEFAULT_WAIT);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_trojan;

    #[test]
    fn parses_standard_trojan_password() {
        let config = parse_trojan(
            "trojan://MiTiVPN@167.82.96.58:443?type=ws&security=tls&sni=ssl.fastly.com",
        )
        .expect("standard Trojan URI should parse");

        assert_eq!(config["settings"]["servers"][0]["password"], "MiTiVPN");
    }

    #[test]
    fn parses_percent_encoded_trojan_password() {
        let config = parse_trojan(
            "trojan://%4D%49%54%49%56%50%4E@104.26.14.137:2096?type=ws&security=tls&sni=de-ms.App-Cloud.ir",
        )
        .expect("percent-encoded Trojan URI should parse");

        assert_eq!(config["settings"]["servers"][0]["password"], "MITIVPN");
    }

    #[test]
    fn parses_trojan_user_password_form() {
        let config = parse_trojan("trojan://user:secret@127.0.0.1:443?security=tls")
            .expect("user/password Trojan URI should parse");

        assert_eq!(config["settings"]["servers"][0]["password"], "secret");
    }
}
