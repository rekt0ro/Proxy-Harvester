use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt};
use percent_encoding::percent_decode_str;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use url::{Host, Url};

pub const PRIMARY_TARGET: &str = "https://www.google.com/generate_204";
pub const THROUGHPUT_TARGET: &str = "https://speed.cloudflare.com/__down?bytes=16384";
pub const COMPATIBILITY_TARGET: &str = PRIMARY_TARGET;
pub const LIGHT_TARGETS: &[&str] = &[
    PRIMARY_TARGET,
    "https://speed.cloudflare.com/__down?bytes=16384",
    "https://example.com/",
];
pub const MAX_RESPONSE_BYTES: usize = 65536;
pub const MIN_RESPONSE_BYTES: usize = 1;
pub const STABILITY_ATTEMPTS: usize = 3;
pub const MIN_SUCCESSFUL_ATTEMPTS: usize = 2;
pub const MIN_SUCCESSFUL_TARGETS: usize = 2;
pub const STRICT_STABILITY_ATTEMPTS: usize = 8;
pub const STRICT_MIN_SUCCESSFUL_ATTEMPTS: usize = 5;
pub const STRICT_MIN_SUCCESSFUL_TARGETS: usize = 2;
pub const STRICT_INTER_ATTEMPT_DELAY: Duration = Duration::from_millis(2500);
pub const STRICT_LATE_SUCCESS_STREAK: usize = 3;
pub const STRICT_RECONNECT_AFTER_ATTEMPTS: &[usize] = &[3, 6];
pub const MAX_LATENCY_MS: f64 = 800.0;
pub const CORE_START_TIMEOUT: Duration = Duration::from_secs(5);
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
    pub jitter_ms: f64,
    pub throughput_kbps: f64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ValidationPolicy {
    pub(crate) max_latency_ms: f64,
    pub(crate) stability_attempts: usize,
    pub(crate) min_successful_attempts: usize,
    pub(crate) min_successful_targets: usize,
}

impl ValidationPolicy {
    pub(crate) const fn new(
        max_latency_ms: f64,
        stability_attempts: usize,
        min_successful_attempts: usize,
        min_successful_targets: usize,
    ) -> Self {
        Self {
            max_latency_ms,
            stability_attempts,
            min_successful_attempts,
            min_successful_targets,
        }
    }
}

type ParsedConfig = (String, Value);
type RejectedConfig = (String, String);

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProbeSample {
    pub(crate) latency_ms: f64,
    pub(crate) bytes: usize,
}

pub(crate) fn latency_jitter(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }

    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| {
            let delta = *value - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;

    variance.sqrt()
}

pub(crate) fn throughput_kbps(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);

    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[middle]
    } else {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    }
}

#[derive(Debug)]
enum ProbeError {
    Failed,
}

fn clean(url: &str) -> &str {
    url.split('#').next().unwrap_or(url)
}

/// Lower-cased scheme taken from the raw text. `Url::parse` cannot be used for
/// this because it rejects valid Hysteria2 port-hopping authorities such as
/// `host:1234,5000-5002`.
fn scheme_of(config: &str) -> String {
    config
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .filter(|scheme| !scheme.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
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

/// Write through a temporary sibling so a crash never leaves a truncated file.
fn write_atomic(path: &str, bytes: &[u8]) -> Result<(), String> {
    let temporary = format!("{path}.tmp");

    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())
}

pub fn write_lines(path: &str, values: &[String]) -> Result<(), String> {
    let mut content = values.join("\n");

    if !values.is_empty() {
        content.push('\n');
    }

    write_atomic(path, content.as_bytes())
}

fn b64decode(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    let mut padded = value.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }

    for candidate in [value, padded.as_str()] {
        if let Some(bytes) = [
            STANDARD.decode(candidate),
            URL_SAFE.decode(candidate),
            URL_SAFE_NO_PAD.decode(candidate),
        ]
        .into_iter()
        .find_map(Result::ok)
        {
            return Some(bytes);
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

/// Host and port of a parsed URL. IPv6 literals are returned WITHOUT brackets:
/// that is what DNS lookup, Xray and sing-box expect, and `config_label` adds
/// the brackets back for display. (`host_str()` keeps them, which broke IPv6
/// probing and produced `[[::1]]` labels.)
fn endpoint_from_url(url: &Url, default_port: Option<u16>) -> Result<(String, u16), String> {
    let host = match url.host().ok_or_else(|| "missing host".to_string())? {
        Host::Domain(domain) => domain.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    let port = url
        .port()
        .or(default_port)
        .ok_or_else(|| "missing port".to_string())?;
    if port == 0 {
        return Err("invalid port".to_string());
    }
    Ok((host, port))
}

/// Decode a legacy fully-base64 Shadowsocks payload
/// (`ss://BASE64(method:password@host:port)`).
fn ss_legacy_decode(payload: &str) -> Option<String> {
    let encoded = payload.split('?').next()?.trim_end_matches('/');

    String::from_utf8(b64decode(&decode_component(encoded))?).ok()
}

pub fn endpoint(config: &str) -> Option<(String, u16)> {
    let config = clean(config);
    let scheme = scheme_of(config);

    if matches!(scheme.as_str(), "hysteria2" | "hy2") {
        return hysteria2_probe_endpoint(config);
    }

    // VMess carries its endpoint inside a base64 JSON blob, so handle it before
    // any URL parsing.
    if scheme == "vmess" {
        let payload = config.split_once("://")?.1;
        let decoded = b64decode(payload)?;
        let value: Value = serde_json::from_slice(&decoded).ok()?;
        let host = value.get("add")?.as_str()?.trim().to_string();
        let port = match value.get("port")? {
            Value::String(value) => value.trim().parse().ok()?,
            Value::Number(value) => u16::try_from(value.as_u64()?).ok()?,
            _ => return None,
        };
        if host.is_empty() || port == 0 {
            return None;
        }
        return Some((host, port));
    }

    // Legacy Shadowsocks links have no authority at all; the endpoint is inside
    // the base64 payload.
    if scheme == "ss" {
        let payload = config.split_once("://")?.1;

        if !payload.contains('@') {
            let decoded = ss_legacy_decode(payload)?;
            let remote = decoded.rsplit_once('@')?.1;
            let remote_url = Url::parse(&format!("ss://{remote}")).ok()?;

            return endpoint_from_url(&remote_url, None).ok();
        }
    }

    let url = Url::parse(config).ok()?;

    let default = match url.scheme().to_ascii_lowercase().as_str() {
        "http" => Some(80),
        "https" => Some(443),
        "socks" | "socks4" | "socks4a" | "socks5" | "socks5h" => Some(1080),
        _ => None,
    };
    endpoint_from_url(&url, default).ok()
}

pub fn config_label(config: &str) -> String {
    let scheme = scheme_of(config);

    match endpoint(config) {
        Some((host, port)) if host.contains(':') => format!("{scheme}://[{host}]:{port}"),
        Some((host, port)) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://<invalid>"),
    }
}

fn hysteria2_parts(config: &str) -> Option<(String, String, String)> {
    let rest = config.split_once("://")?.1;
    let authority = rest.split(['?', '#', '/']).next()?;
    let (auth_raw, host_port) = authority.rsplit_once('@').unwrap_or(("", authority));

    let (host, port_spec) = if let Some(stripped) = host_port.strip_prefix('[') {
        let (host, remainder) = stripped.split_once(']')?;
        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return None;
        }
        (
            host.to_string(),
            remainder.strip_prefix(':').unwrap_or("").to_string(),
        )
    } else if let Some((host, port_spec)) = host_port.rsplit_once(':') {
        if host.is_empty() || host.contains(':') || host.chars().any(char::is_whitespace) {
            return None;
        }
        (host.to_string(), port_spec.to_string())
    } else {
        if host_port.is_empty() || host_port.chars().any(char::is_whitespace) {
            return None;
        }
        (host_port.to_string(), String::new())
    };

    Some((host, port_spec, auth_raw.to_string()))
}

fn hysteria2_probe_endpoint(config: &str) -> Option<(String, u16)> {
    let (host, port_spec, _) = hysteria2_parts(config)?;
    let port = if port_spec.is_empty() {
        443
    } else {
        port_spec
            .split(',')
            .next()
            .unwrap_or("")
            .split('-')
            .next()
            .unwrap_or("")
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)?
    };

    Some((host, port))
}

fn normalize_xhttp_extra(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, normalize_xhttp_extra(value)))
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(normalize_xhttp_extra).collect())
        }
        Value::Number(number) => {
            if number.as_i64().is_some() {
                return Value::Number(number);
            }
            if let Some(value) = number.as_f64() {
                if value.is_finite()
                    && value.fract() == 0.0
                    && value >= i64::MIN as f64
                    && value <= i64::MAX as f64
                {
                    return json!(value as i64);
                }
            }
            Value::Number(number)
        }
        other => other,
    }
}

fn xhttp_extra_value(url: &Url) -> Result<Option<Value>, String> {
    let Some(query) = url.query() else {
        return Ok(None);
    };

    for pair in query.split('&') {
        let Some((raw_key, raw_value)) = pair.split_once('=') else {
            continue;
        };

        let key = percent_decode_str(raw_key).decode_utf8_lossy();
        if !key.eq_ignore_ascii_case("extra") {
            continue;
        }

        if raw_value.is_empty() {
            return Ok(None);
        }

        let mut decoded = percent_decode_str(raw_value)
            .decode_utf8_lossy()
            .into_owned();

        for _ in 0..2 {
            if let Ok(value) = serde_json::from_str::<Value>(&decoded) {
                if !value.is_object() {
                    return Err("XHTTP extra must be a JSON object".to_string());
                }

                return Ok(Some(normalize_xhttp_extra(value)));
            }

            let encoded_object = decoded.trim_start().to_ascii_lowercase().starts_with("%7b")
                && decoded.trim_end().to_ascii_lowercase().ends_with("%7d");

            if !encoded_object {
                break;
            }

            let next = percent_decode_str(&decoded)
                .decode_utf8_lossy()
                .into_owned();
            if next == decoded {
                break;
            }
            decoded = next;
        }

        return Err("invalid XHTTP extra JSON".to_string());
    }

    Ok(None)
}

fn stream_settings(url: &Url, host: &str) -> Result<Value, String> {
    let mut network = first_query(url, &["type", "network"], Some("tcp")).to_ascii_lowercase();
    if network == "tcp" {
        network = "raw".to_string();
    }

    match network.as_str() {
        "raw" | "ws" | "http" | "grpc" | "httpupgrade" | "xhttp" => {}
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
        // Xray removed TLS allowInsecure after 2026-06-01. Do not emit the
        // removed field because certificate pinning cannot be derived from a URL alone.
        let mut tls = json!({ "serverName": sni });
        if !alpn.is_empty() {
            tls["alpn"] = json!(alpn);
        }
        let fp = first_query(url, &["fp", "fingerprint"], Some(""));
        if !fp.is_empty() {
            tls["fingerprint"] = json!(fp);
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

    let mut path = first_query(url, &["path"], Some(""));
    let host_header = first_query(url, &["host"], Some(""));
    let mut ws_early_data = String::new();
    let mut ws_early_data_header = String::new();

    if network == "ws" {
        ws_early_data = first_query(url, &["ed", "maxEarlyData", "max_early_data"], Some(""));
        ws_early_data_header = first_query(
            url,
            &["eh", "earlyDataHeaderName", "early_data_header_name"],
            Some(""),
        );

        if let Some((base_path, encoded_early_data)) = path.split_once("?ed=") {
            if ws_early_data.is_empty() {
                ws_early_data = encoded_early_data
                    .split('&')
                    .next()
                    .unwrap_or("")
                    .to_string();
            }
            if ws_early_data_header.is_empty() {
                ws_early_data_header = "Sec-WebSocket-Protocol".to_string();
            }
            path = base_path.to_string();
        }

        if !ws_early_data.is_empty() {
            let early_data = ws_early_data
                .parse::<u64>()
                .map_err(|_| "invalid WebSocket early-data size".to_string())?;
            if early_data > u32::MAX as u64 {
                return Err("WebSocket early-data size exceeds Xray limit".to_string());
            }
        }
    }

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
        "http" => {
            let mut settings = json!({});
            if !path.is_empty() {
                settings["path"] = json!(path);
            }
            if !host_header.is_empty() {
                settings["host"] = json!(csv(&host_header));
            }
            out["httpSettings"] = settings;
        }
        "ws" => {
            let mut settings = json!({});
            if !path.is_empty() {
                settings["path"] = json!(path);
            }
            if !host_header.is_empty() {
                settings["headers"] = json!({ "Host": host_header });
            }
            if !ws_early_data.is_empty() {
                settings["maxEarlyData"] = json!(ws_early_data
                    .parse::<u32>()
                    .expect("validated WebSocket early-data size"));
            }
            if !ws_early_data.is_empty() && !ws_early_data_header.is_empty() {
                settings["earlyDataHeaderName"] = json!(ws_early_data_header);
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

            let mode = first_query(url, &["mode"], Some("gun")).to_ascii_lowercase();
            match mode.as_str() {
                "gun" => {}
                "multi" => settings["multiMode"] = json!(true),
                "guna" => return Err("unsupported gRPC mode guna".to_string()),
                other => return Err(format!("unsupported gRPC mode {other}")),
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
            if let Some(value) = xhttp_extra_value(url)? {
                settings["extra"] = value;
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
        match flow.as_str() {
            "xtls-rprx-vision" | "xtls-rprx-vision-udp443" => {
                user["flow"] = json!(flow);
            }
            _ => return Err(format!("unsupported VLESS flow {flow}")),
        }
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
            .trim()
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

    let mut network = json_text(value.get("net")).unwrap_or_else(|| "tcp".to_string());
    if network.eq_ignore_ascii_case("h2") {
        network = "http".to_string();
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

    // In the VMess share format a gRPC link keeps its service name in `path`
    // and its mode (`gun`/`multi`) in `type`; without this mapping the service
    // name was silently dropped.
    if network.eq_ignore_ascii_case("grpc") {
        if let Some(service) = json_text(value.get("path")).filter(|value| !value.is_empty()) {
            q.push(("serviceName".to_string(), service));
        }

        if let Some(mode) = json_text(value.get("type"))
            .map(|value| value.to_ascii_lowercase())
            .filter(|value| matches!(value.as_str(), "gun" | "multi"))
        {
            q.push(("mode".to_string(), mode));
        }
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
        "security": json_text(value.get("scy"))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "auto".to_string()),
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

fn parse_trojan(config: &str) -> Result<Value, String> {
    let mut url = Url::parse(clean(config)).map_err(|error| error.to_string())?;
    if !url
        .query_pairs()
        .any(|(key, value)| key.eq_ignore_ascii_case("security") && !value.trim().is_empty())
    {
        url.query_pairs_mut().append_pair("security", "tls");
    }
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

fn supported_ss_plugin(key: &str, value: &str) -> bool {
    if !key.eq_ignore_ascii_case("plugin") {
        return true;
    }

    matches!(
        value.split(';').next().unwrap_or("").trim(),
        "obfs-local" | "v2ray-plugin"
    )
}

fn parse_ss(config: &str) -> Result<Value, String> {
    let url = Url::parse(clean(config)).map_err(|error| error.to_string())?;
    if url
        .query_pairs()
        .any(|(key, value)| !supported_ss_plugin(&key, &value))
    {
        return Err("unsupported Shadowsocks plugin".to_string());
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
            .1;

        let (method, password, remote) =
            if let Some((credentials, remote)) = payload.rsplit_once('@') {
                // SIP002: base64(method:password)@host:port. The credentials may be
                // percent-encoded (`%3D` for padding), so decode that first.
                let decoded = String::from_utf8(
                    b64decode(&decode_component(credentials))
                        .ok_or_else(|| "invalid Shadowsocks base64".to_string())?,
                )
                .map_err(|error| error.to_string())?;
                let (method, password) = decoded
                    .split_once(':')
                    .ok_or_else(|| "invalid Shadowsocks credentials".to_string())?;

                (method.to_string(), password.to_string(), remote.to_string())
            } else {
                // Legacy: base64(method:password@host:port) with no authority.
                let decoded = ss_legacy_decode(payload)
                    .ok_or_else(|| "invalid Shadowsocks base64".to_string())?;
                let (credentials, remote) = decoded
                    .rsplit_once('@')
                    .ok_or_else(|| "invalid Shadowsocks payload".to_string())?;
                let (method, password) = credentials
                    .split_once(':')
                    .ok_or_else(|| "invalid Shadowsocks credentials".to_string())?;

                (method.to_string(), password.to_string(), remote.to_string())
            };

        let remote_url =
            Url::parse(&format!("ss://{remote}")).map_err(|error| error.to_string())?;
        let (host, port) = endpoint_from_url(&remote_url, None)?;
        (host, port, method, password)
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
    let (host, port_spec, auth_raw) =
        hysteria2_parts(config).ok_or_else(|| "invalid Hysteria2 URL".to_string())?;

    let password = percent_decode_str(&auth_raw)
        .decode_utf8()
        .map_err(|error| error.to_string())?
        .into_owned();
    if password.is_empty() {
        return Err("Hysteria2 password missing".to_string());
    }

    let mut first_port = 443u16;
    let mut has_port_hopping = false;
    if !port_spec.is_empty() {
        for (index, entry) in port_spec
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .enumerate()
        {
            if let Some((start, end)) = entry.split_once('-') {
                let start = start
                    .parse::<u16>()
                    .map_err(|_| "invalid Hysteria2 port range".to_string())?;
                let end = end
                    .parse::<u16>()
                    .map_err(|_| "invalid Hysteria2 port range".to_string())?;
                if start == 0 || end == 0 || start > end {
                    return Err("invalid Hysteria2 port range".to_string());
                }
                if index == 0 {
                    first_port = start;
                }
                has_port_hopping = true;
            } else {
                let port = entry
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| "invalid Hysteria2 port".to_string())?;
                if index == 0 {
                    first_port = port;
                }
                if entry.contains(',') {
                    has_port_hopping = true;
                }
            }
        }

        if port_spec.contains(',') {
            has_port_hopping = true;
        }
    }

    let rest = config.split_once("://").map(|(_, rest)| rest).unwrap_or("");
    let query = rest
        .split_once('?')
        .map(|(_, value)| value.split('#').next().unwrap_or(value))
        .unwrap_or("");

    let mut sni = host.clone();
    let mut alpn = Vec::new();
    let mut fingerprint = String::new();
    let mut obfs = None;
    let mut obfs_password = None;

    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.to_ascii_lowercase().as_str() {
            "sni" | "server_name" | "peer" => {
                if !value.is_empty() {
                    sni = value.into_owned();
                }
            }
            "alpn" => {
                alpn.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned),
                );
            }
            "fp" | "fingerprint" => fingerprint = value.into_owned(),
            "obfs" => obfs = Some(value.into_owned()),
            "obfs-password" => obfs_password = Some(value.into_owned()),
            _ => {}
        }
    }

    let mut tls = json!({
        "serverName": sni,
    });
    if !alpn.is_empty() {
        tls["alpn"] = json!(alpn);
    }
    if !fingerprint.is_empty() {
        tls["fingerprint"] = json!(fingerprint);
    }

    let mut stream_settings = json!({
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": tls,
        "hysteriaSettings": {
            "version": 2,
            "auth": password,
        }
    });

    let mut finalmask = json!({});
    if let Some(obfs_type) = obfs.filter(|value| !value.is_empty()) {
        let obfs_type = obfs_type.to_ascii_lowercase();
        if !matches!(obfs_type.as_str(), "salamander" | "gecko") {
            return Err(format!("unsupported Hysteria2 obfs type {obfs_type}"));
        }

        let obfs_password = obfs_password
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Hysteria2 obfs password missing".to_string())?;
        finalmask["udp"] = json!([{
            "type": obfs_type,
            "settings": {
                "password": obfs_password,
            }
        }]);
    } else if obfs_password.is_some() {
        return Err("Hysteria2 obfs-password requires obfs".to_string());
    }

    if has_port_hopping {
        finalmask["quicParams"] = json!({
            "udpHop": {
                "ports": port_spec,
                "interval": 30,
            }
        });
    }

    if !finalmask
        .as_object()
        .is_some_and(|object| object.is_empty())
    {
        stream_settings["finalmask"] = finalmask;
    }

    Ok(json!({
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "address": host,
            "port": first_port,
        },
        "streamSettings": stream_settings,
    }))
}

/// Validate a 32-byte base64 key and return it in canonical standard base64.
/// Unescaped `+` in a query value is decoded to a space by URL parsers, so
/// spaces are turned back into `+` first (base64 never contains spaces).
fn decode_key(value: &str) -> Option<String> {
    let bytes = b64decode(&value.replace(' ', "+"))?;

    (bytes.len() == 32).then(|| STANDARD.encode(bytes))
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
    let private =
        decode_key(&private).ok_or_else(|| "invalid WireGuard private key".to_string())?;
    let public = decode_key(&public).ok_or_else(|| "invalid WireGuard public key".to_string())?;

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

    let peer_endpoint = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut peer = json!({
        "endpoint": peer_endpoint,
        "publicKey": public,
        "allowedIPs": allowed,
    });

    let psk = first_query(
        &url,
        &["presharedkey", "preshared-key", "preshared_key", "psk"],
        Some(""),
    );
    if !psk.is_empty() {
        let psk = decode_key(&psk).ok_or_else(|| "invalid WireGuard preshared key".to_string())?;
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

    // Must match `endpoint()`: HTTP proxies default to port 80 (this used to
    // be 8080, so probing and validation targeted different ports).
    let default = if matches!(scheme.as_str(), "socks" | "socks5" | "socks5h") {
        1080
    } else {
        80
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

pub(crate) fn parse_config(config: &str) -> Result<Value, String> {
    // The scheme comes from the raw text, not `Url::parse`, which rejects
    // Hysteria2 port-hopping authorities before they can reach `parse_hy2`.
    let scheme = scheme_of(clean(config));

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

fn unique_parsed(candidates: &[String]) -> (Vec<ParsedConfig>, Vec<RejectedConfig>) {
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
    let path = std::env::temp_dir().join(format!("proxyrift-xray-{}-{nanos}", std::process::id()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).map_err(|error| error.to_string())?;
    }

    #[cfg(not(unix))]
    std::fs::create_dir(&path).map_err(|error| error.to_string())?;

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

pub(crate) fn rate_limit_wait(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(RATE_LIMIT_DEFAULT_WAIT)
        .max(RATE_LIMIT_MIN_WAIT)
        .min(RATE_LIMIT_MAX_WAIT)
}

pub(crate) fn extend_rate_limit(wait: Duration) {
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

pub(crate) async fn wait_for_rate_limit() {
    loop {
        let now = unix_now_ms();
        let until = RATE_LIMIT_UNTIL_MS.load(Ordering::Acquire);
        if until <= now {
            return;
        }
        sleep(Duration::from_millis(until - now)).await;
    }
}

pub(crate) fn timeout_duration(seconds: f64) -> Result<Duration, String> {
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err("timeout must be a positive finite number".to_string());
    }

    Duration::try_from_secs_f64(seconds)
        .map_err(|_| "timeout exceeds the maximum supported duration".to_string())
}

fn client_for_port(
    port: u16,
    timeout_seconds: f64,
    fresh_connections: bool,
) -> Result<Client, String> {
    // An invalid timeout used to be silently replaced by 1 second, hiding
    // misconfiguration and failing every probe. Report it instead.
    let request_timeout = timeout_duration(timeout_seconds)?;

    let mut builder = Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
                .map_err(|error| error.to_string())?,
        )
        .timeout(request_timeout)
        // A proxy that answers with a redirect (captive portal / injected
        // login page) must fail the probe, not be followed to a page that
        // returns 200.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("ProxyRift/3.0");

    if fresh_connections {
        builder = builder.pool_max_idle_per_host(0);
    }

    builder.build().map_err(|error| error.to_string())
}

fn valid_probe_status(url: &Url, status: u16) -> bool {
    url.as_str() != PRIMARY_TARGET || status == 204
}

fn valid_probe_body(url: &Url, body: &[u8]) -> bool {
    match url.as_str() {
        PRIMARY_TARGET => body.is_empty(),
        "https://speed.cloudflare.com/__down?bytes=16384" => body.len() == 16_384,
        "https://example.com/" => !body.is_empty(),
        _ => true,
    }
}

fn append_limited_response_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> bool {
    if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
        return false;
    }
    body.extend_from_slice(chunk);
    true
}

pub(crate) async fn read_response_body_limited(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, ()> {
    let mut body = Vec::with_capacity(MAX_RESPONSE_BYTES.min(16_384));

    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if !append_limited_response_chunk(&mut body, &chunk) {
            return Err(());
        }
    }

    Ok(body)
}

async fn probe_request(client: &Client, url: Url) -> Result<ProbeSample, ProbeError> {
    wait_for_rate_limit().await;
    let started = Instant::now();
    let response = client
        .get(url.as_str())
        .send()
        .await
        .map_err(|_| ProbeError::Failed)?;

    if response.status().as_u16() == 429 {
        extend_rate_limit(rate_limit_wait(response.headers()));
        return Err(ProbeError::Failed);
    }

    if !response.status().is_success() || !valid_probe_status(&url, response.status().as_u16()) {
        return Err(ProbeError::Failed);
    }

    if response
        .content_length()
        .is_some_and(|length| length as usize > MAX_RESPONSE_BYTES)
    {
        return Err(ProbeError::Failed);
    }

    let status_is_empty_success = response.status().as_u16() == 204;
    let body = read_response_body_limited(response)
        .await
        .map_err(|_| ProbeError::Failed)?;
    if body.len() > MAX_RESPONSE_BYTES
        || (body.len() < MIN_RESPONSE_BYTES && !status_is_empty_success)
        || !valid_probe_body(&url, &body)
    {
        return Err(ProbeError::Failed);
    }

    Ok(ProbeSample {
        latency_ms: started.elapsed().as_secs_f64() * 1000.0,
        bytes: body.len(),
    })
}

async fn functional_attempt(
    client: &Client,
    target: &Url,
    compatibility_target: Option<&Url>,
) -> Result<ProbeSample, ProbeError> {
    if let Some(compatibility_target) =
        compatibility_target.filter(|compatibility_target| *compatibility_target != target)
    {
        probe_request(client, compatibility_target.clone()).await?;
    }

    probe_request(client, target.clone()).await
}

async fn check_batch(
    binary: &str,
    entries: &[(String, Value)],
    target: &Url,
    compatibility_target: Option<&Url>,
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
        let (config, local_ports) = match xray_config(&batch_entries) {
            Ok(value) => value,
            Err(error) => {
                let _ = fs::remove_dir_all(&work);
                return Err(error);
            }
        };

        if let Err(error) = serde_json::to_vec(&config)
            .map_err(|error| error.to_string())
            .and_then(|bytes| fs::write(&config_path, bytes).map_err(|error| error.to_string()))
        {
            let _ = fs::remove_dir_all(&work);
            return Err(error);
        }

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

                // Label only: the full URL carries credentials and CI logs of a
                // public repository are world-readable.
                println!(
                    "[WARN] Validation skipped: {}",
                    config_label(&batch_entries[0].0)
                );
                if !tail.is_empty() {
                    println!("[WARN] Xray core failed to start: {tail}");
                }
            }

            let _ = fs::remove_dir_all(&work);
            continue;
        }

        let mut active = Vec::with_capacity(batch_entries.len());
        for (index, (config, _)) in batch_entries.iter().enumerate() {
            let client = match client_for_port(local_ports[index], timeout_seconds, false) {
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
        let mut throughputs = HashMap::<String, Vec<f64>>::new();

        for _ in 0..STABILITY_ATTEMPTS {
            if active.is_empty() {
                break;
            }

            let results = stream::iter(active.clone())
                .map(|(config, port, client)| {
                    let target = target.clone();
                    async move {
                        let result =
                            functional_attempt(&client, &target, compatibility_target).await;
                        (config, port, result)
                    }
                })
                .buffer_unordered(workers.max(1))
                .collect::<Vec<_>>()
                .await;

            for (config, _, result) in results {
                *attempts.entry(config.clone()).or_insert(0) += 1;
                match result {
                    Ok(sample) => {
                        *successes.entry(config.clone()).or_insert(0) += 1;
                        latencies
                            .entry(config.clone())
                            .or_default()
                            .push(sample.latency_ms);
                        if target.as_str() == THROUGHPUT_TARGET && sample.latency_ms > 0.0 {
                            throughputs
                                .entry(config)
                                .or_default()
                                .push(sample.bytes as f64 * 8.0 / sample.latency_ms);
                        }
                    }
                    Err(ProbeError::Failed) => {}
                }
            }
        }

        for (config, _) in &batch_entries {
            let values = latencies.get(config).cloned().unwrap_or_default();
            let wins = successes.get(config).copied().unwrap_or(0);

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

                combined.insert(
                    config.clone(),
                    ProxyMetrics {
                        successes: wins,
                        attempts: attempts.get(config).copied().unwrap_or(0),
                        median_ms: median,
                        min_ms: values[0],
                        jitter_ms: latency_jitter(&values),
                        throughput_kbps: throughput_kbps(
                            throughputs.get(config).map(Vec::as_slice).unwrap_or(&[]),
                        ),
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

pub async fn validate_candidates_with_targets(
    binary: &str,
    candidates: &[String],
    targets: &[&str],
    workers: usize,
    batch_size: usize,
    timeout_seconds: f64,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    validate_candidates_targets_inner(
        binary,
        candidates,
        targets,
        workers,
        batch_size,
        timeout_seconds,
        ValidationPolicy::new(
            MAX_LATENCY_MS,
            STABILITY_ATTEMPTS,
            MIN_SUCCESSFUL_ATTEMPTS,
            MIN_SUCCESSFUL_TARGETS,
        ),
    )
    .await
}

pub async fn validate_candidates_with_targets_strict(
    binary: &str,
    candidates: &[String],
    targets: &[&str],
    workers: usize,
    batch_size: usize,
    timeout_seconds: f64,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    validate_candidates_targets_inner(
        binary,
        candidates,
        targets,
        workers,
        batch_size,
        timeout_seconds,
        ValidationPolicy::new(
            MAX_LATENCY_MS,
            STRICT_STABILITY_ATTEMPTS,
            STRICT_MIN_SUCCESSFUL_ATTEMPTS,
            STRICT_MIN_SUCCESSFUL_TARGETS,
        ),
    )
    .await
}

pub async fn validate_candidates(
    binary: &str,
    candidates: &[String],
    target: &str,
    workers: usize,
    batch_size: usize,
    timeout_seconds: f64,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    validate_candidates_inner(
        binary,
        candidates,
        target,
        None,
        workers,
        batch_size,
        timeout_seconds,
    )
    .await
}

pub async fn validate_candidates_with_compatibility(
    binary: &str,
    candidates: &[String],
    target: &str,
    compatibility_target: &str,
    workers: usize,
    batch_size: usize,
    timeout_seconds: f64,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    validate_candidates_inner(
        binary,
        candidates,
        target,
        Some(compatibility_target),
        workers,
        batch_size,
        timeout_seconds,
    )
    .await
}

async fn validate_candidates_targets_inner(
    binary: &str,
    candidates: &[String],
    targets: &[&str],
    workers: usize,
    batch_size: usize,
    timeout_seconds: f64,
    policy: ValidationPolicy,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    let mut seen_targets = HashSet::new();
    let targets = targets
        .iter()
        .map(|target| Url::parse(target).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|target| seen_targets.insert(target.as_str().to_string()))
        .collect::<Vec<_>>();

    if targets.len() < policy.min_successful_targets {
        return Err(format!(
            "Light validation requires at least {} targets",
            policy.min_successful_targets
        ));
    }

    let (parsed, rejected) = unique_parsed(candidates);

    println!(
        "loaded {} input URLs, accepted {} for Xray, rejected {}",
        candidates.len(),
        parsed.len(),
        rejected.len()
    );

    for (config, reason) in rejected.iter().take(8) {
        println!("rejected: {} :: {reason}", config_label(config));
    }

    if !rejected.is_empty() {
        let mut counts = HashMap::<String, usize>::new();
        for (config, _) in &rejected {
            *counts.entry(scheme_of(clean(config))).or_insert(0) += 1;
        }
        println!("rejected by scheme: {:?}", counts);
    }

    if parsed.is_empty() {
        return Ok(HashMap::new());
    }

    let batch_size = batch_size.max(1);
    let total_batches = parsed.len().div_ceil(batch_size);
    let mut metadata = HashMap::new();

    for (index, batch) in parsed.chunks(batch_size).enumerate() {
        println!(
            "targets {:?}: batch {}/{} testing {} configs with Xray; requiring {}/{} successful attempts across at least {} destinations",
            targets.iter().map(Url::as_str).collect::<Vec<_>>(),
            index + 1,
            total_batches,
            batch.len(),
            policy.min_successful_attempts,
            policy.stability_attempts,
            policy.min_successful_targets
        );

        let batch_metadata = check_batch_targets(
            binary,
            batch,
            &targets,
            workers.max(1),
            timeout_seconds,
            policy,
        )
        .await?;
        metadata.extend(batch_metadata);
    }

    println!(
        "{}/{} verified by Xray against {} targets with {}/{} successful attempts and at least {} distinct successful destinations",
        metadata.len(),
        candidates.len(),
        targets.len(),
        policy.min_successful_attempts,
        policy.stability_attempts,
        policy.min_successful_targets
    );

    Ok(metadata)
}

async fn check_batch_targets(
    binary: &str,
    entries: &[(String, Value)],
    targets: &[Url],
    workers: usize,
    timeout_seconds: f64,
    policy: ValidationPolicy,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    if entries.is_empty() || targets.is_empty() {
        return Ok(HashMap::new());
    }

    let mut pending_batches = vec![entries.to_vec()];
    let mut combined = HashMap::new();

    while let Some(batch_entries) = pending_batches.pop() {
        let work = make_temp_dir()?;
        let config_path = work.join("xray.json");
        let log_path = work.join("xray.log");
        let (config, local_ports) = match xray_config(&batch_entries) {
            Ok(value) => value,
            Err(error) => {
                let _ = fs::remove_dir_all(&work);
                return Err(error);
            }
        };

        if let Err(error) = serde_json::to_vec(&config)
            .map_err(|error| error.to_string())
            .and_then(|bytes| fs::write(&config_path, bytes).map_err(|error| error.to_string()))
        {
            let _ = fs::remove_dir_all(&work);
            return Err(error);
        }

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

                println!(
                    "[WARN] Validation skipped: {}",
                    config_label(&batch_entries[0].0)
                );
                if !tail.is_empty() {
                    println!("[WARN] Xray core failed to start: {tail}");
                }
            }

            let _ = fs::remove_dir_all(&work);
            continue;
        }

        let mut clients = Vec::with_capacity(batch_entries.len());
        for (index, _) in batch_entries.iter().enumerate() {
            match client_for_port(local_ports[index], timeout_seconds, true) {
                Ok(client) => clients.push(client),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = fs::remove_dir_all(&work);
                    return Err(error);
                }
            }
        }

        let count = batch_entries.len();
        let mut successes = vec![0usize; count];
        let mut attempts = vec![0usize; count];
        let mut late_streak = vec![0usize; count];
        let mut latencies = vec![Vec::<f64>::new(); count];
        let mut throughputs = vec![Vec::<f64>::new(); count];
        let mut active = (0..count).collect::<Vec<_>>();

        for attempt in 0..policy.stability_attempts {
            if active.is_empty() {
                break;
            }

            if policy.stability_attempts >= STRICT_STABILITY_ATTEMPTS
                && STRICT_RECONNECT_AFTER_ATTEMPTS.contains(&(attempt + 1))
            {
                for &entry_index in &active {
                    let client =
                        match client_for_port(local_ports[entry_index], timeout_seconds, true) {
                            Ok(client) => client,
                            Err(error) => {
                                let _ = child.kill();
                                let _ = child.wait();
                                let _ = fs::remove_dir_all(&work);
                                return Err(error);
                            }
                        };
                    clients[entry_index] = client;
                }
            }

            let results = stream::iter(active.iter().copied())
                .map(|entry_index| {
                    let client = &clients[entry_index];
                    let target = targets[0].clone();
                    async move { (entry_index, probe_request(client, target).await) }
                })
                .buffer_unordered(workers.max(1))
                .collect::<Vec<_>>()
                .await;

            for (entry_index, result) in results {
                attempts[entry_index] += 1;
                match result {
                    Ok(sample) => {
                        successes[entry_index] += 1;
                        late_streak[entry_index] += 1;
                        latencies[entry_index].push(sample.latency_ms);
                        if targets[0].as_str() == THROUGHPUT_TARGET && sample.latency_ms > 0.0 {
                            throughputs[entry_index]
                                .push(sample.bytes as f64 * 8.0 / sample.latency_ms);
                        }
                    }
                    Err(ProbeError::Failed) => late_streak[entry_index] = 0,
                }
            }

            let remaining = policy.stability_attempts.saturating_sub(attempt + 1);
            if remaining == 0 {
                active.clear();
            } else {
                active.retain(|&entry_index| {
                    successes[entry_index] + remaining >= policy.min_successful_attempts
                        && (policy.stability_attempts < STRICT_STABILITY_ATTEMPTS
                            || late_streak[entry_index] + remaining >= STRICT_LATE_SUCCESS_STREAK)
                });
            }

            if !active.is_empty()
                && policy.stability_attempts >= STRICT_STABILITY_ATTEMPTS
                && attempt + 1 < policy.stability_attempts
            {
                sleep(STRICT_INTER_ATTEMPT_DELAY).await;
            }
        }

        let mut secondary_success = vec![false; count];
        if policy.min_successful_targets > 1 {
            for target in targets.iter().skip(1) {
                let eligible = (0..count)
                    .filter(|&entry_index| {
                        !secondary_success[entry_index]
                            && successes[entry_index] >= policy.min_successful_attempts
                            && (policy.stability_attempts < STRICT_STABILITY_ATTEMPTS
                                || late_streak[entry_index] >= STRICT_LATE_SUCCESS_STREAK)
                    })
                    .collect::<Vec<_>>();

                if eligible.is_empty() {
                    break;
                }

                let results = stream::iter(eligible)
                    .map(|entry_index| {
                        let client = &clients[entry_index];
                        let target = target.clone();
                        async move { (entry_index, probe_request(client, target).await) }
                    })
                    .buffer_unordered(workers.max(1))
                    .collect::<Vec<_>>()
                    .await;

                for (entry_index, result) in results {
                    if let Ok(sample) = result {
                        if sample.latency_ms <= policy.max_latency_ms {
                            secondary_success[entry_index] = true;
                        }
                        if target.as_str() == THROUGHPUT_TARGET && sample.latency_ms > 0.0 {
                            throughputs[entry_index]
                                .push(sample.bytes as f64 * 8.0 / sample.latency_ms);
                        }
                    }
                }
            }
        }

        for index in 0..count {
            let target_count =
                usize::from(successes[index] > 0) + usize::from(secondary_success[index]);

            if successes[index] >= policy.min_successful_attempts
                && target_count >= policy.min_successful_targets
                && (policy.stability_attempts < STRICT_STABILITY_ATTEMPTS
                    || late_streak[index] >= STRICT_LATE_SUCCESS_STREAK)
                && latencies[index].iter().copied().fold(0.0, f64::max) <= policy.max_latency_ms
            {
                let mut values = std::mem::take(&mut latencies[index]);
                values.sort_by(f64::total_cmp);
                let median = if values.len() % 2 == 1 {
                    values[values.len() / 2]
                } else {
                    let right = values.len() / 2;
                    (values[right - 1] + values[right]) / 2.0
                };

                combined.insert(
                    batch_entries[index].0.clone(),
                    ProxyMetrics {
                        successes: successes[index],
                        attempts: attempts[index],
                        median_ms: median,
                        min_ms: values[0],
                        jitter_ms: latency_jitter(&values),
                        throughput_kbps: throughput_kbps(&throughputs[index]),
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

async fn validate_candidates_inner(
    binary: &str,
    candidates: &[String],
    target: &str,
    compatibility_target: Option<&str>,
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
        println!("rejected: {} :: {reason}", config_label(config));
    }

    if !rejected.is_empty() {
        let mut counts = HashMap::<String, usize>::new();
        for (config, _) in &rejected {
            *counts.entry(scheme_of(clean(config))).or_insert(0) += 1;
        }
        println!("rejected by scheme: {:?}", counts);
    }

    if parsed.is_empty() {
        return Ok(HashMap::new());
    }

    let target = Url::parse(target).map_err(|error| error.to_string())?;
    let compatibility_target = compatibility_target
        .map(Url::parse)
        .transpose()
        .map_err(|error| error.to_string())?;
    let batch_size = batch_size.max(1);
    let total_batches = parsed.len().div_ceil(batch_size);
    let mut metadata = HashMap::new();

    for (index, batch) in parsed.chunks(batch_size).enumerate() {
        if let Some(compatibility_target) = compatibility_target.as_ref() {
            println!(
                "targets {target} + {compatibility_target}: batch {}/{} testing {} configs with Xray core; requiring {}/{}",
                index + 1,
                total_batches,
                batch.len(),
                MIN_SUCCESSFUL_ATTEMPTS,
                STABILITY_ATTEMPTS
            );
        } else {
            println!(
                "target {target}: batch {}/{} testing {} configs with Xray core; requiring {}/{}",
                index + 1,
                total_batches,
                batch.len(),
                MIN_SUCCESSFUL_ATTEMPTS,
                STABILITY_ATTEMPTS
            );
        }

        let batch_metadata = check_batch(
            binary,
            batch,
            &target,
            compatibility_target.as_ref(),
            workers.max(1),
            timeout_seconds,
        )
        .await?;
        metadata.extend(batch_metadata);
    }

    // The summaries below used to print MIN_SUCCESSFUL_TARGETS where the number
    // of required successful attempts was meant.
    if let Some(compatibility_target) = compatibility_target.as_ref() {
        println!(
            "{}/{} verified by Xray against {} and {} with {}/{} successful attempts and every measured latency <= {}ms",
            metadata.len(),
            candidates.len(),
            target,
            compatibility_target,
            MIN_SUCCESSFUL_ATTEMPTS,
            STABILITY_ATTEMPTS,
            MAX_LATENCY_MS
        );
    } else {
        println!(
            "{}/{} verified by Xray with {}/{} successful attempts and every measured latency <= {}ms",
            metadata.len(),
            candidates.len(),
            MIN_SUCCESSFUL_ATTEMPTS,
            STABILITY_ATTEMPTS,
            MAX_LATENCY_MS
        );
    }

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
                "jitter_ms": metrics.jitter_ms,
                "throughput_kbps": metrics.throughput_kbps,
            }),
        );
    }

    write_atomic(
        path,
        &serde_json::to_vec(&Value::Object(output)).map_err(|error| error.to_string())?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn primary_probe_requires_http_204() {
        let primary = Url::parse(PRIMARY_TARGET).expect("primary target should parse");
        assert!(valid_probe_status(&primary, 204));
        assert!(!valid_probe_status(&primary, 200));

        let other = Url::parse("https://example.com/").expect("example target should parse");
        assert!(valid_probe_status(&other, 200));
    }

    #[test]
    fn bounded_response_chunk_rejects_overflow() {
        let mut body = Vec::new();
        assert!(super::append_limited_response_chunk(&mut body, &[1, 2, 3]));
        assert_eq!(body.len(), 3);

        let remaining = super::MAX_RESPONSE_BYTES - body.len();
        assert!(super::append_limited_response_chunk(
            &mut body,
            &vec![0u8; remaining]
        ));
        assert_eq!(body.len(), super::MAX_RESPONSE_BYTES);
        assert!(!super::append_limited_response_chunk(&mut body, &[0]));
        assert_eq!(body.len(), super::MAX_RESPONSE_BYTES);
    }

    #[test]
    fn default_probe_targets_require_expected_payloads() {
        let primary = Url::parse(PRIMARY_TARGET).expect("primary HTTPS target should parse");
        assert!(valid_probe_body(&primary, b""));

        let speed =
            Url::parse("https://speed.cloudflare.com/__down?bytes=16384").expect("speed target");
        assert!(valid_probe_body(&speed, &vec![0_u8; 16_384]));
        assert!(!valid_probe_body(&speed, &vec![0_u8; 16_383]));

        let example = Url::parse("https://example.com/").expect("example.com");
        assert!(valid_probe_body(&example, b"<html>"));
        assert!(!valid_probe_body(&example, b""));
    }

    #[test]
    fn ignores_removed_allow_insecure_vless_option() {
        for parameter in ["insecure=1", "allowInsecure=1"] {
            let config = parse_config(&format!(
                "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&{parameter}"
            ))
            .expect("VLESS TLS should parse");

            assert!(config["streamSettings"]["tlsSettings"]
                .get("allowInsecure")
                .is_none());
        }
    }

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
    fn vless_ws_path_early_data_is_normalized() {
        let config = parse_config(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=none&type=ws&path=/?ed=2560",
        )
        .expect("VLESS WS should parse");

        assert_eq!(config["streamSettings"]["wsSettings"]["path"], "/");
        assert_eq!(config["streamSettings"]["wsSettings"]["maxEarlyData"], 2560);
        assert_eq!(
            config["streamSettings"]["wsSettings"]["earlyDataHeaderName"],
            "Sec-WebSocket-Protocol"
        );
    }

    #[test]
    fn vless_ws_long_early_data_parameters_are_preserved() {
        let config = parse_config(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=none&type=ws&max_early_data=2048&early_data_header_name=Sec-WebSocket-Protocol",
        )
        .expect("VLESS WS should parse");

        assert_eq!(config["streamSettings"]["wsSettings"]["maxEarlyData"], 2048);
        assert_eq!(
            config["streamSettings"]["wsSettings"]["earlyDataHeaderName"],
            "Sec-WebSocket-Protocol"
        );
    }

    #[test]
    fn rejects_invalid_xhttp_extra() {
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=none&type=xhttp&extra=not-json";
        let error = parse_config(config).expect_err("invalid XHTTP extra should be rejected");
        assert!(error.contains("invalid XHTTP extra JSON"));

        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=none&type=xhttp&extra=%5B1%2C2%5D";
        let error = parse_config(config).expect_err("non-object XHTTP extra should be rejected");
        assert!(error.contains("XHTTP extra must be a JSON object"));
    }

    #[test]
    fn accepts_xhttp_extra_with_plus_and_double_encoding() {
        let single_encoded =
            "vless://00000000-0000-0000-0000-000000000001@darsadgir.ir:2087?security=tls&type=xhttp&extra=%7B%22mode%22%3A%22auto%22%2C%22xPaddingKey%22%3A%22a%2Bb%22%7D";
        let parsed = parse_config(single_encoded).expect("single-encoded XHTTP extra should parse");
        assert_eq!(
            parsed["streamSettings"]["xhttpSettings"]["extra"]["xPaddingKey"],
            "a+b"
        );

        let double_encoded =
            "vless://00000000-0000-0000-0000-000000000001@darsadgir.ir:2087?security=tls&type=xhttp&extra=%257B%2522mode%2522%253A%2522auto%2522%252C%2522xPaddingKey%2522%253A%2522a%252Bb%2522%257D";
        let parsed = parse_config(double_encoded).expect("double-encoded XHTTP extra should parse");
        assert_eq!(
            parsed["streamSettings"]["xhttpSettings"]["extra"]["xPaddingKey"],
            "a+b"
        );
    }

    #[test]
    fn accepts_websocket_early_data_header_without_size() {
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&type=ws&eh=Sec-WebSocket-Protocol";
        let parsed = parse_config(config)
            .expect("unused WebSocket early-data header should parse");
        assert!(
            parsed["streamSettings"]["wsSettings"]
                .get("maxEarlyData")
                .is_none()
        );
        assert!(
            parsed["streamSettings"]["wsSettings"]
                .get("earlyDataHeaderName")
                .is_none()
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
    fn vmess_grpc_keeps_service_name_from_path() {
        let payload = json!({
            "add": "example.com",
            "port": 443,
            "id": "00000000-0000-0000-0000-000000000001",
            "net": "grpc",
            "tls": "tls",
            "type": "gun",
            "path": "TunService",
        });
        let config = format!("vmess://{}", STANDARD.encode(payload.to_string()));
        let parsed = parse_config(&config).expect("VMess gRPC should parse");

        assert_eq!(
            parsed["streamSettings"]["grpcSettings"]["serviceName"],
            "TunService"
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
            ("127.0.0.1".to_string(), 80)
        );
    }

    #[test]
    fn http_proxy_parser_uses_same_default_port_as_endpoint() {
        let parsed = parse_config("http://127.0.0.1").expect("HTTP proxy should parse");
        assert_eq!(parsed["settings"]["servers"][0]["port"], 80);
    }

    #[test]
    fn hysteria2_endpoint_defaults_only_when_port_is_omitted() {
        assert_eq!(
            endpoint("hy2://password@proxy.example.com"),
            Some(("proxy.example.com".to_string(), 443))
        );
        assert!(endpoint("hy2://password@proxy.example.com:not-a-port").is_none());
        assert!(endpoint("hy2://password@proxy.example.com:0").is_none());
    }

    #[test]
    fn endpoint_defaults_match_proxy_parser() {
        assert_eq!(
            endpoint("http://127.0.0.1").expect("HTTP endpoint"),
            ("127.0.0.1".to_string(), 80)
        );
    }

    #[test]
    fn config_label_never_exposes_userinfo() {
        assert_eq!(
            config_label("trojan://secret-password@example.com:443"),
            "trojan://example.com:443"
        );
    }

    #[test]
    fn ipv6_endpoints_are_unbracketed_and_labels_bracketed_once() {
        assert_eq!(
            endpoint("trojan://secret@[2001:db8::1]:443"),
            Some(("2001:db8::1".to_string(), 443))
        );
        assert_eq!(
            config_label("trojan://secret@[2001:db8::1]:443"),
            "trojan://[2001:db8::1]:443"
        );

        let parsed =
            parse_config("trojan://secret@[2001:db8::1]:443").expect("IPv6 Trojan should parse");
        assert_eq!(parsed["settings"]["servers"][0]["address"], "2001:db8::1");
    }

    #[test]
    fn hysteria2_endpoint_defaults_to_443() {
        assert_eq!(
            endpoint("hysteria2://password@example.com"),
            Some(("example.com".to_string(), 443))
        );
    }

    #[test]
    fn hysteria2_endpoint_uses_first_multi_port() {
        assert_eq!(
            endpoint("hy2://password@example.com:1234,5000-6000"),
            Some(("example.com".to_string(), 1234))
        );
    }

    #[test]
    fn parse_config_accepts_hysteria2_port_hopping() {
        let parsed = parse_config("hy2://password@example.com:1234,5000-5002")
            .expect("port-hopping Hysteria2 should reach parse_hy2");

        assert_eq!(parsed["settings"]["port"], 1234);
    }

    #[test]
    fn wireguard_ipv6_endpoint_is_bracketed() {
        let private_key = STANDARD.encode([7_u8; 32]);
        let public_key = STANDARD.encode([9_u8; 32]);
        let config =
            format!("wg://[2001:db8::1]:51820?privatekey={private_key}&publickey={public_key}");

        let parsed = parse_config(&config).expect("WireGuard IPv6 endpoint should parse");
        assert_eq!(
            parsed["settings"]["peers"][0]["endpoint"],
            "[2001:db8::1]:51820"
        );
    }

    #[test]
    fn wireguard_keys_with_unescaped_plus_survive_query_parsing() {
        // 0xfb bytes encode to base64 containing both '+' and '/'.
        let key = STANDARD.encode([0xfb_u8; 32]);
        assert!(key.contains('+'));

        let config = format!("wg://192.0.2.1:51820?privatekey={key}&publickey={key}");
        let parsed = parse_config(&config).expect("keys containing '+' should parse");

        assert_eq!(parsed["settings"]["secretKey"], key);
        assert_eq!(parsed["settings"]["peers"][0]["publicKey"], key);
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
    fn legacy_shadowsocks_links_have_an_endpoint_and_parse() {
        let config = format!(
            "ss://{}",
            STANDARD.encode("aes-256-gcm:secret@example.com:8388")
        );

        assert_eq!(endpoint(&config), Some(("example.com".to_string(), 8388)));

        let parsed = parse_config(&config).expect("legacy Shadowsocks should parse");
        assert_eq!(parsed["settings"]["servers"][0]["method"], "aes-256-gcm");
        assert_eq!(parsed["settings"]["servers"][0]["password"], "secret");
        assert_eq!(parsed["settings"]["servers"][0]["port"], 8388);
    }

    #[test]
    fn sip002_shadowsocks_accepts_percent_encoded_padding() {
        let credentials = STANDARD.encode("aes-256-gcm:pw");
        let encoded = credentials.replace('=', "%3D");
        let config = format!("ss://{encoded}@example.com:8388");

        let parsed = parse_config(&config).expect("percent-encoded credentials should parse");
        assert_eq!(parsed["settings"]["servers"][0]["password"], "pw");
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

    #[test]
    fn invalid_timeouts_are_reported_not_replaced() {
        assert!(client_for_port(1080, 0.0, false).is_err());
        assert!(client_for_port(1080, f64::NAN, false).is_err());
        assert!(client_for_port(1080, 3.0, false).is_ok());
    }

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

    #[test]
    fn urlencoding_escapes_reserved_and_non_ascii_bytes() {
        assert_eq!(urlencoding("a b/c?é"), "a%20b%2Fc%3F%C3%A9");
    }

    #[test]
    fn defaults_trojan_to_tls_when_security_is_omitted() {
        let config = parse_trojan("trojan://user:secret@example.com:443?sni=example.com")
            .expect("Trojan without an explicit security mode should parse");

        assert_eq!(config["streamSettings"]["security"], "tls");
        assert_eq!(
            config["streamSettings"]["tlsSettings"]["serverName"],
            "example.com"
        );
    }

    #[test]
    fn defaults_trojan_to_tls_when_security_is_empty() {
        let config = parse_trojan("trojan://user:secret@example.com:443?security=")
            .expect("Trojan with an empty security value should default to TLS");

        assert_eq!(config["streamSettings"]["security"], "tls");
    }

    #[test]
    fn ignores_removed_allow_insecure_hysteria2_option() {
        let config = parse_hy2("hysteria2://password@example.com:443?insecure=1")
            .expect("Hysteria2 TLS should parse");

        assert!(config["streamSettings"]["tlsSettings"]
            .get("allowInsecure")
            .is_none());
    }

    #[test]
    fn parses_hysteria2_obfuscation_and_port_hopping() {
        let config = parse_hy2(
            "hysteria2://password@example.com:1234,5000-6000?obfs=salamander&obfs-password=secret&insecure=1",
        )
        .expect("Hysteria2 obfuscation and port hopping should parse");

        assert_eq!(config["settings"]["port"], 1234);
        assert_eq!(
            config["streamSettings"]["finalmask"]["udp"][0]["type"],
            "salamander"
        );
        assert_eq!(
            config["streamSettings"]["finalmask"]["udp"][0]["settings"]["password"],
            "secret"
        );
        assert_eq!(
            config["streamSettings"]["finalmask"]["quicParams"]["udpHop"]["ports"],
            "1234,5000-6000"
        );
        assert!(config["streamSettings"]["tlsSettings"]
            .get("allowInsecure")
            .is_none());
    }

    #[test]
    fn parses_hysteria2_with_default_port() {
        let config = parse_hy2("hy2://password@example.com").expect("Hysteria2 should parse");

        assert_eq!(config["settings"]["port"], 443);
        assert_eq!(
            config["streamSettings"]["tlsSettings"]["serverName"],
            "example.com"
        );
    }

    #[test]
    fn rejects_unsupported_grpc_mode() {
        let config =
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&type=grpc&serviceName=Tun&mode=guna";

        let error = parse_config(config).expect_err("guna is unsupported by Xray");
        assert!(error.contains("unsupported gRPC mode guna"));
    }

    #[test]
    fn rejects_unsupported_vless_flow() {
        let result = parse_vless(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&flow=xtls-rprx-direct-udp443",
        );

        assert!(result.is_err());
    }
}
