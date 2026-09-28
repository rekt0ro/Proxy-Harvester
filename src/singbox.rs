use crate::validator::{
    config_label, ProxyMetrics, MAX_RESPONSE_BYTES, MIN_RESPONSE_BYTES, MIN_SUCCESSFUL_ATTEMPTS,
    MIN_SUCCESSFUL_TARGETS, PRIMARY_TARGET, STABILITY_ATTEMPTS, STRICT_INTER_ATTEMPT_DELAY,
    STRICT_LATE_SUCCESS_STREAK, STRICT_MIN_SUCCESSFUL_ATTEMPTS, STRICT_MIN_SUCCESSFUL_TARGETS,
    STRICT_STABILITY_ATTEMPTS,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::stream::{self, StreamExt};
use percent_encoding::percent_decode_str;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::Url;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_MAX_LATENCY_MS: f64 = 3000.0;
const START_TIMEOUT: Duration = Duration::from_secs(5);
const BATCH_SIZE: usize = 250;

fn clean(url: &str) -> &str {
    url.split('#').next().unwrap_or(url)
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
            if let Some(early_data) = settings.get("maxEarlyData").and_then(Value::as_u64) {
                transport["max_early_data"] = json!(early_data);
            }
            if let Some(header) = settings
                .get("earlyDataHeaderName")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            {
                transport["early_data_header_name"] = json!(header);
            }

            Ok(Some(transport))
        }
        "http" => {
            let settings = stream
                .get("httpSettings")
                .ok_or_else(|| "missing HTTP transport settings".to_string())?;
            let mut transport = json!({
                "type": "http",
            });
            if let Some(path) = settings.get("path").and_then(Value::as_str) {
                if !path.is_empty() {
                    transport["path"] = json!(path);
                }
            }
            if let Some(host) = settings.get("host") {
                if host.is_array() {
                    transport["host"] = host.clone();
                } else if let Some(host) = host.as_str().filter(|value| !value.is_empty()) {
                    transport["host"] = json!([host]);
                }
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

fn singbox_hysteria2_outbound(config: &str) -> Result<Value, String> {
    let cleaned = clean(config);
    let rest = cleaned
        .split_once("://")
        .ok_or_else(|| "invalid Hysteria2 URL".to_string())?
        .1;
    let (authority, query) = rest
        .split_once('?')
        .map(|(authority, query)| {
            (
                authority.split('#').next().unwrap_or(authority),
                query.split('#').next().unwrap_or(query),
            )
        })
        .unwrap_or_else(|| (rest.split('#').next().unwrap_or(rest), ""));

    let host_port = authority
        .rsplit_once('@')
        .map(|(_, value)| value)
        .unwrap_or(authority);
    let auth_raw = authority
        .rsplit_once('@')
        .map(|(value, _)| value)
        .unwrap_or("");

    let auth = percent_decode_str(auth_raw)
        .decode_utf8()
        .map_err(|error| error.to_string())?
        .into_owned();
    if auth.is_empty() {
        return Err("Hysteria2 password missing".to_string());
    }

    let (host, port_spec) = if let Some(stripped) = host_port.strip_prefix('[') {
        let (host, remainder) = stripped
            .split_once(']')
            .ok_or_else(|| "invalid Hysteria2 host".to_string())?;
        if host.is_empty() {
            return Err("Hysteria2 host missing".to_string());
        }
        (
            host.to_string(),
            remainder.strip_prefix(':').unwrap_or("").to_string(),
        )
    } else if let Some((host, port_spec)) = host_port.rsplit_once(':') {
        if host.contains(':') || host.is_empty() {
            return Err("invalid Hysteria2 host".to_string());
        }
        (host.to_string(), port_spec.to_string())
    } else {
        if host_port.is_empty() {
            return Err("Hysteria2 host missing".to_string());
        }
        (host_port.to_string(), String::new())
    };

    let port_spec = if port_spec.is_empty() {
        None
    } else {
        let entries = port_spec
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if entries.is_empty() {
            return Err("invalid Hysteria2 port".to_string());
        }

        for entry in &entries {
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
            } else if entry
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .is_none()
            {
                return Err("invalid Hysteria2 port".to_string());
            }
        }

        Some(entries)
    };

    let mut pairs = url::form_urlencoded::parse(query.as_bytes());
    let mut sni = None;
    let mut insecure = false;
    let mut alpns = Vec::new();
    let mut obfs = None;
    let mut obfs_password = None;
    let mut has_pin = false;
    let mut has_ech = false;

    for (key, value) in pairs.by_ref() {
        match key.to_ascii_lowercase().as_str() {
            "sni" => sni = Some(value.into_owned()),
            "insecure"
                if matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                ) =>
            {
                insecure = true
            }
            "alpn" => alpns.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned),
            ),
            "obfs" => obfs = Some(value.into_owned()),
            "obfs-password" => obfs_password = Some(value.into_owned()),
            "pinsha256" => has_pin = true,
            "ech" => has_ech = true,
            _ => {}
        }
    }

    if has_pin {
        return Err("Hysteria2 pinSHA256 is unsupported by pinned sing-box 1.14.1".to_string());
    }
    if has_ech {
        return Err("Hysteria2 ECH links are unsupported by the Light URI mapper".to_string());
    }
    if obfs_password.is_some() && obfs.is_none() {
        return Err("Hysteria2 obfs-password requires obfs".to_string());
    }

    let mut outbound = json!({
        "type": "hysteria2",
        "server": host,
        "password": auth,
        "tls": {
            "enabled": true,
        },
    });

    if let Some(ports) = port_spec {
        if ports.len() == 1 && !ports[0].contains('-') {
            outbound["server_port"] = json!(ports[0]
                .parse::<u16>()
                .map_err(|_| "invalid Hysteria2 port".to_string())?);
        } else {
            outbound["server_ports"] = json!(ports);
        }
    } else {
        outbound["server_port"] = json!(443);
    }

    if let Some(sni) = sni.filter(|value| !value.is_empty()) {
        outbound["tls"]["server_name"] = json!(sni);
    } else {
        outbound["tls"]["server_name"] = json!(host);
    }

    if insecure {
        outbound["tls"]["insecure"] = json!(true);
    }
    if !alpns.is_empty() {
        outbound["tls"]["alpn"] = json!(alpns);
    }

    if let Some(obfs_type) = obfs.filter(|value| !value.is_empty()) {
        let obfs_type = obfs_type.to_ascii_lowercase();
        if !matches!(obfs_type.as_str(), "salamander" | "gecko") {
            return Err(format!("unsupported Hysteria2 obfs type {obfs_type}"));
        }
        let password = obfs_password
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Hysteria2 obfs password missing".to_string())?;

        outbound["obfs"] = json!({
            "type": obfs_type,
            "password": password,
        });
    }

    Ok(outbound)
}

fn singbox_outbound(config: &str) -> Result<Value, String> {
    let cleaned = clean(config);
    let scheme = cleaned
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_default();

    if scheme == "hysteria2" || scheme == "hy2" {
        return singbox_hysteria2_outbound(config);
    }

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

            let link = Url::parse(clean(config)).map_err(|error| error.to_string())?;
            if let Some(packet_encoding) = link.query_pairs().find_map(|(key, value)| {
                key.eq_ignore_ascii_case("packetEncoding")
                    .then_some(value.into_owned())
            }) {
                let packet_encoding = packet_encoding.to_ascii_lowercase();
                let packet_encoding = match packet_encoding.as_str() {
                    "" | "none" => "",
                    "xudp" => "xudp",
                    "packetaddr" => "packetaddr",
                    other => return Err(format!("unsupported VLESS packetEncoding {other}")),
                };
                outbound["packet_encoding"] = json!(packet_encoding);
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
            let packet_encoding = {
                let mut value = source
                    .get("packetEncoding")
                    .and_then(Value::as_str)
                    .unwrap_or("xudp")
                    .to_ascii_lowercase();

                if let Some(extra) = source.get("throneExtra").and_then(Value::as_str) {
                    if let Ok(extra_url) = Url::parse(&format!("https://example.invalid/?{extra}"))
                    {
                        if let Some(explicit) = extra_url.query_pairs().find_map(|(key, value)| {
                            key.eq_ignore_ascii_case("packetEncoding")
                                .then_some(value.into_owned())
                        }) {
                            value = explicit.to_ascii_lowercase();
                        }
                    }
                }

                match value.as_str() {
                    "" | "none" => "",
                    "xudp" => "xudp",
                    "packetaddr" => "packetaddr",
                    other => return Err(format!("unsupported VMess packetEncoding {other}")),
                }
            };

            let mut outbound = json!({
                "type": "vmess",
                "server": string_at(&xray, &["settings", "vnext", "0", "address"])?,
                "server_port": u16_at(&xray, &["settings", "vnext", "0", "port"])?,
                "uuid": string_at(user, &["id"])?,
                "security": vmess_security(string_at(user, &["security"] )?)?,
                "alter_id": user.get("alterId").and_then(Value::as_u64).unwrap_or(0),
                "packet_encoding": packet_encoding,
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
    let path =
        std::env::temp_dir().join(format!("proxyrift-singbox-{}-{nanos}", std::process::id()));

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

fn client_for_port(
    port: u16,
    request_timeout: Duration,
    fresh_connections: bool,
) -> Result<Client, String> {
    let mut builder = Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
                .map_err(|error| error.to_string())?,
        )
        .timeout(request_timeout)
        .user_agent("ProxyRift-SingBox/1.0");

    if fresh_connections {
        builder = builder.pool_max_idle_per_host(0);
    }

    builder.build().map_err(|error| error.to_string())
}

fn valid_probe_body(url: &str, body: &[u8]) -> bool {
    match url {
        PRIMARY_TARGET => body.is_empty(),
        "https://speed.cloudflare.com/__down?bytes=16384" => body.len() == 16_384,
        "https://example.com/" => !body.is_empty(),
        _ => true,
    }
}

async fn request_url(client: &Client, url: &str) -> Result<f64, String> {
    let started = std::time::Instant::now();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| error.to_string())?;

    if response.status().as_u16() == 429 {
        return Err("target returned HTTP 429".to_string());
    }

    if !response.status().is_success() {
        return Err(format!("target returned HTTP {}", response.status()));
    }

    if response
        .content_length()
        .is_some_and(|length| length as usize > MAX_RESPONSE_BYTES)
    {
        return Err("response body exceeds validation limit".to_string());
    }

    let status_is_empty_success = response.status().as_u16() == 204;
    let body = response.bytes().await.map_err(|error| error.to_string())?;
    if body.len() > MAX_RESPONSE_BYTES
        || (body.len() < MIN_RESPONSE_BYTES && !status_is_empty_success)
        || !valid_probe_body(url, &body)
    {
        return Err(
            "response body is empty, exceeds validation limit, or is not the expected probe payload"
                .to_string(),
        );
    }

    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

async fn check_batch_targets(
    binary: &str,
    entries: &[(String, Value)],
    targets: &[String],
    workers: usize,
    request_timeout: Duration,
    max_latency_ms: f64,
    stability_attempts: usize,
    min_successful_attempts: usize,
    min_successful_targets: usize,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    if entries.is_empty() || targets.is_empty() {
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

        let mut clients = Vec::with_capacity(batch_entries.len());
        for (index, _) in batch_entries.iter().enumerate() {
            match client_for_port(
                local_ports[index],
                request_timeout,
                stability_attempts >= STRICT_STABILITY_ATTEMPTS,
            ) {
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
        let mut active = (0..count).collect::<Vec<_>>();

        for attempt in 0..stability_attempts {
            if active.is_empty() {
                break;
            }

            let results = stream::iter(active.iter().copied())
                .map(|entry_index| {
                    let client = &clients[entry_index];
                    let target = targets[0].clone();
                    async move { (entry_index, request_url(client, &target).await) }
                })
                .buffer_unordered(workers.max(1))
                .collect::<Vec<_>>()
                .await;

            for (entry_index, result) in results {
                attempts[entry_index] += 1;
                match result {
                    Ok(latency) => {
                        successes[entry_index] += 1;
                        late_streak[entry_index] += 1;
                        latencies[entry_index].push(latency);
                    }
                    Err(_) => late_streak[entry_index] = 0,
                }
            }

            let remaining = stability_attempts.saturating_sub(attempt + 1);
            if remaining == 0 {
                active.clear();
            } else {
                active.retain(|&entry_index| {
                    successes[entry_index] + remaining >= min_successful_attempts
                        && (stability_attempts < STRICT_STABILITY_ATTEMPTS
                            || late_streak[entry_index] + remaining >= STRICT_LATE_SUCCESS_STREAK)
                });
            }

            if !active.is_empty()
                && stability_attempts >= STRICT_STABILITY_ATTEMPTS
                && attempt + 1 < stability_attempts
            {
                tokio::time::sleep(STRICT_INTER_ATTEMPT_DELAY).await;
            }
        }

        let mut secondary_success = vec![false; count];
        if min_successful_targets > 1 {
            for target in targets.iter().skip(1) {
                let eligible = (0..count)
                    .filter(|&entry_index| {
                        !secondary_success[entry_index]
                            && successes[entry_index] >= min_successful_attempts
                            && (stability_attempts < STRICT_STABILITY_ATTEMPTS
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
                        async move { (entry_index, request_url(client, &target).await) }
                    })
                    .buffer_unordered(workers.max(1))
                    .collect::<Vec<_>>()
                    .await;

                for (entry_index, result) in results {
                    if matches!(result, Ok(latency) if latency <= max_latency_ms) {
                        secondary_success[entry_index] = true;
                    }
                }
            }
        }

        for index in 0..count {
            let target_count =
                usize::from(successes[index] > 0) + usize::from(secondary_success[index]);

            if successes[index] >= min_successful_attempts
                && target_count >= min_successful_targets
                && (stability_attempts < STRICT_STABILITY_ATTEMPTS
                    || late_streak[index] >= STRICT_LATE_SUCCESS_STREAK)
                && latencies[index].iter().copied().fold(0.0, f64::max) <= max_latency_ms
            {
                let mut values = std::mem::take(&mut latencies[index]);
                values.sort_by(f64::total_cmp);
                let median = if values.len() % 2 == 1 {
                    values[values.len() / 2]
                } else {
                    let right = values.len() / 2;
                    (values[right - 1] + values[right]) / 2.0
                };

                verified.insert(
                    batch_entries[index].0.clone(),
                    ProxyMetrics {
                        successes: successes[index],
                        attempts: attempts[index],
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

async fn check_batch(
    binary: &str,
    entries: &[(String, Value)],
    workers: usize,
    request_timeout: Duration,
    max_latency_ms: f64,
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
            match client_for_port(local_ports[index], request_timeout, false) {
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

        for _ in 0..STABILITY_ATTEMPTS {
            let results = stream::iter(active.clone())
                .map(|(config, client)| async move {
                    let result = request_url(&client, PRIMARY_TARGET).await;
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
        }

        for (config, _) in &batch_entries {
            let wins = successes.get(config).copied().unwrap_or(0);
            let values = latencies.get(config).cloned().unwrap_or_default();

            if wins >= MIN_SUCCESSFUL_ATTEMPTS
                && !values.is_empty()
                && values.iter().copied().fold(0.0, f64::max) <= max_latency_ms
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

pub async fn validate_candidates_with_targets(
    binary: &str,
    candidates: &[String],
    targets: &[&str],
    workers: usize,
    request_timeout: Duration,
    max_latency_ms: f64,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    validate_candidates_with_targets_policy(
        binary,
        candidates,
        targets,
        workers,
        request_timeout,
        max_latency_ms,
        STABILITY_ATTEMPTS,
        MIN_SUCCESSFUL_ATTEMPTS,
        MIN_SUCCESSFUL_TARGETS,
    )
    .await
}

pub async fn validate_candidates_with_targets_strict(
    binary: &str,
    candidates: &[String],
    targets: &[&str],
    workers: usize,
    request_timeout: Duration,
    max_latency_ms: f64,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    validate_candidates_with_targets_policy(
        binary,
        candidates,
        targets,
        workers,
        request_timeout,
        max_latency_ms,
        STRICT_STABILITY_ATTEMPTS,
        STRICT_MIN_SUCCESSFUL_ATTEMPTS,
        STRICT_MIN_SUCCESSFUL_TARGETS,
    )
    .await
}

async fn validate_candidates_with_targets_policy(
    binary: &str,
    candidates: &[String],
    targets: &[&str],
    workers: usize,
    request_timeout: Duration,
    max_latency_ms: f64,
    stability_attempts: usize,
    min_successful_attempts: usize,
    min_successful_targets: usize,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    let mut parsed = Vec::new();
    let mut rejected = Vec::new();
    let mut seen = HashSet::new();

    if targets.len() < min_successful_targets {
        return Err(format!(
            "Light validation requires at least {min_successful_targets} targets"
        ));
    }

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
        println!("sing-box rejected: {} :: {reason}", config_label(config));
    }

    if parsed.is_empty() {
        return Ok(HashMap::new());
    }

    let target_values = targets
        .iter()
        .map(|target| target.to_string())
        .collect::<Vec<_>>();
    let batch_size = BATCH_SIZE.min(parsed.len()).max(1);
    let total_batches = parsed.len().div_ceil(batch_size);
    let mut metadata = HashMap::new();

    for (index, batch) in parsed.chunks(batch_size).enumerate() {
        println!(
            "targets {:?}: batch {}/{} testing {} configs with sing-box; requiring {}/{} successful attempts across at least {} destinations",
            target_values,
            index + 1,
            total_batches,
            batch.len(),
            min_successful_attempts,
            stability_attempts,
            min_successful_targets
        );

        metadata.extend(
            check_batch_targets(
                binary,
                batch,
                &target_values,
                workers.max(1),
                request_timeout,
                max_latency_ms,
                stability_attempts,
                min_successful_attempts,
                min_successful_targets,
            )
            .await?,
        );
    }

    println!(
        "{}/{} verified by sing-box against {} targets with {}/{} successful GET attempts and at least {} distinct successful destinations",
        metadata.len(),
        candidates.len(),
        targets.len(),
        min_successful_attempts,
        stability_attempts,
        min_successful_targets
    );

    Ok(metadata)
}

pub async fn validate_candidates_with_settings(
    binary: &str,
    candidates: &[String],
    workers: usize,
    request_timeout: Duration,
    max_latency_ms: f64,
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
        println!("sing-box rejected: {} :: {reason}", config_label(config));
    }

    if parsed.is_empty() {
        return Ok(HashMap::new());
    }

    let batch_size = BATCH_SIZE.min(parsed.len()).max(1);
    let total_batches = parsed.len().div_ceil(batch_size);
    let mut metadata = HashMap::new();

    for (index, batch) in parsed.chunks(batch_size).enumerate() {
        println!(
            "target {PRIMARY_TARGET}: batch {}/{} testing {} configs with sing-box; requiring {MIN_SUCCESSFUL_ATTEMPTS}/{} attempts",
            index + 1,
            total_batches,
            batch.len(),
            STABILITY_ATTEMPTS
        );
        metadata.extend(
            check_batch(
                binary,
                batch,
                workers.max(1),
                request_timeout,
                max_latency_ms,
            )
            .await?,
        );
    }

    println!(
        "{}/{} verified by sing-box against {PRIMARY_TARGET} with {MIN_SUCCESSFUL_ATTEMPTS}/{} successful GET attempts and every measured latency <= {}ms",
        metadata.len(),
        candidates.len(),
        STABILITY_ATTEMPTS,
        max_latency_ms
    );

    Ok(metadata)
}

pub async fn validate_candidates(
    binary: &str,
    candidates: &[String],
    workers: usize,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    validate_candidates_with_settings(
        binary,
        candidates,
        workers,
        DEFAULT_REQUEST_TIMEOUT,
        DEFAULT_MAX_LATENCY_MS,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_probe_targets_require_expected_payloads() {
        assert!(valid_probe_body("https://www.google.com/generate_204", b""));
        assert!(!valid_probe_body(
            "https://www.google.com/generate_204",
            b"blocked by upstream"
        ));
        assert!(valid_probe_body(
            "https://speed.cloudflare.com/__down?bytes=16384",
            &vec![0_u8; 16_384]
        ));
        assert!(!valid_probe_body(
            "https://speed.cloudflare.com/__down?bytes=16384",
            &vec![0_u8; 16_383]
        ));
        assert!(valid_probe_body("https://example.com/", b"<html>"));
        assert!(!valid_probe_body("https://example.com/", b""));
    }

    #[test]
    fn maps_vmess_empty_security_to_auto() {
        let payload = json!({
            "v": "2",
            "add": "example.com",
            "port": 443,
            "id": "00000000-0000-0000-0000-000000000001",
            "aid": 0,
            "net": "h2",
            "scy": "",
            "tls": "tls",
            "path": "/grpc",
            "host": "example.com",
        });
        let encoded = STANDARD.encode(serde_json::to_vec(&payload).expect("encode VMess JSON"));
        let config = format!("vmess://{encoded}");
        let outbound = singbox_outbound(&config).expect("VMess empty security should map");
        assert_eq!(outbound["security"], "auto");
        assert_eq!(outbound["transport"]["type"], "http");
    }

    #[test]
    fn maps_vless_packet_encoding() {
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=none&type=tcp&packetEncoding=packetaddr";
        let outbound = singbox_outbound(config).expect("VLESS packet encoding should map");
        assert_eq!(outbound["packet_encoding"], "packetaddr");
    }

    #[test]
    fn maps_vless_packet_encoding_none() {
        let config = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=none&type=tcp&packetEncoding=none";
        let outbound = singbox_outbound(config).expect("VLESS packet encoding none should map");
        assert_eq!(outbound["packet_encoding"], "");
    }

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
    fn maps_hysteria2_obfs_natively() {
        let config = "hy2://password@example.com:8443?sni=edge.example.com&insecure=1&obfs=salamander&obfs-password=secret";
        let outbound = singbox_outbound(config).expect("Hysteria2 obfs should map");
        assert_eq!(outbound["obfs"]["type"], "salamander");
        assert_eq!(outbound["obfs"]["password"], "secret");
        assert_eq!(outbound["tls"]["insecure"], true);
        assert_eq!(outbound["tls"]["server_name"], "edge.example.com");
    }

    #[test]
    fn maps_hysteria2_multi_port_natively() {
        let config = "hy2://password@example.com:1234,5000-6000";
        let outbound = singbox_outbound(config).expect("Hysteria2 multi-port should map");
        assert_eq!(outbound["server_ports"], json!(["1234", "5000-6000"]));
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
