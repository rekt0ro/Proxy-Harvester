use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use proxyrift::singbox::{
    validate_candidates_with_targets as validate_singbox_targets,
    validate_candidates_with_targets_strict as validate_singbox_targets_strict,
};
use proxyrift::validator::{
    endpoint, read_lines, validate_candidates_with_targets,
    validate_candidates_with_targets_strict, write_lines, ProxyMetrics, LIGHT_TARGETS,
    PRIMARY_TARGET,
};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use url::Url;

const DISCOVERY_CHUNK_SIZE: usize = 1000;
const MAX_DISCOVERY_CANDIDATES: usize = 10000;
const FINAL_RECHECK_LIMIT: usize = 500;
const DEFAULT_SELECTION_LIMIT: usize = 200;
const DEFAULT_MAX_PER_ENDPOINT: usize = 1;
const DEFAULT_MAX_PER_FAMILY: usize = 3;
const RECHECK_FAMILY_DIVERSITY: usize = 1;
const MAX_FINAL_RECHECK_ATTEMPTS: usize = 2;

fn value(args: &[String], name: &str, default: &str) -> String {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| default.to_string())
}

fn required(args: &[String], name: &str) -> Result<String, String> {
    let result = value(args, name, "");
    if result.is_empty() {
        Err(format!("missing required argument {name}"))
    } else {
        Ok(result)
    }
}

fn sort_ranked(
    configs: &mut [String],
    metadata: &HashMap<String, ProxyMetrics>,
    positions: &HashMap<String, usize>,
) {
    configs.sort_unstable_by(|a, b| {
        let ma = metadata.get(a);
        let mb = metadata.get(b);

        let a_successes = ma.map(|m| m.successes).unwrap_or(0);
        let b_successes = mb.map(|m| m.successes).unwrap_or(0);
        let a_median = ma.map(|m| m.median_ms).unwrap_or(f64::INFINITY);
        let b_median = mb.map(|m| m.median_ms).unwrap_or(f64::INFINITY);
        let a_min = ma.map(|m| m.min_ms).unwrap_or(f64::INFINITY);
        let b_min = mb.map(|m| m.min_ms).unwrap_or(f64::INFINITY);

        b_successes
            .cmp(&a_successes)
            .then_with(|| a_median.total_cmp(&b_median))
            .then_with(|| a_min.total_cmp(&b_min))
            .then_with(|| {
                positions
                    .get(a)
                    .copied()
                    .unwrap_or(usize::MAX)
                    .cmp(&positions.get(b).copied().unwrap_or(usize::MAX))
            })
            .then_with(|| a.cmp(b))
    });
}

fn family_key(config: &str) -> String {
    let cleaned = config.split('#').next().unwrap_or(config);
    let Ok(url) = Url::parse(cleaned) else {
        return cleaned.to_string();
    };
    let scheme = url.scheme().to_ascii_lowercase();

    if scheme == "vmess" {
        if let Some(payload) = cleaned.split_once("://").map(|(_, value)| value) {
            let mut padded = payload.to_string();
            while !padded.len().is_multiple_of(4) {
                padded.push('=');
            }
            for encoded in [payload, padded.as_str()] {
                for bytes in [
                    STANDARD.decode(encoded),
                    URL_SAFE.decode(encoded),
                    URL_SAFE_NO_PAD.decode(encoded),
                ]
                .into_iter()
                .flatten()
                {
                    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                        let fields = [
                            "id", "aid", "scy", "net", "tls", "sni", "host", "path", "type",
                        ];
                        let mut key = String::from("vmess|");
                        for field in fields {
                            if let Some(value) = value.get(field) {
                                key.push_str(field);
                                key.push('=');
                                key.push_str(&value.to_string());
                                key.push('|');
                            }
                        }
                        return key;
                    }
                }
            }
        }
    }

    let mut pairs = url
        .query_pairs()
        .map(|(key, value)| (key.to_ascii_lowercase(), value.into_owned()))
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "ps" | "name" | "remark" | "remarks" | "test_name" | "telegram"
            )
        })
        .collect::<Vec<_>>();
    pairs.sort_unstable();

    let mut key = format!(
        "{}|{}|{}",
        scheme,
        url.username(),
        url.password().unwrap_or("")
    );
    for (name, value) in pairs {
        key.push('|');
        key.push_str(&name);
        key.push('=');
        key.push_str(&value);
    }
    key
}

fn diversify_recheck_candidates(
    configs: &[String],
    limit: usize,
    max_family: usize,
) -> Vec<String> {
    let mut selected = Vec::new();
    let mut deferred = Vec::new();
    let mut seen_endpoints = HashSet::new();
    let mut family_counts = HashMap::<String, usize>::new();

    for config in configs {
        let family = family_key(config);
        let family_available = family_counts.get(&family).copied().unwrap_or(0) < max_family;
        let endpoint_available = endpoint(config)
            .map(|ep| !seen_endpoints.contains(&ep))
            .unwrap_or(true);

        if family_available && endpoint_available {
            *family_counts.entry(family).or_default() += 1;
            if let Some(ep) = endpoint(config) {
                seen_endpoints.insert(ep);
            }
            selected.push(config.clone());
        } else {
            deferred.push(config.clone());
        }

        if selected.len() >= limit {
            return selected;
        }
    }

    if selected.len() < limit {
        selected.extend(deferred.into_iter().take(limit - selected.len()));
    }

    selected
}

fn normalize_light_config(config: &str) -> String {
    if !config
        .split_once("://")
        .map(|(scheme, _)| scheme.eq_ignore_ascii_case("trojan"))
        .unwrap_or(false)
    {
        return config.to_string();
    }

    let fragment_index = config.find('#').unwrap_or(config.len());
    let base = &config[..fragment_index];
    let fragment = &config[fragment_index..];

    let Ok(url) = Url::parse(base) else {
        return config.to_string();
    };

    if url
        .query_pairs()
        .any(|(key, value)| key.eq_ignore_ascii_case("security") && !value.trim().is_empty())
    {
        return config.to_string();
    }

    let query_parts = url
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|part| !part.is_empty())
        .filter(|part| {
            let mut pairs = url::form_urlencoded::parse(part.as_bytes());
            !matches!(
                pairs.next(),
                Some((key, value))
                    if key.eq_ignore_ascii_case("security") && value.trim().is_empty()
            )
        })
        .collect::<Vec<_>>();

    let path = base.split_once('?').map(|(path, _)| path).unwrap_or(base);
    if query_parts.is_empty() {
        format!("{path}?security=tls{fragment}")
    } else {
        format!("{path}?{}&security=tls{fragment}", query_parts.join("&"))
    }
}

fn write_light_lines(output: &str, values: &[String]) -> Result<(), String> {
    let normalized = values
        .iter()
        .map(|config| normalize_light_config(config))
        .collect::<Vec<_>>();
    write_lines(output, &normalized)
}

fn select_verified_configs(
    configs: &[String],
    limit: usize,
    max_per_endpoint: usize,
    max_per_family: usize,
) -> Vec<String> {
    let mut endpoint_counts = HashMap::<(String, u16), usize>::new();
    let mut family_counts = HashMap::<String, usize>::new();
    let mut result = Vec::with_capacity(limit.min(configs.len()));

    for config in configs {
        if result.len() >= limit {
            break;
        }

        if let Some(endpoint) = endpoint(config) {
            if endpoint_counts.get(&endpoint).copied().unwrap_or(0) >= max_per_endpoint {
                continue;
            }

            let family = family_key(config);
            if family_counts.get(&family).copied().unwrap_or(0) >= max_per_family {
                continue;
            }

            *endpoint_counts.entry(endpoint).or_insert(0) += 1;
            *family_counts.entry(family).or_insert(0) += 1;
            result.push(config.clone());
        } else {
            let family = family_key(config);
            if family_counts.get(&family).copied().unwrap_or(0) >= max_per_family {
                continue;
            }

            *family_counts.entry(family).or_insert(0) += 1;
            result.push(config.clone());
        }
    }

    result
}

#[derive(Clone, Copy, Debug)]
struct ValidationSettings {
    workers: usize,
    batch_size: usize,
    timeout_seconds: f64,
    strict: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LightBackend {
    SingBox,
    Xray,
    Dual,
}

fn query_value(url: &Url, names: &[&str]) -> String {
    url.query_pairs()
        .find(|(key, value)| {
            names.iter().any(|name| key.eq_ignore_ascii_case(name)) && !value.is_empty()
        })
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

fn has_query_key(url: &Url, names: &[&str]) -> bool {
    url.query_pairs()
        .any(|(key, _)| names.iter().any(|name| key.eq_ignore_ascii_case(name)))
}

fn light_backend(config: &str) -> LightBackend {
    let Ok(url) = Url::parse(config.split('#').next().unwrap_or(config)) else {
        return LightBackend::SingBox;
    };

    let transport = query_value(&url, &["type", "network"]).to_ascii_lowercase();
    let security = query_value(&url, &["security"]).to_ascii_lowercase();

    let scheme = url.scheme().to_ascii_lowercase();
    if matches!(scheme.as_str(), "socks4" | "socks4a") {
        return LightBackend::SingBox;
    }

    if matches!(scheme.as_str(), "http" | "socks" | "socks5" | "socks5h") {
        return LightBackend::Xray;
    }

    // XHTTP is an Xray-only path in our Light validator, regardless of the
    // share-link protocol. Sending Trojan/VMess XHTTP to sing-box only creates
    // deterministic parser rejection.
    let raw_http_over_tls = (transport.is_empty() || transport == "tcp" || transport == "raw")
        && query_value(&url, &["headerType"]).eq_ignore_ascii_case("http")
        && ((!security.is_empty() && security != "none")
            || !query_value(&url, &["sni"]).is_empty()
            || !query_value(&url, &["peer"]).is_empty());

    if transport == "xhttp" || raw_http_over_tls {
        return LightBackend::Xray;
    }

    if transport == "grpc"
        && (has_query_key(&url, &["authority"])
            || query_value(&url, &["mode"]).eq_ignore_ascii_case("multi"))
    {
        return LightBackend::Xray;
    }

    if url.scheme().eq_ignore_ascii_case("vless") {
        let flow = query_value(&url, &["flow"]).to_ascii_lowercase();
        if !flow.is_empty() && flow != "xtls-rprx-vision" {
            return LightBackend::Xray;
        }

        if has_query_key(&url, &["fm", "finalmask"])
            || {
                let encryption = query_value(&url, &["encryption"]);
                !encryption.is_empty() && !encryption.eq_ignore_ascii_case("none")
            }
            || !query_value(&url, &["extra"]).is_empty()
        {
            return LightBackend::Xray;
        }
    }

    // Reality is checked by both cores for transport classes that both
    // consumer cores can represent.
    if security == "reality" {
        return LightBackend::Dual;
    }

    LightBackend::SingBox
}

async fn merge_dual(
    xray: &str,
    singbox: &str,
    candidates: &[String],
    targets: &[&str],
    settings: ValidationSettings,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    if candidates.is_empty() {
        return Ok(HashMap::new());
    }

    let request_timeout = std::time::Duration::from_secs_f64(settings.timeout_seconds);
    let xray_future = async {
        if settings.strict {
            validate_candidates_with_targets_strict(
                xray,
                candidates,
                targets,
                settings.workers,
                settings.batch_size,
                settings.timeout_seconds,
            )
            .await
        } else {
            validate_candidates_with_targets(
                xray,
                candidates,
                targets,
                settings.workers,
                settings.batch_size,
                settings.timeout_seconds,
            )
            .await
        }
    };
    let singbox_future = async {
        if settings.strict {
            validate_singbox_targets_strict(
                singbox,
                candidates,
                targets,
                settings.workers.clamp(1, 32),
                request_timeout,
                settings.timeout_seconds * 1000.0,
            )
            .await
        } else {
            validate_singbox_targets(
                singbox,
                candidates,
                targets,
                settings.workers.clamp(1, 32),
                request_timeout,
                settings.timeout_seconds * 1000.0,
            )
            .await
        }
    };

    let (xray_result, singbox_result) = tokio::join!(xray_future, singbox_future);
    let xray_metadata = xray_result?;
    let xray_verified = xray_metadata.len();
    let singbox_metadata = singbox_result?;

    let mut verified = HashMap::new();
    for (config, mut metrics) in xray_metadata {
        if let Some(singbox) = singbox_metadata.get(&config) {
            metrics.successes = metrics.successes.min(singbox.successes);
            metrics.attempts = metrics.attempts.min(singbox.attempts);
            metrics.median_ms = metrics.median_ms.max(singbox.median_ms);
            metrics.min_ms = metrics.min_ms.max(singbox.min_ms);
            verified.insert(config, metrics);
        }
    }

    println!(
        "[INFO] Dual-core Light: Xray verified {}, sing-box verified {}, intersection {}.",
        xray_verified,
        singbox_metadata.len(),
        verified.len()
    );

    Ok(verified)
}

async fn validate_light_batch(
    xray: &str,
    singbox: &str,
    candidates: &[String],
    targets: &[&str],
    settings: ValidationSettings,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    let mut singbox_candidates = Vec::new();
    let mut xray_candidates = Vec::new();
    let mut dual_candidates = Vec::new();

    for config in candidates {
        match light_backend(config) {
            LightBackend::SingBox => singbox_candidates.push(config.clone()),
            LightBackend::Xray => xray_candidates.push(config.clone()),
            LightBackend::Dual => dual_candidates.push(config.clone()),
        }
    }

    println!(
        "[INFO] Light backend routing: sing-box {}, Xray {}, dual {}.",
        singbox_candidates.len(),
        xray_candidates.len(),
        dual_candidates.len()
    );

    let request_timeout = std::time::Duration::from_secs_f64(settings.timeout_seconds);

    let singbox_future = async {
        if singbox_candidates.is_empty() {
            Ok(HashMap::new())
        } else if settings.strict {
            validate_singbox_targets_strict(
                singbox,
                &singbox_candidates,
                targets,
                settings.workers.clamp(1, 32),
                request_timeout,
                settings.timeout_seconds * 1000.0,
            )
            .await
        } else {
            validate_singbox_targets(
                singbox,
                &singbox_candidates,
                targets,
                settings.workers.clamp(1, 32),
                request_timeout,
                settings.timeout_seconds * 1000.0,
            )
            .await
        }
    };

    let xray_future = async {
        if xray_candidates.is_empty() {
            Ok(HashMap::new())
        } else if settings.strict {
            validate_candidates_with_targets_strict(
                xray,
                &xray_candidates,
                targets,
                settings.workers.max(1),
                settings.batch_size,
                settings.timeout_seconds,
            )
            .await
        } else {
            validate_candidates_with_targets(
                xray,
                &xray_candidates,
                targets,
                settings.workers.max(1),
                settings.batch_size,
                settings.timeout_seconds,
            )
            .await
        }
    };

    let (singbox_result, xray_result) = tokio::join!(singbox_future, xray_future);
    let singbox_metadata = singbox_result?;
    let xray_metadata = xray_result?;

    let mut verified = HashMap::with_capacity(singbox_metadata.len() + xray_metadata.len());
    verified.extend(singbox_metadata);
    verified.extend(xray_metadata);

    if !dual_candidates.is_empty() {
        verified.extend(merge_dual(xray, singbox, &dual_candidates, targets, settings).await?);
    }

    println!(
        "[INFO] Multi-target Light validation: {}/{} candidates verified.",
        verified.len(),
        candidates.len()
    );

    Ok(verified)
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: polish_light --candidates FILE --output FILE [--workers N]              [--batch-size N] [--timeout SECONDS] [--selected-recheck-limit N]              [--max-candidates N] [--selected-workers N] [--selected-batch-size N]              [--primary-target URL] [--selection-limit N] [--max-per-endpoint N]              [--max-per-family N] [--xray PATH] [--singbox PATH]"
        );
        return Ok(());
    }

    let candidates_path = required(&args, "--candidates")?;
    let output = required(&args, "--output")?;
    let workers = value(&args, "--workers", "32")
        .parse::<usize>()
        .map_err(|_| "invalid --workers".to_string())?;
    let batch_size = value(&args, "--batch-size", "1000")
        .parse::<usize>()
        .map_err(|_| "invalid --batch-size".to_string())?;
    let timeout = value(&args, "--timeout", "5")
        .parse::<f64>()
        .map_err(|_| "invalid --timeout".to_string())?;
    if !timeout.is_finite() || timeout <= 0.0 {
        return Err("invalid --timeout: must be a positive finite number".to_string());
    }
    let final_recheck_limit = value(
        &args,
        "--selected-recheck-limit",
        FINAL_RECHECK_LIMIT.to_string().as_str(),
    )
    .parse::<usize>()
    .map_err(|_| "invalid --selected-recheck-limit".to_string())?;
    let max_candidates = value(
        &args,
        "--max-candidates",
        MAX_DISCOVERY_CANDIDATES.to_string().as_str(),
    )
    .parse::<usize>()
    .map_err(|_| "invalid --max-candidates".to_string())?
    .clamp(1, MAX_DISCOVERY_CANDIDATES);
    let final_workers = value(&args, "--selected-workers", "16")
        .parse::<usize>()
        .map_err(|_| "invalid --selected-workers".to_string())?;
    let final_batch_size = value(&args, "--selected-batch-size", "500")
        .parse::<usize>()
        .map_err(|_| "invalid --selected-batch-size".to_string())?;
    let primary_target = value(&args, "--primary-target", PRIMARY_TARGET);
    let targets = [primary_target.as_str(), LIGHT_TARGETS[1], LIGHT_TARGETS[2]];
    let xray = value(&args, "--xray", "xray");
    let selection_limit = value(
        &args,
        "--selection-limit",
        DEFAULT_SELECTION_LIMIT.to_string().as_str(),
    )
    .parse::<usize>()
    .map_err(|_| "invalid --selection-limit".to_string())?
    .max(1);
    let max_per_endpoint = value(
        &args,
        "--max-per-endpoint",
        DEFAULT_MAX_PER_ENDPOINT.to_string().as_str(),
    )
    .parse::<usize>()
    .map_err(|_| "invalid --max-per-endpoint".to_string())?
    .max(1);
    let max_per_family = value(
        &args,
        "--max-per-family",
        DEFAULT_MAX_PER_FAMILY.to_string().as_str(),
    )
    .parse::<usize>()
    .map_err(|_| "invalid --max-per-family".to_string())?
    .max(1);
    let singbox = value(&args, "--singbox", "sing-box");

    let candidates = read_lines(&candidates_path)?;
    let candidates = candidates
        .into_iter()
        .take(max_candidates)
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return Err("no Light candidates available".to_string());
    }

    let mut global_verified = Vec::<String>::new();
    let mut global_positions = HashMap::<String, usize>::new();
    let mut global_metadata = HashMap::<String, ProxyMetrics>::new();
    let mut final_verified = Vec::<String>::new();
    let mut final_attempts = HashMap::<String, usize>::new();
    let mut final_metadata = HashMap::<String, ProxyMetrics>::new();

    let chunk_count = candidates.len().div_ceil(DISCOVERY_CHUNK_SIZE);

    for (chunk_index, chunk) in candidates.chunks(DISCOVERY_CHUNK_SIZE).enumerate() {
        let wave = chunk_index + 1;

        println!(
            "[INFO] Global Light discovery {wave}/{chunk_count}: testing {} candidates; {} verified so far.",
            chunk.len(),
            global_verified.len()
        );

        let chunk_metadata = validate_light_batch(
            &xray,
            &singbox,
            chunk,
            &targets,
            ValidationSettings {
                workers,
                batch_size,
                timeout_seconds: timeout,
                strict: false,
            },
        )
        .await?;

        for config in chunk_metadata.keys() {
            if !global_positions.contains_key(config) {
                let position = global_verified.len();
                global_verified.push(config.clone());
                global_positions.insert(config.clone(), position);
            }
        }
        global_metadata.extend(chunk_metadata);

        sort_ranked(&mut global_verified, &global_metadata, &global_positions);
        sort_ranked(&mut final_verified, &final_metadata, &global_positions);

        let remaining = selection_limit.saturating_sub(
            select_verified_configs(
                &final_verified,
                selection_limit,
                max_per_endpoint,
                max_per_family,
            )
            .len(),
        );

        if remaining == 0 {
            let selected = select_verified_configs(
                &final_verified,
                selection_limit,
                max_per_endpoint,
                max_per_family,
            );
            write_light_lines(&output, &selected)?;
            println!(
                "[INFO] Light quality-first selection: {} configs ready; discovery pool {} verified.",
                selected.len(),
                global_verified.len()
            );
            return Ok(());
        }

        let dynamic_limit = final_recheck_limit.min(
            remaining
                .saturating_mul(2)
                .saturating_add(20)
                .max(remaining),
        );

        let untested = global_verified
            .iter()
            .filter(|config| {
                !final_metadata.contains_key(*config)
                    && final_attempts.get(*config).copied().unwrap_or(0)
                        < MAX_FINAL_RECHECK_ATTEMPTS
            })
            .cloned()
            .collect::<Vec<_>>();

        let final_candidates =
            diversify_recheck_candidates(&untested, dynamic_limit, RECHECK_FAMILY_DIVERSITY);

        if final_candidates.is_empty() {
            continue;
        }

        for config in &final_candidates {
            *final_attempts.entry(config.clone()).or_default() += 1;
        }

        println!(
            "[INFO] Final Light recheck wave {wave}: {} candidates ({} slots remaining).",
            final_candidates.len(),
            remaining
        );

        let primary_metadata = validate_light_batch(
            &xray,
            &singbox,
            &final_candidates,
            &targets,
            ValidationSettings {
                workers: final_workers,
                batch_size: final_batch_size,
                timeout_seconds: timeout,
                strict: true,
            },
        )
        .await?;

        for (config, metrics) in primary_metadata {
            if !final_metadata.contains_key(&config) {
                final_verified.push(config.clone());
            }
            final_metadata.insert(config, metrics);
        }

        sort_ranked(&mut final_verified, &final_metadata, &global_positions);
        let selected = select_verified_configs(
            &final_verified,
            selection_limit,
            max_per_endpoint,
            max_per_family,
        );

        println!(
            "[INFO] Light fill progress: {}/{} configs ready.",
            selected.len(),
            selection_limit
        );

        if selected.len() >= selection_limit {
            let mut protocol_counts = BTreeMap::<String, usize>::new();
            for config in &selected {
                let scheme = config
                    .split_once("://")
                    .map(|(scheme, _)| scheme.to_ascii_lowercase())
                    .unwrap_or_else(|| "unknown".to_string());
                *protocol_counts.entry(scheme).or_default() += 1;
            }
            println!("[INFO] Light protocol distribution: {:?}", protocol_counts);
            println!(
                "[INFO] Light quality-first selection: {} configs ready; no protocol quota.",
                selected.len()
            );
            write_light_lines(&output, &selected)?;
            println!(
                "[INFO] Published {} Light configs from {} globally verified candidates.",
                selected.len(),
                global_verified.len()
            );
            return Ok(());
        }
    }

    sort_ranked(&mut final_verified, &final_metadata, &global_positions);
    let selected = select_verified_configs(
        &final_verified,
        selection_limit,
        max_per_endpoint,
        max_per_family,
    );

    if selected.is_empty() {
        return Err("selected Light validation produced zero verified configs".to_string());
    }

    let mut protocol_counts = BTreeMap::<String, usize>::new();
    let mut backend_counts = BTreeMap::<&str, usize>::new();
    for config in &selected {
        let scheme = config
            .split_once("://")
            .map(|(scheme, _)| scheme.to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".to_string());
        *protocol_counts.entry(scheme).or_default() += 1;
        match light_backend(config) {
            LightBackend::SingBox => *backend_counts.entry("sing-box").or_default() += 1,
            LightBackend::Xray => *backend_counts.entry("xray").or_default() += 1,
            LightBackend::Dual => *backend_counts.entry("dual").or_default() += 1,
        }
    }
    println!("[INFO] Light protocol distribution: {:?}", protocol_counts);
    println!("[INFO] Light backend distribution: {:?}", backend_counts);
    println!(
        "[INFO] Light quality-first selection: {} configs ready; no protocol quota.",
        selected.len()
    );

    write_lines(&output, &selected)?;
    println!(
        "[INFO] Published {} Light configs after exhausting {} discovery candidates.",
        selected.len(),
        candidates.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{light_backend, normalize_light_config, select_verified_configs, LightBackend};

    #[test]
    fn routes_basic_proxy_schemes_to_xray() {
        for config in [
            "http://proxy.example:8080",
            "socks://proxy.example:1080",
            "socks5://proxy.example:1080",
            "socks5h://proxy.example:1080",
        ] {
            assert_eq!(light_backend(config), LightBackend::Xray);
        }
    }

    #[test]
    fn routes_reality_to_both_cores() {
        let config =
            "vless://uuid@example.com:443?security=reality&type=tcp&pbk=public&sid=01&sni=example.com";
        assert_eq!(light_backend(config), LightBackend::Dual);
    }

    #[test]
    fn routes_grpc_authority_to_xray() {
        let config =
            "vless://uuid@example.com:443?security=tls&type=grpc&serviceName=Tun&authority=grpc.example.com";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_grpc_multi_to_xray() {
        let config =
            "trojan://pass@example.com:443?security=tls&type=grpc&serviceName=Tun&mode=multi";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_xhttp_to_xray_only() {
        let config = "vless://uuid@example.com:443?security=none&type=xhttp";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_non_vless_xhttp_to_xray() {
        let config = "trojan://pass@example.com:443?security=tls&type=xhttp";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_reality_xhttp_to_xray_only() {
        let config =
            "vless://uuid@example.com:443?security=reality&type=xhttp&pbk=public&sni=example.com";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_reality_vision_udp443_to_xray() {
        let config =
            "vless://uuid@example.com:443?security=reality&type=tcp&flow=xtls-rprx-vision-udp443";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_vision_udp443_to_xray() {
        let config =
            "vless://uuid@example.com:443?security=tls&type=tcp&flow=xtls-rprx-vision-udp443";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_normal_vless_to_singbox() {
        let config = "vless://uuid@example.com:443?security=tls&type=ws&path=%2F&sni=example.com";
        assert_eq!(light_backend(config), LightBackend::SingBox);
    }

    #[test]
    fn routes_socks4_to_singbox() {
        assert_eq!(
            light_backend("socks4://127.0.0.1:1080"),
            LightBackend::SingBox
        );
        assert_eq!(
            light_backend("socks4a://127.0.0.1:1080"),
            LightBackend::SingBox
        );
    }

    #[test]
    fn defaults_trojan_security_in_published_light_links() {
        assert_eq!(
            normalize_light_config("trojan://pass@example.com:443?sni=example.com#Trojan"),
            "trojan://pass@example.com:443?sni=example.com&security=tls#Trojan"
        );
        assert_eq!(
            normalize_light_config("trojan://pass@example.com:443?#Trojan"),
            "trojan://pass@example.com:443?security=tls#Trojan"
        );
        assert_eq!(
            normalize_light_config("trojan://pass@example.com:443?security=tls"),
            "trojan://pass@example.com:443?security=tls"
        );
        assert_eq!(
            normalize_light_config("trojan://pass@example.com:443?security="),
            "trojan://pass@example.com:443?security=tls"
        );
        assert_eq!(
            normalize_light_config("trojan://pass@example.com:443?path=%2Fa%3Fb&security="),
            "trojan://pass@example.com:443?path=%2Fa%3Fb&security=tls"
        );
    }

    #[test]
    fn quality_first_preserves_rank_and_endpoint_limit() {
        let configs = vec![
            "vless://a@example.com:443".to_string(),
            "vless://b@example.com:443".to_string(),
            "trojan://c@example.net:8443".to_string(),
            "vmess://encoded@example.org:9443".to_string(),
        ];

        let selected = select_verified_configs(&configs, 4, 1, 3);

        assert_eq!(
            selected,
            vec![configs[0].clone(), configs[2].clone(), configs[3].clone()]
        );
    }
}
