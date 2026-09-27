use proxy_harvester::singbox::validate_candidates_with_settings as validate_singbox_candidates;
use proxy_harvester::validator::{
    endpoint, read_lines, validate_candidates, write_lines, ProxyMetrics, PRIMARY_TARGET,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use url::Url;

const DISCOVERY_CHUNK_SIZE: usize = 1000;
const MAX_DISCOVERY_CANDIDATES: usize = 6000;
const FINAL_RECHECK_LIMIT: usize = 500;
const DEFAULT_SELECTION_LIMIT: usize = 200;
const DEFAULT_MAX_PER_ENDPOINT: usize = 1;

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

fn ranked(
    configs: impl IntoIterator<Item = String>,
    metadata: &HashMap<String, ProxyMetrics>,
    positions: &HashMap<String, usize>,
) -> Vec<String> {
    let mut values: Vec<_> = configs.into_iter().collect();
    values.sort_unstable_by(|a, b| {
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
    values
}

fn diversify_recheck_candidates(configs: &[String], limit: usize) -> Vec<String> {
    let mut selected = Vec::new();
    let mut deferred = Vec::new();
    let mut seen_endpoints = HashSet::new();

    for config in configs {
        if let Some(ep) = endpoint(config) {
            if seen_endpoints.insert(ep) {
                selected.push(config.clone());
            } else {
                deferred.push(config.clone());
            }
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

fn protocol(config: &str) -> String {
    config
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

fn identity_key(config: &str) -> Option<(String, String)> {
    let (scheme, rest) = config.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let (user, _) = authority.rsplit_once('@')?;

    match scheme.to_ascii_lowercase().as_str() {
        "vless" | "trojan" | "hy2" | "hysteria2" | "ss" => {
            Some((scheme.to_ascii_lowercase(), user.to_string()))
        }
        _ => None,
    }
}

/// Selects from the already-ranked verified pool in protocol round-robin order.
/// Ranking is preserved within each protocol, so the best candidate for a
/// protocol is always selected before its lower-ranked peers. Protocols with
/// fewer candidates naturally exhaust early and their turns are redistributed.
fn protocol_round_robin(configs: &[String], limit: usize, max_per_endpoint: usize) -> Vec<String> {
    let mut groups = BTreeMap::<String, Vec<String>>::new();

    for config in configs {
        groups
            .entry(protocol(config))
            .or_default()
            .push(config.clone());
    }

    let protocols = groups.keys().cloned().collect::<Vec<_>>();
    let mut cursors = HashMap::<String, usize>::new();
    let mut endpoint_counts = HashMap::<(String, u16), usize>::new();
    let mut identity_counts = HashMap::<(String, String), usize>::new();
    let mut result = Vec::with_capacity(limit.min(configs.len()));

    while result.len() < limit {
        let mut made_progress = false;

        for scheme in &protocols {
            let group = groups.get(scheme).expect("protocol group exists");
            let cursor = cursors.entry(scheme.clone()).or_insert(0);

            let mut preferred = None;
            let mut fallback = None;

            for index in *cursor..group.len() {
                let config = &group[index];

                if let Some(ep) = endpoint(config) {
                    let count = endpoint_counts.get(&ep).copied().unwrap_or(0);
                    if count >= max_per_endpoint {
                        continue;
                    }
                }

                let identity_count = identity_key(config)
                    .and_then(|identity| identity_counts.get(&identity).copied())
                    .unwrap_or(0);

                if identity_count == 0 {
                    preferred = Some(index);
                    break;
                }

                if fallback.is_none() {
                    fallback = Some(index);
                }
            }

            let Some(index) = preferred.or(fallback) else {
                continue;
            };

            let config = &group[index];
            *cursor = index + 1;

            if let Some(ep) = endpoint(config) {
                *endpoint_counts.entry(ep).or_insert(0) += 1;
            }
            if let Some(identity) = identity_key(config) {
                *identity_counts.entry(identity).or_insert(0) += 1;
            }

            result.push(config.clone());
            made_progress = true;

            if result.len() >= limit {
                break;
            }
        }

        if !made_progress {
            break;
        }
    }

    result
}

fn quality_first_selection(
    configs: &[String],
    limit: usize,
    max_per_endpoint: usize,
) -> Vec<String> {
    let mut endpoint_counts = HashMap::<(String, u16), usize>::new();
    let mut result = Vec::with_capacity(limit.min(configs.len()));

    for config in configs {
        if result.len() >= limit {
            break;
        }

        if let Some(ep) = endpoint(config) {
            let count = endpoint_counts.get(&ep).copied().unwrap_or(0);
            if count >= max_per_endpoint {
                continue;
            }
            *endpoint_counts.entry(ep).or_insert(0) += 1;
        }

        result.push(config.clone());
    }

    result
}

fn write_experimental_output(
    path: Option<&str>,
    ranked_configs: &[String],
    selection_limit: usize,
    max_per_endpoint: usize,
) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };

    let selected = quality_first_selection(ranked_configs, selection_limit, max_per_endpoint);
    if selected.is_empty() {
        return Ok(());
    }

    write_lines(path, &selected)?;
    println!(
        "[INFO] Experimental Light quality-first selection: {} configs written.",
        selected.len()
    );

    Ok(())
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

    // Reality is checked by both cores for transport classes that both
    // consumer cores can represent.
    if security == "reality" {
        return LightBackend::Dual;
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

    LightBackend::SingBox
}

async fn merge_dual(
    xray: &str,
    singbox: &str,
    candidates: &[String],
    primary_target: &str,
    workers: usize,
    batch_size: usize,
    timeout_seconds: f64,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    if candidates.is_empty() {
        return Ok(HashMap::new());
    }

    let xray_metadata = validate_candidates(
        xray,
        candidates,
        primary_target,
        workers,
        batch_size,
        timeout_seconds,
    )
    .await?;
    let xray_verified = xray_metadata.len();

    let request_timeout = std::time::Duration::from_secs_f64(timeout_seconds);
    let singbox_metadata = validate_singbox_candidates(
        singbox,
        candidates,
        workers.min(32).max(1),
        request_timeout,
        timeout_seconds * 1000.0,
    )
    .await?;

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
    primary_target: &str,
    workers: usize,
    batch_size: usize,
    timeout_seconds: f64,
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

    let mut verified = HashMap::new();

    if !singbox_candidates.is_empty() {
        let request_timeout = std::time::Duration::from_secs_f64(timeout_seconds);
        verified.extend(
            validate_singbox_candidates(
                singbox,
                &singbox_candidates,
                workers.min(32).max(1),
                request_timeout,
                timeout_seconds * 1000.0,
            )
            .await?,
        );
    }

    if !xray_candidates.is_empty() {
        verified.extend(
            validate_candidates(
                xray,
                &xray_candidates,
                primary_target,
                workers,
                batch_size,
                timeout_seconds,
            )
            .await?,
        );
    }

    if !dual_candidates.is_empty() {
        verified.extend(
            merge_dual(
                xray,
                singbox,
                &dual_candidates,
                primary_target,
                workers,
                batch_size,
                timeout_seconds,
            )
            .await?,
        );
    }

    println!(
        "[INFO] Consumer-style Light validation: {}/{} candidates verified.",
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
            "Usage: polish_light --candidates FILE --output FILE [--workers N]              [--batch-size N] [--timeout SECONDS] [--selected-recheck-limit N]              [--max-candidates N] [--selected-workers N] [--selected-batch-size N]              [--primary-target URL] [--selection-limit N] [--max-per-endpoint N]              [--experimental-output FILE] [--xray PATH] [--singbox PATH]"
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
    let experimental_output = value(&args, "--experimental-output", "");
    let experimental_output = (!experimental_output.is_empty()).then_some(experimental_output);
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
    let mut global_seen = HashSet::<String>::new();
    let mut global_metadata = HashMap::<String, ProxyMetrics>::new();
    let mut final_verified = Vec::<String>::new();
    let mut final_seen = HashSet::<String>::new();
    let mut final_metadata = HashMap::<String, ProxyMetrics>::new();

    let chunk_count = (candidates.len() + DISCOVERY_CHUNK_SIZE - 1) / DISCOVERY_CHUNK_SIZE;

    for (chunk_index, chunk) in candidates.chunks(DISCOVERY_CHUNK_SIZE).enumerate() {
        let wave = chunk_index + 1;

        println!(
            "[INFO] Global Light discovery {wave}/{chunk_count}: testing {} candidates; {} verified so far.",
            chunk.len(),
            global_verified.len()
        );

        let chunk_vec = chunk.to_vec();
        let chunk_metadata = validate_light_batch(
            &xray,
            &singbox,
            &chunk_vec,
            &primary_target,
            workers,
            batch_size,
            timeout,
        )
        .await?;

        for config in chunk_metadata.keys() {
            if global_seen.insert(config.clone()) {
                global_verified.push(config.clone());
            }
        }
        global_metadata.extend(chunk_metadata);

        let positions = global_verified
            .iter()
            .enumerate()
            .map(|(index, config)| (config.clone(), index))
            .collect::<HashMap<_, _>>();

        let ranked_global = ranked(global_verified.clone(), &global_metadata, &positions);
        let remaining = selection_limit.saturating_sub(
            protocol_round_robin(
                &ranked(final_verified.clone(), &final_metadata, &positions),
                selection_limit,
                max_per_endpoint,
            )
            .len(),
        );

        if remaining == 0 {
            let ranked_final = ranked(final_verified.clone(), &final_metadata, &positions);
            let selected = protocol_round_robin(&ranked_final, selection_limit, max_per_endpoint);
            write_experimental_output(
                experimental_output.as_deref(),
                &ranked_global,
                selection_limit,
                max_per_endpoint,
            )?;
            write_lines(&output, &selected)?;
            println!("[INFO] Published {} Light configs.", selected.len());
            return Ok(());
        }

        let dynamic_limit = final_recheck_limit.min(
            remaining
                .saturating_mul(2)
                .saturating_add(20)
                .max(remaining),
        );
        let untested = ranked_global
            .into_iter()
            .filter(|config| !final_seen.contains(config))
            .collect::<Vec<_>>();
        let final_candidates = diversify_recheck_candidates(&untested, dynamic_limit);

        if final_candidates.is_empty() {
            continue;
        }

        final_seen.extend(final_candidates.iter().cloned());

        println!(
            "[INFO] Final Light recheck wave {wave}: {} candidates ({} slots remaining).",
            final_candidates.len(),
            remaining
        );

        let primary_metadata = validate_light_batch(
            &xray,
            &singbox,
            &final_candidates,
            &primary_target,
            final_workers,
            final_batch_size,
            timeout,
        )
        .await?;

        for (config, metrics) in primary_metadata {
            if !final_metadata.contains_key(&config) {
                final_verified.push(config.clone());
            }
            final_metadata.insert(config, metrics);
        }

        let positions = global_verified
            .iter()
            .enumerate()
            .map(|(index, config)| (config.clone(), index))
            .collect::<HashMap<_, _>>();

        let ranked_final = ranked(final_verified.clone(), &final_metadata, &positions);
        let selected = protocol_round_robin(&ranked_final, selection_limit, max_per_endpoint);

        println!(
            "[INFO] Light fill progress: {}/{} configs ready.",
            selected.len(),
            selection_limit
        );

        if selected.len() >= selection_limit {
            let mut protocol_counts = BTreeMap::<String, usize>::new();
            for config in &selected {
                *protocol_counts.entry(protocol(config)).or_default() += 1;
            }
            println!("[INFO] Light protocol distribution: {:?}", protocol_counts);
            write_experimental_output(
                experimental_output.as_deref(),
                &ranked_final,
                selection_limit,
                max_per_endpoint,
            )?;
            write_lines(&output, &selected)?;
            println!(
                "[INFO] Published {} Light configs from {} globally verified candidates.",
                selected.len(),
                global_verified.len()
            );
            return Ok(());
        }
    }

    let positions = global_verified
        .iter()
        .enumerate()
        .map(|(index, config)| (config.clone(), index))
        .collect::<HashMap<_, _>>();
    let ranked_final = ranked(final_verified, &final_metadata, &positions);
    let selected = protocol_round_robin(&ranked_final, selection_limit, max_per_endpoint);

    if selected.is_empty() {
        return Err("selected Light validation produced zero verified configs".to_string());
    }

    let mut protocol_counts = BTreeMap::<String, usize>::new();
    let mut backend_counts = BTreeMap::<&str, usize>::new();
    for config in &selected {
        *protocol_counts.entry(protocol(config)).or_default() += 1;
        match light_backend(config) {
            LightBackend::SingBox => *backend_counts.entry("sing-box").or_default() += 1,
            LightBackend::Xray => *backend_counts.entry("xray").or_default() += 1,
            LightBackend::Dual => *backend_counts.entry("dual").or_default() += 1,
        }
    }
    println!("[INFO] Light protocol distribution: {:?}", protocol_counts);
    println!("[INFO] Light backend distribution: {:?}", backend_counts);

    write_experimental_output(
        experimental_output.as_deref(),
        &ranked_final,
        selection_limit,
        max_per_endpoint,
    )?;
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
    use super::{light_backend, protocol_round_robin, LightBackend};

    #[test]
    fn routes_reality_to_both_cores() {
        let config =
            "vless://uuid@example.com:443?security=reality&type=tcp&pbk=public&sid=01&sni=example.com";
        assert_eq!(light_backend(config), LightBackend::Dual);
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
    fn quality_first_preserves_rank_and_endpoint_limit() {
        let configs = vec![
            "vless://a@example.com:443".to_string(),
            "vless://b@example.com:443".to_string(),
            "trojan://c@example.net:8443".to_string(),
            "vmess://encoded@example.org:9443".to_string(),
        ];

        let selected = super::quality_first_selection(&configs, 4, 1);

        assert_eq!(
            selected,
            vec![configs[0].clone(), configs[2].clone(), configs[3].clone()]
        );
    }

    #[test]
    fn round_robin_preserves_rank_within_each_protocol() {
        let configs = vec![
            "vless://a@example.com:443".to_string(),
            "vless://b@example.com:443".to_string(),
            "trojan://c@example.net:443".to_string(),
            "trojan://d@example.net:8443".to_string(),
            "hysteria2://e@example.org:443".to_string(),
        ];

        let selected = protocol_round_robin(&configs, 5, 1);

        assert_eq!(selected.len(), 4);
        assert_eq!(selected[0], configs[4]);
        assert_eq!(selected[1], configs[2]);
        assert_eq!(selected[2], configs[0]);
        assert_eq!(selected[3], configs[3]);
    }

    #[test]
    fn round_robin_respects_endpoint_limit() {
        let configs = vec![
            "vless://a@example.com:443".to_string(),
            "vless://b@example.com:443".to_string(),
            "trojan://c@example.net:443".to_string(),
            "trojan://d@example.net:443".to_string(),
            "hysteria2://e@example.org:443".to_string(),
        ];

        let selected = protocol_round_robin(&configs, 5, 1);

        assert_eq!(selected.len(), 3);
        assert!(selected.contains(&configs[0]));
        assert!(selected.contains(&configs[2]));
        assert!(selected.contains(&configs[4]));
    }
}
