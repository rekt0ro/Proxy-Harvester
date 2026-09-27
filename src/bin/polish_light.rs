use proxy_harvester::singbox::validate_candidates as validate_singbox_candidates;
use proxy_harvester::validator::{
    endpoint, read_lines, validate_candidates_with_compatibility, write_lines, ProxyMetrics,
    COMPATIBILITY_TARGET, PRIMARY_TARGET,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;

const DISCOVERY_CHUNK_SIZE: usize = 1000;
const MAX_DISCOVERY_CANDIDATES: usize = 4000;
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

fn diversified(configs: &[String], limit: usize, max_per_endpoint: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut endpoint_counts = HashMap::<(String, u16), usize>::new();

    for config in configs {
        if let Some(ep) = endpoint(config) {
            let count = endpoint_counts.entry(ep).or_insert(0);
            if *count >= max_per_endpoint {
                continue;
            }
            *count += 1;
        }

        result.push(config.clone());
        if result.len() >= limit {
            break;
        }
    }

    result
}

fn protocol(config: &str) -> String {
    config
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Selects from the already-ranked verified pool in protocol round-robin order.
/// Ranking is preserved within each protocol, so the best candidate for a
/// protocol is always selected before its lower-ranked peers. Protocols with
/// fewer candidates naturally exhaust early and their turns are redistributed.
fn protocol_round_robin(
    configs: &[String],
    limit: usize,
    max_per_endpoint: usize,
) -> Vec<String> {
    let mut groups = BTreeMap::<String, Vec<String>>::new();

    for config in configs {
        groups.entry(protocol(config)).or_default().push(config.clone());
    }

    let protocols = groups.keys().cloned().collect::<Vec<_>>();
    let mut cursors = HashMap::<String, usize>::new();
    let mut endpoint_counts = HashMap::<(String, u16), usize>::new();
    let mut result = Vec::with_capacity(limit.min(configs.len()));

    while result.len() < limit {
        let mut made_progress = false;

        for scheme in &protocols {
            let group = groups.get(scheme).expect("protocol group exists");
            let cursor = cursors.entry(scheme.clone()).or_insert(0);

            while *cursor < group.len() {
                let config = &group[*cursor];
                *cursor += 1;

                if let Some(ep) = endpoint(config) {
                    let count = endpoint_counts.entry(ep).or_insert(0);
                    if *count >= max_per_endpoint {
                        continue;
                    }
                    *count += 1;
                }

                result.push(config.clone());
                made_progress = true;
                break;
            }

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

async fn dual_validate(
    xray: &str,
    singbox: &str,
    candidates: &[String],
    primary_target: &str,
    workers: usize,
    batch_size: usize,
    timeout: f64,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    let xray_metadata = validate_candidates_with_compatibility(
        xray,
        candidates,
        primary_target,
        COMPATIBILITY_TARGET,
        workers,
        batch_size,
        timeout,
    )
    .await?;

    if xray_metadata.is_empty() {
        println!("[INFO] Dual-core Light: Xray verified 0 candidates.");
        return Ok(HashMap::new());
    }

    let xray_candidates = xray_metadata.keys().cloned().collect::<Vec<_>>();
    let singbox_metadata =
        validate_singbox_candidates(singbox, &xray_candidates, workers.min(16).max(1)).await?;

    let mut verified = HashMap::new();
    for (config, metrics) in xray_metadata {
        if singbox_metadata.contains_key(&config) {
            verified.insert(config, metrics);
        }
    }

    println!(
        "[INFO] Dual-core Light: Xray verified {}, sing-box verified {}, intersection {}.",
        xray_candidates.len(),
        singbox_metadata.len(),
        verified.len()
    );

    Ok(verified)
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: polish_light --candidates FILE --output FILE [--workers N] \
             [--batch-size N] [--timeout SECONDS] [--selected-recheck-limit N] \
             [--max-candidates N] [--selected-workers N] [--selected-batch-size N] \
             [--primary-target URL] [--selection-limit N] [--max-per-endpoint N] [--xray PATH] [--singbox PATH]"
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
    let timeout = value(&args, "--timeout", "3")
        .parse::<f64>()
        .map_err(|_| "invalid --timeout".to_string())?;
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
    let xray = value(&args, "--xray", "xray");
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
        let chunk_metadata = dual_validate(
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
            let selected = protocol_round_robin(
                &ranked(final_verified.clone(), &final_metadata, &positions),
                selection_limit,
                max_per_endpoint,
            );
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

        let primary_metadata = dual_validate(
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
            write_lines(&output, &selected)?;
            println!(
                "[INFO] Published {} Light configs from {} globally verified candidates; selected validation used {}.",
                selected.len(),
                global_verified.len(),
                primary_target
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
    use super::protocol_round_robin;

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

        assert_eq!(selected[0], configs[4]);
        assert_eq!(selected[1], configs[0]);
        assert_eq!(selected[2], configs[2]);
        assert_eq!(selected[3], configs[1]);
        assert_eq!(selected[4], configs[3]);
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
