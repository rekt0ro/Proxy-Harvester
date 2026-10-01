use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use proxyrift::intelligence::IntelligenceModel;
use proxyrift::light_training::{persist as persist_light_training, DatasetStats, TrainingRow};
use proxyrift::singbox::{
    validate_candidates_with_targets as validate_singbox_targets,
    validate_candidates_with_targets_strict as validate_singbox_targets_strict,
};
use proxyrift::validator::{
    endpoint, rate_limit_events, read_lines, validate_candidates_with_targets,
    validate_candidates_with_targets_strict, write_lines, ProxyMetrics, LIGHT_TARGETS,
    PRIMARY_TARGET,
};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use url::Url;

const DISCOVERY_CHUNK_SIZE: usize = 1000;
const MAX_DISCOVERY_CANDIDATES: usize = 10000;
const FINAL_RECHECK_LIMIT: usize = 350;
const DEFAULT_SELECTION_LIMIT: usize = 200;
const DEFAULT_MAX_PER_ENDPOINT: usize = 1;
const DEFAULT_MAX_PER_FAMILY: usize = 3;
const RECHECK_FAMILY_DIVERSITY: usize = 1;
const MAX_FINAL_RECHECK_ATTEMPTS: usize = 2;
const TRANSFER_RESERVE_MIN_HEADROOM: usize = 60;
const TRANSFER_RESERVE_DEFAULT_PASS_RATE: f64 = 0.80;
const TRANSFER_RESERVE_SAFETY_FACTOR: f64 = 1.08;
const TRANSFER_RESERVE_MAX_HEADROOM: usize = 120;
const FINAL_TRANSFER_BATCH_SIZE: usize = 32;
const FINAL_TRANSFER_WORKERS: usize = 12;
const FINAL_TRANSFER_INITIAL_WORKERS: usize = 6;
const FINAL_TRANSFER_MIN_WORKERS: usize = 4;
const FINAL_TRANSFER_QUEUE_MULTIPLIER: usize = 3;
const FINAL_TRANSFER_CLEAN_BATCHES_TO_RAMP: usize = 2;
const FINAL_TRANSFER_TEST_LIMIT: usize = 320;
const FINAL_TRANSFER_MAX_ELAPSED_SECS: u64 = 8 * 60;
const FINAL_TRANSFER_TIMEOUT_SECS: f64 = 15.0;
const FINAL_TRANSFER_LATENCY_LIMIT_MS: f64 = 15000.0;
const HISTORY_MAX_ENTRIES: usize = 10000;
const HISTORY_RETENTION_SECS: u64 = 45 * 24 * 60 * 60;
const LIGHT_TRAINING_PATH: &str = "subscriptions/light-training.jsonl";

fn adaptive_recheck_limit(
    remaining: usize,
    configured_limit: usize,
    strict_attempts: usize,
    strict_verified: usize,
) -> usize {
    if remaining == 0 || configured_limit == 0 {
        return 0;
    }

    let observed_rate = if strict_attempts < 20 {
        0.20
    } else {
        ((strict_verified as f64 + 2.0) / (strict_attempts as f64 + 4.0)).clamp(0.05, 1.0)
    };

    let estimated = ((remaining as f64 / observed_rate) * 1.25).ceil() as usize;
    let exploration_floor = if strict_attempts == 0 {
        remaining.saturating_mul(4).saturating_add(50)
    } else {
        remaining.saturating_mul(2).saturating_add(20)
    };

    estimated.max(exploration_floor).min(configured_limit)
}

fn selection_eligible_count(
    configs: &[String],
    max_per_endpoint: usize,
    max_per_family: usize,
) -> usize {
    select_verified_configs(configs, configs.len(), max_per_endpoint, max_per_family).len()
}

fn transfer_reserve_target(
    selection_limit: usize,
    transfer_tested: usize,
    transfer_passed: usize,
) -> usize {
    if selection_limit == 0 {
        return 0;
    }

    let observed_rate = if transfer_tested < 16 {
        TRANSFER_RESERVE_DEFAULT_PASS_RATE
    } else {
        ((transfer_passed as f64 + 2.0) / (transfer_tested as f64 + 4.0)).clamp(0.60, 0.95)
    };

    let estimated =
        ((selection_limit as f64 / observed_rate) * TRANSFER_RESERVE_SAFETY_FACTOR).ceil() as usize;
    let minimum = selection_limit.saturating_add(TRANSFER_RESERVE_MIN_HEADROOM);
    let maximum = selection_limit.saturating_add(TRANSFER_RESERVE_MAX_HEADROOM);

    estimated.clamp(minimum, maximum)
}

fn adaptive_transfer_test_limit(
    selection_limit: usize,
    selected_len: usize,
    transfer_tested: usize,
    transfer_passed: usize,
    eligible_remaining: usize,
) -> usize {
    if selected_len >= selection_limit || eligible_remaining == 0 {
        return transfer_tested;
    }

    let remaining = selection_limit.saturating_sub(selected_len);
    let observed_rate = if transfer_tested < 16 {
        TRANSFER_RESERVE_DEFAULT_PASS_RATE
    } else {
        ((transfer_passed as f64 + 2.0) / (transfer_tested as f64 + 4.0)).clamp(0.35, 0.95)
    };

    let estimated_additional = ((remaining as f64 / observed_rate) * 1.20).ceil() as usize;
    let exploration_floor = remaining.saturating_add(8);
    let additional_budget = estimated_additional
        .max(exploration_floor)
        .min(eligible_remaining);

    transfer_tested
        .saturating_add(additional_budget)
        .min(FINAL_TRANSFER_TEST_LIMIT)
}

fn write_light_stats(
    path: &str,
    input_candidates: usize,
    security_rejected: usize,
    strict_verified: usize,
    transfer_tested: usize,
    transfer_passed: usize,
    published: usize,
) -> Result<(), String> {
    if path.is_empty() {
        return Ok(());
    }

    let stats = serde_json::json!({
        "input_candidates": input_candidates,
        "security_rejected": security_rejected,
        "strict_verified": strict_verified,
        "transfer_tested": transfer_tested,
        "transfer_passed": transfer_passed,
        "published": published,
    });
    let body = serde_json::to_vec_pretty(&stats).map_err(|error| error.to_string())?;
    std::fs::write(path, body).map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn persist_light_result(
    output: &str,
    selected: &[String],
    history_path: &str,
    history: &HashMap<String, HistoryEntry>,
    final_attempts: &HashMap<String, usize>,
    final_metadata: &HashMap<String, ProxyMetrics>,
    intelligence: &IntelligenceModel,
    global_metadata: &HashMap<String, ProxyMetrics>,
    intelligence_path: &str,
    transfer_tested: &HashSet<String>,
    transfer_verified: &HashMap<String, ProxyMetrics>,
) -> Result<(), String> {
    write_light_lines(output, selected)?;
    persist_light_training_data(
        history,
        final_attempts,
        final_metadata,
        global_metadata,
        transfer_tested,
        transfer_verified,
    )?;

    let mut model = intelligence.clone();
    for (config, attempts) in final_attempts {
        model.update(
            config,
            global_metadata.get(config),
            *attempts,
            final_metadata.contains_key(config),
        );
    }
    model.save(intelligence_path)?;
    persist_history(history_path, history, final_attempts, final_metadata)
}

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

#[derive(Clone, Copy, Debug, Default)]
struct HistoryEntry {
    checks: u64,
    passes: u64,
    last_seen: u64,
}

fn history_identity(config: &str) -> String {
    let cleaned = config.split('#').next().unwrap_or(config);

    if cleaned
        .split_once("://")
        .map(|(scheme, _)| scheme.eq_ignore_ascii_case("vmess"))
        .unwrap_or(false)
    {
        if let Some(payload) = cleaned.split_once("://").map(|(_, rest)| rest) {
            let payload = payload.split('#').next().unwrap_or("").trim();
            let mut padded = payload.to_string();
            while !padded.len().is_multiple_of(4) {
                padded.push('=');
            }

            for candidate in [payload, padded.as_str()] {
                for bytes in [
                    STANDARD.decode(candidate),
                    URL_SAFE.decode(candidate),
                    URL_SAFE_NO_PAD.decode(candidate),
                ]
                .into_iter()
                .flatten()
                {
                    if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) {
                        if let Value::Object(object) = &mut value {
                            object.remove("ps");
                        }
                        if let Ok(canonical) = serde_json::to_string(&value) {
                            return canonical;
                        }
                    }
                }
            }
        }
    }

    cleaned.to_string()
}

fn history_fingerprint(config: &str) -> String {
    fn fnv64(input: &[u8], seed: u64) -> u64 {
        let mut hash = seed;
        for byte in input {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    let identity = history_identity(config);
    let first = fnv64(identity.as_bytes(), 0xcbf29ce484222325);
    let second = fnv64(identity.as_bytes(), 0x9e3779b97f4a7c15);
    format!("{first:016x}{second:016x}")
}

fn load_history(path: &str) -> Result<HashMap<String, HistoryEntry>, String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Ok(HashMap::new());
    };

    let value = match serde_json::from_str::<Value>(&content) {
        Ok(value) => value,
        Err(error) => {
            println!("[WARN] ⚠️ Ignoring invalid Light history: {error}");
            return Ok(HashMap::new());
        }
    };

    let Some(entries) = value.get("entries").and_then(Value::as_object) else {
        return Ok(HashMap::new());
    };

    let mut history = HashMap::new();
    for (fingerprint, entry) in entries {
        let checks = entry.get("checks").and_then(Value::as_u64).unwrap_or(0);
        let passes = entry.get("passes").and_then(Value::as_u64).unwrap_or(0);
        let last_seen = entry.get("last_seen").and_then(Value::as_u64).unwrap_or(0);
        if checks == 0 && last_seen == 0 {
            continue;
        }
        history.insert(
            fingerprint.clone(),
            HistoryEntry {
                checks,
                passes: passes.min(checks),
                last_seen,
            },
        );
    }

    Ok(history)
}

fn persist_history(
    path: &str,
    history: &HashMap<String, HistoryEntry>,
    final_attempts: &HashMap<String, usize>,
    final_metadata: &HashMap<String, ProxyMetrics>,
) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();

    let mut updated = history.clone();
    for (config, attempts) in final_attempts {
        let fingerprint = history_fingerprint(config);
        let entry = updated.entry(fingerprint).or_default();
        entry.checks = entry.checks.saturating_add(*attempts as u64);
        entry.passes = entry
            .passes
            .saturating_add(u64::from(final_metadata.contains_key(config)));
        entry.last_seen = now;
    }

    updated.retain(|_, entry| entry.last_seen.saturating_add(HISTORY_RETENTION_SECS) >= now);

    if updated.len() > HISTORY_MAX_ENTRIES {
        let mut entries = updated.into_iter().collect::<Vec<_>>();
        entries.sort_unstable_by_key(|(_, entry)| std::cmp::Reverse(entry.last_seen));
        entries.truncate(HISTORY_MAX_ENTRIES);
        updated = entries.into_iter().collect();
    }

    let mut entries = BTreeMap::new();
    for (fingerprint, entry) in updated {
        entries.insert(
            fingerprint,
            serde_json::json!({
                "checks": entry.checks,
                "passes": entry.passes.min(entry.checks),
                "last_seen": entry.last_seen,
            }),
        );
    }

    let document = serde_json::json!({
        "version": 1,
        "entries": entries,
    });
    let body = serde_json::to_vec_pretty(&document).map_err(|error| error.to_string())?;
    let temporary = format!("{path}.tmp");
    std::fs::write(&temporary, body).map_err(|error| error.to_string())?;
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    Ok(())
}

fn historical_score(config: &str, history: &HashMap<String, HistoryEntry>) -> (f64, u64) {
    history
        .get(&history_fingerprint(config))
        .map(|entry| {
            (
                (entry.passes as f64 + 2.0) / (entry.checks as f64 + 4.0),
                entry.checks,
            )
        })
        .unwrap_or((0.5, 0))
}

fn sort_ranked(
    configs: &mut [String],
    metadata: &HashMap<String, ProxyMetrics>,
    positions: &HashMap<String, usize>,
    history: &HashMap<String, HistoryEntry>,
) {
    configs.sort_unstable_by(|a, b| {
        let ma = metadata.get(a);
        let mb = metadata.get(b);

        let a_successes = ma.map(|m| m.successes).unwrap_or(0);
        let b_successes = mb.map(|m| m.successes).unwrap_or(0);
        let a_attempts = ma.map(|m| m.attempts.max(1)).unwrap_or(1);
        let b_attempts = mb.map(|m| m.attempts.max(1)).unwrap_or(1);
        let a_success_rate = a_successes as f64 / a_attempts as f64;
        let b_success_rate = b_successes as f64 / b_attempts as f64;
        let a_median = ma.map(|m| m.median_ms).unwrap_or(f64::INFINITY);
        let b_median = mb.map(|m| m.median_ms).unwrap_or(f64::INFINITY);
        let a_jitter = ma.map(|m| m.jitter_ms).unwrap_or(f64::INFINITY);
        let b_jitter = mb.map(|m| m.jitter_ms).unwrap_or(f64::INFINITY);
        let a_throughput = ma.map(|m| m.throughput_kbps).unwrap_or(0.0);
        let b_throughput = mb.map(|m| m.throughput_kbps).unwrap_or(0.0);
        let a_min = ma.map(|m| m.min_ms).unwrap_or(f64::INFINITY);
        let b_min = mb.map(|m| m.min_ms).unwrap_or(f64::INFINITY);
        let (a_history_rate, a_history_checks) = historical_score(a, history);
        let (b_history_rate, b_history_checks) = historical_score(b, history);

        b_success_rate
            .total_cmp(&a_success_rate)
            .then_with(|| b_successes.cmp(&a_successes))
            .then_with(|| a_median.total_cmp(&b_median))
            .then_with(|| a_jitter.total_cmp(&b_jitter))
            .then_with(|| b_throughput.total_cmp(&a_throughput))
            .then_with(|| a_history_rate.total_cmp(&b_history_rate))
            .then_with(|| b_history_checks.cmp(&a_history_checks))
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
    let mut seen_endpoints = HashSet::new();
    let mut family_counts = HashMap::<String, usize>::new();

    for config in configs {
        if selected.len() >= limit {
            break;
        }

        let family = family_key(config);
        let family_available = family_counts.get(&family).copied().unwrap_or(0) < max_family;
        let endpoint_available = endpoint(config)
            .map(|ep| !seen_endpoints.contains(&ep))
            .unwrap_or(true);

        if !family_available || !endpoint_available {
            continue;
        }

        *family_counts.entry(family).or_default() += 1;
        if let Some(ep) = endpoint(config) {
            seen_endpoints.insert(ep);
        }
        selected.push(config.clone());
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

#[allow(clippy::too_many_arguments)]
async fn validate_light_transfer_batch(
    xray: &str,
    singbox: &str,
    candidates: &[String],
    workers: usize,
) -> Result<HashMap<String, ProxyMetrics>, String> {
    let mut singbox_candidates = Vec::new();
    let mut xray_candidates = Vec::new();
    let mut fallback_candidates = Vec::new();

    for config in candidates {
        match light_backend(config) {
            LightBackend::SingBox => singbox_candidates.push(config.clone()),
            LightBackend::Xray => xray_candidates.push(config.clone()),
            LightBackend::Fallback => fallback_candidates.push(config.clone()),
        }
    }

    let request_timeout = std::time::Duration::from_secs_f64(FINAL_TRANSFER_TIMEOUT_SECS);

    let mut singbox_validation_candidates = singbox_candidates;
    singbox_validation_candidates.extend(fallback_candidates.iter().cloned());
    let xray_validation_candidates = xray_candidates;

    let singbox_future = async {
        if singbox_validation_candidates.is_empty() {
            Ok(HashMap::new())
        } else {
            proxyrift::singbox::validate_candidates_with_target_once(
                singbox,
                &singbox_validation_candidates,
                proxyrift::validator::STRICT_THROUGHPUT_TARGET,
                workers,
                request_timeout,
                FINAL_TRANSFER_LATENCY_LIMIT_MS,
            )
            .await
        }
    };

    let xray_future = async {
        if xray_validation_candidates.is_empty() {
            Ok(HashMap::new())
        } else {
            proxyrift::validator::validate_candidates_with_target_once(
                xray,
                &xray_validation_candidates,
                proxyrift::validator::STRICT_THROUGHPUT_TARGET,
                workers,
                1000,
                FINAL_TRANSFER_TIMEOUT_SECS,
                FINAL_TRANSFER_LATENCY_LIMIT_MS,
            )
            .await
        }
    };

    let (singbox_result, xray_result) = tokio::join!(singbox_future, xray_future);

    let singbox_metadata = match singbox_result {
        Ok(metadata) => metadata,
        Err(error) => {
            println!("[WARN] ⚠️ sing-box validation failed for this batch; preserving Xray results: {error}");
            HashMap::new()
        }
    };

    let mut xray_metadata = match xray_result {
        Ok(metadata) => metadata,
        Err(error) => {
            println!("[WARN] ⚠️ Xray validation failed for this batch; preserving sing-box results: {error}");
            HashMap::new()
        }
    };

    // Fallback candidates are intentionally sent to sing-box first. A candidate
    // already accepted by sing-box is finished; only the ones not accepted there
    // are retried through Xray. If sing-box itself failed, all fallback candidates
    // are eligible for the Xray retry so a backend outage does not become a proxy
    // quality verdict.
    let fallback_retry = fallback_candidates
        .into_iter()
        .filter(|config| !singbox_metadata.contains_key(config))
        .collect::<Vec<_>>();

    if !fallback_retry.is_empty() {
        match proxyrift::validator::validate_candidates_with_target_once(
            xray,
            &fallback_retry,
            proxyrift::validator::STRICT_THROUGHPUT_TARGET,
            workers,
            1000,
            FINAL_TRANSFER_TIMEOUT_SECS,
            FINAL_TRANSFER_LATENCY_LIMIT_MS,
        )
        .await
        {
            Ok(fallback_xray) => xray_metadata.extend(fallback_xray),
            Err(error) => println!(
                "[WARN] ⚠️ Xray fallback validation failed for {} candidates: {error}",
                fallback_retry.len()
            ),
        }
    }

    Ok(merge_light_metadata(xray_metadata, singbox_metadata))
}

#[allow(clippy::too_many_arguments)]
async fn fill_transfer_gate(
    xray: &str,
    singbox: &str,
    final_verified: &[String],
    transfer_verified: &mut HashMap<String, ProxyMetrics>,
    transfer_tested: &mut HashSet<String>,
    global_positions: &HashMap<String, usize>,
    history: &HashMap<String, HistoryEntry>,
    selection_limit: usize,
    max_per_endpoint: usize,
    max_per_family: usize,
) -> Result<usize, String> {
    let gate_started = Instant::now();
    let mut transfer_workers = FINAL_TRANSFER_INITIAL_WORKERS;
    let mut clean_batches = 0usize;
    loop {
        let mut transfer_ranked = transfer_verified.keys().cloned().collect::<Vec<_>>();
        sort_ranked(
            &mut transfer_ranked,
            transfer_verified,
            global_positions,
            history,
        );

        let selected = select_verified_configs(
            &transfer_ranked,
            selection_limit,
            max_per_endpoint,
            max_per_family,
        );

        if selected.len() >= selection_limit {
            return Ok(selected.len());
        }

        let untested = final_verified
            .iter()
            .filter(|config| !transfer_tested.contains(*config))
            .cloned()
            .collect::<Vec<_>>();

        if untested.is_empty() {
            return Ok(selected.len());
        }

        let eligible_remaining =
            selection_eligible_count(&untested, max_per_endpoint, max_per_family);
        if selected.len().saturating_add(eligible_remaining) < selection_limit {
            println!(
                "[INFO] ⏭️ [10 MiB] TARGET UNREACHABLE WITH CURRENT STRICT POOL | SELECTABLE: {} | UNTESTED ELIGIBLE: {} | TARGET/MAX: {}",
                selected.len(),
                eligible_remaining,
                selection_limit
            );
            return Ok(selected.len());
        }

        if gate_started.elapsed().as_secs() >= FINAL_TRANSFER_MAX_ELAPSED_SECS {
            println!(
                "[WARN] ⏱️ [10 MiB] TIME BUDGET REACHED | TESTED: {} | SELECTABLE: {} | STOPPING BEST-EFFORT GATE",
                transfer_tested.len(),
                selected.len()
            );
            return Ok(selected.len());
        }

        // final_verified is kept ranked before entering the transfer gate,
        // so retaining this order tests the most likely winners first.

        let remaining = selection_limit.saturating_sub(selected.len());
        let dynamic_test_limit = adaptive_transfer_test_limit(
            selection_limit,
            selected.len(),
            transfer_tested.len(),
            transfer_verified.len(),
            eligible_remaining,
        );

        if transfer_tested.len() >= dynamic_test_limit {
            println!(
                "[INFO] 🎯 [10 MiB] ADAPTIVE TEST BUDGET REACHED | TESTED: {} | SELECTABLE: {} | TARGET/MAX: {}",
                transfer_tested.len(),
                selected.len(),
                selection_limit
            );
            return Ok(selected.len());
        }

        let queue_window = transfer_workers
            .saturating_mul(FINAL_TRANSFER_QUEUE_MULTIPLIER)
            .max(8);
        let batch_limit = dynamic_test_limit
            .saturating_sub(transfer_tested.len())
            .min(FINAL_TRANSFER_BATCH_SIZE)
            .min(queue_window)
            .max(1);

        let batch = diversify_recheck_candidates(&untested, batch_limit, 1);
        if batch.is_empty() {
            return Ok(selected.len());
        }

        transfer_tested.extend(batch.iter().cloned());

        println!(
            "[INFO] 📥 [10 MiB] {} SLOTS REMAINING | TESTING {} CANDIDATES | ADAPTIVE MAX TESTS: {}",
            remaining,
            batch.len(),
            dynamic_test_limit
        );

        let rate_limits_before = rate_limit_events();
        let batch_started = Instant::now();
        let metadata =
            validate_light_transfer_batch(xray, singbox, &batch, transfer_workers).await?;
        let batch_elapsed = batch_started.elapsed().as_secs();
        let batch_passed = metadata.len();
        transfer_verified.extend(metadata);

        let rate_limits_after = rate_limit_events();
        let rate_limits = rate_limits_after.saturating_sub(rate_limits_before);
        if rate_limits >= 4 {
            transfer_workers = transfer_workers
                .saturating_sub(2)
                .max(FINAL_TRANSFER_MIN_WORKERS);
            clean_batches = 0;
            println!(
                "[WARN] ⚠️ LIGHT TRANSFER: {} rate-limit responses; reducing workers to {}",
                rate_limits, transfer_workers
            );
        } else if rate_limits > 0 {
            transfer_workers = transfer_workers
                .saturating_sub(1)
                .max(FINAL_TRANSFER_MIN_WORKERS);
            clean_batches = 0;
            println!(
                "[WARN] ⚠️ LIGHT TRANSFER: {} rate-limit responses; reducing workers to {}",
                rate_limits, transfer_workers
            );
        } else {
            clean_batches += 1;
            if clean_batches >= FINAL_TRANSFER_CLEAN_BATCHES_TO_RAMP {
                transfer_workers = (transfer_workers + 1).min(FINAL_TRANSFER_WORKERS);
                clean_batches = 0;
            }
        }

        println!(
            "[INFO] ✅ [10 MiB] {}/{} PASSED IN {}s | TOTAL PASSED: {} | SLOTS REMAINING: {}",
            batch_passed,
            batch.len(),
            batch_elapsed,
            transfer_verified.len(),
            selection_limit.saturating_sub(
                select_verified_configs(
                    &transfer_verified.keys().cloned().collect::<Vec<_>>(),
                    selection_limit,
                    max_per_endpoint,
                    max_per_family,
                )
                .len(),
            ),
        );
    }
}


