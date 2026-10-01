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
const FINAL_TRANSFER_TEST_LIMIT: usize = 600;
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

        if untested.is_empty() || transfer_tested.len() >= FINAL_TRANSFER_TEST_LIMIT {
            return Ok(selected.len());
        }

        // final_verified is kept ranked before entering the transfer gate,
        // so retaining this order tests the most likely winners first.

        let remaining = selection_limit.saturating_sub(selected.len());
        let queue_window = transfer_workers
            .saturating_mul(FINAL_TRANSFER_QUEUE_MULTIPLIER)
            .max(8);
        let batch_limit = remaining
            .min(FINAL_TRANSFER_BATCH_SIZE)
            .min(queue_window)
            .min(FINAL_TRANSFER_TEST_LIMIT.saturating_sub(transfer_tested.len()))
            .max(1);

        let batch = diversify_recheck_candidates(&untested, batch_limit, 1);
        if batch.is_empty() {
            return Ok(selected.len());
        }

        transfer_tested.extend(batch.iter().cloned());

        println!(
            "[INFO] 📥 [10 MiB] {} SLOTS REMAINING | TESTING {} CANDIDATES",
            remaining,
            batch.len()
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
    // Default backend for configurations not known to require Xray.
    SingBox,
    // Direct route for configurations with known Xray-specific features.
    Xray,
    // Ambiguous/feature-sensitive route: try sing-box first, then Xray only if sing-box does not accept it.
    Fallback,
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

fn value_boolish(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_u64().unwrap_or(0) != 0,
        Value::String(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        _ => false,
    }
}

fn has_disabled_tls_verification(config: &str) -> bool {
    let cleaned = config.split('#').next().unwrap_or(config);
    let Ok(url) = Url::parse(cleaned) else {
        return true;
    };

    let scheme = url.scheme().to_ascii_lowercase();

    if scheme == "vmess" {
        let Some(encoded) = cleaned.split_once("://").map(|(_, rest)| rest) else {
            return true;
        };
        let payload = encoded.trim();
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
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    let tls_enabled = match value.get("tls") {
                        Some(Value::Bool(value)) => *value,
                        Some(Value::Number(value)) => value.as_u64().unwrap_or(0) != 0,
                        Some(Value::String(value)) => !matches!(
                            value.trim().to_ascii_lowercase().as_str(),
                            "" | "0" | "false" | "none" | "off"
                        ),
                        _ => false,
                    };
                    let insecure = value.get("allowInsecure").is_some_and(value_boolish);
                    if tls_enabled && insecure {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    url.query_pairs().any(|(key, value)| {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "insecure" | "allowinsecure"
        ) && matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn xray_only_tls_extensions(url: &Url) -> bool {
    let pcs = query_value(url, &["pcs", "pinnedPeerCertSha256"]);
    let vcn = query_value(url, &["vcn", "verifyPeerCertByName"]);
    let ech = query_value(url, &["ech"]);
    !pcs.is_empty() || !vcn.is_empty() || ech.contains("://")
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

    if scheme == "vmess" {
        if let Some(encoded) = config.split_once("://").map(|(_, rest)| rest) {
            let payload = encoded.split('#').next().unwrap_or("").trim();
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
                    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                        let network = value
                            .get("net")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_ascii_lowercase();

                        if matches!(network.as_str(), "xhttp" | "splithttp") {
                            return LightBackend::Xray;
                        }

                        if network == "grpc" {
                            let mode = value
                                .get("type")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_ascii_lowercase();
                            let has_authority = ["authority", "host"].iter().any(|key| {
                                value
                                    .get(*key)
                                    .and_then(Value::as_str)
                                    .is_some_and(|item| !item.is_empty())
                            });

                            if mode == "multi" || has_authority {
                                return LightBackend::Xray;
                            }
                        }

                        let has_certificate_extension = ["pcs", "vcn"].iter().any(|key| {
                            value
                                .get(*key)
                                .and_then(Value::as_str)
                                .is_some_and(|item| !item.is_empty())
                        });
                        let ech = value
                            .get("ech")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .replace(' ', "+");
                        if has_certificate_extension || ech.contains("://") {
                            return LightBackend::Xray;
                        }
                    }
                }
            }
        }
    }

    let legacy_raw_http = (transport.is_empty() || transport == "tcp" || transport == "raw")
        && query_value(&url, &["headerType"]).eq_ignore_ascii_case("http");

    if legacy_raw_http && !xray_only_tls_extensions(&url) {
        return LightBackend::SingBox;
    }

    if matches!(transport.as_str(), "xhttp" | "splithttp") {
        return LightBackend::Xray;
    }

    if transport == "grpc"
        && (has_query_key(&url, &["authority", "host"])
            || query_value(&url, &["mode"]).eq_ignore_ascii_case("multi"))
    {
        return LightBackend::Xray;
    }

    if xray_only_tls_extensions(&url) {
        return LightBackend::Xray;
    }

    if matches!(scheme.as_str(), "hysteria2" | "hy2") && has_query_key(&url, &["pinSHA256"]) {
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

    // Plain Reality is feature-sensitive: let sing-box have the first attempt,
    // then fall back to Xray only when sing-box does not accept the candidate.
    if security == "reality" {
        return LightBackend::Fallback;
    }

    LightBackend::SingBox
}


fn vmess_payload(config: &str) -> Option<Value> {
    let encoded = config.split_once("://").map(|(_, rest)| rest)?;
    let payload = encoded.split('#').next().unwrap_or("").trim();
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
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                return Some(value);
            }
        }
    }

    None
}

fn json_u64(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Number(number)) => number.as_u64().unwrap_or(0),
        Some(Value::String(string)) => string.trim().parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

fn training_number(value: f64) -> Value {
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn light_training_features(
    config: &str,
    early_metadata: Option<&ProxyMetrics>,
    history_rate: f64,
    history_checks: u64,
) -> BTreeMap<String, Value> {
    let cleaned = config.split('#').next().unwrap_or(config);
    let url = Url::parse(cleaned).ok();
    let protocol = url
        .as_ref()
        .map(|value| value.scheme().to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_string());
    let vmess = if protocol == "vmess" {
        vmess_payload(config)
    } else {
        None
    };

    let transport = if let Some(payload) = vmess.as_ref() {
        payload
            .get("net")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "vmess-default".to_string())
    } else {
        url.as_ref()
            .map(|value| query_value(value, &["type", "network"]).to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "default".to_string())
    };

    let security = if let Some(payload) = vmess.as_ref() {
        if value_boolish(payload.get("tls").unwrap_or(&Value::Null)) {
            "tls".to_string()
        } else {
            "none".to_string()
        }
    } else {
        url.as_ref()
            .map(|value| query_value(value, &["security"]).to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "default".to_string())
    };

    let port = if let Some(payload) = vmess.as_ref() {
        json_u64(payload.get("port"))
    } else {
        url.as_ref()
            .and_then(Url::port)
            .map(u64::from)
            .unwrap_or(0)
    };

    let query_parameter_count = url
        .as_ref()
        .map(|value| value.query_pairs().count() as u64)
        .unwrap_or(0);

    let has_sni = if let Some(payload) = vmess.as_ref() {
        ["sni", "serverName", "servername"].iter().any(|key| {
            payload
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        })
    } else {
        url.as_ref()
            .is_some_and(|value| has_query_key(value, &["sni", "serverName", "servername"]))
    };

    let has_host = if let Some(payload) = vmess.as_ref() {
        ["host", "Host"].iter().any(|key| {
            payload
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        })
    } else {
        url.as_ref()
            .is_some_and(|value| has_query_key(value, &["host", "authority"]))
    };

    let has_path = if let Some(payload) = vmess.as_ref() {
        payload
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    } else {
        url.as_ref()
            .is_some_and(|value| has_query_key(value, &["path"]))
    };

    let tls_enabled = if vmess.is_some() {
        security == "tls"
    } else {
        matches!(security.as_str(), "tls" | "reality" | "xtls")
    };
    let reality_enabled = security == "reality";

    let early_attempts = early_metadata.map(|metrics| metrics.attempts).unwrap_or(0);
    let early_success_rate = early_metadata
        .filter(|metrics| metrics.attempts > 0)
        .map(|metrics| metrics.successes as f64 / metrics.attempts as f64)
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);

    let mut features = BTreeMap::new();
    features.insert("protocol".to_string(), Value::String(protocol));
    features.insert(
        "backend".to_string(),
        Value::String(
            match light_backend(config) {
                LightBackend::SingBox => "sing-box",
                LightBackend::Xray => "xray",
                LightBackend::Fallback => "fallback",
            }
            .to_string(),
        ),
    );
    features.insert("transport".to_string(), Value::String(transport));
    features.insert("security".to_string(), Value::String(security));
    features.insert("port".to_string(), Value::from(port));
    features.insert(
        "query_parameter_count".to_string(),
        Value::from(query_parameter_count),
    );
    features.insert("has_sni".to_string(), Value::Bool(has_sni));
    features.insert("has_host".to_string(), Value::Bool(has_host));
    features.insert("has_path".to_string(), Value::Bool(has_path));
    features.insert("tls_enabled".to_string(), Value::Bool(tls_enabled));
    features.insert(
        "reality_enabled".to_string(),
        Value::Bool(reality_enabled),
    );
    features.insert("early_attempts".to_string(), Value::from(early_attempts));
    features.insert(
        "early_success_rate".to_string(),
        training_number(early_success_rate),
    );

    let metrics = early_metadata;
    features.insert(
        "early_median_ms".to_string(),
        training_number(metrics.map(|value| value.median_ms).unwrap_or(0.0)),
    );
    features.insert(
        "early_min_ms".to_string(),
        training_number(metrics.map(|value| value.min_ms).unwrap_or(0.0)),
    );
    features.insert(
        "early_jitter_ms".to_string(),
        training_number(metrics.map(|value| value.jitter_ms).unwrap_or(0.0)),
    );
    features.insert(
        "early_throughput_kbps".to_string(),
        training_number(metrics.map(|value| value.throughput_kbps).unwrap_or(0.0)),
    );
    features.insert("history_checks".to_string(), Value::from(history_checks));
    features.insert(
        "history_pass_rate".to_string(),
        training_number(history_rate.clamp(0.0, 1.0)),
    );

    features
}

fn persist_light_training_data(
    history: &HashMap<String, HistoryEntry>,
    final_attempts: &HashMap<String, usize>,
    final_metadata: &HashMap<String, ProxyMetrics>,
    global_metadata: &HashMap<String, ProxyMetrics>,
    transfer_tested: &HashSet<String>,
    transfer_verified: &HashMap<String, ProxyMetrics>,
) -> Result<DatasetStats, String> {
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let run_id = env::var("GITHUB_RUN_ID")
        .ok()
        .filter(|value| !value.trim().is_empty());

    let mut rows = Vec::with_capacity(final_attempts.len());
    for (config, attempts) in final_attempts {
        let (history_rate, history_checks) = historical_score(config, history);
        let candidate_fingerprint = history_fingerprint(config);
        let observation_id = if let Some(run_id) = run_id.as_deref() {
            format!("{run_id}:{candidate_fingerprint}")
        } else {
            format!("local:{observed_at}:{candidate_fingerprint}")
        };
        let transfer_was_tested = transfer_tested.contains(config);

        rows.push(TrainingRow {
            observed_at,
            run_id: run_id.clone(),
            candidate_fingerprint,
            observation_id,
            features: light_training_features(
                config,
                global_metadata.get(config),
                history_rate,
                history_checks,
            ),
            strict_pass: final_metadata.contains_key(config),
            strict_checks: *attempts as u64,
            transfer_tested: transfer_was_tested,
            transfer_pass: transfer_was_tested
                .then(|| transfer_verified.contains_key(config)),
        });
    }

    let stats = persist_light_training(LIGHT_TRAINING_PATH, &rows)?;
    let strict_rate = if stats.rows == 0 {
        0.0
    } else {
        stats.strict_passes as f64 / stats.rows as f64
    };

    println!(
        "[INFO] 🧠 [LIGHT ML DATA] +{} ROWS | TOTAL: {} | FEATURES: {} | STRICT PASS RATE: {:.1}% | TRANSFER: {}/{}",
        stats.new_rows,
        stats.rows,
        rows.first().map(|row| row.features.len()).unwrap_or(0),
        strict_rate * 100.0,
        stats.transfer_passes,
        stats.transfer_tests
    );

    Ok(stats)
}

fn merge_light_metadata(
    xray_metadata: HashMap<String, ProxyMetrics>,
    singbox_metadata: HashMap<String, ProxyMetrics>,
) -> HashMap<String, ProxyMetrics> {
    let mut verified = singbox_metadata;
    verified.extend(xray_metadata);
    verified
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
    let mut fallback_candidates = Vec::new();

    for config in candidates {
        match light_backend(config) {
            LightBackend::SingBox => singbox_candidates.push(config.clone()),
            LightBackend::Xray => xray_candidates.push(config.clone()),
            LightBackend::Fallback => fallback_candidates.push(config.clone()),
        }
    }

    let mut singbox_validation_candidates = singbox_candidates;
    singbox_validation_candidates.extend(fallback_candidates.iter().cloned());
    let xray_validation_candidates = xray_candidates;

    let request_timeout = std::time::Duration::try_from_secs_f64(settings.timeout_seconds)
        .map_err(|_| "invalid validation timeout: value overflows Duration".to_string())?;

    let singbox_future = async {
        if singbox_validation_candidates.is_empty() {
            Ok(HashMap::new())
        } else if settings.strict {
            validate_singbox_targets_strict(
                singbox,
                &singbox_validation_candidates,
                targets,
                settings.workers.clamp(1, 40),
                request_timeout,
                settings.timeout_seconds * 1000.0,
            )
            .await
        } else {
            validate_singbox_targets(
                singbox,
                &singbox_validation_candidates,
                targets,
                settings.workers.clamp(1, 40),
                request_timeout,
                settings.timeout_seconds * 1000.0,
            )
            .await
        }
    };

    let xray_future = async {
        if xray_validation_candidates.is_empty() {
            Ok(HashMap::new())
        } else if settings.strict {
            validate_candidates_with_targets_strict(
                xray,
                &xray_validation_candidates,
                targets,
                settings.workers.max(1),
                settings.batch_size,
                settings.timeout_seconds,
            )
            .await
        } else {
            validate_candidates_with_targets(
                xray,
                &xray_validation_candidates,
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
    let mut xray_metadata = xray_result?;

    let fallback_retry = fallback_candidates
        .into_iter()
        .filter(|config| !singbox_metadata.contains_key(config))
        .collect::<Vec<_>>();

    if !fallback_retry.is_empty() {
        println!(
            "[INFO] 🔄 [LIGHT FALLBACK] RETRYING {} CANDIDATES WITH XRAY",
            fallback_retry.len()
        );
        let fallback_xray = if settings.strict {
            validate_candidates_with_targets_strict(
                xray,
                &fallback_retry,
                targets,
                settings.workers.max(1),
                settings.batch_size,
                settings.timeout_seconds,
            )
            .await?
        } else {
            validate_candidates_with_targets(
                xray,
                &fallback_retry,
                targets,
                settings.workers.max(1),
                settings.batch_size,
                settings.timeout_seconds,
            )
            .await?
        };
        xray_metadata.extend(fallback_xray);
    }

    let verified = merge_light_metadata(xray_metadata, singbox_metadata);

    println!(
        "[INFO] ✅ [LIGHT VALIDATION] {}/{} CANDIDATES VERIFIED | TARGETS: {}",
        verified.len(),
        candidates.len(),
        targets.len()
    );

    Ok(verified)
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: polish_light --candidates FILE --output FILE [--workers N]              [--batch-size N] [--timeout SECONDS] [--selected-recheck-limit N]              [--max-candidates N] [--selected-workers N] [--selected-batch-size N]              [--primary-target URL] [--selection-limit N] [--max-per-endpoint N]              [--max-per-family N] [--xray PATH] [--singbox PATH] [--stats PATH]"
        );
        return Ok(());
    }

    let candidates_path = required(&args, "--candidates")?;
    let output = required(&args, "--output")?;
    let stats_path = value(&args, "--stats", "");
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
    let light_targets = [primary_target.as_str(), LIGHT_TARGETS[2]];
    let early_targets = light_targets;
    let strict_targets = light_targets;
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

    let raw_candidates = read_lines(&candidates_path)?;
    let input_candidate_count = raw_candidates.len().min(max_candidates);
    let candidates = raw_candidates
        .into_iter()
        .take(max_candidates)
        .filter(|config| !has_disabled_tls_verification(config))
        .collect::<Vec<_>>();
    let security_rejected = input_candidate_count.saturating_sub(candidates.len());
    let history_path = "subscriptions/light-history.json";
    let history = load_history(history_path)?;
    let intelligence_path = "subscriptions/light-ai.json";
    let intelligence = IntelligenceModel::load(intelligence_path);

    if candidates.is_empty() {
        return Err("no Light candidates available".to_string());
    }

    let mut global_verified = Vec::<String>::new();
    let mut global_positions = HashMap::<String, usize>::new();
    let mut global_metadata = HashMap::<String, ProxyMetrics>::new();
    let mut final_verified = Vec::<String>::new();
    let mut final_attempts = HashMap::<String, usize>::new();
    let mut final_metadata = HashMap::<String, ProxyMetrics>::new();
    let mut transfer_verified = HashMap::<String, ProxyMetrics>::new();
    let mut transfer_tested = HashSet::<String>::new();

    let chunk_count = candidates.len().div_ceil(DISCOVERY_CHUNK_SIZE);

    println!(
        "[INFO] 🔬 [LIGHT] VALIDATION STARTED | {} CANDIDATES | TARGETS: {}",
        candidates.len(),
        early_targets.len()
    );

    for (chunk_index, chunk) in candidates.chunks(DISCOVERY_CHUNK_SIZE).enumerate() {
        let wave = chunk_index + 1;

        println!(
            "[INFO] 🔎 [LIGHT DISCOVERY] WAVE {wave}/{chunk_count} | TESTING {} CANDIDATES | VERIFIED SO FAR: {}",
            chunk.len(),
            global_verified.len()
        );

        let chunk_metadata = validate_light_batch(
            &xray,
            &singbox,
            chunk,
            &early_targets,
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

        sort_ranked(
            &mut global_verified,
            &global_metadata,
            &global_positions,
            &history,
        );
        sort_ranked(
            &mut final_verified,
            &final_metadata,
            &global_positions,
            &history,
        );

        let mut transfer_ranked = transfer_verified.keys().cloned().collect::<Vec<_>>();
        sort_ranked(
            &mut transfer_ranked,
            &transfer_verified,
            &global_positions,
            &history,
        );
        let mut transfer_selected = select_verified_configs(
            &transfer_ranked,
            selection_limit,
            max_per_endpoint,
            max_per_family,
        )
        .len();

        let strict_untested = final_verified
            .iter()
            .filter(|config| !transfer_tested.contains(*config))
            .cloned()
            .collect::<Vec<_>>();
        let strict_untested_eligible =
            selection_eligible_count(&strict_untested, max_per_endpoint, max_per_family);
        let reserve_target = transfer_reserve_target(
            selection_limit,
            transfer_tested.len(),
            transfer_verified.len(),
        );

        if transfer_selected >= selection_limit {
            println!(
                "[INFO] ✅ [LIGHT] TRANSFER-QUALIFIED {}/{} | PUBLISH READY",
                transfer_selected, selection_limit
            );

            let selected = select_verified_configs(
                &transfer_ranked,
                selection_limit,
                max_per_endpoint,
                max_per_family,
            );
            persist_light_result(
                &output,
                &selected,
                history_path,
                &history,
                &final_attempts,
                &final_metadata,
                &intelligence,
                &global_metadata,
                intelligence_path,
                &transfer_tested,
                &transfer_verified,
            )?;
            write_light_stats(
                &stats_path,
                input_candidate_count,
                security_rejected,
                final_metadata.len(),
                transfer_tested.len(),
                transfer_verified.len(),
                selected.len(),
            )?;
            println!(
                "[INFO] ✅ [LIGHT] PUBLISHED {} CONFIGS | 10 MiB GATE PASSED",
                selected.len()
            );
            return Ok(());
        }

        if strict_untested_eligible >= reserve_target {
            println!(
                "[INFO] 🎯 [LIGHT] TRANSFER RESERVE READY | UNTESTED STRICT ELIGIBLE: {} | RESERVE TARGET: {} | TRANSFER QUALIFIED: {}",
                strict_untested_eligible, reserve_target, transfer_selected
            );

            transfer_selected = fill_transfer_gate(
                &xray,
                &singbox,
                &final_verified,
                &mut transfer_verified,
                &mut transfer_tested,
                &global_positions,
                &history,
                selection_limit,
                max_per_endpoint,
                max_per_family,
            )
            .await?;

            if transfer_selected >= selection_limit {
                let mut transfer_ranked = transfer_verified.keys().cloned().collect::<Vec<_>>();
                sort_ranked(
                    &mut transfer_ranked,
                    &transfer_verified,
                    &global_positions,
                    &history,
                );
                let selected = select_verified_configs(
                    &transfer_ranked,
                    selection_limit,
                    max_per_endpoint,
                    max_per_family,
                );

                persist_light_result(
                    &output,
                    &selected,
                    history_path,
                    &history,
                    &final_attempts,
                    &final_metadata,
                    &intelligence,
                    &global_metadata,
                    intelligence_path,
                    &transfer_tested,
                    &transfer_verified,
                )?;
                write_light_stats(
                    &stats_path,
                    input_candidate_count,
                    security_rejected,
                    final_metadata.len(),
                    transfer_tested.len(),
                    transfer_verified.len(),
                    selected.len(),
                )?;
                println!(
                    "[INFO] ✅ [LIGHT] PUBLISHED {} CONFIGS | 10 MiB GATE PASSED",
                    selected.len()
                );
                return Ok(());
            }
        }

        let remaining = selection_limit.saturating_sub(transfer_selected);

        let strict_attempts = final_attempts.values().copied().sum::<usize>();
        let dynamic_limit = adaptive_recheck_limit(
            remaining,
            final_recheck_limit,
            strict_attempts,
            final_metadata.len(),
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

        let mut ai_ranked = untested;
        intelligence.rank(&mut ai_ranked, &global_metadata, &global_positions);
        let final_candidates =
            diversify_recheck_candidates(&ai_ranked, dynamic_limit, RECHECK_FAMILY_DIVERSITY);

        if final_candidates.is_empty() {
            continue;
        }

        for config in &final_candidates {
            *final_attempts.entry(config.clone()).or_default() += 1;
        }

        println!(
            "[INFO] 🔎 [LIGHT RECHECK] WAVE {wave} | TESTING {} CANDIDATES",
            final_candidates.len()
        );

        let primary_metadata = validate_light_batch(
            &xray,
            &singbox,
            &final_candidates,
            &strict_targets,
            ValidationSettings {
                workers: final_workers,
                batch_size: final_batch_size,
                timeout_seconds: timeout,
                strict: true,
            },
        )
        .await?;

        for (config, mut metrics) in primary_metadata {
            if metrics.throughput_kbps <= 0.0 {
                if let Some(early) = global_metadata.get(&config) {
                    metrics.throughput_kbps = early.throughput_kbps;
                }
            }
            if !final_metadata.contains_key(&config) {
                final_verified.push(config.clone());
            }
            final_metadata.insert(config, metrics);
        }

        if let Some(message) = intelligence
            .anomaly_message(final_attempts.values().copied().sum(), final_metadata.len())
        {
            println!("[WARN] ⚠️ {message}");
        }

        sort_ranked(
            &mut final_verified,
            &final_metadata,
            &global_positions,
            &history,
        );
        let selected = select_verified_configs(
            &final_verified,
            selection_limit,
            max_per_endpoint,
            max_per_family,
        );

        let strict_untested = final_verified
            .iter()
            .filter(|config| !transfer_tested.contains(*config))
            .cloned()
            .collect::<Vec<_>>();
        let strict_untested_eligible =
            selection_eligible_count(&strict_untested, max_per_endpoint, max_per_family);
        let reserve_target = transfer_reserve_target(
            selection_limit,
            transfer_tested.len(),
            transfer_verified.len(),
        );
        let mut transfer_ranked_after = transfer_verified.keys().cloned().collect::<Vec<_>>();
        sort_ranked(
            &mut transfer_ranked_after,
            &transfer_verified,
            &global_positions,
            &history,
        );
        let transfer_eligible =
            selection_eligible_count(&transfer_ranked_after, max_per_endpoint, max_per_family);
        let transfer_slots_remaining = selection_limit.saturating_sub(transfer_eligible);

        println!(
            "[INFO] 📈 [LIGHT FILL] STRICT POOL: {}/{} | UNTESTED STRICT ELIGIBLE: {} | TRANSFER QUALIFIED: {} | TRANSFER SLOTS REMAINING: {} | RESERVE TARGET: {} | STRICT CHECKS: {}",
            selected.len(),
            selection_limit,
            strict_untested_eligible,
            transfer_eligible,
            transfer_slots_remaining,
            reserve_target,
            final_attempts.values().copied().sum::<usize>()
        );

        if strict_untested_eligible >= reserve_target {
            println!(
                "[INFO] 🎯 [LIGHT] TRANSFER RESERVE READY | UNTESTED STRICT ELIGIBLE: {} | RESERVE TARGET: {}",
                strict_untested_eligible, reserve_target
            );
        } else {
            println!(
                "[INFO] ⏭️ [LIGHT] DISCOVER MORE | UNTESTED STRICT ELIGIBLE: {} | RESERVE TARGET: {} | NEED {} MORE",
                strict_untested_eligible,
                reserve_target,
                reserve_target.saturating_sub(strict_untested_eligible)
            );
        }
    }

    sort_ranked(
        &mut final_verified,
        &final_metadata,
        &global_positions,
        &history,
    );
    let _ = fill_transfer_gate(
        &xray,
        &singbox,
        &final_verified,
        &mut transfer_verified,
        &mut transfer_tested,
        &global_positions,
        &history,
        selection_limit,
        max_per_endpoint,
        max_per_family,
    )
    .await?;

    let mut transfer_ranked = transfer_verified.keys().cloned().collect::<Vec<_>>();
    sort_ranked(
        &mut transfer_ranked,
        &transfer_verified,
        &global_positions,
        &history,
    );
    let selected = select_verified_configs(
        &transfer_ranked,
        selection_limit,
        max_per_endpoint,
        max_per_family,
    );

    if selected.len() < selection_limit {
        persist_light_training_data(
            &history,
            &final_attempts,
            &final_metadata,
            &global_metadata,
            &transfer_tested,
            &transfer_verified,
        )?;
        persist_history(history_path, &history, &final_attempts, &final_metadata)?;
        write_light_stats(
            &stats_path,
            input_candidate_count,
            security_rejected,
            final_metadata.len(),
            transfer_tested.len(),
            transfer_verified.len(),
            selected.len(),
        )?;
        return Err(format!(
            "selected Light validation produced {} configs after the 10 MiB gate; required {}",
            selected.len(),
            selection_limit
        ));
    }

    write_light_stats(
        &stats_path,
        input_candidate_count,
        security_rejected,
        final_metadata.len(),
        transfer_tested.len(),
        transfer_verified.len(),
        selected.len(),
    )?;

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
            LightBackend::Fallback => *backend_counts.entry("fallback").or_default() += 1,
        }
    }
    for chunk in protocol_counts
        .iter()
        .map(|(scheme, count)| format!("{scheme} {count}"))
        .collect::<Vec<_>>()
        .chunks(4)
    {
        println!("[INFO] 📊 [LIGHT PROTOCOLS] {}", chunk.join(" | "));
    }

    let backend_summary = backend_counts
        .iter()
        .map(|(backend, count)| format!("{backend} {count}"))
        .collect::<Vec<_>>()
        .join(" | ");
    println!("[INFO] 📊 [LIGHT BACKENDS] {backend_summary}");

    println!(
        "[INFO] 🎯 [LIGHT SELECTION] {} CONFIGS READY | NO PROTOCOL QUOTA",
        selected.len()
    );

    persist_light_result(
        &output,
        &selected,
        history_path,
        &history,
        &final_attempts,
        &final_metadata,
        &intelligence,
        &global_metadata,
        intelligence_path,
        &transfer_tested,
        &transfer_verified,
    )?;
    println!(
        "[INFO] ✅ [LIGHT] PUBLISHED {} CONFIGS | DISCOVERY: {} | STRICT CHECKS: {} | TRANSFER TESTED: {} | TRANSFER PASSES: {}",
        selected.len(),
        candidates.len(),
        final_attempts.values().copied().sum::<usize>(),
        transfer_tested.len(),
        transfer_verified.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        adaptive_recheck_limit, has_disabled_tls_verification, history_fingerprint, light_backend,
        merge_light_metadata, normalize_light_config, select_verified_configs,
        selection_eligible_count, transfer_reserve_target, LightBackend, ProxyMetrics,
    };
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use std::collections::HashMap;

    #[test]
    fn rejects_explicit_tls_verification_bypass() {
        assert!(has_disabled_tls_verification(
            "trojan://password@example.com:443?security=tls&allowInsecure=1"
        ));
        assert!(has_disabled_tls_verification(
            "hysteria2://password@example.com:443?insecure=true"
        ));
        assert!(!has_disabled_tls_verification(
            "vless://uuid@example.com:443?security=tls&allowInsecure=0"
        ));
        assert!(!has_disabled_tls_verification(
            "vless://uuid@example.com:443?security=none"
        ));
    }

    #[test]
    fn rejects_vmess_tls_verification_bypass() {
        let payload = serde_json::json!({
            "add": "example.com",
            "port": 443,
            "id": "00000000-0000-0000-0000-000000000001",
            "tls": "tls",
            "allowInsecure": true
        });
        let encoded = STANDARD.encode(payload.to_string());
        assert!(has_disabled_tls_verification(&format!("vmess://{encoded}")));
    }

    #[test]
    fn allows_vmess_tls_with_certificate_verification() {
        let payload = serde_json::json!({
            "add": "example.com",
            "port": 443,
            "id": "00000000-0000-0000-0000-000000000001",
            "tls": "tls",
            "allowInsecure": false
        });
        let encoded = STANDARD.encode(payload.to_string());
        assert!(!has_disabled_tls_verification(&format!(
            "vmess://{encoded}"
        )));
    }

    #[test]
    fn adaptive_recheck_expands_when_yield_is_low() {
        assert_eq!(adaptive_recheck_limit(100, 500, 0, 0), 500);
        assert_eq!(adaptive_recheck_limit(100, 500, 100, 50), 250);
        assert_eq!(adaptive_recheck_limit(100, 500, 100, 20), 500);
    }

    #[test]
    fn transfer_reserve_is_conservative_at_start() {
        assert_eq!(transfer_reserve_target(200, 0, 0), 270);
        assert_eq!(transfer_reserve_target(200, 200, 190), 260);
    }

    #[test]
    fn transfer_reserve_scales_with_low_pass_rate_and_is_capped() {
        assert_eq!(transfer_reserve_target(200, 200, 160), 273);
        assert_eq!(transfer_reserve_target(200, 200, 100), 320);
    }

    #[test]
    fn selection_eligible_count_respects_endpoint_limit() {
        let configs = vec![
            "vless://a@example.com:443".to_string(),
            "vless://b@example.com:443".to_string(),
            "vless://c@example.net:443".to_string(),
        ];
        assert_eq!(selection_eligible_count(&configs, 1, 3), 2);
    }

    #[test]
    fn history_fingerprint_ignores_vmess_ps_label() {
        let a = format!(
            "vmess://{}",
            STANDARD.encode(br#"{"ps":"A 01","add":"example.com","port":443}"#)
        );
        let b = format!(
            "vmess://{}",
            STANDARD.encode(br#"{"ps":"B 01","add":"example.com","port":443}"#)
        );
        assert_eq!(history_fingerprint(&a), history_fingerprint(&b));
    }

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
    fn routes_reality_to_backend_fallback() {
        let config =
            "vless://uuid@example.com:443?security=reality&type=tcp&pbk=public&sid=01&sni=example.com";
        assert_eq!(light_backend(config), LightBackend::Fallback);
    }

    #[test]
    fn routes_grpc_authority_to_xray() {
        let config =
            "vless://uuid@example.com:443?security=tls&type=grpc&serviceName=Tun&authority=grpc.example.com";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_grpc_host_to_xray() {
        let config =
            "vless://uuid@example.com:443?security=tls&type=grpc&serviceName=Tun&host=grpc.example.com";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_legacy_raw_http_to_singbox() {
        let config =
            "vless://uuid@example.com:443?security=tls&type=tcp&headerType=http&host=example.com&path=%2Fproxy";
        assert_eq!(light_backend(config), LightBackend::SingBox);
    }

    #[test]
    fn routes_vmess_xhttp_to_xray_only() {
        let payload = r#"{"v":"2","add":"example.com","port":"443","id":"00000000-0000-0000-0000-000000000001","net":"xhttp"}"#;
        let config = format!("vmess://{}", STANDARD.encode(payload));
        assert_eq!(light_backend(&config), LightBackend::Xray);
    }

    #[test]
    fn routes_vmess_splithttp_to_xray_only() {
        let payload = r#"{"v":"2","add":"example.com","port":"443","id":"00000000-0000-0000-0000-000000000001","net":"splithttp"}"#;
        let config = format!("vmess://{}", STANDARD.encode(payload));
        assert_eq!(light_backend(&config), LightBackend::Xray);
    }

    #[test]
    fn routes_url_splithttp_to_xray_only() {
        let config = "vless://uuid@example.com:443?security=tls&type=splithttp";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_vmess_grpc_host_to_xray() {
        let payload = r#"{"v":"2","add":"example.com","port":"443","id":"00000000-0000-0000-0000-000000000001","net":"grpc","type":"gun","host":"grpc.example.com"}"#;
        let config = format!("vmess://{}", STANDARD.encode(payload));
        assert_eq!(light_backend(&config), LightBackend::Xray);
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
    fn routes_vless_ech_dns_resolver_to_xray() {
        let config =
            "vless://uuid@example.com:443?security=tls&type=ws&ech=example.com%2Bhttps%3A%2F%2Fdns.example%2Fdns-query";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn routes_vless_certificate_pinning_to_xray() {
        let config =
            "vless://uuid@example.com:443?security=tls&type=ws&pcs=0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(light_backend(config), LightBackend::Xray);

        let config = "vless://uuid@example.com:443?security=tls&type=ws&vcn=example.com";
        assert_eq!(light_backend(config), LightBackend::Xray);
    }

    #[test]
    fn keeps_raw_vless_ech_on_singbox() {
        let config = "vless://uuid@example.com:443?security=tls&type=ws&ech=YWJj";
        assert_eq!(light_backend(config), LightBackend::SingBox);
    }

    #[test]
    fn routes_hysteria2_pin_sha256_to_xray() {
        let config = "hysteria2://password@example.com:443?pinSHA256=AA%3ABB%3ACC%3ADD";
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
    fn explicit_tcp_transport_is_supported_by_light_parser() {
        let config =
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&type=tcp";
        assert_eq!(light_backend(config), LightBackend::SingBox);
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
    fn light_training_features_are_precheck_only() {
        let metrics = ProxyMetrics {
            successes: 2,
            attempts: 3,
            median_ms: 120.0,
            min_ms: 80.0,
            jitter_ms: 10.0,
            throughput_kbps: 900.0,
        };

        let features = super::light_training_features(
            "vless://uuid@example.com:443?security=tls&type=ws&sni=example.com&path=%2F",
            Some(&metrics),
            0.75,
            4,
        );

        assert_eq!(features.len(), proxyrift::light_training::FEATURE_COUNT);
        assert_eq!(
            features.get("protocol"),
            Some(&serde_json::Value::String("vless".to_string()))
        );
        assert_eq!(
            features.get("transport").and_then(serde_json::Value::as_str),
            Some("ws")
        );
        assert_eq!(
            features.get("security").and_then(serde_json::Value::as_str),
            Some("tls")
        );
        assert_eq!(
            features.get("early_attempts").and_then(serde_json::Value::as_u64),
            Some(3)
        );
        assert_eq!(
            features.get("history_checks").and_then(serde_json::Value::as_u64),
            Some(4)
        );
        assert!(!features.values().any(|value| {
            value
                .as_str()
                .is_some_and(|text| text.contains("uuid@example.com"))
        }));
    }

    #[test]
    fn backend_metadata_accepts_either_core() {
        let xray = HashMap::from([(
            "xray-only".to_string(),
            ProxyMetrics {
                successes: 5,
                attempts: 8,
                median_ms: 10.0,
                min_ms: 4.0,
                jitter_ms: 2.0,
                throughput_kbps: 80.0,
            },
        )]);
        let singbox = HashMap::from([(
            "singbox-only".to_string(),
            ProxyMetrics {
                successes: 5,
                attempts: 6,
                median_ms: 12.0,
                min_ms: 6.0,
                jitter_ms: 1.5,
                throughput_kbps: 70.0,
            },
        )]);

        let merged = merge_light_metadata(xray, singbox);

        assert!(merged.contains_key("xray-only"));
        assert!(merged.contains_key("singbox-only"));
    }

    #[test]
    fn recheck_diversity_limits_are_not_relaxed_by_fallback() {
        let configs = vec![
            "vless://a@example.com:443".to_string(),
            "vless://b@example.com:443".to_string(),
            "vless://c@example.net:443".to_string(),
        ];

        let selected = super::diversify_recheck_candidates(&configs, 3, 1);

        assert_eq!(
            selected,
            vec![
                "vless://a@example.com:443".to_string(),
                "vless://c@example.net:443".to_string(),
            ]
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
