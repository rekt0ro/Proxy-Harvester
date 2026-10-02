use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DATASET_VERSION: u64 = 1;
pub const FEATURE_COUNT: usize = 19;

const MAX_ROWS: usize = 50_000;
const RETENTION_SECS: u64 = 45 * 24 * 60 * 60;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DatasetStats {
    pub rows: usize,
    pub new_rows: usize,
    pub strict_passes: usize,
    pub transfer_tests: usize,
    pub transfer_passes: usize,
}

#[derive(Clone, Debug)]
pub struct TrainingRow {
    pub observed_at: u64,
    pub run_id: Option<String>,
    pub candidate_fingerprint: String,
    pub observation_id: String,
    pub features: BTreeMap<String, Value>,
    pub strict_pass: bool,
    pub strict_checks: u64,
    pub transfer_tested: bool,
    pub transfer_pass: Option<bool>,
}

pub fn persist(path: &str, rows: &[TrainingRow]) -> Result<DatasetStats, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();

    persist_at(path, rows, now)
}

fn persist_at(path: &str, rows: &[TrainingRow], now: u64) -> Result<DatasetStats, String> {
    let mut by_id = BTreeMap::<String, Value>::new();

    if let Ok(file) = File::open(path) {
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|error| error.to_string())?;
            if line.trim().is_empty() {
                continue;
            }

            let Ok(value) = serde_json::from_str::<Value>(&line) else {
                continue;
            };

            if !valid_stored_row(&value) {
                continue;
            }

            let observed_at = value
                .get("observed_at")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if observed_at.saturating_add(RETENTION_SECS) < now {
                continue;
            }

            let Some(observation_id) = value.get("observation_id").and_then(Value::as_str) else {
                continue;
            };

            by_id.insert(observation_id.to_string(), value);
        }
    }

    let mut new_rows = 0usize;
    for row in rows {
        if row.observed_at.saturating_add(RETENTION_SECS) < now {
            continue;
        }

        let value = row.to_value();
        if by_id.insert(row.observation_id.clone(), value).is_none() {
            new_rows += 1;
        }
    }

    let mut values = by_id.into_values().collect::<Vec<_>>();
    values.sort_unstable_by(|a, b| {
        b.get("observed_at")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .cmp(&a.get("observed_at").and_then(Value::as_u64).unwrap_or(0))
            .then_with(|| {
                a.get("observation_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(
                        b.get("observation_id")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    )
            })
    });
    values.truncate(MAX_ROWS);

    let mut strict_passes = 0usize;
    let mut transfer_tests = 0usize;
    let mut transfer_passes = 0usize;
    for value in &values {
        let label = value.get("label").and_then(Value::as_object);
        if label
            .and_then(|label| label.get("strict_pass"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            strict_passes += 1;
        }
        if label
            .and_then(|label| label.get("transfer_tested"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            transfer_tests += 1;
            if label
                .and_then(|label| label.get("transfer_pass"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                transfer_passes += 1;
            }
        }
    }

    let temporary = format!("{path}.tmp");
    let mut body = String::new();
    for value in &values {
        let line = serde_json::to_string(value).map_err(|error| error.to_string())?;
        body.push_str(&line);
        body.push('\n');
    }

    if let Err(error) = fs::write(&temporary, body) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }

    Ok(DatasetStats {
        rows: values.len(),
        new_rows,
        strict_passes,
        transfer_tests,
        transfer_passes,
    })
}

impl TrainingRow {
    fn to_value(&self) -> Value {
        let mut root = Map::new();
        root.insert("schema_version".to_string(), Value::from(DATASET_VERSION));
        root.insert(
            "observation_id".to_string(),
            Value::from(self.observation_id.clone()),
        );
        root.insert("observed_at".to_string(), Value::from(self.observed_at));
        root.insert(
            "candidate_fingerprint".to_string(),
            Value::from(self.candidate_fingerprint.clone()),
        );

        if let Some(run_id) = &self.run_id {
            root.insert("run_id".to_string(), Value::from(run_id.clone()));
        }

        root.insert(
            "features".to_string(),
            Value::Object(
                self.features
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            ),
        );

        let mut label = Map::new();
        label.insert("strict_pass".to_string(), Value::from(self.strict_pass));
        label.insert("strict_checks".to_string(), Value::from(self.strict_checks));
        label.insert(
            "transfer_tested".to_string(),
            Value::from(self.transfer_tested),
        );
        label.insert(
            "transfer_pass".to_string(),
            self.transfer_pass.map(Value::from).unwrap_or(Value::Null),
        );
        root.insert("label".to_string(), Value::Object(label));

        Value::Object(root)
    }
}

const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "protocol",
    "backend",
    "transport",
    "security",
    "port",
    "query_parameter_count",
    "has_sni",
    "has_host",
    "has_path",
    "tls_enabled",
    "reality_enabled",
    "early_attempts",
    "early_success_rate",
    "early_median_ms",
    "early_min_ms",
    "early_jitter_ms",
    "early_throughput_kbps",
    "history_checks",
    "history_pass_rate",
];

fn finite_number(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_f64)
        .is_some_and(f64::is_finite)
}

fn valid_stored_row(value: &Value) -> bool {
    if value
        .get("schema_version")
        .and_then(Value::as_u64)
        != Some(DATASET_VERSION)
        || value
            .get("observation_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || value.get("candidate_fingerprint").and_then(Value::as_str).is_none_or(str::is_empty)
        || value.get("observed_at").and_then(Value::as_u64).is_none()
    {
        return false;
    }

    let Some(features) = value.get("features").and_then(Value::as_object) else {
        return false;
    };

    if features.len() != FEATURE_COUNT
        || !FEATURE_NAMES.iter().all(|name| features.contains_key(*name))
    {
        return false;
    }

    for name in ["protocol", "backend", "transport", "security"] {
        if features
            .get(name)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return false;
        }
    }

    for name in ["port", "query_parameter_count", "early_attempts", "history_checks"] {
        if features.get(name).and_then(Value::as_u64).is_none() {
            return false;
        }
    }

    for name in [
        "has_sni",
        "has_host",
        "has_path",
        "tls_enabled",
        "reality_enabled",
    ] {
        if features.get(name).and_then(Value::as_bool).is_none() {
            return false;
        }
    }

    for name in [
        "early_success_rate",
        "early_median_ms",
        "early_min_ms",
        "early_jitter_ms",
        "early_throughput_kbps",
        "history_pass_rate",
    ] {
        if !finite_number(features.get(name)) {
            return false;
        }
    }

    let Some(label) = value.get("label").and_then(Value::as_object) else {
        return false;
    };

    if label.get("strict_pass").and_then(Value::as_bool).is_none()
        || label.get("strict_checks").and_then(Value::as_u64).is_none()
        || label.get("transfer_tested").and_then(Value::as_bool).is_none()
    {
        return false;
    }

    if label
        .get("strict_checks")
        .and_then(Value::as_u64)
        .is_none_or(|checks| checks == 0)
    {
        return false;
    }

    let transfer_tested = label
        .get("transfer_tested")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match label.get("transfer_pass") {
        Some(Value::Null) if !transfer_tested => true,
        Some(Value::Bool(_)) if transfer_tested => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{persist_at, TrainingRow, DATASET_VERSION, FEATURE_COUNT};
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path() -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        format!(
            "{}/proxyrift-light-training-{}-{nonce}.jsonl",
            std::env::temp_dir().display(),
            std::process::id()
        )
    }

    fn row(
        id: &str,
        observed_at: u64,
        strict_pass: bool,
        transfer_pass: Option<bool>,
    ) -> TrainingRow {
        TrainingRow {
            observed_at,
            run_id: Some("test-run".to_string()),
            candidate_fingerprint: format!("fp-{id}"),
            observation_id: id.to_string(),
            features: BTreeMap::from([
                ("protocol".to_string(), Value::from("vless")),
                ("latency".to_string(), Value::from(100.0)),
            ]),
            strict_pass,
            strict_checks: 1,
            transfer_tested: transfer_pass.is_some(),
            transfer_pass,
        }
    }

    #[test]
    fn schema_is_versioned_and_stats_are_reported() {
        let path = temp_path();
        let stats = persist_at(
            &path,
            &[
                row("one", 1_000, true, Some(true)),
                row("two", 1_001, false, Some(false)),
            ],
            1_001,
        )
        .expect("persist dataset");

        assert_eq!(stats.rows, 2);
        assert_eq!(stats.new_rows, 2);
        assert_eq!(stats.strict_passes, 1);
        assert_eq!(stats.transfer_tests, 2);
        assert_eq!(stats.transfer_passes, 1);

        let body = fs::read_to_string(&path).expect("read dataset");
        let first = body.lines().next().expect("first row");
        let value: Value = serde_json::from_str(first).expect("parse row");
        assert_eq!(
            value.get("schema_version").and_then(Value::as_u64),
            Some(DATASET_VERSION)
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn duplicate_observation_ids_are_idempotent() {
        let path = temp_path();
        let first = row("same", 1_000, true, None);
        let second = row("same", 1_001, false, None);

        persist_at(&path, &[first], 1_001).expect("initial persist");
        let stats = persist_at(&path, &[second], 1_001).expect("deduplicated persist");

        assert_eq!(stats.rows, 1);
        assert_eq!(stats.new_rows, 0);
        assert_eq!(stats.strict_passes, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn old_rows_and_excess_rows_are_pruned() {
        let path = temp_path();
        let mut rows = vec![row("fresh", 1_000, true, None)];
        rows.push(row("old", 1, true, None));

        persist_at(&path, &rows, 1_000 + 45 * 24 * 60 * 60).expect("persist retained rows");

        let body = fs::read_to_string(&path).expect("read dataset");
        assert_eq!(body.lines().count(), 1);
        assert!(body.contains("\"fresh\""));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_rows_with_wrong_feature_schema() {
        let path = temp_path();
        let mut value = row("invalid", 1_000, true, None).to_value();
        value["features"]
            .as_object_mut()
            .expect("features object")
            .remove("history_pass_rate");

        assert!(!super::valid_stored_row(&value));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_zero_strict_checks() {
        let mut value = row("invalid-checks", 1_000, true, None).to_value();
        value["label"]["strict_checks"] = Value::from(0u64);
        assert!(!super::valid_stored_row(&value));
    }

    #[test]
    fn feature_count_contract_is_explicit() {
        assert_eq!(FEATURE_COUNT, 19);
    }
}
