use crate::validator::ProxyMetrics;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;

const MODEL_VERSION: u64 = 1;
const MIN_TRAINING_SAMPLES: u64 = 50;
const MIN_FEATURES: usize = 3;
const MIN_ANOMALY_TRAINING_SAMPLES: u64 = 200;
const MIN_ANOMALY_CANDIDATES: usize = 50;
const MIN_ANOMALY_GAP: f64 = 0.15;
const ANOMALY_Z_SCORE: f64 = 1.96;

#[derive(Clone, Debug, Default)]
struct FeatureStats {
    attempts: u64,
    successes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct IntelligenceModel {
    features: HashMap<String, FeatureStats>,
    total_attempts: u64,
    total_successes: u64,
}

impl IntelligenceModel {
    pub fn load(path: &str) -> Self {
        let Ok(content) = fs::read_to_string(path) else {
            return Self::default();
        };
        let Ok(value) = serde_json::from_str::<Value>(&content) else {
            return Self::default();
        };

        let mut model = Self {
            total_attempts: value
                .get("total_attempts")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            total_successes: value
                .get("total_successes")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            ..Self::default()
        };
        model.total_successes = model.total_successes.min(model.total_attempts);

        if let Some(features) = value.get("features").and_then(Value::as_object) {
            for (key, entry) in features {
                let attempts = entry.get("attempts").and_then(Value::as_u64).unwrap_or(0);
                let successes = entry
                    .get("successes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .min(attempts);
                if attempts > 0 {
                    model.features.insert(
                        key.clone(),
                        FeatureStats {
                            attempts,
                            successes,
                        },
                    );
                }
            }
        }

        model
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let mut features = serde_json::Map::new();
        for (key, stats) in &self.features {
            features.insert(
                key.clone(),
                serde_json::json!({
                    "attempts": stats.attempts,
                    "successes": stats.successes.min(stats.attempts),
                }),
            );
        }

        let value = serde_json::json!({
            "version": MODEL_VERSION,
            "total_attempts": self.total_attempts,
            "total_successes": self.total_successes.min(self.total_attempts),
            "features": features,
        });
        let body = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
        let temporary = format!("{path}.tmp");
        fs::write(&temporary, body).map_err(|error| error.to_string())?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error.to_string());
        }
        Ok(())
    }

    pub fn is_mature(&self) -> bool {
        self.total_attempts >= MIN_TRAINING_SAMPLES && self.features.len() >= MIN_FEATURES
    }

    pub fn update(
        &mut self,
        config: &str,
        metrics: Option<&ProxyMetrics>,
        observations: usize,
        passed: bool,
    ) {
        if observations == 0 {
            return;
        }

        let successes = u64::from(passed);
        let observations = observations as u64;
        let key = feature_key(config, metrics);
        let entry = self.features.entry(key).or_default();
        entry.attempts = entry.attempts.saturating_add(observations);
        entry.successes = entry
            .successes
            .saturating_add(successes)
            .min(entry.attempts);
        self.total_attempts = self.total_attempts.saturating_add(observations);
        self.total_successes = self
            .total_successes
            .saturating_add(successes)
            .min(self.total_attempts);
    }

    pub fn rank(
        &self,
        configs: &mut [String],
        metadata: &HashMap<String, ProxyMetrics>,
        positions: &HashMap<String, usize>,
    ) {
        if !self.is_mature() || configs.len() < 2 {
            return;
        }

        configs.sort_unstable_by(|a, b| {
            self.score(b, metadata.get(b))
                .total_cmp(&self.score(a, metadata.get(a)))
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

    pub fn anomaly_message(&self, checked_candidates: usize, successes: usize) -> Option<String> {
        if !self.is_mature()
            || self.total_attempts < MIN_ANOMALY_TRAINING_SAMPLES
            || checked_candidates < MIN_ANOMALY_CANDIDATES
        {
            return None;
        }

        let checked_candidates = checked_candidates as f64;
        let successes = (successes as f64).min(checked_candidates);
        let observed = successes / checked_candidates;
        let expected = (self.total_successes as f64 + 2.0) / (self.total_attempts as f64 + 4.0);
        let gap = (observed - expected).abs();

        if gap < MIN_ANOMALY_GAP {
            return None;
        }

        let (lower, upper) = wilson_interval(successes, checked_candidates, ANOMALY_Z_SCORE);
        let statistically_distinct = if observed < expected {
            upper < expected
        } else {
            lower > expected
        };

        if !statistically_distinct {
            return None;
        }

        Some(format!(
            "AI anomaly signal: current strict pass rate {:.1}% vs learned baseline {:.1}%",
            observed * 100.0,
            expected * 100.0
        ))
    }

    fn score(&self, config: &str, metrics: Option<&ProxyMetrics>) -> f64 {
        let key = feature_key(config, metrics);
        let stats = self.features.get(&key);
        let (attempts, successes) = stats
            .map(|value| (value.attempts, value.successes))
            .unwrap_or((0, 0));

        let mean = if attempts == 0 {
            (self.total_successes as f64 + 2.0) / (self.total_attempts as f64 + 4.0)
        } else {
            (successes as f64 + 2.0) / (attempts as f64 + 4.0)
        };

        let exploration = 0.05 / ((attempts + 1) as f64).sqrt();
        (mean + exploration).clamp(0.0, 1.0)
    }
}

fn wilson_interval(successes: f64, attempts: f64, z: f64) -> (f64, f64) {
    let proportion = (successes / attempts).clamp(0.0, 1.0);
    let z_squared = z * z;
    let denominator = 1.0 + z_squared / attempts;
    let center = (proportion + z_squared / (2.0 * attempts)) / denominator;
    let margin = z
        * ((proportion * (1.0 - proportion) / attempts) + z_squared / (4.0 * attempts * attempts))
            .sqrt()
        / denominator;

    (
        (center - margin).clamp(0.0, 1.0),
        (center + margin).clamp(0.0, 1.0),
    )
}

fn feature_key(config: &str, metrics: Option<&ProxyMetrics>) -> String {
    let scheme = config
        .split_once("://")
        .map(|(value, _)| value.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_string());

    let latency = metrics.map(|value| value.median_ms).unwrap_or(1200.0);
    let latency_bucket = if latency.is_finite() {
        ((latency.max(0.0) / 100.0).floor() as u64).min(12)
    } else {
        12
    };

    format!("{scheme}|latency:{latency_bucket}")
}
#[cfg(test)]
mod tests {
    use super::IntelligenceModel;
    use crate::validator::ProxyMetrics;
    use std::collections::HashMap;

    fn metrics(latency: f64) -> ProxyMetrics {
        ProxyMetrics {
            successes: 1,
            attempts: 1,
            median_ms: latency,
            min_ms: latency,
            jitter_ms: 1.0,
            throughput_kbps: 1000.0,
        }
    }

    fn mature_model_with_baseline(attempts: usize, successes: usize) -> IntelligenceModel {
        let mut model = IntelligenceModel::default();
        let configs = [
            "vless://a@example.com:443",
            "trojan://b@example.com:443",
            "hysteria2://c@example.com:443",
        ];

        for index in 0..attempts {
            model.update(
                configs[index % configs.len()],
                Some(&metrics((index % 3 * 100 + 100) as f64)),
                1,
                index < successes,
            );
        }

        model
    }

    #[test]
    fn anomaly_signal_waits_for_historical_and_current_sample_sizes() {
        let model = mature_model_with_baseline(100, 80);
        assert!(model.anomaly_message(50, 10).is_none());

        let model = mature_model_with_baseline(200, 160);
        assert!(model.anomaly_message(30, 18).is_none());
    }

    #[test]
    fn anomaly_signal_requires_meaningful_gap_and_statistical_separation() {
        let model = mature_model_with_baseline(200, 160);

        assert!(model.anomaly_message(50, 34).is_none());
        assert!(model.anomaly_message(50, 32).is_some());
    }

    #[test]
    fn anomaly_signal_uses_unique_candidate_checks() {
        let model = mature_model_with_baseline(200, 160);

        assert!(model.anomaly_message(100, 52).is_some());
        assert!(model.anomaly_message(100, 75).is_none());
    }

    #[test]
    fn wilson_interval_stays_within_probability_bounds() {
        let (lower, upper) = super::wilson_interval(32.0, 50.0, 1.96);
        assert!((0.0..=1.0).contains(&lower));
        assert!((0.0..=1.0).contains(&upper));
        assert!(lower < 0.64);
        assert!(upper > 0.64);
    }

    #[test]
    fn remains_inert_until_enough_training_data() {
        let model = IntelligenceModel::default();
        let mut configs = vec![
            "vless://a@example.com:443".to_string(),
            "trojan://b@example.com:443".to_string(),
        ];
        let mut metadata = HashMap::new();
        metadata.insert(configs[0].clone(), metrics(50.0));
        metadata.insert(configs[1].clone(), metrics(900.0));
        let positions = configs
            .iter()
            .enumerate()
            .map(|(index, config)| (config.clone(), index))
            .collect::<HashMap<_, _>>();

        model.rank(&mut configs, &metadata, &positions);
        assert_eq!(configs[0], "vless://a@example.com:443");
    }

    #[test]
    fn candidate_observation_counts_success_once() {
        let mut model = IntelligenceModel::default();
        model.update("vless://a@example.com:443", Some(&metrics(50.0)), 6, true);

        assert_eq!(model.total_attempts, 6);
        assert_eq!(model.total_successes, 1);

        let key = super::feature_key("vless://a@example.com:443", Some(&metrics(50.0)));
        let stats = model.features.get(&key).expect("feature bucket");
        assert_eq!(stats.attempts, 6);
        assert_eq!(stats.successes, 1);
    }

    #[test]
    fn learned_score_can_be_trained_without_external_services() {
        let mut model = IntelligenceModel::default();
        for _ in 0..60 {
            model.update("vless://a@example.com:443", Some(&metrics(50.0)), 1, true);
        }
        for _ in 0..60 {
            model.update(
                "trojan://b@example.com:443",
                Some(&metrics(900.0)),
                1,
                false,
            );
        }
        for _ in 0..60 {
            model.update(
                "hysteria2://c@example.com:443",
                Some(&metrics(300.0)),
                1,
                true,
            );
        }

        assert!(model.is_mature());

        let mut configs = vec![
            "trojan://b@example.com:443".to_string(),
            "vless://a@example.com:443".to_string(),
        ];
        let mut metadata = HashMap::new();
        metadata.insert(configs[0].clone(), metrics(900.0));
        metadata.insert(configs[1].clone(), metrics(50.0));
        let positions = configs
            .iter()
            .enumerate()
            .map(|(index, config)| (config.clone(), index))
            .collect::<HashMap<_, _>>();

        model.rank(&mut configs, &metadata, &positions);
        assert_eq!(configs[0], "vless://a@example.com:443");
    }
}
