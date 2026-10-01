use crate::validator::ProxyMetrics;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;

const MODEL_VERSION: u64 = 1;
const MIN_TRAINING_SAMPLES: u64 = 50;
const MIN_FEATURES: usize = 3;

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

        let mut model = Self::default();
        model.total_attempts = value
            .get("total_attempts")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        model.total_successes = value
            .get("total_successes")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        if let Some(features) = value.get("features").and_then(Value::as_object) {
            for (key, entry) in features {
                let attempts = entry.get("attempts").and_then(Value::as_u64).unwrap_or(0);
                let successes = entry
                    .get("successes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .min(attempts);
                if attempts > 0 {
                    model
                        .features
                        .insert(key.clone(), FeatureStats { attempts, successes });
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

    pub fn update(&mut self, config: &str, metrics: Option<&ProxyMetrics>, attempts: usize, passed: bool) {
        if attempts == 0 {
            return;
        }

        let successes = u64::from(passed);
        let attempts = attempts as u64;
        let key = feature_key(config, metrics);
        let entry = self.features.entry(key).or_default();
        entry.attempts = entry.attempts.saturating_add(attempts);
        entry.successes = entry.successes.saturating_add(successes).min(entry.attempts);
        self.total_attempts = self.total_attempts.saturating_add(attempts);
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

    pub fn anomaly_message(&self, attempts: usize, successes: usize) -> Option<String> {
        if !self.is_mature() || attempts < 20 {
            return None;
        }

        let observed = successes as f64 / attempts as f64;
        let expected = (self.total_successes as f64 + 2.0)
            / (self.total_attempts as f64 + 4.0);

        if (observed - expected).abs() < 0.20 {
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

    #[test]
    fn remains_inert_until_enough_training_data() {
        let mut model = IntelligenceModel::default();
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
    fn learned_score_can_be_trained_without_external_services() {
        let mut model = IntelligenceModel::default();
        for _ in 0..60 {
            model.update(
                "vless://a@example.com:443",
                Some(&metrics(50.0)),
                1,
                true,
            );
        }
        for _ in 0..60 {
            model.update(
                "trojan://b@example.com:443",
                Some(&metrics(900.0)),
                1,
                false,
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
