# Light ML Training Dataset

ProxyRift records supervised-learning observations from Light strict rechecks in
`subscriptions/light-training.jsonl`.

## Purpose

This dataset is groundwork for the future local LightGBM model. The current
validator does not use these rows for ranking or publication decisions.

Each row represents one candidate observed during one update run. Repeated
observations of the same candidate across different runs are intentional so a
future model can learn time-varying behavior.

## Row schema

Each JSONL row contains:

- `schema_version`: dataset format version.
- `observation_id`: unique run/candidate observation identifier.
- `observed_at`: Unix timestamp for the observation.
- `run_id`: GitHub Actions run ID when available.
- `candidate_fingerprint`: stable non-reversible candidate identity used for
  linking observations without storing the raw proxy URL.
- `features`: values known before strict validation starts.
- `label.strict_pass`: whether the candidate survived strict validation.
- `label.strict_checks`: number of strict recheck rounds applied.
- `label.transfer_tested`: whether the candidate reached the 10 MiB gate.
- `label.transfer_pass`: transfer result when the 10 MiB gate was tested,
  otherwise `null`.

The current feature contract has 19 fields:

`protocol`, `backend`, `transport`, `security`, `port`,
`query_parameter_count`, `has_sni`, `has_host`, `has_path`,
`tls_enabled`, `reality_enabled`, `early_attempts`,
`early_success_rate`, `early_median_ms`, `early_min_ms`,
`early_jitter_ms`, `early_throughput_kbps`, `history_checks`,
`history_pass_rate`.

## Leakage rules

Only information available before the strict validation decision may be stored
under `features`.

Strict-validation outcomes and 10 MiB transfer outcomes are labels, not model
features. Raw proxy URLs are not stored in the training dataset.

A future training pipeline should preserve this separation and must not derive
features from strict or transfer results.

## Dataset hygiene

Rows older than 45 days are removed during persistence. The dataset is capped
at 50,000 rows. Malformed or incompatible rows are ignored rather than causing
the Light validation pipeline to fail.

Persistence is atomic and observation IDs are idempotent, so retrying the same
update run does not duplicate its observations.

## Future LightGBM gate

This PR deliberately does not add model training or model-driven ranking.

A future PR can train and evaluate LightGBM using time-ordered data, compare its
candidate ordering against the deterministic baseline, and only enable model
ranking after the model passes an explicit quality gate.

The existing strict validator and mandatory 10 MiB gate remain authoritative.
