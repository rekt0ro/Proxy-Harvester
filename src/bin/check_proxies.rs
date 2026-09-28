use proxyrift::singbox::validate_candidates_with_target as validate_singbox_candidates;
use proxyrift::validator::{
    read_lines, validate_candidates, write_lines, write_metadata, ProxyMetrics, MAX_LATENCY_MS,
    PRIMARY_TARGET,
};
use std::collections::HashMap;
use std::env;
use std::time::Duration;

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

fn requires_singbox(config: &str) -> bool {
    config.split_once("://").is_some_and(|(scheme, _)| {
        matches!(
            scheme.to_ascii_lowercase().as_str(),
            "hysteria" | "socks4" | "socks4a"
        )
    })
}

fn ranked(metadata: &std::collections::HashMap<String, ProxyMetrics>) -> Vec<String> {
    let mut configs: Vec<_> = metadata.keys().cloned().collect();
    configs.sort_unstable_by(|a, b| {
        let ma = &metadata[a];
        let mb = &metadata[b];
        mb.successes
            .cmp(&ma.successes)
            .then_with(|| ma.median_ms.total_cmp(&mb.median_ms))
            .then_with(|| ma.min_ms.total_cmp(&mb.min_ms))
            .then_with(|| a.cmp(b))
    });
    configs
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: check_proxies --input FILE --output FILE [--metadata FILE] [--workers N] \
             [--batch-size N] [--timeout SECONDS] [--target URL] [--xray PATH] [--singbox PATH]"
        );
        return Ok(());
    }

    let input = required(&args, "--input")?;
    let output = required(&args, "--output")?;
    let metadata_path = value(&args, "--metadata", "");
    let workers = value(&args, "--workers", "20")
        .parse::<usize>()
        .map_err(|_| "invalid --workers".to_string())?;
    let batch_size = value(&args, "--batch-size", "100")
        .parse::<usize>()
        .map_err(|_| "invalid --batch-size".to_string())?;
    let timeout = value(&args, "--timeout", "1")
        .parse::<f64>()
        .map_err(|_| "invalid --timeout".to_string())?;
    if !timeout.is_finite() || timeout <= 0.0 {
        return Err("invalid --timeout: must be a positive finite number".to_string());
    }
    let target = value(&args, "--target", PRIMARY_TARGET);
    let xray = value(&args, "--xray", "xray");
    let singbox = value(&args, "--singbox", "sing-box");

    let candidates = read_lines(&input)?;

    let mut xray_candidates = Vec::new();
    let mut singbox_candidates = Vec::new();

    for config in candidates {
        if requires_singbox(&config) {
            singbox_candidates.push(config);
        } else {
            xray_candidates.push(config);
        }
    }

    let mut metadata = HashMap::<String, ProxyMetrics>::new();

    if !xray_candidates.is_empty() {
        metadata.extend(
            validate_candidates(
                &xray,
                &xray_candidates,
                &target,
                workers,
                batch_size,
                timeout,
            )
            .await?,
        );
    }

    if !singbox_candidates.is_empty() {
        metadata.extend(
            validate_singbox_candidates(
                &singbox,
                &singbox_candidates,
                &target,
                workers,
                Duration::from_secs_f64(timeout),
                MAX_LATENCY_MS,
            )
            .await?,
        );
    }

    write_lines(&output, &ranked(&metadata))?;

    if !metadata_path.is_empty() {
        write_metadata(&metadata_path, &metadata)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::requires_singbox;

    #[test]
    fn routes_singbox_only_protocols_correctly() {
        assert!(requires_singbox(
            "hysteria://example.com:443?upmbps=100&downmbps=100"
        ));
        assert!(requires_singbox("socks4://example.com:1080"));
        assert!(requires_singbox("socks4a://example.com:1080"));
        assert!(!requires_singbox("socks5://example.com:1080"));
        assert!(!requires_singbox(
            "vless://uuid@example.com:443?security=tls"
        ));
    }
}

