
use proxy_harvester::validator::{read_lines, validate_candidates, write_lines, write_metadata, ProxyMetrics, PRIMARY_TARGET};
use std::env;

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
             [--batch-size N] [--timeout SECONDS] [--target URL] [--xray PATH]"
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
    let target = value(&args, "--target", PRIMARY_TARGET);
    let xray = value(&args, "--xray", "xray");

    let candidates = read_lines(&input)?;
    let metadata = validate_candidates(&xray, &candidates, &target, workers, batch_size, timeout).await?;
    write_lines(&output, &ranked(&metadata))?;

    if !metadata_path.is_empty() {
        write_metadata(&metadata_path, &metadata)?;
    }

    Ok(())
}
