use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("[INFO] 🔭 [DISCOVERY] autonomous GitHub source discovery starting");

    let (new_sources, active_sources) = proxyrift::source_discovery::discover_and_write().await?;

    println!(
        "[INFO] 🔭 [DISCOVERY] complete | NEW: {} | ACTIVE: {}",
        new_sources, active_sources
    );

    Ok(())
}
