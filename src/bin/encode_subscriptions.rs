use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fs;
use std::path::{Path, PathBuf};

fn encode_file(path: &str) -> Result<(), String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };

    let payload = String::from_utf8_lossy(&bytes);
    let payload = payload.trim_end_matches(['\r', '\n']);

    let encoded = STANDARD.encode(payload.as_bytes());
    fs::write(output_path(path), format!("{encoded}\n")).map_err(|error| error.to_string())
}

fn output_path(path: &str) -> PathBuf {
    let path = Path::new(path);

    path.file_stem()
        .and_then(|stem| stem.to_str())
        .map(|stem| path.with_file_name(format!("{stem}-base64.txt")))
        .unwrap_or_else(|| PathBuf::from(format!("{path}-base64.txt")))
}

#[cfg(test)]
mod tests {
    use super::output_path;
    use std::path::Path;

    #[test]
    fn keeps_base64_output_next_to_source() {
        assert_eq!(
            output_path("subscriptions/all.txt"),
            Path::new("subscriptions/all-base64.txt")
        );
        assert_eq!(
            output_path("subscriptions/light.txt"),
            Path::new("subscriptions/light-base64.txt")
        );
    }

fn main() -> Result<(), String> {
    encode_file("subscriptions/all.txt")?;
    encode_file("subscriptions/light.txt")?;
    Ok(())
}
