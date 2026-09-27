use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fs;

fn encode_file(path: &str) -> Result<(), String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };

    let payload = bytes.iter().copied().collect::<Vec<_>>();
    let payload = String::from_utf8_lossy(&payload)
        .trim_end_matches(['\r', '\n'])
        .as_bytes()
        .to_vec();

    let encoded = STANDARD.encode(payload);
    let output = path.replace(".txt", "-base64.txt");
    fs::write(output, format!("{encoded}\n")).map_err(|error| error.to_string())
}

fn main() -> Result<(), String> {
    encode_file("subscriptions/all.txt")?;
    encode_file("subscriptions/light.txt")?;
    Ok(())
}
