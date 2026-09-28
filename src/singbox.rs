    Command::new(binary)
        .args(["run", "-c"])
        .arg(config_path)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .stdin(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())
}

async fn ports_ready(child: &mut Child, ports: &[u16]) -> bool {
    let deadline = tokio::time::Instant::now() + START_TIMEOUT;
    let workers = ports.len().clamp(1, 64);
    let mut pending = ports.to_vec();

    while !pending.is_empty() && tokio::time::Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }

        let checks = stream::iter(pending.clone())
            .map(|port| async move {
                let ready = timeout(
                    Duration::from_millis(150),
                    TcpStream::connect(("127.0.0.1", port)),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .is_some();
                (port, ready)
            })
            .buffer_unordered(workers)
            .collect::<Vec<_>>()
            .await;

        pending = checks
            .into_iter()
            .filter_map(|(port, ready)| (!ready).then_some(port))
            .collect();

        if !pending.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pending.is_empty()
}

fn client_for_port(
    port: u16,
    request_timeout: Duration,
    fresh_connections: bool,
) -> Result<Client, String> {
    let mut builder = Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
                .map_err(|error| error.to_string())?,
        )
        .timeout(request_timeout)