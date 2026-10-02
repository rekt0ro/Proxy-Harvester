    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("[INFO] 🚀 ProxyRift starting...");

    let root = project_root()?;
    let sources_path = root.join("sources.txt");
    let output_dir = root.join("subscriptions");
    fs::create_dir_all(&output_dir).await?;

    let sources = load_sources(&sources_path).await?;
    println!("[INFO] 📡 Loaded {} sources", sources.len());

    let mut unique = HashSet::new();
    let source_http_warnings = Arc::new(Mutex::new(Vec::<(usize, u16)>::new()));

    let mut source_results = stream::iter(sources.iter().cloned().enumerate())
        .map(|(source_index, url)| {
            let source_http_warnings = Arc::clone(&source_http_warnings);

            async move {
                let source_number = source_index + 1;
                let mut current_url = match Url::parse(&url) {
                    Ok(url) if matches!(url.scheme(), "http" | "https") => url,

                    _ => {
                        println!(
                            "[WARN] ⚠️ Source #{source_number} has an invalid or unsupported URL."
                        );
                        return (source_index, Vec::new(), CollectionOutcome::Failed);
                    }
                };

                let mut client = match safe_source_client(&current_url).await {
                    Ok(client) => client,

                    Err(reason) => {
                        println!(
                            "[WARN] ⚠️ Source #{source_number} rejected by safety policy: {reason}."
                        );
                        return (source_index, Vec::new(), CollectionOutcome::Failed);
                    }
                };

                let mut redirect_count = 0usize;
                let mut attempt = 0usize;
                loop {
                    match client.get(current_url.clone()).send().await {
                        Ok(response) => {
                            let status = response.status();

                            if status.is_redirection() {
                                if redirect_count == MAX_SOURCE_REDIRECTS {
                                    println!(
                                        "[WARN] ⚠️ Source #{source_number} exceeded the {}-redirect limit.",
                                        MAX_SOURCE_REDIRECTS
                                    );
                                    return (source_index, Vec::new(), CollectionOutcome::Failed);
                                }

                                let Some(location) = response.headers().get(LOCATION) else {
                                    println!(
                                        "[WARN] ⚠️ Source #{source_number} returned HTTP status {status} without a Location header."
                                    );
                                    return (source_index, Vec::new(), CollectionOutcome::Failed);
                                };

                                let location = match location.to_str() {
                                    Ok(location) => location,

                                    Err(_) => {
                                        println!(
                                            "[WARN] ⚠️ Source #{source_number} returned an invalid redirect Location header."
                                        );
                                        return (source_index, Vec::new(), CollectionOutcome::Failed);
                                    }
                                };

                                match safe_source_redirect(&current_url, location).await {
                                    Ok(next_url) => {
                                        current_url = next_url;

                                        client = match safe_source_client(&current_url).await {
                                            Ok(client) => client,

                                            Err(reason) => {
                                                println!(
                                                    "[WARN] ⚠️ Source #{source_number} redirect rejected by safety policy: {reason}."
                                                );
                                                return (source_index, Vec::new(), CollectionOutcome::Failed);
                                            }
                                        };

                                        redirect_count += 1;
                                        attempt = 0;
                                        continue;
                                    }

                                    Err(reason) => {
                                        println!(
                                            "[WARN] ⚠️ Source #{source_number} redirect rejected by safety policy: {reason}."
                                        );
                                        return (source_index, Vec::new(), CollectionOutcome::Failed);
                                    }
                                }
                            }

                            if !status.is_success() {
                                let retryable = status.as_u16() == 408
                                    || status.as_u16() == 425
                                    || status.as_u16() == 429
                                    || status.is_server_error();

                                if retryable && attempt < SOURCE_RETRIES {
                                    let delay = Duration::from_millis(
                                        SOURCE_RETRY_BASE_MS
                                            .saturating_mul(1u64 << attempt.min(4)),
                                    );
                                    tokio::time::sleep(delay).await;
                                    attempt += 1;
                                    continue;
                                }

                                if let Ok(mut warnings) = source_http_warnings.lock() {
                                    warnings.push((source_number, status.as_u16()));
                                }
                                let outcome = if matches!(status.as_u16(), 404 | 410) {
                                    CollectionOutcome::PermanentlyFailed(status.as_u16())
                                } else {
                                    CollectionOutcome::Failed
                                };
                                return (source_index, Vec::new(), outcome);
                            }

                            if response
                                .content_length()
                                .is_some_and(|length| length > MAX_SOURCE_BYTES as u64)
                            {
                                return (source_index, Vec::new(), CollectionOutcome::Failed);
                            }

                            match read_source_body(response).await {
                                Ok(bytes) => {
                                    let text = String::from_utf8_lossy(&bytes);
                                    let configs = extract_configs(&text);


                                    return (source_index, configs, CollectionOutcome::Success(configs.len()));
                                }

                                Err(SourceBodyError::TooLarge) => {
                                    return (source_index, Vec::new(), CollectionOutcome::Failed);
                                }

                                Err(SourceBodyError::Read) => {
                                    println!("[INFO] ↪️ Failed to read source #{source_number}.");
                                    return (source_index, Vec::new(), CollectionOutcome::Failed);
                                }
                            }
                        }

                        Err(error) => {
                            if attempt < SOURCE_RETRIES {
                                let delay = Duration::from_millis(
                                    SOURCE_RETRY_BASE_MS
                                        .saturating_mul(1u64 << attempt.min(4)),
                                );
                                tokio::time::sleep(delay).await;
                                attempt += 1;
                                continue;
                            }

                            println!(
                                "[WARN] ⚠️ Failed to download source #{source_number}: {error}"
                            );
                            return (source_index, Vec::new(), CollectionOutcome::Failed);
                        }
                    }
                }

            }
        })
        .buffer_unordered(DOWNLOAD_CONCURRENCY.min(sources.len()).max(1));

    let mut source_health = Vec::<(String, CollectionOutcome)>::with_capacity(sources.len());

    while let Some((source_index, configs, outcome)) = source_results.next().await {
        source_health.push((sources[source_index].clone(), outcome));
        unique.extend(configs);
    }

    proxyrift::source_discovery::record_collection_results(&source_health).await?;

    let mut warnings = source_http_warnings
        .lock()
        .map(|warnings| warnings.clone())
        .unwrap_or_default();

    if !warnings.is_empty() {
        warnings.sort_unstable();

        let mut grouped = HashMap::<u16, Vec<usize>>::new();
        for (source_number, status_code) in warnings {
            grouped.entry(status_code).or_default().push(source_number);
        }

        let mut groups = grouped.into_iter().collect::<Vec<_>>();