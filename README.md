# Proxy-Harvester

Automated collection, validation, testing, and publishing of publicly available proxy configurations.

Proxy-Harvester collects configurations from multiple public sources, filters invalid entries, performs transport-aware reachability screening, and publishes working configurations automatically every 2 hours.

## Subscriptions

### Light (Recommended)

Up to 200 proxy-level verified configurations:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/light.txt
```

Base64:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/light-base64.txt
```

Light validation is implemented entirely in Rust. Each candidate is tested through Xray with a real HTTPS transaction: a tiny 4 KiB download and 1 KiB upload. A candidate can pass early after two successful attempts, while impossible candidates are stopped early. Candidates are processed in adaptive 1,000-config discovery waves, with a hard 4,000-candidate ceiling. Later waves are only tested when the current final pool does not fill the 200-slot Light subscription.

Cloudflare HTTP 429 responses are handled with a shared process-wide backoff. The validator uses the server's `Retry-After` value when present, falls back to a conservative 5-second delay, and caps any single wait at 5 minutes. A 429 backoff is shared across concurrent workers so they do not immediately continue sending requests.

The normal scheduled update runs every 2 hours with the full 4,000-candidate ceiling. Manual workflow runs default to 1,000 candidates and expose 500, 1,000, 2,000, and 4,000 as explicit choices for faster development checks.

The validator prioritizes reliability first, then median latency, then minimum latency. Final selection is limited to one config per parsed endpoint.

### All

All working configurations:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/all.txt
```

Base64:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/all-base64.txt
```

Both plain-text and Base64 formats are provided for compatibility with different clients. The collection, validation, ranking, Light selection, and subscription encoding pipeline is implemented in Rust.

## Supported Protocols

VMess · VLESS · Trojan · Shadowsocks · Hysteria · Hysteria 2 · SOCKS · WireGuard

## Disclaimer

Configurations are collected from publicly available sources. Use them responsibly and in accordance with applicable laws and service terms.
