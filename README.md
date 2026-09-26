# Proxy-Harvester

Automated collection, validation, testing, and publishing of publicly available proxy configurations.

Proxy-Harvester collects configurations from multiple public sources, normalizes them, removes invalid entries, performs a TCP reachability prefilter, and publishes refreshed subscriptions automatically every 2 hours.

## Subscriptions

### Light

Up to 200 conservatively verified proxy configurations:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/light.txt
```

Base64:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/light-base64.txt
```

Light validation uses a broad first pass followed by an individual per-profile recheck and a second independent HTTP target. Only configurations that survive both stages are eligible for the published list. The final list also enforces endpoint and obvious service-family diversity and never pads the list with unverified configurations.

### All

All configurations whose endpoints pass the collector's TCP reachability prefilter:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/all.txt
```

Base64:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/all-base64.txt
```

The All subscription is a broad reachability pool, not a guarantee that every individual protocol profile is usable end-to-end.

Both plain-text and Base64 formats are provided for compatibility with different clients.

## Supported Protocols

VMess · VLESS · Trojan · Shadowsocks · Hysteria · Hysteria 2 · SOCKS

## Validation model

The GitHub-hosted workflow is intentionally self-contained. It uses the hosted runner only and does not require a personal machine, self-hosted runner, VPS, or other private infrastructure.

The validation pipeline is:

```text
public sources
    ↓
normalization and deduplication
    ↓
TCP reachability prefilter
    ↓
broad protocol validation
    ↓
individual per-profile recheck
    ↓
second HTTP target recheck
    ↓
endpoint and service-family diversity
    ↓
Light
```

Because hosted runners use cloud infrastructure, the resulting Light pool is a globally validated pool rather than a guarantee for any particular ISP or network.

## Disclaimer

Configurations are collected from publicly available sources. Use them responsibly and in accordance with applicable laws and service terms.
