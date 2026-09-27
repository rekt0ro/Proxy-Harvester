# Proxy-Harvester

Automated collection, validation, and publishing of publicly available proxy configurations.

Built in Rust, with native Rust tooling powering the collection, validation, and publishing pipeline.

## Subscriptions

### Light (Recommended)

Up to 200 verified proxy configurations, selected for reliability and performance.

Plain text:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/light.txt
```

Base64:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/light-base64.txt
```

### All

All configurations that pass validation.

Plain text:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/all.txt
```

Base64:

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/all-base64.txt
```

## Validation

All subscriptions are validated through the Rust-based validation pipeline.

Light applies additional verification, ranking, and selection to provide a smaller curated subscription.

## Supported Protocols

VMess · VLESS · Trojan · Shadowsocks · Hysteria · Hysteria 2 · SOCKS

## Updates

Subscriptions are refreshed automatically every 2 hours.

## Disclaimer

Configurations are collected from publicly available sources. Use them responsibly and in accordance with applicable laws and service terms.
