# Proxy-Harvester

An automated garden of publicly available proxy configurations.

Proxy-Harvester collects, validates, tests, and publishes working proxy configurations from multiple public sources.

## Subscriptions

**All**

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/all.txt
```

**Light**

```text
https://raw.githubusercontent.com/rekt0ro/Proxy-Harvester/main/subscriptions/light.txt
```

`light.txt` contains up to 200 working configurations.

## Supported Protocols

VMess, VLESS, Trojan, Shadowsocks, Hysteria, Hysteria 2, SOCKS, HTTP/HTTPS.

## Updates

Automatically updated every 6 hours using GitHub Actions.

## Architecture

The collector is written in Rust. Input is downloaded concurrently, deduplicated in memory, processed in bounded chunks, and tested through the standalone `sb2p` engine backed by sing-box.

Working results are written only after a successful test run, so a failed update does not replace the previous subscription.

## Disclaimer

This project aggregates publicly available configurations. Use them at your own discretion and follow applicable laws and service terms.
