## Subscriptions

### Light (Recommended)

Up to 200 verified proxy configurations that pass multi-target consumer-style checks. Reality configurations are checked through both Xray and sing-box; other transports use the core selected for their compatibility.

Plain text:

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/light.txt
```

Base64:

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/light-base64.txt
```

### All

All configurations that pass validation.

Plain text:

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all.txt
```

Base64:

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all-base64.txt
```

## Validation

All subscriptions are validated through the Rust-based validation pipeline.

Light uses a Throne-compatible URL-test target plus independent HTTP/HTTPS connectivity targets, performs a full stability window during strict recheck, and applies endpoint and service-family diversity before publishing.

## Supported Protocols

VMess · VLESS · Trojan · Shadowsocks · Hysteria · Hysteria 2 · SOCKS

## Updates

Subscriptions are refreshed automatically every 2 hours.

## Disclaimer

Configurations are collected from publicly available sources. Use them responsibly and in accordance with applicable laws and service terms.
