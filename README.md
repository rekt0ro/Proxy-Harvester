# ProxyRift

**Supported:** VLESS · VMess · Trojan · Shadowsocks · Hysteria · Hysteria2 · SOCKS · HTTP

## 📡 Subscriptions

| List      | Description                              |
| --------- | ---------------------------------------- |
| **Light** | Up to 200 configs, deeply validated      |
| **All**   | Up to 2,000 configs, transport-reachable |


**Light**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/light.txt
```

**Light · Base64**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/light-base64.txt
```

**All**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all.txt
```

**All · Base64**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all-base64.txt
```

## ⚙️ Pipeline

```text
Public Sources
      │
      ▼
Normalize & Deduplicate
      │
      ▼
Transport Reachability
      │
      ├──────────────► All
      │                 │
      │                 ▼
      │              Rank & Limit
      │
      └──────────────► Light
                        │
                        ▼
                   Deep Validation
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
        Xray Validation     sing-box Validation
              └─────────┬─────────┘
                        ▼
              Quality & Diversity
                        │
                        ▼
                     Publish
```

The **All** list is built from transport-reachable configurations and limited to 2,000 entries.

The **Light** list goes through deeper validation using multiple targets, endpoint diversity, reliability, latency, jitter, transfer performance, and protocol-specific checks.

## 🔄 Automatic Updates

ProxyRift regenerates its subscriptions through GitHub Actions.

Each update collects fresh public configurations, screens them, builds the All and Light pools, generates the subscription formats, and publishes the results.
