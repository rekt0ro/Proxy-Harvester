# ProxyRift

ProxyRift collects public proxy configurations, removes duplicates, checks transport reachability, and publishes two refreshed subscription lists.

## Subscriptions

**All**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all.txt
```

**All (Base64)**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all_base64.txt
```

**Light**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/light.txt
```

**Light (Base64)**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/light_base64.txt
```

## How it works

`collect → deduplicate → reachability check → select → publish`

`All` contains up to 2,000 transport-reachable configurations and does not use the more expensive Light validation stage.

`Light` is a smaller pool selected from the same screened candidates using deeper connectivity checks, multiple targets, endpoint diversity, reliability and jitter signals, and a small transfer test.

The lists are regenerated automatically, so individual endpoints may come and go.

## Supported protocols

VLESS, VMess, Trojan, Shadowsocks, Hysteria/Hysteria2, and SOCKS where supported by the validation cores.

Xray and sing-box are used for protocol-specific validation where appropriate.
