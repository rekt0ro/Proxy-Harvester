# ProxyRift

ProxyRift builds refreshed proxy subscription lists by collecting public configurations, removing duplicates, testing reachability, and applying additional connectivity and quality checks to a smaller quality-focused pool.

**Supported:** VLESS · VMess · Trojan · Shadowsocks · Hysteria/Hysteria2 · SOCKS

## Subscription

| Subscription | Description                                                  |
| ------------ | ------------------------------------------------------------ |
| **Light**    | Smaller pool with deeper connectivity and quality validation |
| **All**      | Up to 2,000 transport-reachable configurations               |

**Light**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/light.txt
```

**Light · Base64**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/light_base64.txt
```

**All**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all.txt
```
**All · Base64**

```text
https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all_base64.txt
```
## How it works

```text
                       Public Sources
                             ↓
                   Normalize & Deduplicate
                             ↓
                   Transport Reachability
                             │
              ┌──────────────┴──────────────┐
              ↓                             ↓
             All                          Light
              ↓                             ↓
     Rank & Apply Limits           Build Candidate Pool
                                            ↓
                                     Deep Validation
                                            ↓
                               ┌────────────┴────────────┐
                               ↓                         ↓
                        Xray Validation          sing-box Validation
                               └────────────┬────────────┘
                                            ↓
                              Quality & Diversity Selection
              └──────────────┬──────────────┘
                             ↓
                          Publish
```

The **All** list uses the transport-reachable pool directly, then ranks and limits the results to a maximum of 2,000 configurations. It does not go through the more expensive Light validation stage.

The **Light** list starts from the same screened candidates but goes through deeper validation using multiple targets, endpoint diversity, reliability, latency, jitter, transfer performance, and protocol-specific checks.

**Xray** and **sing-box** are used for protocol-specific validation where appropriate before the final quality and diversity selection.

Light also uses a safety threshold when publishing updates. If a new run produces too few valid configurations, the previous Light list is preserved rather than being replaced with an unexpectedly small result.

## Supported Protocols

* VLESS
* VMess
* Trojan
* Shadowsocks
* Hysteria
* Hysteria2
* SOCKS

## Automatic Updates

ProxyRift regenerates the subscription lists automatically every **30 minutes** through GitHub Actions.

Each update collects fresh public configurations, screens them, builds the All and Light pools, generates the subscription formats, and publishes the results.

Because the source pool and network conditions are dynamic, individual endpoints may appear, disappear, or change between updates.
