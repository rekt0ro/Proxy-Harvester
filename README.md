# ProxyRift

ProxyRift builds refreshed proxy subscription lists by collecting public configurations, removing duplicates, testing reachability, and applying additional connectivity and quality checks to a smaller quality-focused pool.

**Supported:** VLESS · VMess · Trojan · Shadowsocks · Hysteria/Hysteria2 · HTTP · SOCKS

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

The **Light** list starts from transport-screened candidates and also retains Hysteria/Hysteria2 candidates for protocol-specific validation. Configurations that explicitly disable TLS certificate verification are excluded from Light.

Light then goes through deeper validation using multiple targets, repeated stability checks, endpoint diversity, reliability, latency, jitter, and throughput. Every configuration published to Light must pass a dedicated 10 MiB transfer gate, and Light publishes only when the full 200-config selection is available. The transfer stage is bounded and tuned to run as a final quality gate rather than repeatedly benchmarking the pool during discovery.

**Xray** and **sing-box** are used as complementary validation cores before the final quality and diversity selection. Known Xray-only configurations go directly to Xray; other configurations use sing-box by default; only feature-sensitive fallback configurations try sing-box first and then Xray when sing-box does not accept them. A configuration is valid after one suitable core accepts it, so Light does not require duplicate validation by both cores. The normal Light latency ceiling remains 1200 ms; the 10 MiB transfer gate uses a separate longer timeout so throughput is not confused with probe latency.

Light also uses a safety threshold when publishing updates. If a new run produces too few valid configurations, the previous Light list is preserved rather than being replaced with an unexpectedly small result.

## Automatic Updates

ProxyRift regenerates the subscription lists automatically through GitHub Actions.

Each update collects fresh public configurations, screens them, builds the All and Light pools, generates the subscription formats, and publishes the results.

Because the source pool and network conditions are dynamic, individual endpoints may appear, disappear, or change between updates.
