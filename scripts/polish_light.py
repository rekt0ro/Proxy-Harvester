#!/usr/bin/env python3
"""Build the recommended Light subscription from a global, protocol-agnostic pool."""

import argparse
import base64
import json
import subprocess
import sys
from collections import defaultdict
from urllib.parse import parse_qs, urlsplit

SUPPORTED = {"vmess", "vless", "trojan", "ss", "hysteria", "hysteria2", "hy2", "tuic", "socks", "socks5", "socks5h", "naive+https"}
DEFAULT_BUDGET = 16000
MAX_PER_ENDPOINT = 4


def scheme(config):
    return config.split("://", 1)[0].lower() if "://" in config else ""


def endpoint(config):
    s = scheme(config)
    if s == "vmess":
        try:
            raw = config.split("://", 1)[1].split("#", 1)[0]
            raw += "=" * (-len(raw) % 4)
            obj = json.loads(base64.urlsafe_b64decode(raw).decode())
            return str(obj.get("add", "")), int(obj.get("port", 0))
        except Exception:
            return None
    try:
        parsed = urlsplit(config)
        if not parsed.hostname or not parsed.port:
            return None
        return parsed.hostname.lower(), parsed.port
    except Exception:
        return None


def heuristic(config):
    """Cheap client-compatibility ordering only. It is never a substitute for testing."""
    s = scheme(config)
    score = 0
    if s in {"vless", "trojan", "vmess"}:
        score += 2
    if s in {"hysteria2", "hy2"}:
        score += 2
    try:
        if s == "vmess":
            raw = config.split("://", 1)[1].split("#", 1)[0]
            raw += "=" * (-len(raw) % 4)
            q = json.loads(base64.urlsafe_b64decode(raw).decode())
            net = str(q.get("net", "")).lower()
            tls = str(q.get("tls", "")).lower()
            if net == "ws": score += 3
            if tls == "tls": score += 3
            if q.get("host"): score += 1
            if q.get("sni"): score += 1
            if q.get("path"): score += 1
        else:
            p = urlsplit(config)
            q = {k.lower(): v[0] for k, v in parse_qs(p.query).items()}
            transport = q.get("type", "").lower()
            security = q.get("security", "").lower()
            if transport == "ws": score += 3
            if security == "tls": score += 3
            if q.get("host"): score += 1
            if q.get("sni"): score += 1
            if q.get("path") and q.get("path") != "/": score += 1
            if q.get("allowinsecure", "").lower() in {"1", "true"}: score -= 3
            if q.get("insecure", "").lower() in {"1", "true"}: score -= 3
        ep = endpoint(config)
        if ep and ep[1] in {443, 2053, 2083, 2087, 2096, 8443}: score += 1
    except Exception:
        pass
    return score


def read_lines(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def build_candidates(all_configs, seed_configs, budget):
    seen = set()
    selected = []
    endpoint_counts = defaultdict(int)
    per_scheme = defaultdict(list)

    def add(config):
        if config in seen or scheme(config) not in SUPPORTED:
            return False
        ep = endpoint(config)
        if ep is None or endpoint_counts[ep] >= MAX_PER_ENDPOINT:
            return False
        seen.add(config)
        endpoint_counts[ep] += 1
        selected.append(config)
        return True

    # Re-test the previous Light pool first. It carries the existing EU preference
    # and proven client-compatible candidates from the previous cycle.
    for config in seed_configs:
        add(config)
        if len(selected) >= budget:
            return selected

    for config in all_configs:
        s = scheme(config)
        if s in SUPPORTED:
            per_scheme[s].append(config)

    # Discovery is stratified so a huge VMess/Trojan source cannot starve VLESS,
    # Hysteria2 or Shadowsocks. This is only a testing allocation, not a final quota.
    for configs in per_scheme.values():
        configs.sort(key=lambda value: (-heuristic(value), value))

    schemes = sorted(per_scheme)
    cursor = {s: 0 for s in schemes}
    while len(selected) < budget:
        progress = False
        for s in schemes:
            items = per_scheme[s]
            while cursor[s] < len(items):
                candidate = items[cursor[s]]
                cursor[s] += 1
                if add(candidate):
                    progress = True
                    break
            if len(selected) >= budget:
                break
        if not progress:
            break

    return selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", dest="all_path", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--checker", required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    args = parser.parse_args()

    all_configs = read_lines(args.all_path)
    seed_configs = read_lines(args.seed)
    candidates = build_candidates(all_configs, seed_configs, max(1, args.budget))

    if not candidates:
        print("[WARN] No Light candidates available after global filtering.")
        open(args.output, "w", encoding="utf-8").close()
        return 0

    candidate_path = args.output + ".candidates"
    verified_path = args.output + ".verified"
    with open(candidate_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(candidates) + "\n")

    print(f"[INFO] Light polish: testing {len(candidates)} global candidates, with no final protocol quota.")

    command = [
        sys.executable,
        args.checker,
        "--input", candidate_path,
        "--output", verified_path,
        "--workers", "12",
        "--batch-size", "100",
        "--timeout", "6",
        "--metadata", args.metadata,
    ]
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        print(f"[WARN] Light polish checker exited with {result.returncode}; preserving the previous Light pool.")
        return 0

    verified = read_lines(verified_path)
    if not verified:
        print("[WARN] Global Light verification produced zero stable configs; preserving the previous Light pool.")
        return 0

    with open(args.metadata, encoding="utf-8") as handle:
        metadata = json.load(handle)

    # Stability is the hard gate. Within each stability tier, prefer
    # mainstream-client-friendly transport parameters and then latency.
    # Protocol quotas are deliberately absent.
    ranked = []
    endpoint_counts = defaultdict(int)
    for position, config in enumerate(verified):
        metrics = metadata.get(config)
        if not metrics:
            continue
        ep = endpoint(config)
        ranked.append((
            -int(metrics["successes"]),
            -heuristic(config),
            float(metrics["median_ms"]),
            float(metrics["min_ms"]),
            position,
            config,
            ep,
        ))

    ranked.sort()
    final = []
    for item in ranked:
        config = item[5]
        ep = item[6]
        if ep is not None and endpoint_counts[ep] >= 2:
            continue
        final.append(config)
        if ep is not None:
            endpoint_counts[ep] += 1
        if len(final) >= 200:
            break

    # If diversity prevented a full list, fill remaining slots from the same
    # stability-verified pool without the endpoint cap.
    if len(final) < 200:
        chosen = set(final)
        for item in ranked:
            config = item[5]
            if config in chosen:
                continue
            final.append(config)
            chosen.add(config)
            if len(final) >= 200:
                break
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write("\n".join(final) + "\n")

    print(f"[INFO] Light polish selected {len(final)} verified configs from {len(candidates)} candidates.")
    print("[INFO] Final Light selection is protocol-agnostic: no VMess/Trojan/VLESS/etc. quota is applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
