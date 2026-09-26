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
TEST_CHUNK_SIZE = 4000
TARGET_VERIFIED = 250


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
        try:
            parsed = urlsplit(config)
            query = {
                key.lower(): values[0].lower()
                for key, values in parse_qs(parsed.query).items()
                if values
            }
            if query.get("flow", "") in {"xtls-rprx-direct-udp443", "xtls-rprx-origin"}:
                return False
        except Exception:
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

    print(
        f"[INFO] Light polish: {len(candidates)} global candidates available; "
        f"testing in chunks of {TEST_CHUNK_SIZE}, with no final protocol quota."
    )

    verified = []
    verified_seen = set()
    metadata = {}
    chunk_count = (len(candidates) + TEST_CHUNK_SIZE - 1) // TEST_CHUNK_SIZE

    for chunk_number, start in enumerate(range(0, len(candidates), TEST_CHUNK_SIZE), 1):
        chunk = candidates[start:start + TEST_CHUNK_SIZE]
        candidate_path = f"{args.output}.candidates.{chunk_number}"
        verified_path = f"{args.output}.verified.{chunk_number}"
        chunk_metadata_path = f"{args.metadata}.chunk-{chunk_number}"

        with open(candidate_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(chunk) + "\n")

        print(
            f"[INFO] Light chunk {chunk_number}/{chunk_count}: "
            f"testing {len(chunk)} candidates; "
            f"{len(verified)} verified so far."
        )

        command = [
            sys.executable,
            args.checker,
            "--input", candidate_path,
            "--output", verified_path,
            "--workers", "24",
            "--batch-size", "100",
            "--timeout", "12",
            "--warm-timeout", "5",
            "--metadata", chunk_metadata_path,
        ]
        result = subprocess.run(command, check=False)
        if result.returncode != 0:
            print(
                f"[WARN] Light chunk {chunk_number} checker exited with "
                f"{result.returncode}; continuing with the next chunk."
            )
            continue

        chunk_verified = read_lines(verified_path)
        for config in chunk_verified:
            if config not in verified_seen:
                verified_seen.add(config)
                verified.append(config)

        try:
            with open(chunk_metadata_path, encoding="utf-8") as handle:
                chunk_metadata = json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError):
            chunk_metadata = {}
        metadata.update(chunk_metadata)

        print(
            f"[INFO] Light chunk {chunk_number}/{chunk_count}: "
            f"{len(chunk_verified)} verified; {len(verified)} total verified."
        )

        if len(verified) >= TARGET_VERIFIED:
            print(
                f"[INFO] Reached {TARGET_VERIFIED} verified configs; "
                "stopping Light discovery early."
            )
            break

    for path in [args.metadata]:
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(metadata, handle, separators=(",", ":"))
        except OSError:
            pass

    if not verified:
        print("[WARN] Global Light verification produced zero stable configs; preserving the previous Light pool.")
        return 0

    # Stability is the hard gate. Rank only after validation; protocol quotas
    # are deliberately absent from the final selection.
    ranked = []
    endpoint_counts = defaultdict(int)
    for position, config in enumerate(verified):
        metrics = metadata.get(config)
        if not metrics:
            continue
        ep = endpoint(config)
        ranked.append((
            -int(metrics["successes"]),
            float(metrics["median_ms"]),
            float(metrics["min_ms"]),
            position,
            config,
            ep,
        ))

    ranked.sort()
    final = []
    for item in ranked:
        config = item[4]
        ep = item[5]
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
            config = item[4]
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
