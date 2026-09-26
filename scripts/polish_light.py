#!/usr/bin/env python3
"""Build a conservative Light subscription from globally validated public configs."""

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from urllib.parse import parse_qs, urlsplit

DEFAULT_BUDGET = 5000
DISCOVERY_CHUNK_SIZE = 4000
FINAL_RECHECK_LIMIT = 500
DEFAULT_SELECTION_LIMIT = 200
DEFAULT_MAX_PER_ENDPOINT = 1
PRIMARY_TARGET = "https://cp.cloudflare.com/"
SECONDARY_TARGET = "https://www.google.com/generate_204"


def scheme(config):
    return config.split("://", 1)[0].lower() if "://" in config else ""


def vmess_object(config):
    try:
        encoded = config.split("://", 1)[1].split("#", 1)[0]
        encoded += "=" * (-len(encoded) % 4)
        decoded = base64.urlsafe_b64decode(encoded).decode()
        value = json.loads(decoded)
        return value if isinstance(value, dict) else None
    except (IndexError, ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def endpoint(config):
    s = scheme(config)
    if s == "vmess":
        value = vmess_object(config)
        if not value:
            return None
        try:
            host = str(value.get("add", "")).strip().lower()
            port = int(value.get("port", 0))
        except (TypeError, ValueError):
            return None
        return (host, port) if host and 0 < port <= 65535 else None

    try:
        parsed = urlsplit(config)
        if not parsed.hostname or not parsed.port:
            return None
        return parsed.hostname.lower(), parsed.port
    except ValueError:
        return None


def read_lines(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def build_candidates(candidate_configs, budget):
    selected = []
    seen = set()

    for config in candidate_configs:
        config = config.strip()
        if not config or config in seen:
            continue

        seen.add(config)
        selected.append(config)

        if len(selected) >= budget:
            break

    return selected


def write_lines(path, values):
    with open(path, "w", encoding="utf-8") as handle:
        if values:
            handle.write("\n".join(values) + "\n")


def load_metadata(path):
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def run_checker(
    checker,
    candidates,
    target,
    output_path,
    metadata_path,
    workers,
    batch_size,
    timeout,
):
    if not candidates:
        write_lines(output_path, [])
        with open(metadata_path, "w", encoding="utf-8") as handle:
            json.dump({}, handle)
        return False

    input_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="proxy-check-",
            suffix=".txt",
            delete=False,
        ) as handle:
            input_path = handle.name
            handle.write("\n".join(candidates) + "\n")

        command = [
            sys.executable,
            checker,
            "--input",
            input_path,
            "--output",
            output_path,
            "--metadata",
            metadata_path,
            "--workers",
            str(max(1, workers)),
            "--batch-size",
            str(max(1, batch_size)),
            "--timeout",
            str(timeout),
            "--target",
            target,
        ]

        result = subprocess.run(command, check=False)
        return result.returncode == 0
    finally:
        if input_path:
            try:
                os.unlink(input_path)
            except OSError:
                pass


def global_rank(config, metadata, position):
    metrics = metadata.get(config, {})
    return (
        -int(metrics.get("successes", 0)),
        float(metrics.get("median_ms", float("inf"))),
        float(metrics.get("min_ms", float("inf"))),
        position,
        config,
    )


def diversify_recheck_candidates(configs, limit):
    selected = []
    seen_endpoints = set()
    deferred = []

    for config in configs:
        ep = endpoint(config)

        if ep is None:
            selected.append(config)
        elif ep not in seen_endpoints:
            seen_endpoints.add(ep)
            selected.append(config)
        else:
            deferred.append(config)

        if len(selected) >= limit:
            return selected

    if len(selected) < limit:
        selected.extend(deferred[:limit - len(selected)])

    return selected


def diversified(configs, limit, max_per_endpoint):
    final = []
    endpoint_counts = defaultdict(int)

    for config in configs:
        ep = endpoint(config)
        if ep is not None and endpoint_counts[ep] >= max_per_endpoint:
            continue
        final.append(config)

        if ep is not None:
            endpoint_counts[ep] += 1
        if len(final) >= limit:
            break

    return final


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--checker", required=True)
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=1)
    parser.add_argument("--final-recheck-limit", type=int, default=FINAL_RECHECK_LIMIT)
    parser.add_argument("--final-workers", type=int, default=12)
    parser.add_argument("--final-batch-size", type=int, default=1)
    parser.add_argument("--primary-target", default=PRIMARY_TARGET)
    parser.add_argument("--secondary-target", default=SECONDARY_TARGET)
    parser.add_argument("--selection-limit", type=int, default=DEFAULT_SELECTION_LIMIT)
    parser.add_argument("--max-per-endpoint", type=int, default=DEFAULT_MAX_PER_ENDPOINT)
    args = parser.parse_args()

    budget = max(1, args.budget)
    candidates = build_candidates(
        read_lines(args.candidates),
        budget,
    )

    if not candidates:
        print("[WARN] No Light candidates available.")
        return 1

    work_dir = tempfile.mkdtemp(prefix="proxy-harvester-light-")
    global_verified = []
    global_seen = set()
    global_metadata = {}

    try:
        chunk_count = (
            len(candidates) + DISCOVERY_CHUNK_SIZE - 1
        ) // DISCOVERY_CHUNK_SIZE

        for chunk_number, start in enumerate(
            range(0, len(candidates), DISCOVERY_CHUNK_SIZE), 1
        ):
            chunk = candidates[start:start + DISCOVERY_CHUNK_SIZE]
            chunk_output = os.path.join(
                work_dir, f"chunk-{chunk_number}.verified.txt"
            )
            chunk_metadata = os.path.join(
                work_dir, f"chunk-{chunk_number}.metadata.json"
            )

            print(
                f"[INFO] Global Light pass {chunk_number}/{chunk_count}: "
                f"testing {len(chunk)} candidates; "
                f"{len(global_verified)} verified so far."
            )

            ok = run_checker(
                args.checker,
                chunk,
                args.primary_target,
                chunk_output,
                chunk_metadata,
                args.workers,
                args.batch_size,
                args.timeout,
            )

            if not ok:
                print(
                    f"[WARN] Global checker failed for chunk {chunk_number}; "
                    "continuing."
                )
                continue

            chunk_verified = read_lines(chunk_output)
            global_chunk_metadata = load_metadata(chunk_metadata)

            for config in chunk_verified:
                if config not in global_seen:
                    global_seen.add(config)
                    global_verified.append(config)

            global_metadata.update(global_chunk_metadata)

            print(
                f"[INFO] Global Light pass {chunk_number}/{chunk_count}: "
                f"{len(chunk_verified)} verified; "
                f"{len(global_verified)} total."
            )

        if not global_verified:
            print("[WARN] Global validation produced zero verified configs.")
            return 1

        global_positions = {
            config: position for position, config in enumerate(global_verified)
        }
        ranked_global = sorted(
            global_verified,
            key=lambda config: global_rank(
                config,
                global_metadata,
                global_positions.get(config, len(global_verified)),
            ),
        )

        final_candidates = diversify_recheck_candidates(
            ranked_global,
            max(1, args.final_recheck_limit),
        )
        final_recheck_endpoints = {
            ep
            for config in final_candidates
            if (ep := endpoint(config)) is not None
        }

        print(
            f"[INFO] Final Light recheck: {len(final_candidates)} "
            f"individually tested candidates covering "
            f"{len(final_recheck_endpoints)} unique parsed endpoints."
        )

        primary_output = os.path.join(work_dir, "primary.txt")
        primary_metadata_path = os.path.join(work_dir, "primary.json")

        if not run_checker(
            args.checker,
            final_candidates,
            args.primary_target,
            primary_output,
            primary_metadata_path,
            args.final_workers,
            args.final_batch_size,
            args.timeout,
        ):
            print("[WARN] Final primary validation failed.")
            return 1

        primary_verified = read_lines(primary_output)
        primary_metadata = load_metadata(primary_metadata_path)

        if not primary_verified:
            print("[WARN] No configs survived the final primary validation.")
            return 1

        print(
            f"[INFO] Secondary target recheck: {len(primary_verified)} "
            f"configs against {args.secondary_target}."
        )

        secondary_output = os.path.join(work_dir, "secondary.txt")
        secondary_metadata_path = os.path.join(work_dir, "secondary.json")

        if not run_checker(
            args.checker,
            primary_verified,
            args.secondary_target,
            secondary_output,
            secondary_metadata_path,
            args.final_workers,
            args.final_batch_size,
            args.timeout,
        ):
            print("[WARN] Final secondary validation failed.")
            return 1

        secondary_verified = set(read_lines(secondary_output))
        secondary_metadata = load_metadata(secondary_metadata_path)

        both = [
            config
            for config in primary_verified
            if config in secondary_verified
        ]

        if not both:
            print(
                "[WARN] No configs survived both independent validation targets."
            )
            return 1

        ranked_final = sorted(
            both,
            key=lambda config: (
                -(
                    int(primary_metadata.get(config, {}).get("successes", 0))
                    + int(secondary_metadata.get(config, {}).get("successes", 0))
                ),
                (
                    float(primary_metadata.get(config, {}).get("median_ms", float("inf")))
                    + float(secondary_metadata.get(config, {}).get("median_ms", float("inf")))
                ),
                global_positions.get(config, len(global_verified)),
                config,
            ),
        )

        final = diversified(
            ranked_final,
            max(1, args.selection_limit),
            max(1, args.max_per_endpoint),
        )

        final_endpoints = {
            ep
            for config in final
            if (ep := endpoint(config)) is not None
        }

        if not final:
            print("[WARN] Diversity filtering left no verified configs.")
            return 1

        write_lines(args.output, final)

        print(
            f"[INFO] Published {len(final)} Light configs from "
            f"{len(global_verified)} globally verified candidates; "
            f"{len(final_endpoints)} unique parsed endpoints; "
            "final validation required both targets."
        )
        return 0
    finally:
        for root, _, files in os.walk(work_dir, topdown=False):
            for name in files:
                try:
                    os.unlink(os.path.join(root, name))
                except OSError:
                    pass
        try:
            os.rmdir(work_dir)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
