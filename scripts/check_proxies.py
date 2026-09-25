#!/usr/bin/env python3
"""Protocol-level proxy checker with multiple public reachability targets."""

import argparse
import concurrent.futures
import sys
import time

from singbox2proxy import SingBoxBatch

DEFAULT_TARGETS = (
    "https://www.google.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://api.ipify.org?format=json",
)


def load_urls(path):
    with open(path, encoding="utf-8") as handle:
        return [
            line.strip()
            for line in handle
            if line.strip() and not line.lstrip().startswith("#")
        ]


def check_proxy(proxy, target, timeout):
    started = time.monotonic()
    try:
        response = proxy.get(target, timeout=timeout)
        elapsed_ms = (time.monotonic() - started) * 1000
        if 200 <= response.status_code < 400:
            return True, elapsed_ms, ""
        return False, elapsed_ms, f"HTTP {response.status_code}"
    except Exception as exc:
        elapsed_ms = (time.monotonic() - started) * 1000
        return False, elapsed_ms, str(exc)[:160]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    urls = load_urls(args.input)
    if not urls:
        open(args.output, "w", encoding="utf-8").close()
        print("0/0 working")
        return 0

    try:
        batch = SingBoxBatch.from_file(
            args.input,
            batch_size=args.batch_size,
            log_level="error",
        )
    except Exception as exc:
        print(f"failed to start singbox2proxy: {exc}", file=sys.stderr)
        return 2

    proxies = {proxy.url: proxy for proxy in batch}
    working = {}
    remaining = [proxy for proxy in batch if proxy.url in urls]
    targets_used = 0

    try:
        for target in DEFAULT_TARGETS:
            if not remaining:
                break

            targets_used += 1
            print(
                f"target {targets_used}/{len(DEFAULT_TARGETS)}: {target}",
                flush=True,
            )

            next_remaining = []
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, min(args.workers, len(remaining)))
            ) as pool:
                futures = {
                    pool.submit(check_proxy, proxy, target, args.timeout): proxy
                    for proxy in remaining
                }

                for future in concurrent.futures.as_completed(futures):
                    proxy = futures[future]
                    ok, latency_ms, error = future.result()
                    if ok:
                        previous = working.get(proxy.url)
                        if previous is None or latency_ms < previous:
                            working[proxy.url] = latency_ms
                    else:
                        next_remaining.append(proxy)

            print(
                f"  {len(working)}/{len(urls)} working after this target",
                flush=True,
            )
            remaining = next_remaining

        ordered = sorted(
            working,
            key=lambda url: (working[url], url),
        )

        with open(args.output, "w", encoding="utf-8") as handle:
            for url in ordered:
                handle.write(url + "\n")

        print(
            f"{len(ordered)}/{len(urls)} working across {targets_used} targets",
            flush=True,
        )
        return 0
    finally:
        batch.stop()


if __name__ == "__main__":
    raise SystemExit(main())
