#!/usr/bin/env python3
"""Protocol-level proxy checker with multiple public reachability targets."""

import argparse
import collections
import concurrent.futures
import statistics
import time

from singbox2proxy import SingBoxBatch

DEFAULT_TARGETS = (
    "http://cp.cloudflare.com/",
)

MIN_SUCCESSFUL_TARGETS = 1
MAX_MEDIAN_LATENCY_MS = 800


def load_urls(path):
    with open(path, encoding="utf-8") as handle:
        return [
            line.strip()
            for line in handle
            if line.strip() and not line.lstrip().startswith("#")
        ]


def strip_fragment(url):
    """Remove the display name fragment before handing the URL to sing-box."""
    return url.split("#", 1)[0]


def start_group(urls, batch_size, rejected):
    """Start a group, recursively isolating configs that poison a sing-box batch."""
    if not urls:
        return []

    try:
        batch = SingBoxBatch(
            urls,
            batch_size=batch_size,
            log_level="error",
        )
    except Exception as exc:
        if len(urls) == 1:
            rejected.append((urls[0], str(exc)))
            return []
        midpoint = len(urls) // 2
        return (
            start_group(urls[:midpoint], batch_size, rejected)
            + start_group(urls[midpoint:], batch_size, rejected)
        )

    try:
        parsed = list(batch)
    except Exception as exc:
        batch.stop()
        if len(urls) == 1:
            rejected.append((urls[0], str(exc)))
            return []
        midpoint = len(urls) // 2
        return (
            start_group(urls[:midpoint], batch_size, rejected)
            + start_group(urls[midpoint:], batch_size, rejected)
        )

    if len(parsed) == len(urls):
        return [batch]

    batch.stop()

    if len(urls) == 1:
        reason = f"sing-box accepted {len(parsed)}/1 proxy handles"
        rejected.append((urls[0], reason))
        return []

    midpoint = len(urls) // 2
    return (
        start_group(urls[:midpoint], batch_size, rejected)
        + start_group(urls[midpoint:], batch_size, rejected)
    )


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

    original_urls = load_urls(args.input)
    if not original_urls:
        open(args.output, "w", encoding="utf-8").close()
        print("0/0 working")
        return 0

    test_urls = []
    original_by_test_url = {}
    for original in original_urls:
        test_url = strip_fragment(original)
        if test_url not in original_by_test_url:
            original_by_test_url[test_url] = original
            test_urls.append(test_url)

    rejected = []
    batches = []
    groups = [
        test_urls[index : index + max(1, args.batch_size)]
        for index in range(0, len(test_urls), max(1, args.batch_size))
    ]

    try:
        for group in groups:
            batches.extend(start_group(group, max(1, args.batch_size), rejected))

        proxies = [proxy for batch in batches for proxy in batch]
        print(
            f"loaded {len(original_urls)} input URLs, started {len(proxies)} proxy handles "
            f"in {len(batches)} batch(es), rejected {len(rejected)}",
            flush=True,
        )

        if rejected:
            for url, reason in rejected[:8]:
                print(f"rejected: {original_by_test_url.get(url, url)} :: {reason}", flush=True)

        if not proxies:
            open(args.output, "w", encoding="utf-8").close()
            print(f"0/{len(original_urls)} working", flush=True)
            return 0

        latencies = collections.defaultdict(list)
        failures = collections.Counter()
        first_success_counts = collections.Counter()
        targets_used = 0

        active_proxies = list(proxies)

        for target in DEFAULT_TARGETS:
            if not active_proxies:
                break

            targets_used += 1
            print(
                f"target {targets_used}/{len(DEFAULT_TARGETS)}: {target} "
                f"({len(active_proxies)} active proxies)",
                flush=True,
            )

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, min(args.workers, len(active_proxies)))
            ) as pool:
                futures = {
                    pool.submit(check_proxy, proxy, target, args.timeout): proxy
                    for proxy in active_proxies
                }

                next_active = []
                for future in concurrent.futures.as_completed(futures):
                    proxy = futures[future]
                    ok, latency_ms, error = future.result()
                    original_url = original_by_test_url.get(proxy.url, proxy.url)

                    if ok:
                        if not latencies[original_url]:
                            first_success_counts[target] += 1
                        latencies[original_url].append(latency_ms)
                    else:
                        failures[error or "unknown error"] += 1

                    if len(latencies[original_url]) < MIN_SUCCESSFUL_TARGETS:
                        next_active.append(proxy)

                active_proxies = next_active

            working = sum(bool(values) for values in latencies.values())
            print(
                f"  {working}/{len(proxies)} working after this target",
                flush=True,
            )

        eligible = {}
        for url, values in latencies.items():
            if not values:
                continue

            success_count = len(values)
            median_latency = statistics.median(values)
            min_latency = min(values)

            if (
                success_count >= MIN_SUCCESSFUL_TARGETS
                and median_latency <= MAX_MEDIAN_LATENCY_MS
            ):
                eligible[url] = (
                    median_latency,
                    success_count,
                    min_latency,
                )

        print(
            f"  {len(eligible)}/{len(latencies)} verified configs meet "
            f"{MIN_SUCCESSFUL_TARGETS}+ target successes and <= "
            f"{MAX_MEDIAN_LATENCY_MS}ms median latency",
            flush=True,
        )

        ordered = sorted(
            eligible,
            key=lambda url: (
                eligible[url][0],
                -eligible[url][1],
                eligible[url][2],
                url,
            ),
        )

        with open(args.output, "w", encoding="utf-8") as handle:
            for url in ordered:
                handle.write(url + "\n")

        print(
            f"{len(ordered)}/{len(proxies)} verified configs with reliable "
            f"multi-target latency across {targets_used} targets",
            flush=True,
        )
        print("first-success by target:", flush=True)
        for target in DEFAULT_TARGETS[:targets_used]:
            print(f"  {first_success_counts[target]}x {target}", flush=True)

        success_distribution = collections.Counter(
            len(values) for values in latencies.values()
        )
        print("target-success distribution:", flush=True)
        for count in sorted(success_distribution):
            print(f"  {count}/{targets_used} targets: {success_distribution[count]}", flush=True)

        if failures:
            print("failure summary:", flush=True)
            for error, count in failures.most_common(8):
                print(f"  {count}x {error}", flush=True)

        return 0
    finally:
        for batch in batches:
            batch.stop()


if __name__ == "__main__":
    raise SystemExit(main())
