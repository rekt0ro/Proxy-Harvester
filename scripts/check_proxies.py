#!/usr/bin/env python3
"""Protocol-level proxy checker using the same Cloudflare URL used by Throne."""

import argparse
import base64
import collections
import concurrent.futures
import json
import logging
import socket
import statistics
import time
from urllib.parse import urlsplit

from singbox2proxy import SingBoxBatch

# The proxy library logs every rejected/invalid URL at ERROR level. Those
# per-config diagnostics can flood Actions logs without changing validation
# results, so keep our own aggregate summaries while silencing that logger.
logging.getLogger("singbox2proxy").setLevel(logging.CRITICAL + 1)

DEFAULT_TARGETS = (
    "http://cp.cloudflare.com/",
)

MIN_SUCCESSFUL_TARGETS = 2
STABILITY_ATTEMPTS = 3
MAX_MEDIAN_LATENCY_MS = 3000
DEFAULT_WARM_TIMEOUT = 5

TCP_SCHEMES = {"vmess", "vless", "trojan", "ss", "socks", "socks5", "socks5h"}


def load_urls(path):
    with open(path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.lstrip().startswith("#")]


def strip_fragment(url):
    return url.split("#", 1)[0]


def endpoint(url):
    scheme = url.split("://", 1)[0].lower()
    if scheme == "vmess":
        try:
            raw = url.split("://", 1)[1].split("#", 1)[0]
            raw += "=" * (-len(raw) % 4)
            obj = json.loads(base64.urlsafe_b64decode(raw).decode())
            host = str(obj.get("add", "")).strip()
            port = int(obj.get("port", 0))
            if host and port:
                return host, port
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        return None

    try:
        parsed = urlsplit(url)
        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port
    except ValueError:
        pass
    return None


def tcp_prefilter(urls, timeout, workers):
    """Drop TCP proxy URLs whose endpoint cannot accept a TCP connection.

    This is a safe prefilter: a failed TCP connect means a TCP-based proxy
    cannot establish its proxy session. UDP/QUIC protocols are left untouched.
    Each endpoint is probed once even when several configs share it.
    """
    endpoint_to_urls = collections.defaultdict(list)
    passthrough = []

    for url in urls:
        scheme = url.split("://", 1)[0].lower()
        if scheme not in TCP_SCHEMES:
            passthrough.append(url)
            continue
        ep = endpoint(url)
        if ep is None:
            continue
        endpoint_to_urls[ep].append(url)

    def probe(ep):
        host, port = ep
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return ep, True, ""
        except OSError as exc:
            return ep, False, str(exc)[:120]

    reachable = set()
    failures = 0
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, min(workers, len(endpoint_to_urls) or 1))
    ) as pool:
        futures = [pool.submit(probe, ep) for ep in endpoint_to_urls]
        for future in concurrent.futures.as_completed(futures):
            ep, ok, _ = future.result()
            if ok:
                reachable.add(ep)
            else:
                failures += 1

    filtered = passthrough[:]
    for ep, ep_urls in endpoint_to_urls.items():
        if ep in reachable:
            filtered.extend(ep_urls)

    print(
        f"TCP prefilter: {len(urls)} input URLs -> {len(filtered)} URLs; "
        f"{len(endpoint_to_urls)} unique TCP endpoints, "
        f"{len(reachable)} reachable, {failures} unreachable; "
        f"UDP/QUIC URLs passed through {len(passthrough)}",
        flush=True,
    )
    return filtered


def configure_proxy(proxy):
    """Disable nested automatic retries so each stability attempt is real."""
    client = getattr(proxy, "client", None)
    if client is None:
        request = getattr(proxy, "request", None)
        client = getattr(request, "__self__", None)
    if client is None:
        return
    if hasattr(client, "auto_retry"):
        client.auto_retry = False
    if hasattr(client, "retry_times"):
        client.retry_times = 0


def start_group(urls, batch_size, rejected, chain_proxy=None):
    if not urls:
        return []
    try:
        batch = SingBoxBatch(urls, batch_size=batch_size, chain_proxy=chain_proxy, log_level="error")
    except Exception as exc:
        if len(urls) == 1:
            rejected.append((urls[0], str(exc)))
            return []
        midpoint = len(urls) // 2
        return start_group(urls[:midpoint], batch_size, rejected, chain_proxy) + start_group(urls[midpoint:], batch_size, rejected, chain_proxy)

    try:
        parsed = list(batch)
    except Exception as exc:
        batch.stop()
        if len(urls) == 1:
            rejected.append((urls[0], str(exc)))
            return []
        midpoint = len(urls) // 2
        return start_group(urls[:midpoint], batch_size, rejected, chain_proxy) + start_group(urls[midpoint:], batch_size, rejected, chain_proxy)

    if len(parsed) == len(urls):
        for proxy in parsed:
            configure_proxy(proxy)
        return [batch]

    batch.stop()
    if len(urls) == 1:
        rejected.append((urls[0], f"sing-box accepted {len(parsed)}/1 proxy handles"))
        return []
    midpoint = len(urls) // 2
    return start_group(urls[:midpoint], batch_size, rejected, chain_proxy) + start_group(urls[midpoint:], batch_size, rejected, chain_proxy)


def check_proxy(proxy, target, timeout):
    started = time.monotonic()
    try:
        response = proxy.get(target, timeout=timeout)
        elapsed_ms = (time.monotonic() - started) * 1000
        status = response.status_code
        try:
            response.close()
        except Exception:
            pass
        if not (200 <= status < 400):
            return False, elapsed_ms, f"HTTP {status}"
        return True, elapsed_ms, ""
    except Exception as exc:
        return False, (time.monotonic() - started) * 1000, str(exc)[:160]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument(
        "--timeout",
        type=float,
        default=8,
        help="Maximum time for the first/cold request.",
    )
    parser.add_argument(
        "--warm-timeout",
        type=float,
        default=DEFAULT_WARM_TIMEOUT,
        help="Maximum time for subsequent warm stability requests.",
    )
    parser.add_argument("--chain-proxy", default=None)
    parser.add_argument("--metadata", default=None)
    parser.add_argument(
        "--target",
        default=None,
        help="Validation target URL. Defaults to the same Cloudflare URL used by Throne.",
    )
    parser.add_argument(
        "--tcp-prefilter",
        action="store_true",
        help="Before sing-box validation, drop TCP configs whose endpoint cannot accept TCP connections.",
    )
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

    if args.tcp_prefilter:
        test_urls = tcp_prefilter(
            test_urls,
            timeout=3.0,
            workers=max(1, min(args.workers, 50)),
        )

    rejected = []
    batches = []
    groups = [test_urls[index:index + max(1, args.batch_size)] for index in range(0, len(test_urls), max(1, args.batch_size))]

    try:
        for group in groups:
            batches.extend(start_group(group, max(1, args.batch_size), rejected, args.chain_proxy))

        proxies = [proxy for batch in batches for proxy in batch]
        print(f"loaded {len(original_urls)} input URLs, started {len(proxies)} proxy handles in {len(batches)} batch(es), rejected {len(rejected)}", flush=True)

        if rejected:
            for url, reason in rejected[:8]:
                print(f"rejected: {original_by_test_url.get(url, url)} :: {reason}", flush=True)

        if not proxies:
            open(args.output, "w", encoding="utf-8").close()
            print(f"0/{len(original_urls)} working", flush=True)
            return 0

        latencies = collections.defaultdict(list)
        success_counts = collections.Counter()
        attempt_counts = collections.Counter()
        active_proxies = list(proxies)

        targets = (args.target,) if args.target else DEFAULT_TARGETS
        for target in targets:
            if not active_proxies:
                break

            print(f"target {target}: {len(active_proxies)} active proxies, requiring {MIN_SUCCESSFUL_TARGETS}/{STABILITY_ATTEMPTS} successful attempts", flush=True)

            for attempt in range(1, STABILITY_ATTEMPTS + 1):
                if not active_proxies:
                    break

                with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(args.workers, len(active_proxies)))) as pool:
                    request_timeout = (
                        args.timeout
                        if attempt == 1
                        else min(args.timeout, args.warm_timeout)
                    )
                    futures = {
                        pool.submit(
                            check_proxy,
                            proxy,
                            target,
                            request_timeout,
                        ): proxy
                        for proxy in active_proxies
                    }
                    for future in concurrent.futures.as_completed(futures):
                        proxy = futures[future]
                        ok, latency_ms, _ = future.result()
                        original_url = original_by_test_url.get(proxy.url, proxy.url)
                        attempt_counts[original_url] += 1
                        if ok:
                            success_counts[original_url] += 1
                            latencies[original_url].append(latency_ms)

                remaining = []
                attempts_left = STABILITY_ATTEMPTS - attempt
                for proxy in active_proxies:
                    original_url = original_by_test_url.get(proxy.url, proxy.url)
                    successes = success_counts[original_url]
                    if successes >= MIN_SUCCESSFUL_TARGETS:
                        continue
                    if successes + attempts_left >= MIN_SUCCESSFUL_TARGETS:
                        remaining.append(proxy)
                active_proxies = remaining

                stable = sum(1 for count in success_counts.values() if count >= MIN_SUCCESSFUL_TARGETS)
                print(
                    f"  attempt {attempt}/{STABILITY_ATTEMPTS}: "
                    f"{stable}/{len(proxies)} stable so far; "
                    f"{len(active_proxies)} still testing; "
                    f"timeout={request_timeout:g}s",
                    flush=True,
                )

        eligible = {}
        for url, values in latencies.items():
            if success_counts[url] < MIN_SUCCESSFUL_TARGETS or not values:
                continue
            median_latency = statistics.median(values)
            min_latency = min(values)
            if median_latency <= MAX_MEDIAN_LATENCY_MS:
                eligible[url] = (
                    median_latency,
                    success_counts[url],
                    min_latency,
                    attempt_counts[url],
                )

        print(f"  {len(eligible)}/{len(latencies)} verified configs meet {MIN_SUCCESSFUL_TARGETS}/{STABILITY_ATTEMPTS} successful attempts and <= {MAX_MEDIAN_LATENCY_MS}ms median latency", flush=True)

        ordered = sorted(
            eligible,
            key=lambda url: (-eligible[url][1], eligible[url][0], eligible[url][2], url),
        )
        with open(args.output, "w", encoding="utf-8") as handle:
            for url in ordered:
                handle.write(url + "\n")

        print(f"{len(ordered)}/{len(proxies)} verified configs with stability-tested reachability across {len(targets)} target(s)", flush=True)
        distribution = collections.Counter(
            (success_counts[url], attempt_counts[url]) for url in eligible
        )
        print("success distribution:", flush=True)
        for (successes, attempts), number in sorted(distribution.items()):
            print(f"  {successes}/{attempts}: {number}", flush=True)

        if args.metadata:
            metadata = {
                url: {
                    "successes": success_counts[url],
                    "attempts": eligible[url][3],
                    "median_ms": eligible[url][0],
                    "min_ms": eligible[url][2],
                }
                for url in eligible
            }
            with open(args.metadata, "w", encoding="utf-8") as handle:
                json.dump(metadata, handle, separators=(",", ":"))
    finally:
        for batch in batches:
            try:
                batch.stop()
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
