#!/usr/bin/env python3
"""Xray-core proxy checker for HTTP connectivity and stability."""

import argparse
import base64
import collections
import concurrent.futures
import json
import os
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlsplit

DEFAULT_TARGET = "http://cp.cloudflare.com"
MIN_SUCCESSFUL_TARGETS = 2
STABILITY_ATTEMPTS = 3
MAX_LATENCY_MS = 800
DOWNLOAD_BYTES = 4096
UPLOAD_BYTES = 1024
MAX_RESPONSE_BYTES = 65536
RATE_LIMIT_RETRIES = 1
RATE_LIMIT_MAX_WAIT = 2.0
CORE_START_TIMEOUT = 5.0
SUPPORTED = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "wg", "socks", "socks5", "socks5h", "http"}


def load_urls(path):
    with open(path, encoding="utf-8") as f:
        return [x.strip() for x in f if x.strip() and not x.lstrip().startswith("#")]


def clean(url):
    return url.split("#", 1)[0]


def b64text(value):
    value = value.strip()
    for candidate in (value, value + "=" * (-len(value) % 4)):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                return decoder(candidate).decode()
            except (ValueError, UnicodeError, base64.binascii.Error):
                pass
    return None


def first(query, *names, default=None):
    wanted = {name.lower() for name in names}
    for name, values in query.items():
        if name.lower() in wanted and values and values[0] != "":
            return values[0]
    return default


def truthy(query, *names):
    return str(first(query, *names, default="")).lower() in {"1", "true", "yes", "on"}


def csv(value):
    return [x.strip() for x in value.split(",") if x.strip()]


def endpoint(parsed, default_port=None):
    if not parsed.hostname:
        raise ValueError("missing host")
    port = parsed.port or default_port
    if not port or not 0 < port <= 65535:
        raise ValueError("missing or invalid port")
    return parsed.hostname, port


def stream(query, host):
    network = first(query, "type", "network", default="tcp").lower()
    if network == "tcp":
        network = "raw"
    if network not in {"raw", "ws", "grpc", "httpupgrade", "xhttp"}:
        raise ValueError(f"unsupported transport {network}")

    security = first(query, "security", default="none").lower()
    if security not in {"none", "tls", "reality"}:
        raise ValueError(f"unsupported security {security}")
    if security == "reality" and network not in {"raw", "xhttp", "grpc"}:
        raise ValueError("reality unsupported with this transport")

    out = {"network": network, "security": security}
    sni = first(query, "sni", "server_name", "peer", default=host)
    alpn = csv(first(query, "alpn", default=""))
    if security == "tls":
        tls = {"serverName": sni}
        if alpn:
            tls["alpn"] = alpn
        fp = first(query, "fp", "fingerprint")
        if fp:
            tls["fingerprint"] = fp
        if truthy(query, "insecure", "allowInsecure"):
            tls["allowInsecure"] = True
        out["tlsSettings"] = tls
    elif security == "reality":
        pbk = first(query, "pbk", "publicKey")
        if not pbk:
            raise ValueError("reality public key missing")
        reality = {"show": False, "serverName": sni, "publicKey": pbk}
        fp = first(query, "fp", "fingerprint")
        sid = first(query, "sid", "shortId")
        spx = first(query, "spx", "spiderX")
        if fp:
            reality["fingerprint"] = fp
        if sid:
            reality["shortId"] = sid
        if spx:
            reality["spiderX"] = unquote(spx)
        out["realitySettings"] = reality

    path = first(query, "path")
    host_header = first(query, "host")
    if network == "raw":
        header_type = first(query, "headerType", "header_type")
        if header_type and header_type.lower() == "http":
            header = {"type": "http"}
            request = {}
            if path:
                request["path"] = [path]
            if host_header:
                request["headers"] = {"Host": csv(host_header)}
            if request:
                header["request"] = request
            out["rawSettings"] = {"header": header}
    elif network == "ws":
        ws = {}
        if path:
            ws["path"] = path
        if host_header:
            ws["headers"] = {"Host": host_header}
        out["wsSettings"] = ws
    elif network == "httpupgrade":
        hu = {}
        if path:
            hu["path"] = path
        if host_header:
            hu["host"] = host_header
        out["httpupgradeSettings"] = hu
    elif network == "grpc":
        grpc = {}
        authority = first(query, "authority", "host")
        service = first(query, "serviceName", "service_name")
        if authority:
            grpc["authority"] = authority
        if service:
            grpc["serviceName"] = service
        if str(first(query, "mode", default="")).lower() == "multi":
            grpc["multiMode"] = True
        out["grpcSettings"] = grpc
    else:
        xhttp = {"mode": first(query, "mode", default="auto")}
        if path:
            xhttp["path"] = path
        if host_header:
            xhttp["host"] = host_header
        extra = first(query, "extra")
        if extra:
            try:
                value = json.loads(unquote(extra))
                if isinstance(value, dict):
                    xhttp["extra"] = value
            except json.JSONDecodeError:
                pass
        out["xhttpSettings"] = xhttp
    return out


def parse_vless(config):
    p = urlsplit(clean(config))
    host, port = endpoint(p)
    q = parse_qs(p.query, keep_blank_values=True)
    uuid = unquote(p.username or "")
    if not uuid:
        raise ValueError("VLESS UUID missing")
    user = {"id": uuid, "encryption": first(q, "encryption", default="none")}
    flow = first(q, "flow")
    if flow:
        user["flow"] = flow
    return {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": stream(q, host),
    }


def parse_vmess(config):
    decoded = b64text(clean(config).split("://", 1)[1])
    if not decoded:
        raise ValueError("invalid VMess base64")
    value = json.loads(decoded)
    host = str(value.get("add", "")).strip()
    port = int(value.get("port", 0) or 0)
    uuid = str(value.get("id", "")).strip()
    if not host or not uuid or not 0 < port <= 65535:
        raise ValueError("VMess endpoint or UUID missing")
    network = str(value.get("net", "tcp") or "tcp").lower()
    if network == "h2":
        raise ValueError("VMess h2 transport unsupported")
    q = {"type": [network], "security": [str(value.get("tls", "") or "none")]}
    for src, dst in (("sni", "sni"), ("alpn", "alpn"), ("fp", "fp"), ("host", "host"), ("path", "path"), ("allowInsecure", "insecure")):
        if value.get(src) not in (None, ""):
            q[dst] = [str(value[src])]
    if str(value.get("type", "none")).lower() == "http" and network == "tcp":
        q["headerType"] = ["http"]
    user = {"id": uuid, "alterId": int(value.get("aid", 0) or 0), "security": str(value.get("scy", "auto") or "auto")}
    return {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": stream(q, host),
    }


def parse_trojan(config):
    p = urlsplit(clean(config))
    host, port = endpoint(p)
    password = unquote(p.username or "")
    if not password:
        raise ValueError("Trojan password missing")
    q = parse_qs(p.query, keep_blank_values=True)
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": stream(q, host),
    }


def parse_ss(config):
    p = urlsplit(clean(config))
    q = parse_qs(p.query, keep_blank_values=True)
    if first(q, "plugin"):
        raise ValueError("Shadowsocks plugins unsupported")
    if p.hostname and p.port and p.username:
        host, port, method, password = p.hostname, p.port, unquote(p.username), unquote(p.password or "")
    else:
        decoded = b64text(p.netloc)
        if not decoded or "@" not in decoded or ":" not in decoded.split("@", 1)[0]:
            raise ValueError("invalid Shadowsocks payload")
        credentials, remote = decoded.rsplit("@", 1)
        method, password = credentials.split(":", 1)
        host, port = endpoint(urlsplit("ss://" + remote))
    return {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
    }


def parse_hy2(config):
    p = urlsplit(clean(config))
    host, port = endpoint(p)
    q = parse_qs(p.query, keep_blank_values=True)
    if first(q, "obfs") or first(q, "obfs-password"):
        raise ValueError("Hysteria2 obfs unsupported by Xray")
    password = unquote(p.username or "")
    if p.password is not None:
        password += ":" + unquote(p.password)
    if not password:
        raise ValueError("Hysteria2 password missing")
    tls_query = dict(q)
    tls_query["security"] = ["tls"]
    return {
        "protocol": "hysteria",
        "settings": {"version": 2, "address": host, "port": port},
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": stream(tls_query, host)["tlsSettings"],
            "hysteriaSettings": {"version": 2, "auth": password},
        },
    }


def parse_wg(config):
    p = urlsplit(clean(config))
    host, port = endpoint(p)
    q = parse_qs(p.query, keep_blank_values=True)
    private = unquote(p.username or "") or first(q, "privatekey", "private-key", "private_key", "private_key_base64")
    public = first(q, "publickey", "public-key", "public_key", "peer-public-key", "peer_public_key", "pubkey")
    if not private or not public:
        raise ValueError("WireGuard keys missing")
    address = csv(first(q, "address", "addresses", "local-address", default="10.0.0.1"))
    peer = {
        "endpoint": f"{host}:{port}",
        "publicKey": public,
        "allowedIPs": csv(first(q, "allowedIPs", "allowed-ips", default="0.0.0.0/0,::/0")),
    }
    psk = first(q, "presharedkey", "preshared-key", "preshared_key", "psk")
    if psk:
        peer["preSharedKey"] = psk
    keepalive = first(q, "keepalive", "keep-alive")
    if keepalive:
        peer["keepAlive"] = int(keepalive)
    return {
        "protocol": "wireguard",
        "settings": {
            "secretKey": private,
            "address": address,
            "peers": [peer],
            "noKernelTun": True,
            "remoteDNS": ["1.1.1.1", "1.0.0.1"],
        },
    }


def parse_basic(config):
    p = urlsplit(clean(config))
    host, port = endpoint(p, 1080 if p.scheme in {"socks", "socks5", "socks5h"} else 8080)
    protocol = "http" if p.scheme == "http" else "socks"
    server = {"address": host, "port": port}
    if p.username:
        server["users"] = [{"user": unquote(p.username), "pass": unquote(p.password or "")}]
    return {"protocol": protocol, "settings": {"servers": [server]}}


def parse_config(config):
    scheme = urlsplit(clean(config)).scheme.lower()
    if scheme not in SUPPORTED:
        raise ValueError(f"unsupported scheme {scheme or 'unknown'}")
    if scheme == "vless":
        return parse_vless(config)
    if scheme == "vmess":
        return parse_vmess(config)
    if scheme == "trojan":
        return parse_trojan(config)
    if scheme == "ss":
        return parse_ss(config)
    if scheme in {"hysteria2", "hy2"}:
        return parse_hy2(config)
    if scheme == "wg":
        return parse_wg(config)
    return parse_basic(config)


def ports(count):
    sockets = []
    values = []
    try:
        for _ in range(count):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            values.append(s.getsockname()[1])
            sockets.append(s)
        return values
    finally:
        for s in sockets:
            s.close()


def xray_config(entries):
    selected = ports(len(entries))
    ins = []
    outs = []
    rules = []
    for i, (_, outbound) in enumerate(entries):
        itag, otag = f"in-{i}", f"out-{i}"
        ins.append({
            "tag": itag,
            "listen": "127.0.0.1",
            "port": selected[i],
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        })
        outbound["tag"] = otag
        outs.append(outbound)
        rules.append({"type": "field", "inboundTag": [itag], "outboundTag": otag})
    return {
        "log": {"loglevel": "error"},
        "inbounds": ins,
        "outbounds": outs,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }, selected


def start_xray(binary, config_path, log_path):
    log = open(log_path, "w", encoding="utf-8")
    return subprocess.Popen(
        [binary, "run", "-c", config_path],
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    ), log


def wait_ports(process, values):
    deadline = time.monotonic() + CORE_START_TIMEOUT
    pending = list(values)
    workers = max(1, min(64, len(pending)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        while pending and time.monotonic() < deadline:
            if process.poll() is not None:
                return False

            ready = list(pool.map(_port_ready, pending))
            pending = [
                port
                for port, is_ready in zip(pending, ready)
                if not is_ready
            ]

            if pending:
                time.sleep(0.05)

    return not pending


def _port_ready(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.15):
            return True
    except OSError:
        return False


class RateLimited(Exception):
    def __init__(self, retry_after=0.0):
        super().__init__("target rate limited")
        self.retry_after = retry_after


def _response_body(sock, headers):
    length = headers.get("content-length")
    if length is not None:
        try:
            expected = int(length)
        except ValueError:
            raise OSError("invalid Content-Length")
        if expected < 0 or expected > MAX_RESPONSE_BYTES:
            raise OSError("response body too large")
        data = bytearray()
        while len(data) < expected:
            chunk = sock.recv(min(4096, expected - len(data)))
            if not chunk:
                raise OSError("HTTP response body truncated")
            data.extend(chunk)
        return bytes(data)

    data = bytearray()
    while len(data) <= MAX_RESPONSE_BYTES:
        chunk = sock.recv(min(4096, MAX_RESPONSE_BYTES + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > MAX_RESPONSE_BYTES:
            raise OSError("response body too large")
    return bytes(data)


def _http_transfer(port, scheme, host, target_port, path, timeout_seconds, method, body=b""):
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout_seconds)
    sock.settimeout(timeout_seconds)
    try:
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise OSError("SOCKS5 auth negotiation failed")

        name = host.encode("idna")
        if len(name) > 255:
            raise OSError("target hostname too long")
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(name)])
            + name
            + target_port.to_bytes(2, "big")
        )

        head = sock.recv(4)
        if len(head) != 4 or head[0] != 5 or head[1] != 0:
            raise OSError("SOCKS5 CONNECT failed")

        atyp = head[3]
        size = 4 if atyp == 1 else 16 if atyp == 4 else None
        if atyp == 3:
            length = sock.recv(1)
            if not length:
                raise OSError("SOCKS5 response truncated")
            size = length[0]
        if size is None:
            raise OSError("SOCKS5 response address type invalid")

        left = size + 2
        while left:
            chunk = sock.recv(left)
            if not chunk:
                raise OSError("SOCKS5 response truncated")
            left -= len(chunk)

        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=host)

        headers = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host}",
            "Connection: close",
            "User-Agent: Proxy-Harvester/3.0",
            "Accept: */*",
        ]
        if body:
            headers.append("Content-Type: application/octet-stream")
            headers.append(f"Content-Length: {len(body)}")

        request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
        started = time.monotonic()
        sock.sendall(request)

        raw = bytearray()
        while b"\r\n\r\n" not in raw and len(raw) < MAX_RESPONSE_BYTES:
            chunk = sock.recv(min(4096, MAX_RESPONSE_BYTES - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)

        marker = b"\r\n\r\n"
        if marker not in raw:
            raise OSError("HTTP response headers not received")

        header_bytes, remainder = bytes(raw).split(marker, 1)
        lines = header_bytes.decode("iso-8859-1").split("\r\n")
        if not lines or len(lines[0].split()) < 2:
            raise OSError("invalid HTTP status line")

        try:
            status = int(lines[0].split()[1])
        except ValueError:
            raise OSError("invalid HTTP status code")

        response_headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                response_headers[key.strip().lower()] = value.strip()

        if status == 429:
            retry_after = 0.0
            try:
                retry_after = float(response_headers.get("retry-after", "0"))
            except ValueError:
                pass
            raise RateLimited(min(max(retry_after, 0.0), RATE_LIMIT_MAX_WAIT))

        if status < 200 or status >= 300:
            raise OSError(f"HTTP status {status}")

        if "content-length" in response_headers:
            length = int(response_headers["content-length"])
            remaining = length - len(remainder)
            if remaining > 0:
                remainder += sock.recv(remaining)
            if len(remainder) < length:
                raise OSError("HTTP response body truncated")
            body_data = remainder[:length]
        else:
            body_data = bytes(remainder) + _response_body(sock, {})
        return (time.monotonic() - started) * 1000, body_data
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _probe_once(port, host, target_port, timeout_seconds):
    download_path = f"/__down?bytes={DOWNLOAD_BYTES}"
    upload_body = b"0" * UPLOAD_BYTES

    download_latency, download_body = _http_transfer(
        port,
        "https",
        host,
        target_port,
        download_path,
        timeout_seconds,
        "GET",
    )
    if len(download_body) < DOWNLOAD_BYTES:
        raise OSError(
            f"download body too small: {len(download_body)} < {DOWNLOAD_BYTES}"
        )

    upload_latency, upload_response = _http_transfer(
        port,
        "https",
        host,
        target_port,
        "/__up",
        timeout_seconds,
        "POST",
        upload_body,
    )

    return max(download_latency, upload_latency), (download_latency, upload_latency, len(upload_response))


def probe(port, target, timeout_seconds):
    p = urlsplit(target)
    default_port = {"http": 80, "https": 443}.get(p.scheme.lower())
    host, target_port = endpoint(p, default_port)

    last_rate_limit = None
    for retry in range(RATE_LIMIT_RETRIES + 1):
        try:
            return True, _probe_once(port, host, target_port, timeout_seconds)[0], ""
        except RateLimited as exc:
            last_rate_limit = exc
            if retry >= RATE_LIMIT_RETRIES:
                break
            if exc.retry_after:
                time.sleep(exc.retry_after)

    if last_rate_limit is not None:
        raise OSError("Cloudflare test endpoint rate limited after retry")
    raise OSError("probe failed")

def check_batch(binary, entries, target, timeout_seconds, workers):
    with tempfile.TemporaryDirectory(prefix="proxy-harvester-xray-") as work:
        config_path = os.path.join(work, "xray.json")
        log_path = os.path.join(work, "xray.log")
        conf, local_ports = xray_config(entries)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(conf, f, separators=(",", ":"))

        process, log = start_xray(binary, config_path, log_path)
        try:
            if not wait_ports(process, local_ports):
                if len(entries) == 1:
                    reason = "Xray core failed to start"
                    try:
                        with open(log_path, encoding="utf-8", errors="replace") as f:
                            tail = f.read()[-700:].strip()
                        if tail:
                            reason += f": {tail}"
                    except OSError:
                        pass
                    return {}, {entries[0][0]: reason}

                mid = len(entries) // 2
                left = check_batch(binary, entries[:mid], target, timeout_seconds, workers)
                right = check_batch(binary, entries[mid:], target, timeout_seconds, workers)
                left[0].update(right[0])
                left[1].update(right[1])
                return left

            active = [(config, local_ports[i]) for i, (config, _) in enumerate(entries)]
            successes = collections.Counter()
            attempts = collections.Counter()
            latencies = collections.defaultdict(list)
            errors = {}

            for attempt in range(STABILITY_ATTEMPTS):
                if not active:
                    break
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=max(1, min(workers, len(active)))
                ) as pool:
                    futures = {
                        pool.submit(probe, port, target, timeout_seconds): config
                        for config, port in active
                    }
                    for future in concurrent.futures.as_completed(futures):
                        config = futures[future]
                        try:
                            ok, latency, error = future.result()
                        except Exception as exc:
                            ok, latency, error = False, 0, str(exc)[:160]
                        attempts[config] += 1
                        if ok:
                            successes[config] += 1
                            latencies[config].append(latency)
                        else:
                            errors[config] = error

                left = STABILITY_ATTEMPTS - attempt - 1
                active = [
                    (config, port)
                    for config, port in active
                    if successes[config] < MIN_SUCCESSFUL_TARGETS
                    and successes[config] + left >= MIN_SUCCESSFUL_TARGETS
                ]

            metadata = {}
            failures = {}
            for config, _ in entries:
                values = latencies[config]
                if (
                    successes[config] >= MIN_SUCCESSFUL_TARGETS
                    and values
                    and max(values) <= MAX_LATENCY_MS
                ):
                    values = sorted(values)
                    mid = len(values) // 2
                    median = (
                        values[mid]
                        if len(values) % 2
                        else (values[mid - 1] + values[mid]) / 2
                    )
                    metadata[config] = {
                        "successes": successes[config],
                        "attempts": attempts[config],
                        "median_ms": median,
                        "min_ms": min(values),
                    }
                else:
                    failures[config] = errors.get(config, "validation failed")
            return metadata, failures
        finally:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
            log.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--batch-size", type=int, default=100)
    ap.add_argument("--timeout", type=float, default=1)
    ap.add_argument("--metadata")
    ap.add_argument("--target", default=DEFAULT_TARGET)
    ap.add_argument("--xray", default="xray")
    args = ap.parse_args()

    originals = load_urls(args.input)
    unique = []
    original_for = {}
    for original in originals:
        value = clean(original)
        if value not in original_for:
            original_for[value] = original
            unique.append(value)

    parsed = []
    rejected = []
    rejected_by_scheme = collections.Counter()
    for config in unique:
        try:
            parsed.append((config, parse_config(config)))
        except Exception as exc:
            rejected.append((config, str(exc)))
            rejected_by_scheme[urlsplit(config).scheme.lower() or "unknown"] += 1

    print(
        f"loaded {len(originals)} input URLs, accepted {len(parsed)} for Xray, rejected {len(rejected)}",
        flush=True,
    )
    if rejected:
        for config, reason in rejected[:8]:
            print(f"rejected: {original_for[config]} :: {reason}", flush=True)
        print("rejected by scheme:", dict(sorted(rejected_by_scheme.items())), flush=True)

    metadata = {}
    batch_size = max(1, args.batch_size)
    for i in range(0, len(parsed), batch_size):
        batch = parsed[i:i + batch_size]
        batch_number = i // batch_size + 1
        batch_count = (len(parsed) + batch_size - 1) // batch_size
        print(
            f"target {args.target}: batch {batch_number}/{batch_count}, "
            f"testing {len(batch)} configs with Xray core; "
            f"requiring {MIN_SUCCESSFUL_TARGETS}/{STABILITY_ATTEMPTS}",
            flush=True,
        )
        batch_meta, _ = check_batch(args.xray, batch, args.target, args.timeout, args.workers)
        metadata.update(batch_meta)

    ordered = sorted(
        metadata,
        key=lambda c: (
            -metadata[c]["successes"],
            metadata[c]["median_ms"],
            metadata[c]["min_ms"],
            c,
        ),
    )
    with open(args.output, "w", encoding="utf-8") as f:
        for config in ordered:
            f.write(original_for[config] + "\n")

    print(
        f"{len(ordered)}/{len(originals)} verified by Xray with "
        f"{MIN_SUCCESSFUL_TARGETS}/{STABILITY_ATTEMPTS} successful attempts and "
        f"every measured latency <= {MAX_LATENCY_MS}ms",
        flush=True,
    )
    if args.metadata:
        with open(args.metadata, "w", encoding="utf-8") as f:
            json.dump(metadata, f, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
