from pathlib import Path
import base64
import re
import requests
from singbox2proxy import SingBoxBatch


ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT / "sources.txt"
OUTPUT_DIR = ROOT / "subscriptions"

TIMEOUT = 8
WORKERS = 4
BATCH_SIZE = 10
CHUNK_SIZE = 100
LIGHT_LIMIT = 200

SCHEMES = (
    "vmess://",
    "vless://",
    "trojan://",
    "ss://",
    "ssr://",
    "socks://",
    "socks5://",
    "http://",
    "https://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
)

SCHEME_PATTERN = re.compile(
    r"(?:vmess|vless|trojan|ssr?|socks5?|https?|hysteria2?|hy2)://[^\s<>\"']+",
    re.IGNORECASE,
)


def load_sources():
    if not SOURCES_FILE.exists():
        return []

    sources = []

    for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        sources.append(line)

    return sources


def decode_base64(text):
    compact = "".join(text.split())

    if len(compact) < 16:
        return ""

    padding = "=" * (-len(compact) % 4)

    try:
        decoded = base64.b64decode(compact + padding, validate=True)
        result = decoded.decode("utf-8", errors="ignore")
    except (ValueError, UnicodeDecodeError):
        try:
            decoded = base64.urlsafe_b64decode(compact + padding)
            result = decoded.decode("utf-8", errors="ignore")
        except (ValueError, UnicodeDecodeError):
            return ""

    if "://" not in result:
        return ""

    return result


def extract_configs(text):
    configs = []

    for match in SCHEME_PATTERN.finditer(text):
        config = match.group(0).rstrip("),]}\n\r")
        configs.append(config)

    if configs:
        return configs

    decoded = decode_base64(text)

    if decoded:
        for match in SCHEME_PATTERN.finditer(decoded):
            config = match.group(0).rstrip("),]}\n\r")
            configs.append(config)

    return configs


def download_source(url):
    try:
        response = requests.get(
            url,
            timeout=20,
            headers={
                "User-Agent": "Proxy-Harvester/1.0",
            },
        )

        response.raise_for_status()
        return response.text

    except requests.RequestException as exc:
        print(f"[WARN] Failed to download {url}: {exc}")
        return ""


def collect():
    configs = []

    for source in load_sources():
        print(f"[INFO] Downloading {source}")

        content = download_source(source)

        if content:
            found = extract_configs(content)
            print(f"[INFO] Found {len(found)} configs.")
            configs.extend(found)

    return list(dict.fromkeys(configs))


def test_configs(configs):
    if not configs:
        return []

    supported = [
        config
        for config in configs
        if config.lower().startswith(tuple(
            scheme for scheme in SCHEMES if scheme != "ssr://"
        ))
    ]

    skipped = len(configs) - len(supported)

    if skipped:
        print(f"[INFO] Skipping {skipped} unsupported SSR configs.")

    if not supported:
        return []

    print(f"[INFO] Testing {len(supported)} configurations...")

    working = []

    for start in range(0, len(supported), CHUNK_SIZE):
        chunk = supported[start:start + CHUNK_SIZE]
        print(
            f"[INFO] Testing chunk {start + 1}-{start + len(chunk)} "
            f"of {len(supported)}..."
        )

        try:
            batch = SingBoxBatch(
                chunk,
                batch_size=BATCH_SIZE,
            )

            try:
                for result in batch.check_iter(
                    timeout=TIMEOUT,
                    workers=WORKERS,
                ):
                    if result.working:
                        working.append(result.url)
            finally:
                batch.stop()

        except Exception as exc:
            print(f"[WARN] Testing chunk failed: {exc}")

    return list(dict.fromkeys(working))


def write_outputs(configs):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_file = OUTPUT_DIR / "all.txt"
    light_file = OUTPUT_DIR / "light.txt"

    all_file.write_text(
        "\n".join(configs) + ("\n" if configs else ""),
        encoding="utf-8",
    )

    light_configs = configs[:LIGHT_LIMIT]

    light_file.write_text(
        "\n".join(light_configs) + ("\n" if light_configs else ""),
        encoding="utf-8",
    )

    print(f"[INFO] Published {len(configs)} configs to all.txt")
    print(f"[INFO] Published {len(light_configs)} configs to light.txt")


def main():
    print("[INFO] Proxy-Harvester starting...")

    collected = collect()

    print(f"[INFO] Collected {len(collected)} unique configs.")

    working = test_configs(collected)

    print(f"[INFO] {len(working)} configs passed the URL test.")

    write_outputs(working)

    print("[INFO] Done.")


if __name__ == "__main__":
    main()
