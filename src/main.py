from pathlib import Path
from urllib.parse import urlparse
import re
import requests
from singbox2proxy import SingBoxBatch


ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT / "sources.txt"
OUTPUT_DIR = ROOT / "subscriptions"

TEST_URL = "https://www.gstatic.com/generate_204"
TIMEOUT = 8
WORKERS = 10

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


def load_sources():
    if not SOURCES_FILE.exists():
        return []

    sources = []

    for line in SOURCES_FILE.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        sources.append(line)

    return sources


def extract_configs(text):
    configs = []

    for line in text.splitlines():
        line = line.strip()


        line = line.split("#", 1)[0].strip()

        if not line:
            continue

        for scheme in SCHEMES:
            if line.lower().startswith(scheme):
                configs.append(line)
                break

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
            configs.extend(extract_configs(content))


    return list(dict.fromkeys(configs))


def protocol(config):
    return config.split("://", 1)[0].lower()


def test_configs(configs):
    if not configs:
        return []

    print(f"[INFO] Testing {len(configs)} unique configurations...")

    working = []

    try:
        batch = SingBoxBatch(
            configs,
            batch_size=50,
        )

        for result in batch.check(
            timeout=TIMEOUT,
            workers=WORKERS,
        ):
            if result.working:
                working.append(result.url)

        batch.stop()

    except Exception as exc:
        print(f"[ERROR] Proxy testing failed: {exc}")

    return list(dict.fromkeys(working))


def write_outputs(configs):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


    for file in OUTPUT_DIR.glob("*.txt"):
        file.unlink()

    grouped = {}

    for config in configs:
        grouped.setdefault(protocol(config), []).append(config)

    all_configs = []

    for values in grouped.values():
        all_configs.extend(values)

    all_configs = list(dict.fromkeys(all_configs))

    (OUTPUT_DIR / "all.txt").write_text(
        "\n".join(all_configs) + ("\n" if all_configs else "")
    )

    for name, values in sorted(grouped.items()):
        filename = name.replace("socks5", "socks") + ".txt"

        (OUTPUT_DIR / filename).write_text(
            "\n".join(values) + ("\n" if values else "")
        )

    print(f"[INFO] Published {len(all_configs)} working configurations.")


def main():
    print("[INFO] Proxy-Harvester starting...")

    collected = collect()

    print(f"[INFO] Collected {len(collected)} unique configurations.")

    working = test_configs(collected)

    print(f"[INFO] {len(working)} configurations passed the URL test.")

    write_outputs(working)

    print("[INFO] Done.")


if __name__ == "__main__":
    main()
