"""Fetch checksum-pinned external PCAP fixtures for integration tests."""

import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "sensor" / "tests" / "external" / "manifest.json"


def main() -> None:
    fixtures = json.loads(MANIFEST.read_text(encoding="utf-8"))
    destination_dir = MANIFEST.parent
    destination_dir.mkdir(parents=True, exist_ok=True)
    for fixture in fixtures:
        destination = destination_dir / fixture["filename"]
        request = urllib.request.Request(
            fixture["url"], headers={"User-Agent": "OT-Sentinel integration tests"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            content = response.read()
        digest = hashlib.sha256(content).hexdigest()
        if digest != fixture["sha256"]:
            raise RuntimeError(
                f"checksum mismatch for {fixture['filename']}: {digest}"
            )
        destination.write_bytes(content)
        print(f"verified {fixture['filename']} ({len(content)} bytes)")


if __name__ == "__main__":
    main()
