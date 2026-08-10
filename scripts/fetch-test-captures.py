"""Fetch checksum-pinned external PCAP fixtures for integration tests."""

import hashlib
import json
import re
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "sensor" / "tests" / "external" / "manifest.json"
REQUIRED_FIELDS = {
    "filename",
    "url",
    "sha256",
    "source",
    "source_repository",
    "license",
    "license_url",
    "upstream_commit",
    "provenance",
}
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def validate_manifest(fixtures: Any) -> list[dict[str, str]]:
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("capture manifest must be a non-empty list")
    filenames: set[str] = set()
    validated: list[dict[str, str]] = []
    for index, fixture in enumerate(fixtures):
        if not isinstance(fixture, dict) or not REQUIRED_FIELDS <= fixture.keys():
            missing = (
                REQUIRED_FIELDS - fixture.keys()
                if isinstance(fixture, dict)
                else REQUIRED_FIELDS
            )
            raise ValueError(f"fixture {index} has invalid structure; missing: {sorted(missing)}")
        invalid_values = (
            not isinstance(fixture[field], str) or not fixture[field] for field in REQUIRED_FIELDS
        )
        if any(invalid_values):
            raise ValueError(f"fixture {index} has an empty or non-string provenance field")
        filename = fixture["filename"]
        if Path(filename).name != filename or filename in filenames:
            raise ValueError(f"fixture {index} has an unsafe or duplicate filename")
        filenames.add(filename)
        commit = fixture["upstream_commit"]
        if not COMMIT_PATTERN.fullmatch(commit):
            raise ValueError(f"fixture {filename} has an invalid upstream commit")
        if not SHA256_PATTERN.fullmatch(fixture["sha256"]):
            raise ValueError(f"fixture {filename} has an invalid SHA-256")
        for field in ("url", "license_url"):
            if not fixture[field].startswith("https://") or commit not in fixture[field]:
                raise ValueError(f"fixture {filename} has an unpinned {field}")
        if not fixture["source_repository"].startswith("https://github.com/"):
            raise ValueError(f"fixture {filename} has an invalid source repository")
        validated.append(fixture)
    return validated


def main() -> None:
    fixtures = validate_manifest(json.loads(MANIFEST.read_text(encoding="utf-8")))
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
