import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from app.audit import append_audit_log
from app.cve.correlation import correlate_assets
from app.cve.importer import apply_cisa_kev_document, import_nvd_document
from app.database import SessionLocal


def main() -> None:
    parser = argparse.ArgumentParser(description="Import offline vulnerability feeds")
    parser.add_argument("--nvd", type=Path)
    parser.add_argument("--kev", type=Path)
    parser.add_argument("--correlate", action="store_true")
    parser.add_argument("--watch-directory", type=Path)
    parser.add_argument("--interval-seconds", type=int, default=3600)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.interval_seconds < 30:
        parser.error("--interval-seconds must be at least 30")
    if args.watch_directory:
        _watch(args.watch_directory, args.interval_seconds, args.correlate, args.once)
    else:
        _process(args.nvd, args.kev, args.correlate)


def _watch(directory: Path, interval: int, correlate: bool, once: bool) -> None:
    processed: tuple[str | None, str | None] | None = None
    while True:
        nvd = _latest(directory, "nvd*.json")
        kev = _latest(directory, "*known_exploited*.json")
        digests = (_digest(nvd), _digest(kev))
        if digests != processed and any(digests):
            try:
                _process(nvd, kev, correlate)
                processed = digests
            except (OSError, ValueError) as exc:
                _record_failure(str(exc))
                print(f"Feed processing failed: {exc}")
        if once:
            return
        time.sleep(interval)


def _process(nvd: Path | None, kev: Path | None, correlate: bool) -> None:
    with SessionLocal() as session:
        if nvd:
            print(f"Imported {import_nvd_document(session, _load(nvd))} NVD records")
        if kev:
            print(f"Updated {apply_cisa_kev_document(session, _load(kev))} KEV records")
        if correlate:
            print(f"Created or updated {correlate_assets(session)} CVE matches")


def _latest(directory: Path, pattern: str) -> Path | None:
    matches = list(directory.glob(pattern))
    return max(matches, key=lambda item: item.stat().st_mtime) if matches else None


def _digest(path: Path | None) -> str | None:
    if path is None:
        return None
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record_failure(message: str) -> None:
    with SessionLocal() as session:
        append_audit_log(
            session,
            action="vulnerability_feed.failed",
            object_type="vulnerability_catalog",
            object_id="offline-feed",
            details={"error": message[:500]},
            actor_subject="system:cve-import",
        )
        session.commit()


def _load(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


if __name__ == "__main__":
    main()
