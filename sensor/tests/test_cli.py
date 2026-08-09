import json
import os
import time
from pathlib import Path

from ot_sentinel_sensor.cli import (
    enforce_archive_retention,
    event_id,
    recover_abandoned_captures,
    spool_usage,
    write_health,
)


def test_event_id_is_stable_and_protocol_specific() -> None:
    observation = {
        "sensor_id": "tap-01",
        "observed_at": "2026-08-09T12:00:00+00:00",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "source_port": 50000,
        "destination_port": 502,
        "payload_sha256": "a" * 64,
    }

    first = event_id("modbus", observation)

    assert event_id("modbus", dict(reversed(observation.items()))) == first
    assert event_id("dnp3", observation) != first


def test_spool_recovery_health_and_retention(tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    archive = tmp_path / "archive"
    incoming.mkdir()
    archive.mkdir()
    abandoned = incoming / "capture.writing.pcap"
    abandoned.write_bytes(b"x" * 25)
    empty = incoming / "empty.writing.pcap"
    empty.write_bytes(b"x" * 24)

    assert recover_abandoned_captures(incoming) == 1
    assert (incoming / "capture.ready.pcap").exists()
    assert not empty.exists()

    old_capture = archive / "old.pcap"
    old_capture.write_bytes(b"old")
    old_timestamp = time.time() - 3 * 86400
    os.utime(old_capture, (old_timestamp, old_timestamp))
    assert enforce_archive_retention(archive, 2) == 1

    write_health(tmp_path, mode="forward", healthy=True)
    health = json.loads((tmp_path / "health.json").read_text(encoding="utf-8"))
    assert health["mode"] == "forward"
    assert health["healthy"] is True
    assert spool_usage(tmp_path) == (tmp_path / "health.json").stat().st_size + 25
