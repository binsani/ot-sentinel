"""Passive capture and store-and-forward command line interface."""

import argparse
import json
import os
import queue
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from scapy.all import AsyncSniffer, PcapWriter  # type: ignore[import-untyped]

from ot_sentinel_sensor.pcap import (
    dnp3_observations_from_pcap,
    iec61850_observations_from_pcap,
    observations_from_pcap,
    opcua_observations_from_pcap,
    s7_observations_from_pcap,
)

BPF_FILTER = "tcp port 502 or tcp port 20000 or tcp port 102 or tcp port 4840"
EVENT_NAMESPACE = uuid.UUID("470eb47a-41dc-4d96-9768-d3e031adfd47")
GENERATORS = {
    "modbus": observations_from_pcap,
    "dnp3": dnp3_observations_from_pcap,
    "s7comm": s7_observations_from_pcap,
    "opcua": opcua_observations_from_pcap,
    "iec61850": iec61850_observations_from_pcap,
}


def spool_usage(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def write_health(spool: Path, **status: Any) -> None:
    document = {"updated_at": datetime.now(UTC).isoformat(), **status}
    temporary = spool / "health.json.tmp"
    temporary.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    temporary.replace(spool / "health.json")


def recover_abandoned_captures(incoming: Path) -> int:
    recovered = 0
    for temporary in incoming.glob("*.writing.pcap"):
        if temporary.stat().st_size <= 24:
            temporary.unlink(missing_ok=True)
            continue
        ready = temporary.with_name(temporary.name.replace(".writing", ".ready"))
        temporary.replace(ready)
        recovered += 1
    return recovered


def enforce_archive_retention(archive: Path, retention_days: int) -> int:
    if retention_days <= 0:
        return 0
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    removed = 0
    for capture_file in archive.glob("*.pcap"):
        modified = datetime.fromtimestamp(capture_file.stat().st_mtime, UTC)
        if modified < cutoff:
            capture_file.unlink()
            removed += 1
    return removed


def event_id(protocol: str, observation: dict[str, Any]) -> str:
    identity = {
        "protocol": protocol,
        "sensor_id": observation["sensor_id"],
        "observed_at": observation["observed_at"],
        "source_ip": observation["source_ip"],
        "destination_ip": observation["destination_ip"],
        "source_port": observation["source_port"],
        "destination_port": observation["destination_port"],
        "payload_sha256": observation["payload_sha256"],
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return str(uuid.uuid5(EVENT_NAMESPACE, canonical))


def capture(args: argparse.Namespace) -> int:
    spool = args.spool.resolve()
    incoming = spool / "incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    recovered = recover_abandoned_captures(incoming)
    packets: queue.Queue[Any] = queue.Queue(maxsize=args.queue_size)
    dropped = 0

    def enqueue(packet: Any) -> None:
        nonlocal dropped
        try:
            packets.put_nowait(packet)
        except queue.Full:
            dropped += 1

    sniffer = AsyncSniffer(iface=args.interface, filter=BPF_FILTER, store=False, prn=enqueue)
    sniffer.start()
    print(f"Passive capture started on {args.interface}; press Ctrl+C to stop.")
    stopped = False
    try:
        while True:
            usage = spool_usage(spool)
            if usage >= args.max_spool_bytes:
                write_health(
                    spool,
                    mode="capture",
                    healthy=False,
                    reason="spool_limit_reached",
                    spool_bytes=usage,
                    dropped_packets=dropped,
                )
                print(
                    "Capture stopped because the configured spool limit was reached.",
                    file=sys.stderr,
                )
                return 2
            started = time.monotonic()
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            temporary = incoming / f"{stamp}-{uuid.uuid4().hex}.writing.pcap"
            writer = PcapWriter(str(temporary), append=False, sync=False)
            written = 0
            interrupted = False
            try:
                while time.monotonic() - started < args.rotate_seconds:
                    try:
                        writer.write(packets.get(timeout=0.5))
                        written += 1
                    except queue.Empty:
                        continue
            except KeyboardInterrupt:
                interrupted = True
                sniffer.stop()
                stopped = True
                while True:
                    try:
                        writer.write(packets.get_nowait())
                        written += 1
                    except queue.Empty:
                        break
            finally:
                writer.close()
            if written:
                try:
                    temporary.chmod(0o600)
                except OSError:
                    pass
                temporary.replace(temporary.with_name(temporary.name.replace(".writing", ".ready")))
                print(f"Sealed capture with {written} packets (dropped since start: {dropped}).")
            else:
                temporary.unlink(missing_ok=True)
            if interrupted:
                print("Stopping passive capture.")
                break
            write_health(
                spool,
                mode="capture",
                healthy=True,
                spool_bytes=spool_usage(spool),
                dropped_packets=dropped,
                recovered_captures=recovered,
            )
    finally:
        if not stopped:
            sniffer.stop()
    return 0


def post_event(url: str, sensor_key: str, payload: dict[str, Any], retries: int) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Sensor-Key": sensor_key},
        method="POST",
    )
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()):
                return
        except urllib.error.HTTPError as exc:
            if exc.code < 500 or attempt == retries:
                raise
        except urllib.error.URLError:
            if attempt == retries:
                raise
        time.sleep(min(2**attempt, 30))


def forward_file(path: Path, args: argparse.Namespace, sensor_key: str) -> int:
    delivered = 0
    for protocol, generator in GENERATORS.items():
        for observation in generator(path, sensor_id=args.sensor_id, site_id=args.site_id):
            observation["event_id"] = event_id(protocol, observation)
            post_event(
                f"{args.backend_url.rstrip('/')}/api/v1/ingest/{protocol}",
                sensor_key,
                observation,
                args.retries,
            )
            delivered += 1
    return delivered


def forward(args: argparse.Namespace) -> int:
    if not args.backend_url.startswith("https://") and not args.allow_http:
        raise SystemExit(
            "backend URL must use HTTPS (use --allow-http only for trusted local tests)"
        )
    sensor_key = os.environ.get(args.sensor_key_env)
    if not sensor_key:
        raise SystemExit(
            f"required sensor key environment variable is unset: {args.sensor_key_env}"
        )
    spool = args.spool.resolve()
    incoming, archive = spool / "incoming", spool / "archive"
    incoming.mkdir(parents=True, exist_ok=True)
    archive.mkdir(parents=True, exist_ok=True)
    recovered = recover_abandoned_captures(incoming)
    while True:
        captures = sorted(incoming.glob("*.ready.pcap"))
        failures = 0
        delivered_total = 0
        for path in captures:
            try:
                delivered = forward_file(path, args, sensor_key)
                destination = archive / path.name
                if destination.exists():
                    destination = archive / f"{path.stem}-{uuid.uuid4().hex}{path.suffix}"
                shutil.move(str(path), destination)
                delivered_total += delivered
                print(f"Archived {path.name} after delivering {delivered} events.")
            except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
                failures += 1
                print(f"Delivery deferred for {path.name}: {exc}", file=sys.stderr)
        removed = enforce_archive_retention(archive, args.archive_retention_days)
        if removed:
            print(f"Removed {removed} archived captures under the configured retention policy.")
        write_health(
            spool,
            mode="forward",
            healthy=failures == 0,
            pending_captures=len(list(incoming.glob("*.ready.pcap"))),
            failed_captures=failures,
            delivered_events=delivered_total,
            recovered_captures=recovered,
            spool_bytes=spool_usage(spool),
        )
        if args.once:
            return 0
        time.sleep(args.poll_seconds)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="OT Sentinel passive sensor")
    commands = root.add_subparsers(dest="command", required=True)
    capture_parser = commands.add_parser("capture", help="capture passively into a spool")
    capture_parser.add_argument("--interface", required=True)
    capture_parser.add_argument("--spool", type=Path, required=True)
    capture_parser.add_argument("--rotate-seconds", type=int, default=300)
    capture_parser.add_argument("--queue-size", type=int, default=10000)
    capture_parser.add_argument("--max-spool-bytes", type=int, default=10 * 1024**3)
    capture_parser.set_defaults(handler=capture)

    forward_parser = commands.add_parser("forward", help="deliver sealed captures")
    forward_parser.add_argument("--spool", type=Path, required=True)
    forward_parser.add_argument("--backend-url", required=True)
    forward_parser.add_argument("--sensor-id", required=True)
    forward_parser.add_argument("--site-id", default="default")
    forward_parser.add_argument("--sensor-key-env", default="SENSOR_INGEST_API_KEY")
    forward_parser.add_argument("--retries", type=int, default=4)
    forward_parser.add_argument("--poll-seconds", type=int, default=15)
    forward_parser.add_argument("--archive-retention-days", type=int, default=0)
    forward_parser.add_argument("--once", action="store_true")
    forward_parser.add_argument("--allow-http", action="store_true")
    forward_parser.set_defaults(handler=forward)
    return root


def main() -> int:
    args = parser().parse_args()
    positive_values = (
        getattr(args, "rotate_seconds", 1),
        getattr(args, "queue_size", 1),
        getattr(args, "max_spool_bytes", 1),
        getattr(args, "poll_seconds", 1),
    )
    if any(value < 1 for value in positive_values):
        raise SystemExit("rotation, queue, spool, and polling values must be positive")
    if getattr(args, "archive_retention_days", 0) < 0:
        raise SystemExit("archive retention cannot be negative")
    return int(args.handler(args))
