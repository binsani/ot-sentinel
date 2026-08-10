"""Seed a disposable OT-Sentinel database with deterministic synthetic inventory."""

import argparse
import os
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
from psycopg.types.json import Jsonb

CONFIRMATION = "SEED DISPOSABLE PERFORMANCE DATABASE"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=int, default=10_000)
    parser.add_argument("--observations-per-asset", type=int, default=4)
    parser.add_argument("--sites", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=1_000)
    parser.add_argument("--confirmation", required=True)
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.confirmation != CONFIRMATION:
        raise SystemExit(f"confirmation must be exactly: {CONFIRMATION}")
    if not 1 <= args.assets <= 1_000_000:
        raise SystemExit("--assets must be between 1 and 1000000")
    if not 0 <= args.observations_per_asset <= 100:
        raise SystemExit("--observations-per-asset must be between 0 and 100")
    if not 1 <= args.sites <= 10_000 or not 1 <= args.batch_size <= 10_000:
        raise SystemExit("--sites and --batch-size must be between 1 and 10000")


def database_url() -> str:
    value = os.environ.get("DATABASE_URL")
    if not value:
        raise SystemExit("DATABASE_URL is required")
    return value.replace("postgresql+psycopg://", "postgresql://", 1)


def chunks(total: int, size: int):
    for start in range(0, total, size):
        yield range(start, min(start + size, total))


def synthetic_seen_times(index: int, now: datetime) -> tuple[datetime, datetime]:
    last_seen = now - timedelta(seconds=index % 3_600)
    first_seen = last_seen - timedelta(days=1 + index % 90)
    return first_seen, last_seen


def main() -> None:
    args = parse_args()
    validate_args(args)
    now = datetime.now(UTC)
    namespace = uuid.UUID("858440c7-38d5-4d38-98eb-0572152b3684")

    with psycopg.connect(database_url()) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database()")
            name = cursor.fetchone()[0]
            if not name.endswith(("_performance", "_perf")):
                raise SystemExit(
                    "refusing to seed: database name must end in _performance or _perf"
                )
            cursor.execute("SELECT count(*) FROM assets")
            if cursor.fetchone()[0]:
                raise SystemExit("refusing to seed: assets table is not empty")

            for batch in chunks(args.assets, args.batch_size):
                rows = []
                for index in batch:
                    asset_id = uuid.uuid5(namespace, f"asset-{index}")
                    ip = f"10.{(index // 65_536) % 256}.{(index // 256) % 256}.{index % 256}"
                    first_seen, last_seen = synthetic_seen_times(index, now)
                    rows.append(
                        (
                            asset_id,
                            f"performance-site-{index % args.sites:04d}",
                            ip,
                            f"perf-asset-{index:07d}",
                            ("Acme Controls", "Example Automation", "Synthetic PLC")[index % 3],
                            f"model-{index % 25:02d}",
                            f"{1 + index % 4}.{index % 10}",
                            Jsonb(["modbus" if index % 2 == 0 else "opcua"]),
                            Jsonb({"synthetic": True, "dataset": "performance-v1"}),
                            1 + index % 5,
                            first_seen,
                            last_seen,
                        )
                    )
                cursor.executemany(
                    """INSERT INTO assets
                    (id, site_id, ip_address, hostname, vendor, model, firmware_version,
                     protocols, fingerprint, criticality, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    rows,
                )

            observation_total = args.assets * args.observations_per_asset
            for batch in chunks(observation_total, args.batch_size):
                rows = []
                for index in batch:
                    asset_index = index // args.observations_per_asset
                    peer = (asset_index * 17 + index) % max(args.assets, 1)
                    source_ip = (
                        f"10.{(asset_index // 65_536) % 256}."
                        f"{(asset_index // 256) % 256}.{asset_index % 256}"
                    )
                    rows.append(
                        (
                            uuid.uuid5(namespace, f"asset-{asset_index}"),
                            f"performance-sensor-{asset_index % args.sites:04d}",
                            now - timedelta(seconds=index % 86_400),
                            source_ip,
                            f"172.20.{(peer // 256) % 256}.{peer % 256}",
                            40_000 + index % 20_000,
                            502 if asset_index % 2 == 0 else 4840,
                            "modbus" if asset_index % 2 == 0 else "opcua",
                            1 + index % 10,
                            128 + index % 4096,
                            Jsonb({"synthetic": True}),
                        )
                    )
                cursor.executemany(
                    """INSERT INTO observations
                    (asset_id, sensor_id, observed_at, source_ip, destination_ip, source_port,
                     destination_port, protocol, packet_count, byte_count, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    rows,
                )
        connection.commit()
    print(f"Seeded {args.assets} assets and {observation_total} observations in {name}.")


if __name__ == "__main__":
    main()
