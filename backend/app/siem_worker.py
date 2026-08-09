import argparse
import socket
import ssl
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import append_audit_log
from app.database import SessionLocal
from app.models import SiemDelivery, SiemDestination
from app.siem import configured_allowed_networks, rfc5424_message, validate_destination

MAX_ATTEMPTS = 5


def process_pending(session: Session, limit: int = 25) -> int:
    rows = list(
        session.scalars(
            select(SiemDelivery)
            .where(
                SiemDelivery.status.in_(("queued", "retrying")),
                SiemDelivery.next_attempt_at <= datetime.now(UTC),
            )
            .order_by(SiemDelivery.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    allowed_networks = configured_allowed_networks()
    for delivery in rows:
        destination = session.get(SiemDestination, delivery.destination_id)
        if destination is None or not destination.enabled:
            _fail(session, delivery, "SIEM destination is missing or disabled")
            continue
        try:
            addresses = validate_destination(destination.host, destination.port, allowed_networks)
            _send_tls(
                addresses,
                destination.host,
                destination.port,
                rfc5424_message(delivery),
            )
            delivery.status = "delivered"
            delivery.delivered_at = datetime.now(UTC)
            delivery.last_error = None
            delivery.attempts += 1
            append_audit_log(
                session,
                action="siem.delivered",
                object_type="siem_delivery",
                object_id=str(delivery.id),
                details={
                    "destination_id": str(destination.id),
                    "attempts": delivery.attempts,
                },
                actor_subject="system:siem-worker",
            )
        except (OSError, ValueError, ssl.SSLError) as exc:
            _retry(session, delivery, str(exc))
    session.commit()
    return len(rows)


def _send_tls(addresses: list[str], hostname: str, port: int, message: bytes) -> None:
    context = ssl.create_default_context()
    last_error: OSError | None = None
    for address in addresses:
        try:
            with socket.create_connection((address, port), timeout=10) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                    tls_socket.sendall(message)
                    return
        except OSError as exc:
            last_error = exc
    raise last_error or OSError("no SIEM destination address was available")


def _retry(session: Session, delivery: SiemDelivery, error: str) -> None:
    delivery.attempts += 1
    delivery.last_error = error[:500]
    if delivery.attempts >= MAX_ATTEMPTS:
        _fail(session, delivery, error)
        return
    delivery.status = "retrying"
    delivery.next_attempt_at = datetime.now(UTC) + timedelta(minutes=2 ** (delivery.attempts - 1))


def _fail(session: Session, delivery: SiemDelivery, error: str) -> None:
    delivery.status = "failed"
    delivery.last_error = error[:500]
    append_audit_log(
        session,
        action="siem.failed",
        object_type="siem_delivery",
        object_id=str(delivery.id),
        details={
            "destination_id": str(delivery.destination_id),
            "attempts": delivery.attempts,
        },
        actor_subject="system:siem-worker",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Deliver queued RFC 5424 Syslog events over TLS")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=15)
    args = parser.parse_args()
    while True:
        with SessionLocal() as session:
            process_pending(session)
        if not args.watch:
            return
        time.sleep(max(1, args.interval_seconds))


if __name__ == "__main__":
    main()
