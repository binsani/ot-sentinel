import argparse
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.alerting import canonical_webhook_body, validate_webhook_url, webhook_signature
from app.audit import append_audit_log
from app.config import get_settings
from app.database import SessionLocal
from app.models import AlertDelivery, AlertRule

MAX_ATTEMPTS = 5


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def process_pending(session: Session, limit: int = 25) -> int:
    secret_value = get_settings().webhook_signing_secret
    if secret_value is None or len(secret_value.get_secret_value()) < 32:
        raise RuntimeError("WEBHOOK_SIGNING_SECRET must contain at least 32 characters")
    deliveries = list(
        session.scalars(
            select(AlertDelivery)
            .where(
                AlertDelivery.status.in_(("queued", "retrying")),
                AlertDelivery.next_attempt_at <= datetime.now(UTC),
            )
            .order_by(AlertDelivery.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    for delivery in deliveries:
        rule = session.get(AlertRule, delivery.rule_id)
        if rule is None or not rule.enabled:
            _fail_permanently(session, delivery, "alert rule is missing or disabled")
            continue
        try:
            url = validate_webhook_url(rule.webhook_url)
            body = canonical_webhook_body(delivery)
            request = urllib.request.Request(
                url,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "OT-Sentinel/0.1",
                    "X-OT-Sentinel-Delivery": str(delivery.id),
                    "X-OT-Sentinel-Signature-256": webhook_signature(
                        secret_value.get_secret_value(), body
                    ),
                },
            )
            with urllib.request.build_opener(NoRedirect).open(request, timeout=10) as response:
                delivery.response_status = response.status
                if not 200 <= response.status < 300:
                    raise RuntimeError(f"webhook returned HTTP {response.status}")
            delivery.status = "delivered"
            delivery.delivered_at = datetime.now(UTC)
            delivery.last_error = None
            delivery.attempts += 1
            append_audit_log(
                session,
                action="alert.delivered",
                object_type="alert_delivery",
                object_id=str(delivery.id),
                details={"rule_id": str(rule.id), "attempts": delivery.attempts},
                actor_subject="system:alert-worker",
            )
        except (ValueError, OSError, RuntimeError, urllib.error.URLError) as exc:
            _schedule_retry(session, delivery, str(exc))
    session.commit()
    return len(deliveries)


def _schedule_retry(session: Session, delivery: AlertDelivery, error: str) -> None:
    delivery.attempts += 1
    delivery.last_error = error[:500]
    if delivery.attempts >= MAX_ATTEMPTS:
        _fail_permanently(session, delivery, error)
        return
    delivery.status = "retrying"
    delivery.next_attempt_at = datetime.now(UTC) + timedelta(minutes=2 ** (delivery.attempts - 1))


def _fail_permanently(session: Session, delivery: AlertDelivery, error: str) -> None:
    delivery.status = "failed"
    delivery.last_error = error[:500]
    append_audit_log(
        session,
        action="alert.failed",
        object_type="alert_delivery",
        object_id=str(delivery.id),
        details={"rule_id": str(delivery.rule_id), "attempts": delivery.attempts},
        actor_subject="system:alert-worker",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Deliver queued OT-Sentinel webhook alerts")
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
