import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import AuditLog


def calculate_audit_hash(
    *,
    occurred_at: datetime,
    actor_subject: str | None,
    action: str,
    object_type: str,
    object_id: str | None,
    details: dict[str, Any],
    previous_hash: str | None,
) -> str:
    canonical = json.dumps(
        {
            "occurred_at": occurred_at.isoformat(),
            "actor_subject": actor_subject,
            "action": action,
            "object_type": object_type,
            "object_id": object_id,
            "details": details,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def verify_audit_chain(entries: list[AuditLog]) -> tuple[bool, int | None]:
    previous_hash: str | None = None
    for entry in entries:
        expected = calculate_audit_hash(
            occurred_at=entry.occurred_at,
            actor_subject=entry.actor_subject,
            action=entry.action,
            object_type=entry.object_type,
            object_id=entry.object_id,
            details=entry.details,
            previous_hash=entry.previous_hash,
        )
        if entry.previous_hash != previous_hash or entry.entry_hash != expected:
            return False, entry.id
        previous_hash = entry.entry_hash
    return True, None


def append_audit_log(
    session: Session,
    *,
    action: str,
    object_type: str,
    object_id: str | None,
    details: dict[str, Any],
    actor_subject: str,
) -> AuditLog:
    # Serializes writers so the hash chain cannot fork under concurrent ingestion.
    session.execute(text("SELECT pg_advisory_xact_lock(684726193)"))
    previous = session.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    previous_hash = previous.entry_hash if previous else None
    occurred_at = datetime.now(UTC)
    entry = AuditLog(
        occurred_at=occurred_at,
        actor_subject=actor_subject,
        action=action,
        object_type=object_type,
        object_id=object_id,
        details=details,
        previous_hash=previous_hash,
        entry_hash=calculate_audit_hash(
            occurred_at=occurred_at,
            actor_subject=actor_subject,
            action=action,
            object_type=object_type,
            object_id=object_id,
            details=details,
            previous_hash=previous_hash,
        ),
    )
    session.add(entry)
    session.flush()
    return entry
