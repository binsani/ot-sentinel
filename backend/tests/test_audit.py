from datetime import UTC, datetime

from app.audit import calculate_audit_hash, verify_audit_chain
from app.models import AuditLog


def _entry(entry_id: int, previous_hash: str | None, details: dict[str, object]) -> AuditLog:
    occurred_at = datetime(2026, 8, 9, 12, entry_id, tzinfo=UTC)
    entry = AuditLog(
        id=entry_id,
        occurred_at=occurred_at,
        actor_subject="auditor@example.test",
        action="asset.viewed",
        object_type="asset",
        object_id=str(entry_id),
        details=details,
        previous_hash=previous_hash,
        entry_hash="",
    )
    entry.entry_hash = calculate_audit_hash(
        occurred_at=occurred_at,
        actor_subject=entry.actor_subject,
        action=entry.action,
        object_type=entry.object_type,
        object_id=entry.object_id,
        details=entry.details,
        previous_hash=entry.previous_hash,
    )
    return entry


def test_verify_audit_chain_detects_changed_details() -> None:
    first = _entry(1, None, {"site_id": "plant-a"})
    second = _entry(2, first.entry_hash, {"site_id": "plant-b"})

    assert verify_audit_chain([first, second]) == (True, None)

    first.details = {"site_id": "altered"}
    assert verify_audit_chain([first, second]) == (False, 1)
