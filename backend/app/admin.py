import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit import append_audit_log, verify_audit_chain
from app.auth import Principal, require_admin
from app.database import get_session
from app.models import Asset, AuditLog, User, UserRole

router = APIRouter(prefix="/api/v1/admin", tags=["administration"])


class UserUpdate(BaseModel):
    role: UserRole | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def require_change(self) -> "UserUpdate":
        if self.role is None and self.is_active is None:
            raise ValueError("at least one user property must be supplied")
        return self


class FirmwareBaselineUpdate(BaseModel):
    version: str | None = None


@router.put("/assets/{asset_id}/firmware-baseline")
def set_firmware_baseline(
    asset_id: uuid.UUID,
    update: FirmwareBaselineUpdate,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    asset = session.scalar(select(Asset).where(Asset.id == asset_id).with_for_update())
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")
    version = (update.version or asset.firmware_version or "").strip()
    if not version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no observed firmware is available to baseline",
        )
    if len(version) > 255:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="version too long"
        )
    previous = asset.firmware_baseline
    asset.firmware_baseline = version
    asset.firmware_baseline_set_at = datetime.now(UTC)
    asset.firmware_baseline_set_by = principal.subject
    drifted = bool(asset.firmware_version and asset.firmware_version != version)
    asset.firmware_drift_detected_at = datetime.now(UTC) if drifted else None
    append_audit_log(
        session,
        action="firmware.baseline_set",
        object_type="asset",
        object_id=str(asset.id),
        details={"previous": previous, "current": version, "drift": drifted},
        actor_subject=principal.subject,
    )
    session.commit()
    return {
        "asset_id": str(asset.id),
        "firmware_version": asset.firmware_version,
        "firmware_baseline": asset.firmware_baseline,
        "firmware_drift": drifted,
        "firmware_drift_detected_at": asset.firmware_drift_detected_at,
    }


@router.delete("/assets/{asset_id}/firmware-baseline", status_code=status.HTTP_204_NO_CONTENT)
def clear_firmware_baseline(
    asset_id: uuid.UUID,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> None:
    asset = session.scalar(select(Asset).where(Asset.id == asset_id).with_for_update())
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")
    previous = asset.firmware_baseline
    asset.firmware_baseline = None
    asset.firmware_baseline_set_at = None
    asset.firmware_baseline_set_by = None
    asset.firmware_drift_detected_at = None
    append_audit_log(
        session,
        action="firmware.baseline_cleared",
        object_type="asset",
        object_id=str(asset.id),
        details={"previous": previous},
        actor_subject=principal.subject,
    )
    session.commit()


@router.get("/audit")
def list_audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    events = list(
        session.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit))
    )
    result = [
        {
            "id": event.id,
            "occurred_at": event.occurred_at,
            "actor_subject": event.actor_subject,
            "action": event.action,
            "object_type": event.object_type,
            "object_id": event.object_id,
            "details": event.details,
            "entry_hash": event.entry_hash,
            "previous_hash": event.previous_hash,
        }
        for event in events
    ]
    append_audit_log(
        session,
        action="audit.viewed",
        object_type="audit_log",
        object_id=None,
        details={"limit": limit, "result_count": len(events)},
        actor_subject=principal.subject,
    )
    session.commit()
    return result


@router.get("/feeds/status")
def feed_status(
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    events = list(
        session.scalars(
            select(AuditLog)
            .where(
                AuditLog.action.in_(
                    {
                        "vulnerability_feed.imported",
                        "vulnerability_feed.enriched",
                        "vulnerability_feed.failed",
                    }
                )
            )
            .order_by(AuditLog.id.desc())
            .limit(100)
        )
    )
    latest: dict[str, dict[str, Any]] = {}
    for event in events:
        source = event.object_id or "unknown"
        if source not in latest:
            latest[source] = {
                "source": source,
                "status": "failed" if event.action.endswith(".failed") else "healthy",
                "occurred_at": event.occurred_at,
                "details": event.details,
            }
    append_audit_log(
        session,
        action="vulnerability_feed_status.viewed",
        object_type="vulnerability_catalog",
        object_id=None,
        details={"source_count": len(latest)},
        actor_subject=principal.subject,
    )
    session.commit()
    return {"sources": list(latest.values())}


@router.get("/audit/verify")
def verify_audit_log(
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    entries = list(session.scalars(select(AuditLog).order_by(AuditLog.id)))
    valid, first_invalid_id = verify_audit_chain(entries)
    head_hash = entries[-1].entry_hash if entries else None
    append_audit_log(
        session,
        action="audit.verified",
        object_type="audit_log",
        object_id=None,
        details={
            "valid": valid,
            "verified_entries": len(entries),
            "first_invalid_id": first_invalid_id,
            "verified_head_hash": head_hash,
        },
        actor_subject=principal.subject,
    )
    session.commit()
    return {
        "valid": valid,
        "verified_entries": len(entries),
        "first_invalid_id": first_invalid_id,
        "verified_head_hash": head_hash,
    }


@router.get("/users")
def list_users(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    users = list(
        session.scalars(select(User).order_by(User.created_at).limit(limit).offset(offset))
    )
    append_audit_log(
        session,
        action="users.viewed",
        object_type="user_collection",
        object_id=None,
        details={"limit": limit, "offset": offset, "result_count": len(users)},
        actor_subject=principal.subject,
    )
    session.commit()
    return [_user_dict(user) for user in users]


@router.patch("/users/{user_id}")
def update_user(
    user_id: uuid.UUID,
    update: UserUpdate,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    user = session.scalar(select(User).where(User.id == user_id).with_for_update())
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    removes_admin = user.role == UserRole.ADMIN and (
        update.role == UserRole.VIEWER or update.is_active is False
    )
    if removes_admin and _active_admin_count(session) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="cannot remove or disable the last active administrator",
        )
    previous = {"role": user.role.value, "is_active": user.is_active}
    if update.role is not None:
        user.role = update.role
    if update.is_active is not None:
        user.is_active = update.is_active
    append_audit_log(
        session,
        action="user.updated",
        object_type="user",
        object_id=str(user.id),
        details={
            "previous": previous,
            "current": {"role": user.role.value, "is_active": user.is_active},
        },
        actor_subject=principal.subject,
    )
    session.commit()
    return _user_dict(user)


def _active_admin_count(session: Session) -> int:
    return int(
        session.scalar(
            select(func.count()).select_from(User).where(
                User.role == UserRole.ADMIN, User.is_active.is_(True)
            )
        )
        or 0
    )


def _user_dict(user: User) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "subject": user.subject,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role.value,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }
