import hashlib
import hmac
import ipaddress
import json
import socket
import uuid
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import append_audit_log
from app.auth import Principal, require_admin
from app.config import get_settings
from app.database import get_session
from app.models import AlertDelivery, AlertRule
from app.siem import enqueue_siem_event, event_severity

router = APIRouter(prefix="/api/v1/admin/alerts", tags=["alerting"])
EventType = Literal["firmware_drift", "vulnerability_match", "communication_anomaly"]


class AlertRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    event_type: EventType
    site_id: str | None = Field(default=None, max_length=128)
    webhook_url: str = Field(max_length=2048)
    enabled: bool = True

    @field_validator("webhook_url")
    @classmethod
    def secure_webhook_url(cls, value: str) -> str:
        return validate_webhook_url(value)


def validate_webhook_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("webhook URL must use HTTPS and include a host")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("webhook URL must not contain credentials or a fragment")
    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(
                parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM
            )
        }
    except socket.gaierror as exc:
        raise ValueError("webhook host could not be resolved") from exc
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("webhook host must resolve only to public IP addresses")
    netloc = parsed.hostname.lower()
    if parsed.port and parsed.port != 443:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit(("https", netloc, parsed.path or "/", parsed.query, ""))


def webhook_signature(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@router.post("/rules", status_code=status.HTTP_201_CREATED)
def create_rule(
    data: AlertRuleCreate,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    signing_secret = get_settings().webhook_signing_secret
    if signing_secret is None or len(signing_secret.get_secret_value()) < 32:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="configure WEBHOOK_SIGNING_SECRET with at least 32 characters",
        )
    rule = AlertRule(**data.model_dump(), created_by=principal.subject)
    session.add(rule)
    append_audit_log(
        session,
        action="alert_rule.created",
        object_type="alert_rule",
        object_id=str(rule.id),
        details={"name": rule.name, "event_type": rule.event_type, "site_id": rule.site_id},
        actor_subject=principal.subject,
    )
    session.commit()
    return rule_dict(rule)


@router.get("/rules")
def list_rules(
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rules = list(session.scalars(select(AlertRule).order_by(AlertRule.created_at.desc())))
    return [rule_dict(rule) for rule in rules]


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: uuid.UUID,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> None:
    rule = session.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert rule not found")
    session.delete(rule)
    append_audit_log(
        session,
        action="alert_rule.deleted",
        object_type="alert_rule",
        object_id=str(rule.id),
        details={"name": rule.name},
        actor_subject=principal.subject,
    )
    session.commit()


@router.get("/deliveries")
def list_deliveries(
    limit: int = Query(default=100, ge=1, le=500),
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(AlertDelivery).order_by(AlertDelivery.created_at.desc()).limit(limit)
    )
    return [
        {
            "id": str(row.id),
            "rule_id": str(row.rule_id),
            "event_type": row.event_type,
            "status": row.status,
            "attempts": row.attempts,
            "response_status": row.response_status,
            "last_error": row.last_error,
            "created_at": row.created_at,
            "delivered_at": row.delivered_at,
        }
        for row in rows
    ]


def enqueue_alert(
    session: Session, *, event_type: EventType, site_id: str, payload: dict[str, Any]
) -> int:
    rules = session.scalars(
        select(AlertRule).where(
            AlertRule.enabled.is_(True),
            AlertRule.event_type == event_type,
            (AlertRule.site_id.is_(None)) | (AlertRule.site_id == site_id),
        )
    )
    count = 0
    envelope = {
        "event_type": event_type,
        "site_id": site_id,
        "occurred_at": datetime.now(UTC).isoformat(),
        "data": payload,
    }
    for rule in rules:
        session.add(AlertDelivery(rule_id=rule.id, event_type=event_type, payload=envelope))
        count += 1
    enqueue_siem_event(
        session,
        event_type=event_type,
        severity=event_severity(event_type, payload),
        payload={"site_id": site_id, **payload},
    )
    return count


def canonical_webhook_body(delivery: AlertDelivery) -> bytes:
    return json.dumps(
        {"id": str(delivery.id), **delivery.payload},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def rule_dict(rule: AlertRule) -> dict[str, Any]:
    return {
        "id": str(rule.id),
        "name": rule.name,
        "event_type": rule.event_type,
        "site_id": rule.site_id,
        "webhook_url": rule.webhook_url,
        "enabled": rule.enabled,
        "created_by": rule.created_by,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }
