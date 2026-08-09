import ipaddress
import json
import socket
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import append_audit_log
from app.auth import Principal, require_admin
from app.config import get_settings
from app.database import get_session
from app.models import SiemDelivery, SiemDestination

router = APIRouter(prefix="/api/v1/admin/siem", tags=["SIEM integration"])
Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SYSLOG_SEVERITY = {"info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2}


class SiemDestinationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=6514, ge=1, le=65535)
    minimum_severity: Severity = "medium"

    @field_validator("host")
    @classmethod
    def clean_host(cls, value: str) -> str:
        host = value.strip().rstrip(".").lower()
        if not host or any(character in host for character in " /\\@#"):
            raise ValueError("host must be a DNS name or IP address without a URL scheme")
        return host


@router.get("/destinations")
def list_destinations(
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(select(SiemDestination).order_by(SiemDestination.created_at))
    return [destination_dict(row) for row in rows]


@router.post("/destinations", status_code=status.HTTP_201_CREATED)
def create_destination(
    data: SiemDestinationCreate,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    validate_destination(data.host, data.port, configured_allowed_networks())
    destination = SiemDestination(**data.model_dump(), enabled=False, created_by=principal.subject)
    session.add(destination)
    session.flush()
    append_audit_log(
        session,
        action="siem_destination.created",
        object_type="siem_destination",
        object_id=str(destination.id),
        details={"host": destination.host, "port": destination.port, "enabled": False},
        actor_subject=principal.subject,
    )
    session.commit()
    return destination_dict(destination)


@router.post("/destinations/{destination_id}/enable")
def enable_destination(
    destination_id: uuid.UUID,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    destination = _locked_destination(session, destination_id)
    validate_destination(destination.host, destination.port, configured_allowed_networks())
    destination.enabled = True
    append_audit_log(
        session,
        action="siem_destination.enabled",
        object_type="siem_destination",
        object_id=str(destination.id),
        details={},
        actor_subject=principal.subject,
    )
    session.commit()
    return destination_dict(destination)


@router.post("/destinations/{destination_id}/disable")
def disable_destination(
    destination_id: uuid.UUID,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    destination = _locked_destination(session, destination_id)
    destination.enabled = False
    append_audit_log(
        session,
        action="siem_destination.disabled",
        object_type="siem_destination",
        object_id=str(destination.id),
        details={},
        actor_subject=principal.subject,
    )
    session.commit()
    return destination_dict(destination)


@router.get("/deliveries")
def list_deliveries(
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(select(SiemDelivery).order_by(SiemDelivery.created_at.desc()).limit(200))
    return [
        {
            "id": str(row.id),
            "destination_id": str(row.destination_id),
            "event_type": row.event_type,
            "severity": row.severity,
            "status": row.status,
            "attempts": row.attempts,
            "last_error": row.last_error,
            "created_at": row.created_at,
            "delivered_at": row.delivered_at,
        }
        for row in rows
    ]


def enqueue_siem_event(
    session: Session,
    *,
    event_type: str,
    severity: Severity,
    payload: dict[str, Any],
) -> int:
    destinations = session.scalars(select(SiemDestination).where(SiemDestination.enabled.is_(True)))
    count = 0
    for destination in destinations:
        if SEVERITY_ORDER[severity] < SEVERITY_ORDER[destination.minimum_severity]:
            continue
        session.add(
            SiemDelivery(
                destination_id=destination.id,
                event_type=event_type,
                severity=severity,
                payload={
                    "event_type": event_type,
                    "severity": severity,
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "data": payload,
                },
            )
        )
        count += 1
    return count


def event_severity(event_type: str, payload: dict[str, Any]) -> Severity:
    if event_type == "communication_anomaly":
        return "high"
    if event_type == "vulnerability_match":
        value = str(payload.get("severity") or "medium").casefold()
        if payload.get("known_exploited"):
            return "critical"
        if value in SEVERITY_ORDER:
            return value  # type: ignore[return-value]
    return "medium"


def configured_allowed_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    values = [value.strip() for value in get_settings().siem_allowed_cidrs.split(",")]
    networks = [ipaddress.ip_network(value, strict=True) for value in values if value]
    if not networks:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="SIEM_ALLOWED_CIDRS must explicitly allow destination networks",
        )
    return networks


def validate_destination(
    host: str,
    port: int,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> list[str]:
    try:
        addresses = sorted(
            {
                str(result[4][0])
                for result in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            }
        )
    except socket.gaierror as exc:
        raise ValueError("SIEM destination could not be resolved") from exc
    if not addresses:
        raise ValueError("SIEM destination did not resolve to an address")
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not any(
            address.version == network.version and address in network for network in networks
        ):
            raise ValueError("every resolved SIEM address must be inside SIEM_ALLOWED_CIDRS")
    return addresses


def rfc5424_message(delivery: SiemDelivery, hostname: str = "ot-sentinel") -> bytes:
    severity = SYSLOG_SEVERITY.get(delivery.severity, 4)
    priority = 16 * 8 + severity
    timestamp = delivery.payload.get("occurred_at") or datetime.now(UTC).isoformat()
    event_type = _syslog_token(delivery.event_type)
    message_id = _syslog_token(str(delivery.id))
    body = json.dumps(delivery.payload, sort_keys=True, separators=(",", ":"))
    if len(body.encode()) > 6144:
        body = json.dumps(
            {"truncated": True, "delivery_id": str(delivery.id)}, separators=(",", ":")
        )
    message = (
        f"<{priority}>1 {timestamp} {_syslog_token(hostname)} ot-sentinel - {event_type} "
        f'[ot-sentinel@32473 delivery="{message_id}" severity="{delivery.severity}"] {body}'
    ).encode()
    return str(len(message)).encode() + b" " + message


def destination_dict(destination: SiemDestination) -> dict[str, Any]:
    return {
        "id": str(destination.id),
        "name": destination.name,
        "host": destination.host,
        "port": destination.port,
        "transport": "tcp_tls",
        "minimum_severity": destination.minimum_severity,
        "enabled": destination.enabled,
        "created_by": destination.created_by,
        "created_at": destination.created_at,
        "updated_at": destination.updated_at,
    }


def _locked_destination(session: Session, destination_id: uuid.UUID) -> SiemDestination:
    destination = session.scalar(
        select(SiemDestination).where(SiemDestination.id == destination_id).with_for_update()
    )
    if destination is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="SIEM destination not found"
        )
    return destination


def _syslog_token(value: str) -> str:
    return (
        "".join(character if 33 <= ord(character) <= 126 else "_" for character in value)[:255]
        or "-"
    )
