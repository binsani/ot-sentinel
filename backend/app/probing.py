import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import append_audit_log
from app.auth import Principal, require_admin
from app.config import get_settings
from app.database import get_session
from app.models import ProbePolicy

router = APIRouter(prefix="/api/v1/admin/probing", tags=["active probing policy"])
ProbeProtocol = Literal["icmp_echo", "tcp_connect"]
APPROVAL_CONFIRMATION = "I APPROVE CONTROLLED ACTIVE PROBING"


class ProbePolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    site_id: str = Field(min_length=1, max_length=128)
    allowed_cidrs: list[str] = Field(min_length=1, max_length=64)
    protocols: list[ProbeProtocol] = Field(min_length=1, max_length=2)
    max_targets: int = Field(default=16, ge=1, le=1000)
    rate_per_minute: int = Field(default=6, ge=1, le=60)
    maintenance_start_hour: int = Field(default=0, ge=0, le=23)
    maintenance_end_hour: int = Field(default=0, ge=0, le=23)

    @field_validator("allowed_cidrs")
    @classmethod
    def safe_cidrs(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            network = ipaddress.ip_network(value, strict=True)
            if network.prefixlen == 0:
                raise ValueError("default routes are not permitted in probing allowlists")
            if network.is_multicast or network.is_loopback or network.is_unspecified:
                raise ValueError("special-use networks are not permitted")
            canonical = str(network)
            if canonical not in normalized:
                normalized.append(canonical)
        return normalized


class ProbeApproval(BaseModel):
    confirmation: str
    approval_hours: int = Field(default=4, ge=1, le=24)


class ProbeEvaluation(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=1000)
    protocol: ProbeProtocol


@router.get("/status")
def probing_status(
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    policies = list(session.scalars(select(ProbePolicy).order_by(ProbePolicy.created_at)))
    return {
        "global_enabled": get_settings().active_probing_enabled,
        "executor_available": False,
        "transmission_capable": False,
        "policies": [policy_dict(policy) for policy in policies],
    }


@router.post("/policies", status_code=status.HTTP_201_CREATED)
def create_policy(
    data: ProbePolicyCreate,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    policy = ProbePolicy(**data.model_dump(), enabled=False, created_by=principal.subject)
    session.add(policy)
    session.flush()
    append_audit_log(
        session,
        action="probe_policy.created",
        object_type="probe_policy",
        object_id=str(policy.id),
        details={"site_id": policy.site_id, "enabled": False},
        actor_subject=principal.subject,
    )
    session.commit()
    return policy_dict(policy)


@router.post("/policies/{policy_id}/approve")
def approve_policy(
    policy_id: uuid.UUID,
    approval: ProbeApproval,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    if approval.confirmation != APPROVAL_CONFIRMATION:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="explicit active-probing confirmation is required",
        )
    policy = _locked_policy(session, policy_id)
    now = datetime.now(UTC)
    policy.enabled = True
    policy.approved_by = principal.subject
    policy.approved_at = now
    policy.approval_expires_at = now + timedelta(hours=approval.approval_hours)
    append_audit_log(
        session,
        action="probe_policy.approved",
        object_type="probe_policy",
        object_id=str(policy.id),
        details={"expires_at": policy.approval_expires_at.isoformat()},
        actor_subject=principal.subject,
    )
    session.commit()
    return policy_dict(policy)


@router.post("/policies/{policy_id}/disable")
def disable_policy(
    policy_id: uuid.UUID,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    policy = _locked_policy(session, policy_id)
    policy.enabled = False
    policy.approved_by = None
    policy.approved_at = None
    policy.approval_expires_at = None
    append_audit_log(
        session,
        action="probe_policy.disabled",
        object_type="probe_policy",
        object_id=str(policy.id),
        details={},
        actor_subject=principal.subject,
    )
    session.commit()
    return policy_dict(policy)


@router.post("/policies/{policy_id}/evaluate")
def evaluate_plan(
    policy_id: uuid.UUID,
    request: ProbeEvaluation,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    policy = session.get(ProbePolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="probe policy not found")
    result = evaluate_policy(
        policy,
        targets=request.targets,
        protocol=request.protocol,
        global_enabled=get_settings().active_probing_enabled,
        now=datetime.now(UTC),
    )
    append_audit_log(
        session,
        action="probe_plan.evaluated",
        object_type="probe_policy",
        object_id=str(policy.id),
        details={"target_count": len(request.targets), "allowed": result["allowed"]},
        actor_subject=principal.subject,
    )
    session.commit()
    return result


def evaluate_policy(
    policy: ProbePolicy,
    *,
    targets: list[str],
    protocol: str,
    global_enabled: bool,
    now: datetime,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not global_enabled:
        reasons.append("global_active_probing_disabled")
    if not policy.enabled:
        reasons.append("policy_disabled")
    if policy.approval_expires_at is None or policy.approval_expires_at <= now:
        reasons.append("approval_missing_or_expired")
    if protocol not in policy.protocols:
        reasons.append("protocol_not_allowed")
    if len(targets) > policy.max_targets:
        reasons.append("target_limit_exceeded")
    if not _inside_maintenance_window(policy, now.hour):
        reasons.append("outside_maintenance_window")
    networks = [ipaddress.ip_network(value) for value in policy.allowed_cidrs]
    decisions = []
    for target in targets:
        try:
            address = ipaddress.ip_address(target)
            allowed = any(
                address.version == network.version and address in network for network in networks
            )
        except ValueError:
            allowed = False
        decisions.append({"target": target, "allowed_by_cidr": allowed})
    if not all(decision["allowed_by_cidr"] for decision in decisions):
        reasons.append("target_outside_allowlist")
    policy_allows = not reasons
    return {
        "allowed": False,
        "policy_allows": policy_allows,
        "transmission_performed": False,
        "executor_available": False,
        "reasons": [*reasons, "probe_executor_not_installed"],
        "targets": decisions,
        "rate_per_minute": policy.rate_per_minute,
    }


def _inside_maintenance_window(policy: ProbePolicy, hour: int) -> bool:
    start, end = policy.maintenance_start_hour, policy.maintenance_end_hour
    if start == end:
        return True
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def _locked_policy(session: Session, policy_id: uuid.UUID) -> ProbePolicy:
    policy = session.scalar(
        select(ProbePolicy).where(ProbePolicy.id == policy_id).with_for_update()
    )
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="probe policy not found")
    return policy


def policy_dict(policy: ProbePolicy) -> dict[str, Any]:
    return {
        "id": str(policy.id),
        "name": policy.name,
        "site_id": policy.site_id,
        "enabled": policy.enabled,
        "allowed_cidrs": policy.allowed_cidrs,
        "protocols": policy.protocols,
        "max_targets": policy.max_targets,
        "rate_per_minute": policy.rate_per_minute,
        "maintenance_start_hour": policy.maintenance_start_hour,
        "maintenance_end_hour": policy.maintenance_end_hour,
        "approved_by": policy.approved_by,
        "approved_at": policy.approved_at,
        "approval_expires_at": policy.approval_expires_at,
        "created_by": policy.created_by,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at,
    }
