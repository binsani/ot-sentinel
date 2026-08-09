import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.models import ProbePolicy
from app.probing import ProbePolicyCreate, evaluate_policy


def policy(**changes: object) -> ProbePolicy:
    values = {
        "id": uuid.uuid4(),
        "name": "Approved maintenance discovery",
        "site_id": "plant-a",
        "enabled": True,
        "allowed_cidrs": ["192.0.2.0/24"],
        "protocols": ["icmp_echo"],
        "max_targets": 4,
        "rate_per_minute": 2,
        "maintenance_start_hour": 22,
        "maintenance_end_hour": 4,
        "approved_by": "admin@example.com",
        "approved_at": datetime.now(UTC),
        "approval_expires_at": datetime.now(UTC) + timedelta(hours=2),
        "created_by": "admin@example.com",
    }
    values.update(changes)
    return ProbePolicy(**values)


def test_active_probing_global_gate_defaults_off() -> None:
    assert Settings(_env_file=None).active_probing_enabled is False


def test_policy_creation_rejects_default_route_and_special_networks() -> None:
    base = {
        "name": "unsafe",
        "site_id": "plant-a",
        "protocols": ["icmp_echo"],
    }
    with pytest.raises(ValidationError, match="default routes"):
        ProbePolicyCreate(**base, allowed_cidrs=["0.0.0.0/0"])
    with pytest.raises(ValidationError, match="special-use"):
        ProbePolicyCreate(**base, allowed_cidrs=["127.0.0.0/8"])


def test_evaluation_never_transmits_even_when_policy_gates_pass() -> None:
    now = datetime(2026, 8, 9, 23, tzinfo=UTC)
    result = evaluate_policy(
        policy(approval_expires_at=now + timedelta(hours=1)),
        targets=["192.0.2.10"],
        protocol="icmp_echo",
        global_enabled=True,
        now=now,
    )
    assert result["policy_allows"] is True
    assert result["allowed"] is False
    assert result["transmission_performed"] is False
    assert result["reasons"] == ["probe_executor_not_installed"]


def test_evaluation_reports_every_failed_gate() -> None:
    now = datetime(2026, 8, 9, 12, tzinfo=UTC)
    result = evaluate_policy(
        policy(enabled=False, approval_expires_at=now - timedelta(minutes=1)),
        targets=["198.51.100.10"],
        protocol="tcp_connect",
        global_enabled=False,
        now=now,
    )
    assert result["policy_allows"] is False
    assert "global_active_probing_disabled" in result["reasons"]
    assert "policy_disabled" in result["reasons"]
    assert "approval_missing_or_expired" in result["reasons"]
    assert "protocol_not_allowed" in result["reasons"]
    assert "outside_maintenance_window" in result["reasons"]
    assert "target_outside_allowlist" in result["reasons"]
