import ipaddress
import socket
import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.models import SiemDelivery
from app.siem import (
    configured_allowed_networks,
    event_severity,
    rfc5424_message,
    validate_destination,
)


def private_resolution(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", 6514))]


@patch("app.siem.socket.getaddrinfo", private_resolution)
def test_destination_must_resolve_inside_explicit_allowlist() -> None:
    assert validate_destination("siem.example", 6514, [ipaddress.ip_network("10.20.30.0/24")]) == [
        "10.20.30.40"
    ]
    with pytest.raises(ValueError, match="SIEM_ALLOWED_CIDRS"):
        validate_destination("siem.example", 6514, [ipaddress.ip_network("10.20.40.0/24")])


def test_empty_destination_allowlist_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = type("Settings", (), {"siem_allowed_cidrs": ""})()
    monkeypatch.setattr("app.siem.get_settings", lambda: settings)
    with pytest.raises(HTTPException) as error:
        configured_allowed_networks()
    assert error.value.status_code == 409


def test_rfc5424_message_uses_tls_octet_counting_payload_format() -> None:
    delivery = SiemDelivery(
        id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        destination_id=uuid.uuid4(),
        event_type="firmware_drift",
        severity="high",
        payload={
            "occurred_at": datetime(2026, 8, 9, tzinfo=UTC).isoformat(),
            "data": {"asset_id": "asset-1"},
        },
    )
    framed = rfc5424_message(delivery)
    length, message = framed.split(b" ", 1)
    assert int(length) == len(message)
    assert message.startswith(b"<131>1 2026-08-09T00:00:00+00:00 ot-sentinel")
    assert b"event_type" not in message
    assert b'"asset_id":"asset-1"' in message


def test_known_exploited_vulnerability_maps_to_critical() -> None:
    assert (
        event_severity("vulnerability_match", {"severity": "low", "known_exploited": True})
        == "critical"
    )
    assert event_severity("firmware_drift", {}) == "medium"
