import uuid
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from app import ingestion
from app.models import Asset


def _asset() -> Asset:
    now = datetime.now(UTC)
    return Asset(
        id=uuid.uuid4(),
        site_id="plant-a",
        ip_address="192.0.2.10",
        firmware_version="1.0",
        firmware_baseline="1.0",
        protocols=["modbus_tcp"],
        fingerprint={},
        first_seen=now,
        last_seen=now,
    )


def test_firmware_drift_transition_is_audited(monkeypatch: pytest.MonkeyPatch) -> None:
    asset = _asset()
    audit = Mock()
    monkeypatch.setattr(ingestion, "append_audit_log", audit)
    observed_at = datetime.now(UTC)

    ingestion._apply_firmware_version(Mock(), asset, "2.0", observed_at, "tap-01")

    assert asset.firmware_version == "2.0"
    assert asset.firmware_drift_detected_at == observed_at
    assert audit.call_args.kwargs["action"] == "firmware.drift_detected"

    ingestion._apply_firmware_version(Mock(), asset, "1.0", observed_at, "tap-01")
    assert asset.firmware_drift_detected_at is None
    assert audit.call_args.kwargs["action"] == "firmware.drift_resolved"
