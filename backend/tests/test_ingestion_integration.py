import os
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.main import app

pytestmark = pytest.mark.skipif(
    not os.environ.get("INTEGRATION_DATABASE_URL"),
    reason="PostgreSQL integration database is not configured",
)


def test_sensor_event_replay_is_idempotent() -> None:
    event_id = str(uuid.uuid4())
    payload = {
        "event_id": event_id,
        "sensor_id": "ci-sensor",
        "site_id": "ci-site",
        "observed_at": datetime.now(UTC).isoformat(),
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "source_port": 42000,
        "destination_port": 502,
        "transaction_id": 1,
        "unit_id": 1,
        "function_code": 3,
        "fields": {"function_name": "read_holding_registers"},
        "byte_count": 12,
        "payload_sha256": "a" * 64,
    }
    headers = {"X-Sensor-Key": os.environ["SENSOR_INGEST_API_KEY"]}
    client = TestClient(app)

    first = client.post("/api/v1/ingest/modbus", json=payload, headers=headers)
    replay = client.post("/api/v1/ingest/modbus", json=payload, headers=headers)

    assert first.status_code == 201
    assert replay.status_code == 201
    assert replay.json()["observation_id"] == first.json()["observation_id"]
    assert replay.json()["protocol_event_id"] == first.json()["protocol_event_id"]
    assert replay.json()["created_asset"] is False
