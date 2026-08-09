import uuid
from datetime import UTC, datetime

from app.anomalies import anomaly_dict, baseline_dict
from app.models import GraphAnomaly, GraphBaseline
from app.siem import event_severity


def test_baseline_and_anomaly_evidence_are_serialized() -> None:
    now = datetime.now(UTC)
    baseline = GraphBaseline(
        id=uuid.uuid4(),
        site_id="plant-a",
        active=True,
        captured_at=now,
        captured_by="admin@example.com",
        edge_count=12,
    )
    anomaly = GraphAnomaly(
        id=uuid.uuid4(),
        baseline_id=baseline.id,
        site_id="plant-a",
        source_ip="192.0.2.10",
        destination_ip="192.0.2.20",
        protocol="modbus_tcp",
        status="open",
        first_seen=now,
        last_seen=now,
        observation_count=3,
    )
    assert baseline_dict(baseline)["edge_count"] == 12
    result = anomaly_dict(anomaly)
    assert result["source_ip"] == "192.0.2.10"
    assert result["observation_count"] == 3


def test_communication_anomaly_maps_to_high_siem_severity() -> None:
    assert event_severity("communication_anomaly", {}) == "high"
