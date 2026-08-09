from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.schemas import (
    Dnp3ObservationIn,
    ModbusObservationIn,
    OpcUaObservationIn,
    S7ObservationIn,
)


def valid_observation() -> dict[str, object]:
    return {
        "sensor_id": "sensor-1",
        "observed_at": datetime.now(UTC),
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "source_port": 49152,
        "destination_port": 502,
        "transaction_id": 1,
        "unit_id": 1,
        "function_code": 3,
        "byte_count": 12,
        "payload_sha256": "a" * 64,
    }


def test_observation_schema_accepts_valid_modbus_event() -> None:
    observation = ModbusObservationIn.model_validate(valid_observation())
    assert str(observation.destination_ip) == "192.0.2.20"


def test_observation_schema_rejects_naive_timestamp() -> None:
    data = valid_observation()
    data["observed_at"] = datetime.now()
    with pytest.raises(ValidationError):
        ModbusObservationIn.model_validate(data)


def test_observation_schema_rejects_invalid_mac() -> None:
    data = valid_observation()
    data["destination_mac"] = "not-a-mac"
    with pytest.raises(ValidationError):
        ModbusObservationIn.model_validate(data)


def test_dnp3_schema_accepts_link_and_application_metadata() -> None:
    data = {
        "sensor_id": "sensor-1",
        "observed_at": datetime.now(UTC),
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "source_port": 50100,
        "destination_port": 20000,
        "link_source_address": 1,
        "link_destination_address": 100,
        "direction_from_master": True,
        "link_function": 4,
        "transport_sequence": 0,
        "application_function": 1,
        "application_function_name": "read",
        "application_sequence": 0,
        "byte_count": 18,
        "payload_sha256": "b" * 64,
    }
    observation = Dnp3ObservationIn.model_validate(data)
    assert observation.link_destination_address == 100


def test_s7_schema_accepts_rack_slot_evidence() -> None:
    observation = S7ObservationIn.model_validate(
        {
            "sensor_id": "sensor-1",
            "observed_at": datetime.now(UTC),
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "source_port": 51000,
            "destination_port": 102,
            "cotp_type": "connection_request",
            "destination_tsap": "0102",
            "rack": 0,
            "slot": 2,
            "byte_count": 22,
            "payload_sha256": "c" * 64,
        }
    )
    assert observation.rack == 0
    assert observation.slot == 2


def test_opcua_schema_accepts_browse_metadata() -> None:
    observation = OpcUaObservationIn.model_validate(
        {
            "sensor_id": "sensor-1",
            "observed_at": datetime.now(UTC),
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "source_port": 52000,
            "destination_port": 4840,
            "message_type": "MSG",
            "chunk_type": "F",
            "secure_channel_id": 10,
            "token_id": 20,
            "service_node_id": 527,
            "service_name": "browse_request",
            "byte_count": 28,
            "payload_sha256": "d" * 64,
        }
    )
    assert observation.service_name == "browse_request"
