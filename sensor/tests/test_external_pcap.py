from pathlib import Path

import pytest

from ot_sentinel_sensor.pcap import observations_from_pcap, opcua_observations_from_pcap

CAPTURE = Path(__file__).parent / "external" / "modbus_write_single_coil.pcap"
OPCUA_CAPTURE = Path(__file__).parent / "external" / "opcua-encrypted.pcapng"


@pytest.mark.skipif(not CAPTURE.exists(), reason="external fixtures were not fetched")
def test_public_modbus_capture_to_observations() -> None:
    observations = list(observations_from_pcap(CAPTURE, sensor_id="public-fixture"))

    assert len(observations) == 6
    assert {item["function_code"] for item in observations} == {5, 6}
    assert {item["fields"]["function_name"] for item in observations} == {
        "write_single_coil",
        "write_single_register",
    }
    assert {str(item["source_ip"]) for item in observations} == {"10.0.0.3", "10.0.0.9"}


@pytest.mark.skipif(not OPCUA_CAPTURE.exists(), reason="external fixtures were not fetched")
def test_public_encrypted_opcua_capture_exposes_metadata_only() -> None:
    observations = list(
        opcua_observations_from_pcap(OPCUA_CAPTURE, sensor_id="public-fixture")
    )

    assert len(observations) == 33
    assert {item["message_type"] for item in observations} >= {"HEL", "ACK", "OPN", "MSG"}
    assert any(item["security_policy_uri"] for item in observations)
