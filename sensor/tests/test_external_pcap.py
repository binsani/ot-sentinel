from pathlib import Path

import pytest

from ot_sentinel_sensor.pcap import (
    dnp3_observations_from_pcap,
    observations_from_pcap,
    opcua_observations_from_pcap,
    s7_observations_from_pcap,
)

CAPTURE = Path(__file__).parent / "external" / "modbus_write_single_coil.pcap"
OPCUA_CAPTURE = Path(__file__).parent / "external" / "opcua-encrypted.pcapng"
DNP3_CAPTURE = Path(__file__).parent / "external" / "dnp3_example.pcap"
S7_SNAP7_CAPTURE = Path(__file__).parent / "external" / "cisa_snap7.pcap"
S7_IDENT_CAPTURE = Path(__file__).parent / "external" / "cisa_s7ident.pcap"


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


@pytest.mark.skipif(not DNP3_CAPTURE.exists(), reason="external fixtures were not fetched")
def test_official_cisa_dnp3_capture_to_observations() -> None:
    observations = list(
        dnp3_observations_from_pcap(DNP3_CAPTURE, sensor_id="cisa-public-fixture")
    )

    assert len(observations) == 834
    assert {item["application_function_name"] for item in observations} >= {
        "read",
        "select",
        "operate",
        "response",
        "unsolicited_response",
    }
    assert {item["link_source_address"] for item in observations} == {5, 100}
    assert {str(item["source_ip"]) for item in observations} == {"10.10.20.5", "10.10.20.8"}


@pytest.mark.skipif(not S7_SNAP7_CAPTURE.exists(), reason="external fixtures were not fetched")
def test_official_cisa_snap7_capture_to_observations() -> None:
    observations = list(
        s7_observations_from_pcap(S7_SNAP7_CAPTURE, sensor_id="cisa-public-fixture")
    )

    assert len(observations) == 64
    assert {item["function_name"] for item in observations} >= {
        "setup_communication",
        "read_var",
        "write_var",
        "start_upload",
        "upload",
        "end_upload",
        "plc_stop",
    }
    setup = next(item for item in observations if item["function_name"] == "setup_communication")
    assert setup["fields"]["negotiated_pdu_length"] == 480


@pytest.mark.skipif(not S7_IDENT_CAPTURE.exists(), reason="external fixtures were not fetched")
def test_official_cisa_s7_ident_capture_exposes_connection_metadata() -> None:
    observations = list(
        s7_observations_from_pcap(S7_IDENT_CAPTURE, sensor_id="cisa-public-fixture")
    )

    assert len(observations) == 24
    connection = next(item for item in observations if item["cotp_type"] == "connection_request")
    assert connection["source_tsap"] == "0100"
    assert connection["destination_tsap"] == "0101"
    assert connection["rack"] == 0
    assert connection["slot"] == 1
