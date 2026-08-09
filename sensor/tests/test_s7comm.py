import pytest

from ot_sentinel_sensor.s7comm import S7ParseError, parse_s7comm_tpkt, split_tpkt_stream


def test_parses_cotp_connection_request_rack_and_slot() -> None:
    packet = bytes.fromhex("0300001611e00000000100c1020100c2020102c0010a")
    message = parse_s7comm_tpkt(packet)
    assert message.cotp_type == "connection_request"
    assert message.destination_tsap == "0102"
    assert message.rack == 0
    assert message.slot == 2


def test_parses_setup_communication_job() -> None:
    packet = bytes.fromhex("0300001902f08032010000000100080000f0000001000101e0")
    message = parse_s7comm_tpkt(packet)
    assert message.rosctr_name == "job"
    assert message.function_name == "setup_communication"
    assert message.fields["negotiated_pdu_length"] == 480
    assert message.fields["observed_write_or_control"] is False


def test_marks_observed_write_request() -> None:
    packet = bytes.fromhex("0300001202f0803201000000020001000005")
    message = parse_s7comm_tpkt(packet)
    assert message.function_name == "write_var"
    assert message.fields["observed_write_or_control"] is True


def test_split_tpkt_stream_retains_partial_packet() -> None:
    packet = bytes.fromhex("0300001202f0803201000000020001000005")
    packets, remainder = split_tpkt_stream(packet + packet[:6])
    assert packets == [packet]
    assert remainder == packet[:6]


def test_rejects_s7_length_mismatch() -> None:
    packet = bytearray(bytes.fromhex("0300001202f0803201000000020001000005"))
    packet[14] = 2
    with pytest.raises(S7ParseError, match="length mismatch"):
        parse_s7comm_tpkt(bytes(packet))
