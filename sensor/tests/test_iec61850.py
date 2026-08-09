import pytest

from ot_sentinel_sensor.iec61850 import (
    Iec61850ParseError,
    parse_iec61850_mms,
    split_tpkt_stream,
)
from ot_sentinel_sensor.s7comm import S7ParseError, parse_s7comm_tpkt


def test_parses_confirmed_mms_request_and_visible_object_reference() -> None:
    mms = bytes.fromhex("a00f020101a40a1a084c44302f4c4c4e30")
    packet = b"\x03\x00" + (7 + len(mms)).to_bytes(2, "big") + b"\x02\xf0\x80" + mms
    message = parse_iec61850_mms(packet)
    assert message.mms_pdu_type == "confirmed_request"
    assert message.invoke_id == 1
    assert message.service_tag == 0xA4
    assert message.object_references == ["LD0/LLN0"]


def test_rejects_s7comm_payload_on_shared_port() -> None:
    packet = bytes.fromhex("0300001202f0803201000000020001000005")
    with pytest.raises(Iec61850ParseError, match="not IEC 61850"):
        parse_iec61850_mms(packet)


def test_stream_split_retains_partial_mms_packet() -> None:
    mms = bytes.fromhex("a003020101")
    packet = b"\x03\x00" + (7 + len(mms)).to_bytes(2, "big") + b"\x02\xf0\x80" + mms
    frames, remainder = split_tpkt_stream(packet + packet[:5])
    assert frames == [packet]
    assert remainder == packet[:5]


def test_mms_transport_setup_is_not_misclassified_as_s7() -> None:
    packet = bytes.fromhex("0300001611e00000000100c1020001c2020001c0010a")
    with pytest.raises(S7ParseError, match="recognized S7 TSAP"):
        parse_s7comm_tpkt(packet)
