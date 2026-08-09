import pytest

from ot_sentinel_sensor.dnp3 import (
    Dnp3ParseError,
    dnp3_crc,
    parse_dnp3_frame,
    split_dnp3_stream,
)


def frame_with_user_data(user_data: bytes, *, control: int = 0xC4) -> bytes:
    header = b"\x05\x64" + bytes([5 + len(user_data), control]) + b"\x01\x00\x64\x00"
    encoded = header + dnp3_crc(header).to_bytes(2, "little")
    for offset in range(0, len(user_data), 16):
        block = user_data[offset : offset + 16]
        encoded += block + dnp3_crc(block).to_bytes(2, "little")
    return encoded


def test_parses_read_request_and_link_addresses() -> None:
    frame = parse_dnp3_frame(frame_with_user_data(bytes.fromhex("c0c001")))
    assert frame.source_address == 100
    assert frame.destination_address == 1
    assert frame.transport_sequence == 0
    assert frame.application_function_name == "read"
    assert frame.application_sequence == 0
    assert frame.direction_from_master is True
    assert frame.fields["control_operation"] is False


def test_marks_observed_control_operation() -> None:
    frame = parse_dnp3_frame(frame_with_user_data(bytes.fromhex("c0c004")))
    assert frame.application_function_name == "operate"
    assert frame.fields["control_operation"] is True


def test_parses_response_internal_indications() -> None:
    frame = parse_dnp3_frame(
        frame_with_user_data(bytes.fromhex("c0c0810100"), control=0x44)
    )
    assert frame.application_function_name == "response"
    assert frame.internal_indications == 1
    assert frame.direction_from_master is False


def test_stream_split_retains_partial_frame() -> None:
    first = frame_with_user_data(bytes.fromhex("c0c001"))
    second = frame_with_user_data(bytes.fromhex("c1c101"))
    frames, remainder = split_dnp3_stream(first + second[:8])
    assert frames == [first]
    assert remainder == second[:8]


def test_rejects_corrupt_crc() -> None:
    frame = bytearray(frame_with_user_data(bytes.fromhex("c0c001")))
    frame[-1] ^= 0xFF
    with pytest.raises(Dnp3ParseError, match="CRC"):
        parse_dnp3_frame(bytes(frame))
