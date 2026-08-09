import struct

import pytest

from ot_sentinel_sensor.opcua import OpcUaParseError, parse_opcua_tcp, split_opcua_stream


def ua_string(value: str | None) -> bytes:
    if value is None:
        return struct.pack("<i", -1)
    encoded = value.encode()
    return struct.pack("<i", len(encoded)) + encoded


def message(kind: bytes, body: bytes) -> bytes:
    return kind + struct.pack("<I", 8 + len(body)) + body


def test_parses_hello_endpoint_and_limits() -> None:
    body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + ua_string(
        "opc.tcp://plc.example:4840"
    )
    parsed = parse_opcua_tcp(message(b"HELF", body))
    assert parsed.endpoint_url == "opc.tcp://plc.example:4840"
    assert parsed.fields["receive_buffer_size"] == 65536


def test_parses_open_secure_channel_none() -> None:
    policy = "http://opcfoundation.org/UA/SecurityPolicy#None"
    body = (
        struct.pack("<I", 10)
        + ua_string(policy)
        + ua_string(None)
        + ua_string(None)
        + struct.pack("<II", 1, 7)
        + bytes.fromhex("0100be01")
    )
    parsed = parse_opcua_tcp(message(b"OPNF", body))
    assert parsed.security_policy_uri == policy
    assert parsed.service_name == "open_secure_channel_request"
    assert parsed.secure_channel_id == 10


def test_identifies_cleartext_browse_request() -> None:
    body = struct.pack("<IIII", 10, 20, 2, 8) + bytes.fromhex("01000f02")
    parsed = parse_opcua_tcp(message(b"MSGF", body), security_policy_none=True)
    assert parsed.service_node_id == 527
    assert parsed.service_name == "browse_request"
    assert parsed.fields["payload_encrypted_or_signed"] is False


def test_encrypted_message_remains_opaque() -> None:
    body = struct.pack("<II", 10, 20) + b"opaque-ciphertext"
    parsed = parse_opcua_tcp(message(b"MSGF", body), security_policy_none=False)
    assert parsed.service_name is None
    assert parsed.fields["payload_encrypted_or_signed"] is True


def test_stream_split_retains_partial_message() -> None:
    ack = message(b"ACKF", struct.pack("<IIIII", 0, 8192, 8192, 0, 0))
    messages, remainder = split_opcua_stream(ack + ack[:7])
    assert messages == [ack]
    assert remainder == ack[:7]


def test_rejects_declared_length_mismatch() -> None:
    packet = bytearray(message(b"ACKF", struct.pack("<IIIII", 0, 8192, 8192, 0, 0)))
    packet[4:8] = struct.pack("<I", len(packet) + 1)
    with pytest.raises(OpcUaParseError, match="length mismatch"):
        parse_opcua_tcp(bytes(packet))

