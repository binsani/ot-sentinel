import pytest

from ot_sentinel_sensor.modbus import (
    ModbusParseError,
    parse_modbus_tcp,
    split_modbus_tcp_stream,
)


def test_parse_read_device_identification_response() -> None:
    objects = b"\x00\x09Schneider\x01\x06TM221C\x02\x051.2.3\x05\x06M221-X"
    data = b"\x0e\x01\x01\x00\x00\x04" + objects
    payload = b"\x00\x01\x00\x00" + (len(data) + 2).to_bytes(2, "big") + b"\x01\x2b" + data

    message = parse_modbus_tcp(payload, is_response=True)

    assert message.fields["device_identification"] == {
        "vendor_name": "Schneider",
        "product_code": "TM221C",
        "revision": "1.2.3",
        "model_name": "M221-X",
    }


def test_read_holding_registers_request() -> None:
    message = parse_modbus_tcp(bytes.fromhex("0001000000060103006b0003"), is_response=False)
    assert message.transaction_id == 1
    assert message.unit_id == 1
    assert message.function_name == "read_holding_registers"
    assert message.fields == {"address": 107, "quantity": 3}
    assert len(message.payload_sha256) == 64


def test_read_holding_registers_response() -> None:
    message = parse_modbus_tcp(
        bytes.fromhex("000100000009010306022b00000064"), is_response=True
    )
    assert message.fields == {"byte_count": 6}


def test_exception_response() -> None:
    message = parse_modbus_tcp(bytes.fromhex("000100000003018302"), is_response=True)
    assert message.is_exception is True
    assert message.function_code == 3
    assert message.fields == {"exception_code": 2}


def test_stream_split_handles_coalesced_and_partial_frames() -> None:
    first = bytes.fromhex("0001000000060103006b0003")
    second = bytes.fromhex("000200000006010300010001")
    frames, remainder = split_modbus_tcp_stream(first + second[:7])
    assert frames == [first]
    assert remainder == second[:7]
    frames, remainder = split_modbus_tcp_stream(remainder + second[7:])
    assert frames == [second]
    assert remainder == b""


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        bytes.fromhex("0001000100060103006b0003"),
        bytes.fromhex("0001000000070103006b0003"),
        bytes.fromhex("00010000000301830200"),
    ],
)
def test_rejects_malformed_adus(payload: bytes) -> None:
    with pytest.raises(ModbusParseError):
        parse_modbus_tcp(payload)
