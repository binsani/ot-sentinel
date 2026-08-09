import hashlib
import struct
from dataclasses import dataclass
from typing import Any


class ModbusParseError(ValueError):
    """Raised when a payload is not a complete, valid Modbus TCP ADU."""


FUNCTION_NAMES = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
    17: "report_server_id",
    43: "encapsulated_interface_transport",
}


@dataclass(frozen=True, slots=True)
class ModbusMessage:
    transaction_id: int
    unit_id: int
    function_code: int
    function_name: str
    is_exception: bool
    fields: dict[str, Any]
    payload_sha256: str


def split_modbus_tcp_stream(data: bytes) -> tuple[list[bytes], bytes]:
    """Split complete MBAP-framed ADUs, retaining a final partial ADU."""
    frames: list[bytes] = []
    offset = 0
    while len(data) - offset >= 6:
        protocol_id = int.from_bytes(data[offset + 2 : offset + 4], "big")
        length = int.from_bytes(data[offset + 4 : offset + 6], "big")
        if protocol_id != 0 or not 2 <= length <= 254:
            raise ModbusParseError("invalid MBAP header in TCP stream")
        frame_size = 6 + length
        if len(data) - offset < frame_size:
            break
        frames.append(data[offset : offset + frame_size])
        offset += frame_size
    return frames, data[offset:]


def parse_modbus_tcp(payload: bytes, *, is_response: bool | None = None) -> ModbusMessage:
    if len(payload) < 8:
        raise ModbusParseError("Modbus TCP ADU is shorter than the 8-byte minimum")
    transaction_id, protocol_id, length = struct.unpack(">HHH", payload[:6])
    if protocol_id != 0:
        raise ModbusParseError("MBAP protocol identifier must be zero")
    if not 2 <= length <= 254:
        raise ModbusParseError("MBAP length is outside the valid range")
    expected_size = 6 + length
    if len(payload) != expected_size:
        raise ModbusParseError(
            f"MBAP length mismatch: expected {expected_size} bytes, received {len(payload)}"
        )

    unit_id = payload[6]
    raw_function = payload[7]
    is_exception = bool(raw_function & 0x80)
    function_code = raw_function & 0x7F
    data = payload[8:]
    fields: dict[str, Any] = {}
    if is_exception:
        if len(data) != 1:
            raise ModbusParseError("exception response must contain exactly one exception code")
        fields["exception_code"] = data[0]
    else:
        fields = _parse_function(function_code, data, is_response)

    return ModbusMessage(
        transaction_id=transaction_id,
        unit_id=unit_id,
        function_code=function_code,
        function_name=FUNCTION_NAMES.get(function_code, "unknown"),
        is_exception=is_exception,
        fields=fields,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )


def _parse_function(code: int, data: bytes, is_response: bool | None) -> dict[str, Any]:
    if code in {1, 2, 3, 4}:
        if is_response is True:
            return _byte_count_response(data)
        if len(data) == 4:
            address, quantity = struct.unpack(">HH", data)
            return {"address": address, "quantity": quantity}
    if code in {5, 6} and len(data) == 4:
        address, value = struct.unpack(">HH", data)
        return {"address": address, "value": value}
    if code in {15, 16}:
        if len(data) == 4:
            address, quantity = struct.unpack(">HH", data)
            return {"address": address, "quantity": quantity}
        if len(data) >= 5:
            address, quantity, byte_count = struct.unpack(">HHB", data[:5])
            if len(data[5:]) != byte_count:
                raise ModbusParseError("write request byte count does not match payload")
            return {"address": address, "quantity": quantity, "byte_count": byte_count}
    if code == 43 and data and data[0] == 0x0E:
        return _parse_device_identification(data, is_response)
    return {"data_length": len(data)}


def _parse_device_identification(data: bytes, is_response: bool | None) -> dict[str, Any]:
    if is_response is not True:
        if len(data) != 3:
            raise ModbusParseError("device identification request must contain three bytes")
        return {"mei_type": data[0], "read_device_id_code": data[1], "object_id": data[2]}
    if len(data) < 6:
        raise ModbusParseError("device identification response is truncated")
    _, read_code, conformity, more_follows, next_object_id, object_count = data[:6]
    offset = 6
    names = {
        0: "vendor_name",
        1: "product_code",
        2: "revision",
        3: "vendor_url",
        4: "product_name",
        5: "model_name",
        6: "user_application_name",
    }
    objects: dict[str, str] = {}
    for _ in range(object_count):
        if len(data) - offset < 2:
            raise ModbusParseError("device identification object header is truncated")
        object_id, length = data[offset : offset + 2]
        offset += 2
        if len(data) - offset < length:
            raise ModbusParseError("device identification object value is truncated")
        value = data[offset : offset + length].decode("utf-8", errors="replace")
        offset += length
        objects[names.get(object_id, f"object_{object_id}")] = value
    if offset != len(data):
        raise ModbusParseError("device identification response has trailing bytes")
    return {
        "mei_type": 0x0E,
        "read_device_id_code": read_code,
        "conformity_level": conformity,
        "more_follows": bool(more_follows),
        "next_object_id": next_object_id,
        "device_identification": objects,
    }


def _byte_count_response(data: bytes) -> dict[str, Any]:
    if not data or len(data[1:]) != data[0]:
        raise ModbusParseError("response byte count does not match payload")
    return {"byte_count": data[0]}
