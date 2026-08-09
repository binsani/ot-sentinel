import hashlib
import math
from dataclasses import dataclass
from typing import Any


class Dnp3ParseError(ValueError):
    """Raised when a DNP3 data-link frame is incomplete or invalid."""


APPLICATION_FUNCTIONS = {
    0x00: "confirm",
    0x01: "read",
    0x02: "write",
    0x03: "select",
    0x04: "operate",
    0x05: "direct_operate",
    0x06: "direct_operate_no_ack",
    0x0D: "cold_restart",
    0x0E: "warm_restart",
    0x14: "enable_unsolicited",
    0x15: "disable_unsolicited",
    0x17: "delay_measurement",
    0x81: "response",
    0x82: "unsolicited_response",
}


@dataclass(frozen=True, slots=True)
class Dnp3Frame:
    source_address: int
    destination_address: int
    link_function: int
    direction_from_master: bool
    primary: bool
    transport_sequence: int | None
    application_function: int | None
    application_function_name: str | None
    application_sequence: int | None
    internal_indications: int | None
    fields: dict[str, Any]
    payload_sha256: str


def parse_dnp3_frame(frame: bytes) -> Dnp3Frame:
    if len(frame) < 10:
        raise Dnp3ParseError("DNP3 frame is shorter than the 10-byte link header")
    if frame[:2] != b"\x05\x64":
        raise Dnp3ParseError("DNP3 sync bytes are invalid")
    length = frame[2]
    if length < 5:
        raise Dnp3ParseError("DNP3 length must include the five link-header octets")
    user_length = length - 5
    expected_size = 10 + user_length + 2 * math.ceil(user_length / 16)
    if len(frame) != expected_size:
        raise Dnp3ParseError(
            f"DNP3 length mismatch: expected {expected_size} bytes, received {len(frame)}"
        )
    _verify_crc(frame[:8], frame[8:10], "link header")
    user_data = _decode_user_blocks(frame[10:], user_length)

    control = frame[3]
    destination = int.from_bytes(frame[4:6], "little")
    source = int.from_bytes(frame[6:8], "little")
    transport_sequence: int | None = None
    application_function: int | None = None
    application_sequence: int | None = None
    internal_indications: int | None = None
    fields: dict[str, Any] = {"user_data_length": len(user_data)}

    if user_data:
        transport = user_data[0]
        transport_sequence = transport & 0x3F
        fields.update(
            {
                "transport_first": bool(transport & 0x80),
                "transport_final": bool(transport & 0x40),
            }
        )
        application = user_data[1:]
        if len(application) >= 2 and bool(transport & 0x80):
            application_control = application[0]
            application_sequence = application_control & 0x0F
            application_function = application[1]
            fields.update(
                {
                    "application_first": bool(application_control & 0x80),
                    "application_final": bool(application_control & 0x40),
                    "confirmation_requested": bool(application_control & 0x20),
                    "unsolicited": bool(application_control & 0x10),
                    "control_operation": application_function in {0x02, 0x03, 0x04, 0x05, 0x06},
                }
            )
            if application_function in {0x81, 0x82} and len(application) >= 4:
                internal_indications = int.from_bytes(application[2:4], "little")

    return Dnp3Frame(
        source_address=source,
        destination_address=destination,
        link_function=control & 0x0F,
        direction_from_master=bool(control & 0x80),
        primary=bool(control & 0x40),
        transport_sequence=transport_sequence,
        application_function=application_function,
        application_function_name=APPLICATION_FUNCTIONS.get(application_function),
        application_sequence=application_sequence,
        internal_indications=internal_indications,
        fields=fields,
        payload_sha256=hashlib.sha256(frame).hexdigest(),
    )


def split_dnp3_stream(data: bytes) -> tuple[list[bytes], bytes]:
    frames: list[bytes] = []
    offset = 0
    while len(data) - offset >= 3:
        if data[offset : offset + 2] != b"\x05\x64":
            raise Dnp3ParseError("invalid DNP3 sync bytes in TCP stream")
        length = data[offset + 2]
        if length < 5:
            raise Dnp3ParseError("invalid DNP3 link length in TCP stream")
        user_length = length - 5
        frame_size = 10 + user_length + 2 * math.ceil(user_length / 16)
        if len(data) - offset < frame_size:
            break
        frames.append(data[offset : offset + frame_size])
        offset += frame_size
    return frames, data[offset:]


def dnp3_crc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def _verify_crc(data: bytes, encoded_crc: bytes, context: str) -> None:
    if len(encoded_crc) != 2 or int.from_bytes(encoded_crc, "little") != dnp3_crc(data):
        raise Dnp3ParseError(f"DNP3 {context} CRC is invalid")


def _decode_user_blocks(encoded: bytes, user_length: int) -> bytes:
    output = bytearray()
    offset = 0
    while len(output) < user_length:
        block_length = min(16, user_length - len(output))
        block = encoded[offset : offset + block_length]
        encoded_crc = encoded[offset + block_length : offset + block_length + 2]
        if len(block) != block_length:
            raise Dnp3ParseError("DNP3 user-data block is truncated")
        _verify_crc(block, encoded_crc, "user-data block")
        output.extend(block)
        offset += block_length + 2
    return bytes(output)
