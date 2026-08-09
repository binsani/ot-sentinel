import hashlib
from dataclasses import dataclass
from typing import Any


class Iec61850ParseError(ValueError):
    """Raised when RFC 1006/COTP or MMS framing is invalid."""


MMS_PDU_TYPES = {
    0xA0: "confirmed_request",
    0xA1: "confirmed_response",
    0xA2: "confirmed_error",
    0xA3: "unconfirmed",
    0xA4: "reject",
    0xA8: "initiate_request",
    0xA9: "initiate_response",
    0xAA: "initiate_error",
    0x8B: "conclude_request",
    0x8C: "conclude_response",
    0x8D: "conclude_error",
}


@dataclass(frozen=True, slots=True)
class Iec61850Message:
    cotp_type: str
    mms_pdu_type: str
    invoke_id: int | None
    service_tag: int | None
    object_references: list[str]
    fields: dict[str, Any]
    payload_sha256: str


def split_tpkt_stream(data: bytes) -> tuple[list[bytes], bytes]:
    packets: list[bytes] = []
    offset = 0
    while len(data) - offset >= 4:
        if data[offset] != 3:
            raise Iec61850ParseError("invalid TPKT version in TCP stream")
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        if length < 7:
            raise Iec61850ParseError("invalid TPKT length in TCP stream")
        if len(data) - offset < length:
            break
        packets.append(data[offset : offset + length])
        offset += length
    return packets, data[offset:]


def parse_iec61850_mms(packet: bytes) -> Iec61850Message:
    if len(packet) < 7 or packet[0] != 3:
        raise Iec61850ParseError("invalid RFC 1006 TPKT")
    if int.from_bytes(packet[2:4], "big") != len(packet):
        raise Iec61850ParseError("TPKT length mismatch")
    cotp = packet[4:]
    header_length = cotp[0]
    if header_length < 1 or header_length + 1 > len(cotp):
        raise Iec61850ParseError("invalid COTP header")
    pdu_type = cotp[1] & 0xF0
    if pdu_type in {0xE0, 0xD0}:
        raise Iec61850ParseError("MMS application identity is not present in COTP setup")
    if pdu_type != 0xF0 or header_length < 2:
        raise Iec61850ParseError("COTP packet does not contain MMS data")
    payload = cotp[header_length + 1 :]
    if not payload or payload[0] == 0x32:
        raise Iec61850ParseError("COTP payload is not IEC 61850 MMS")
    digest = hashlib.sha256(packet).hexdigest()
    mms_offset = _find_mms_tag(payload)
    tag = payload[mms_offset]
    length, value_offset = _ber_length(payload, mms_offset + 1)
    end = value_offset + length
    if end > len(payload):
        raise Iec61850ParseError("MMS BER value is truncated")
    value = payload[value_offset:end]
    invoke_id = _invoke_id(value)
    service_tag = _service_tag(value, invoke_id is not None)
    return Iec61850Message(
        cotp_type="data",
        mms_pdu_type=MMS_PDU_TYPES[tag],
        invoke_id=invoke_id,
        service_tag=service_tag,
        object_references=_visible_strings(value),
        fields={"presentation_prefix_bytes": mms_offset, "mms_payload_length": length},
        payload_sha256=digest,
    )


def _find_mms_tag(payload: bytes) -> int:
    for offset, value in enumerate(payload[:64]):
        if value in MMS_PDU_TYPES:
            try:
                length, start = _ber_length(payload, offset + 1)
            except Iec61850ParseError:
                continue
            if start + length <= len(payload):
                return offset
    raise Iec61850ParseError("no complete MMS BER PDU found")


def _ber_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise Iec61850ParseError("BER length is missing")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    octets = first & 0x7F
    if octets == 0 or octets > 4 or offset + 1 + octets > len(data):
        raise Iec61850ParseError("invalid BER length")
    return int.from_bytes(data[offset + 1 : offset + 1 + octets], "big"), offset + 1 + octets


def _invoke_id(value: bytes) -> int | None:
    if len(value) >= 3 and value[0] == 0x02 and 0 < value[1] <= 4 and len(value) >= 2 + value[1]:
        return int.from_bytes(value[2 : 2 + value[1]], "big")
    return None


def _service_tag(value: bytes, has_invoke_id: bool) -> int | None:
    offset = 2 + value[1] if has_invoke_id else 0
    return value[offset] if offset < len(value) else None


def _visible_strings(data: bytes) -> list[str]:
    strings: list[str] = []
    offset = 0
    while offset + 2 <= len(data):
        if data[offset] in {0x1A, 0x16}:
            length = data[offset + 1]
            raw = data[offset + 2 : offset + 2 + length]
            if len(raw) == length:
                text = raw.decode("ascii", errors="ignore")
                if text and text not in strings:
                    strings.append(text[:255])
            offset += 2 + length
        else:
            offset += 1
    return strings[:32]
