import hashlib
from dataclasses import dataclass
from typing import Any


class S7ParseError(ValueError):
    """Raised when RFC 1006, COTP, or S7comm framing is invalid."""


ROSCTR_NAMES = {1: "job", 2: "ack", 3: "ack_data", 7: "user_data"}
FUNCTION_NAMES = {
    0x04: "read_var",
    0x05: "write_var",
    0x1A: "request_download",
    0x1B: "download_block",
    0x1C: "download_ended",
    0x1D: "start_upload",
    0x1E: "upload",
    0x1F: "end_upload",
    0x28: "pi_service",
    0x29: "plc_stop",
    0xF0: "setup_communication",
}


@dataclass(frozen=True, slots=True)
class S7Message:
    cotp_type: str
    pdu_reference: int | None
    rosctr: int | None
    rosctr_name: str | None
    function_code: int | None
    function_name: str | None
    error_class: int | None
    error_code: int | None
    source_tsap: str | None
    destination_tsap: str | None
    rack: int | None
    slot: int | None
    fields: dict[str, Any]
    payload_sha256: str


def parse_s7comm_tpkt(packet: bytes) -> S7Message:
    if len(packet) < 7:
        raise S7ParseError("TPKT is shorter than the RFC 1006 minimum")
    if packet[0] != 3:
        raise S7ParseError("TPKT version must be 3")
    packet_length = int.from_bytes(packet[2:4], "big")
    if packet_length != len(packet):
        raise S7ParseError(
            f"TPKT length mismatch: expected {packet_length} bytes, received {len(packet)}"
        )
    cotp = packet[4:]
    header_length = cotp[0]
    if header_length + 1 > len(cotp) or header_length < 1:
        raise S7ParseError("COTP header length is invalid")
    pdu_type = cotp[1] & 0xF0
    digest = hashlib.sha256(packet).hexdigest()
    if pdu_type in {0xE0, 0xD0}:
        return _parse_connection(cotp, pdu_type, digest)
    if pdu_type != 0xF0:
        return S7Message(
            cotp_type=f"0x{pdu_type:02x}",
            pdu_reference=None,
            rosctr=None,
            rosctr_name=None,
            function_code=None,
            function_name=None,
            error_class=None,
            error_code=None,
            source_tsap=None,
            destination_tsap=None,
            rack=None,
            slot=None,
            fields={},
            payload_sha256=digest,
        )
    if header_length < 2:
        raise S7ParseError("COTP data header is too short")
    s7_payload = cotp[header_length + 1 :]
    return _parse_s7_payload(s7_payload, digest, bool(cotp[2] & 0x80))


def split_tpkt_stream(data: bytes) -> tuple[list[bytes], bytes]:
    packets: list[bytes] = []
    offset = 0
    while len(data) - offset >= 4:
        if data[offset] != 3:
            raise S7ParseError("invalid TPKT version in TCP stream")
        packet_length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        if packet_length < 7:
            raise S7ParseError("invalid TPKT length in TCP stream")
        if len(data) - offset < packet_length:
            break
        packets.append(data[offset : offset + packet_length])
        offset += packet_length
    return packets, data[offset:]


def _parse_connection(cotp: bytes, pdu_type: int, digest: str) -> S7Message:
    if cotp[0] < 6:
        raise S7ParseError("COTP connection header is too short")
    parameters = _cotp_parameters(cotp[7 : cotp[0] + 1])
    source = parameters.get(0xC1)
    destination = parameters.get(0xC2)
    device_tsap = destination if pdu_type == 0xE0 else source
    rack, slot = _rack_slot(device_tsap)
    fields: dict[str, Any] = {}
    if 0xC0 in parameters and len(parameters[0xC0]) == 1:
        fields["tpdu_size_exponent"] = parameters[0xC0][0]
    return S7Message(
        cotp_type="connection_request" if pdu_type == 0xE0 else "connection_confirm",
        pdu_reference=None,
        rosctr=None,
        rosctr_name=None,
        function_code=None,
        function_name=None,
        error_class=None,
        error_code=None,
        source_tsap=source.hex() if source else None,
        destination_tsap=destination.hex() if destination else None,
        rack=rack,
        slot=slot,
        fields=fields,
        payload_sha256=digest,
    )


def _parse_s7_payload(payload: bytes, digest: str, end_of_tsd_unit: bool) -> S7Message:
    if len(payload) < 10 or payload[0] != 0x32:
        raise S7ParseError("COTP data does not contain a complete S7comm header")
    rosctr = payload[1]
    header_length = 12 if rosctr in {2, 3} else 10
    if len(payload) < header_length:
        raise S7ParseError("S7comm header is truncated")
    parameter_length = int.from_bytes(payload[6:8], "big")
    data_length = int.from_bytes(payload[8:10], "big")
    expected_length = header_length + parameter_length + data_length
    if len(payload) != expected_length:
        raise S7ParseError(
            f"S7comm length mismatch: expected {expected_length}, received {len(payload)}"
        )
    parameters = payload[header_length : header_length + parameter_length]
    function = parameters[0] if parameters else None
    fields: dict[str, Any] = {
        "parameter_length": parameter_length,
        "data_length": data_length,
        "end_of_tsd_unit": end_of_tsd_unit,
        "observed_write_or_control": function in {0x05, 0x1A, 0x1B, 0x1C, 0x28, 0x29},
    }
    if function == 0xF0 and len(parameters) >= 8:
        fields.update(
            {
                "max_amq_calling": int.from_bytes(parameters[2:4], "big"),
                "max_amq_called": int.from_bytes(parameters[4:6], "big"),
                "negotiated_pdu_length": int.from_bytes(parameters[6:8], "big"),
            }
        )
    return S7Message(
        cotp_type="data",
        pdu_reference=int.from_bytes(payload[4:6], "big"),
        rosctr=rosctr,
        rosctr_name=ROSCTR_NAMES.get(rosctr, "unknown"),
        function_code=function,
        function_name=FUNCTION_NAMES.get(function, "unknown") if function is not None else None,
        error_class=payload[10] if header_length == 12 else None,
        error_code=payload[11] if header_length == 12 else None,
        source_tsap=None,
        destination_tsap=None,
        rack=None,
        slot=None,
        fields=fields,
        payload_sha256=digest,
    )


def _cotp_parameters(data: bytes) -> dict[int, bytes]:
    parameters: dict[int, bytes] = {}
    offset = 0
    while offset < len(data):
        if len(data) - offset < 2:
            raise S7ParseError("COTP parameter header is truncated")
        code = data[offset]
        length = data[offset + 1]
        value = data[offset + 2 : offset + 2 + length]
        if len(value) != length:
            raise S7ParseError("COTP parameter is truncated")
        parameters[code] = value
        offset += 2 + length
    return parameters


def _rack_slot(tsap: bytes | None) -> tuple[int | None, int | None]:
    if tsap is None or len(tsap) != 2 or tsap[0] not in {1, 2, 3}:
        return None, None
    return tsap[1] >> 5, tsap[1] & 0x1F

