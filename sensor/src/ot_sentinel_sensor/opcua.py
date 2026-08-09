import hashlib
from dataclasses import dataclass
from typing import Any


class OpcUaParseError(ValueError):
    """Raised when OPC UA TCP framing or cleartext metadata is invalid."""


SERVICE_NAMES = {
    420: "find_servers_request",
    423: "find_servers_response",
    426: "get_endpoints_request",
    429: "get_endpoints_response",
    446: "open_secure_channel_request",
    449: "open_secure_channel_response",
    452: "close_secure_channel_request",
    455: "close_secure_channel_response",
    461: "create_session_request",
    464: "create_session_response",
    467: "activate_session_request",
    470: "activate_session_response",
    473: "close_session_request",
    476: "close_session_response",
    527: "browse_request",
    530: "browse_response",
    533: "browse_next_request",
    536: "browse_next_response",
    631: "read_request",
    634: "read_response",
    673: "write_request",
    676: "write_response",
}
MAX_CAPTURE_MESSAGE_SIZE = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class OpcUaMessage:
    message_type: str
    chunk_type: str
    endpoint_url: str | None
    security_policy_uri: str | None
    secure_channel_id: int | None
    token_id: int | None
    sequence_number: int | None
    request_id: int | None
    service_node_id: int | None
    service_name: str | None
    fields: dict[str, Any]
    payload_sha256: str


def parse_opcua_tcp(packet: bytes, *, security_policy_none: bool = False) -> OpcUaMessage:
    if len(packet) < 8:
        raise OpcUaParseError("OPC UA TCP message is shorter than its header")
    try:
        message_type = packet[:3].decode("ascii")
        chunk_type = chr(packet[3])
    except (UnicodeDecodeError, ValueError):
        raise OpcUaParseError("OPC UA TCP message header is not ASCII") from None
    if message_type not in {"HEL", "ACK", "ERR", "RHE", "OPN", "MSG", "CLO"}:
        raise OpcUaParseError("unknown OPC UA TCP message type")
    if chunk_type not in {"F", "C", "A"}:
        raise OpcUaParseError("invalid OPC UA TCP chunk type")
    message_size = int.from_bytes(packet[4:8], "little")
    if message_size > MAX_CAPTURE_MESSAGE_SIZE:
        raise OpcUaParseError("OPC UA TCP message exceeds the sensor safety limit")
    if message_size != len(packet):
        raise OpcUaParseError(
            f"OPC UA TCP length mismatch: expected {message_size}, received {len(packet)}"
        )
    body = packet[8:]
    digest = hashlib.sha256(packet).hexdigest()
    if message_type == "HEL":
        return _parse_hello(body, message_type, chunk_type, digest)
    if message_type == "ACK":
        return _parse_ack(body, message_type, chunk_type, digest)
    if message_type == "RHE":
        return _parse_reverse_hello(body, message_type, chunk_type, digest)
    if message_type == "ERR":
        return _parse_error(body, message_type, chunk_type, digest)
    if message_type == "OPN":
        return _parse_open_secure_channel(body, chunk_type, digest)
    if message_type in {"MSG", "CLO"}:
        return _parse_symmetric_message(
            body, message_type, chunk_type, digest, security_policy_none
        )
    raise OpcUaParseError("unsupported OPC UA TCP message")


def split_opcua_stream(data: bytes) -> tuple[list[bytes], bytes]:
    messages: list[bytes] = []
    offset = 0
    while len(data) - offset >= 8:
        try:
            message_type = data[offset : offset + 3].decode("ascii")
        except UnicodeDecodeError:
            raise OpcUaParseError("invalid OPC UA message type in TCP stream") from None
        if message_type not in {"HEL", "ACK", "ERR", "RHE", "OPN", "MSG", "CLO"}:
            raise OpcUaParseError("unknown OPC UA message type in TCP stream")
        size = int.from_bytes(data[offset + 4 : offset + 8], "little")
        if size < 8:
            raise OpcUaParseError("invalid OPC UA message size in TCP stream")
        if size > MAX_CAPTURE_MESSAGE_SIZE:
            raise OpcUaParseError("OPC UA message exceeds the sensor safety limit")
        if len(data) - offset < size:
            break
        messages.append(data[offset : offset + size])
        offset += size
    return messages, data[offset:]


def _parse_hello(body: bytes, message_type: str, chunk_type: str, digest: str) -> OpcUaMessage:
    if len(body) < 20:
        raise OpcUaParseError("OPC UA Hello body is truncated")
    fields = _limits(body)
    endpoint, offset = _ua_string(body, 20)
    _validate_url_size(endpoint)
    if offset != len(body):
        raise OpcUaParseError("OPC UA Hello contains trailing bytes")
    return _message(message_type, chunk_type, digest, endpoint_url=endpoint, fields=fields)


def _parse_ack(body: bytes, message_type: str, chunk_type: str, digest: str) -> OpcUaMessage:
    if len(body) != 20:
        raise OpcUaParseError("OPC UA Acknowledge body must be 20 bytes")
    return _message(message_type, chunk_type, digest, fields=_limits(body))


def _parse_reverse_hello(
    body: bytes, message_type: str, chunk_type: str, digest: str
) -> OpcUaMessage:
    server_uri, offset = _ua_string(body, 0)
    endpoint, offset = _ua_string(body, offset)
    _validate_url_size(server_uri)
    _validate_url_size(endpoint)
    if offset != len(body):
        raise OpcUaParseError("OPC UA ReverseHello contains trailing bytes")
    return _message(
        message_type,
        chunk_type,
        digest,
        endpoint_url=endpoint,
        fields={"server_uri": server_uri},
    )


def _parse_error(body: bytes, message_type: str, chunk_type: str, digest: str) -> OpcUaMessage:
    if len(body) < 4:
        raise OpcUaParseError("OPC UA Error body is truncated")
    reason, offset = _ua_string(body, 4)
    if offset != len(body):
        raise OpcUaParseError("OPC UA Error contains trailing bytes")
    return _message(
        message_type,
        chunk_type,
        digest,
        fields={"status_code": int.from_bytes(body[:4], "little"), "reason": reason},
    )


def _parse_open_secure_channel(body: bytes, chunk_type: str, digest: str) -> OpcUaMessage:
    if len(body) < 4:
        raise OpcUaParseError("OpenSecureChannel body is truncated")
    channel_id = int.from_bytes(body[:4], "little")
    policy, offset = _ua_string(body, 4)
    _, offset = _byte_string(body, offset)
    _, offset = _byte_string(body, offset)
    fields: dict[str, Any] = {"payload_encrypted_or_signed": policy != _none_policy()}
    sequence = request_id = service_id = None
    service_name = None
    if policy == _none_policy():
        if len(body) - offset < 8:
            raise OpcUaParseError("OpenSecureChannel sequence header is truncated")
        sequence = int.from_bytes(body[offset : offset + 4], "little")
        request_id = int.from_bytes(body[offset + 4 : offset + 8], "little")
        service_id, _ = _numeric_node_id(body, offset + 8)
        service_name = SERVICE_NAMES.get(service_id, "unknown")
    return _message(
        "OPN",
        chunk_type,
        digest,
        security_policy_uri=policy,
        secure_channel_id=channel_id,
        sequence_number=sequence,
        request_id=request_id,
        service_node_id=service_id,
        service_name=service_name,
        fields=fields,
    )


def _parse_symmetric_message(
    body: bytes,
    message_type: str,
    chunk_type: str,
    digest: str,
    security_policy_none: bool,
) -> OpcUaMessage:
    if len(body) < 8:
        raise OpcUaParseError("OPC UA symmetric security header is truncated")
    channel_id = int.from_bytes(body[:4], "little")
    token_id = int.from_bytes(body[4:8], "little")
    if not security_policy_none:
        return _message(
            message_type,
            chunk_type,
            digest,
            secure_channel_id=channel_id,
            token_id=token_id,
            fields={"payload_encrypted_or_signed": True},
        )
    if len(body) < 16:
        raise OpcUaParseError("OPC UA sequence header is truncated")
    sequence = int.from_bytes(body[8:12], "little")
    request_id = int.from_bytes(body[12:16], "little")
    if chunk_type != "F":
        return _message(
            message_type,
            chunk_type,
            digest,
            secure_channel_id=channel_id,
            token_id=token_id,
            sequence_number=sequence,
            request_id=request_id,
            fields={"payload_encrypted_or_signed": False, "continuation_chunk": True},
        )
    service_id, _ = _numeric_node_id(body, 16)
    return _message(
        message_type,
        chunk_type,
        digest,
        secure_channel_id=channel_id,
        token_id=token_id,
        sequence_number=sequence,
        request_id=request_id,
        service_node_id=service_id,
        service_name=SERVICE_NAMES.get(service_id, "unknown"),
        fields={"payload_encrypted_or_signed": False},
    )


def _limits(body: bytes) -> dict[str, int]:
    return {
        "protocol_version": int.from_bytes(body[0:4], "little"),
        "receive_buffer_size": int.from_bytes(body[4:8], "little"),
        "send_buffer_size": int.from_bytes(body[8:12], "little"),
        "max_message_size": int.from_bytes(body[12:16], "little"),
        "max_chunk_count": int.from_bytes(body[16:20], "little"),
    }


def _ua_string(data: bytes, offset: int) -> tuple[str | None, int]:
    raw, offset = _byte_string(data, offset)
    if raw is None:
        return None, offset
    try:
        return raw.decode("utf-8"), offset
    except UnicodeDecodeError:
        raise OpcUaParseError("OPC UA String is not valid UTF-8") from None


def _byte_string(data: bytes, offset: int) -> tuple[bytes | None, int]:
    if len(data) - offset < 4:
        raise OpcUaParseError("OPC UA length-prefixed field is truncated")
    length = int.from_bytes(data[offset : offset + 4], "little", signed=True)
    offset += 4
    if length == -1:
        return None, offset
    if length < -1 or len(data) - offset < length:
        raise OpcUaParseError("OPC UA length-prefixed field has an invalid length")
    return data[offset : offset + length], offset + length


def _numeric_node_id(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise OpcUaParseError("OPC UA service NodeId is missing")
    encoding = data[offset]
    form = encoding & 0x3F
    if encoding & 0xC0:
        raise OpcUaParseError("expanded service NodeIds are not supported")
    if form == 0x00 and len(data) - offset >= 2:
        return data[offset + 1], offset + 2
    if form == 0x01 and len(data) - offset >= 4:
        namespace = data[offset + 1]
        if namespace != 0:
            raise OpcUaParseError("service NodeId must use namespace zero")
        return int.from_bytes(data[offset + 2 : offset + 4], "little"), offset + 4
    if form == 0x02 and len(data) - offset >= 7:
        namespace = int.from_bytes(data[offset + 1 : offset + 3], "little")
        if namespace != 0:
            raise OpcUaParseError("service NodeId must use namespace zero")
        return int.from_bytes(data[offset + 3 : offset + 7], "little"), offset + 7
    raise OpcUaParseError("unsupported or truncated OPC UA service NodeId")


def _message(
    message_type: str,
    chunk_type: str,
    digest: str,
    *,
    endpoint_url: str | None = None,
    security_policy_uri: str | None = None,
    secure_channel_id: int | None = None,
    token_id: int | None = None,
    sequence_number: int | None = None,
    request_id: int | None = None,
    service_node_id: int | None = None,
    service_name: str | None = None,
    fields: dict[str, Any] | None = None,
) -> OpcUaMessage:
    return OpcUaMessage(
        message_type=message_type,
        chunk_type=chunk_type,
        endpoint_url=endpoint_url,
        security_policy_uri=security_policy_uri,
        secure_channel_id=secure_channel_id,
        token_id=token_id,
        sequence_number=sequence_number,
        request_id=request_id,
        service_node_id=service_node_id,
        service_name=service_name,
        fields=fields or {},
        payload_sha256=digest,
    )


def _none_policy() -> str:
    return "http://opcfoundation.org/UA/SecurityPolicy#None"


def _validate_url_size(value: str | None) -> None:
    if value is not None and len(value.encode("utf-8")) > 4096:
        raise OpcUaParseError("OPC UA URI exceeds the 4096-byte protocol limit")
