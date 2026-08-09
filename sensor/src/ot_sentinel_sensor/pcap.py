from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, Ether, IPv6, PcapReader, Raw  # type: ignore[import-untyped]

from ot_sentinel_sensor.dnp3 import Dnp3ParseError, parse_dnp3_frame, split_dnp3_stream
from ot_sentinel_sensor.modbus import (
    ModbusParseError,
    parse_modbus_tcp,
    split_modbus_tcp_stream,
)
from ot_sentinel_sensor.opcua import OpcUaParseError, parse_opcua_tcp, split_opcua_stream
from ot_sentinel_sensor.s7comm import S7ParseError, parse_s7comm_tpkt, split_tpkt_stream


def observations_from_pcap(
    path: Path, *, sensor_id: str, site_id: str = "default"
) -> Iterator[dict[str, Any]]:
    """Read an existing capture only; this function never opens a live interface."""
    streams: dict[tuple[str, int, str, int], tuple[int, bytes]] = {}
    with PcapReader(str(path)) as packets:
        for packet in packets:
            if TCP not in packet or Raw not in packet:
                continue
            tcp = packet[TCP]
            if tcp.sport != 502 and tcp.dport != 502:
                continue
            network = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
            if network is None:
                continue
            payload = bytes(packet[Raw])
            flow = (network.src, tcp.sport, network.dst, tcp.dport)
            sequence = int(tcp.seq)
            previous_sequence, buffered = streams.get(flow, (sequence, b""))
            expected_sequence = previous_sequence + len(buffered)
            if buffered and sequence != expected_sequence:
                # A gap or out-of-order segment invalidates the partial application frame.
                buffered = b""
            stream_data = buffered + payload
            try:
                frames, remainder = split_modbus_tcp_stream(stream_data)
            except ModbusParseError:
                streams.pop(flow, None)
                continue
            streams[flow] = (sequence + len(payload) - len(remainder), remainder)
            for frame in frames:
                try:
                    message = parse_modbus_tcp(frame, is_response=tcp.sport == 502)
                except ModbusParseError:
                    continue
                yield {
                    "sensor_id": sensor_id,
                    "site_id": site_id,
                    "observed_at": datetime.fromtimestamp(
                        float(packet.time), UTC
                    ).isoformat(),
                    "source_ip": network.src,
                    "destination_ip": network.dst,
                    "source_port": tcp.sport,
                    "destination_port": tcp.dport,
                    "source_mac": packet[Ether].src if Ether in packet else None,
                    "destination_mac": packet[Ether].dst if Ether in packet else None,
                    "transaction_id": message.transaction_id,
                    "unit_id": message.unit_id,
                    "function_code": message.function_code,
                    "is_exception": message.is_exception,
                    "fields": {"function_name": message.function_name, **message.fields},
                    "byte_count": len(frame),
                    "payload_sha256": message.payload_sha256,
                }


def dnp3_observations_from_pcap(
    path: Path, *, sensor_id: str, site_id: str = "default"
) -> Iterator[dict[str, Any]]:
    """Read DNP3/TCP from an existing capture without opening a live interface."""
    streams: dict[tuple[str, int, str, int], tuple[int, bytes]] = {}
    with PcapReader(str(path)) as packets:
        for packet in packets:
            if TCP not in packet or Raw not in packet:
                continue
            tcp = packet[TCP]
            if tcp.sport != 20000 and tcp.dport != 20000:
                continue
            network = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
            if network is None:
                continue
            payload = bytes(packet[Raw])
            flow = (network.src, tcp.sport, network.dst, tcp.dport)
            sequence = int(tcp.seq)
            previous_sequence, buffered = streams.get(flow, (sequence, b""))
            expected_sequence = previous_sequence + len(buffered)
            if buffered and sequence != expected_sequence:
                buffered = b""
            try:
                frames, remainder = split_dnp3_stream(buffered + payload)
            except Dnp3ParseError:
                streams.pop(flow, None)
                continue
            streams[flow] = (sequence + len(payload) - len(remainder), remainder)
            for raw_frame in frames:
                try:
                    frame = parse_dnp3_frame(raw_frame)
                except Dnp3ParseError:
                    continue
                yield {
                    "sensor_id": sensor_id,
                    "site_id": site_id,
                    "observed_at": datetime.fromtimestamp(
                        float(packet.time), UTC
                    ).isoformat(),
                    "source_ip": network.src,
                    "destination_ip": network.dst,
                    "source_port": tcp.sport,
                    "destination_port": tcp.dport,
                    "source_mac": packet[Ether].src if Ether in packet else None,
                    "destination_mac": packet[Ether].dst if Ether in packet else None,
                    "link_source_address": frame.source_address,
                    "link_destination_address": frame.destination_address,
                    "direction_from_master": frame.direction_from_master,
                    "link_function": frame.link_function,
                    "transport_sequence": frame.transport_sequence,
                    "application_function": frame.application_function,
                    "application_function_name": frame.application_function_name,
                    "application_sequence": frame.application_sequence,
                    "internal_indications": frame.internal_indications,
                    "fields": frame.fields,
                    "byte_count": len(raw_frame),
                    "payload_sha256": frame.payload_sha256,
                }


def s7_observations_from_pcap(
    path: Path, *, sensor_id: str, site_id: str = "default"
) -> Iterator[dict[str, Any]]:
    """Read RFC 1006/S7comm from an existing capture without live capture."""
    streams: dict[tuple[str, int, str, int], tuple[int, bytes]] = {}
    with PcapReader(str(path)) as packets:
        for packet in packets:
            if TCP not in packet or Raw not in packet:
                continue
            tcp = packet[TCP]
            if tcp.sport != 102 and tcp.dport != 102:
                continue
            network = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
            if network is None:
                continue
            payload = bytes(packet[Raw])
            flow = (network.src, tcp.sport, network.dst, tcp.dport)
            sequence = int(tcp.seq)
            previous_sequence, buffered = streams.get(flow, (sequence, b""))
            if buffered and sequence != previous_sequence + len(buffered):
                buffered = b""
            try:
                frames, remainder = split_tpkt_stream(buffered + payload)
            except S7ParseError:
                streams.pop(flow, None)
                continue
            streams[flow] = (sequence + len(payload) - len(remainder), remainder)
            for raw_frame in frames:
                try:
                    message = parse_s7comm_tpkt(raw_frame)
                except S7ParseError:
                    continue
                yield {
                    "sensor_id": sensor_id,
                    "site_id": site_id,
                    "observed_at": datetime.fromtimestamp(
                        float(packet.time), UTC
                    ).isoformat(),
                    "source_ip": network.src,
                    "destination_ip": network.dst,
                    "source_port": tcp.sport,
                    "destination_port": tcp.dport,
                    "source_mac": packet[Ether].src if Ether in packet else None,
                    "destination_mac": packet[Ether].dst if Ether in packet else None,
                    "cotp_type": message.cotp_type,
                    "pdu_reference": message.pdu_reference,
                    "rosctr": message.rosctr,
                    "rosctr_name": message.rosctr_name,
                    "function_code": message.function_code,
                    "function_name": message.function_name,
                    "error_class": message.error_class,
                    "error_code": message.error_code,
                    "source_tsap": message.source_tsap,
                    "destination_tsap": message.destination_tsap,
                    "rack": message.rack,
                    "slot": message.slot,
                    "fields": message.fields,
                    "byte_count": len(raw_frame),
                    "payload_sha256": message.payload_sha256,
                }


def opcua_observations_from_pcap(
    path: Path, *, sensor_id: str, site_id: str = "default"
) -> Iterator[dict[str, Any]]:
    """Read OPC UA TCP metadata without decrypting or opening a live interface."""
    streams: dict[tuple[str, int, str, int], tuple[int, bytes]] = {}
    none_channels: set[tuple[tuple[tuple[str, int], tuple[str, int]], int]] = set()
    with PcapReader(str(path)) as packets:
        for packet in packets:
            if TCP not in packet or Raw not in packet:
                continue
            tcp = packet[TCP]
            if tcp.sport != 4840 and tcp.dport != 4840:
                continue
            network = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
            if network is None:
                continue
            payload = bytes(packet[Raw])
            flow = (network.src, tcp.sport, network.dst, tcp.dport)
            connection = tuple(sorted(((network.src, tcp.sport), (network.dst, tcp.dport))))
            sequence = int(tcp.seq)
            previous_sequence, buffered = streams.get(flow, (sequence, b""))
            if buffered and sequence != previous_sequence + len(buffered):
                buffered = b""
            try:
                frames, remainder = split_opcua_stream(buffered + payload)
            except OpcUaParseError:
                streams.pop(flow, None)
                continue
            streams[flow] = (sequence + len(payload) - len(remainder), remainder)
            for raw_message in frames:
                channel_id = (
                    int.from_bytes(raw_message[8:12], "little")
                    if raw_message[:3] in {b"OPN", b"MSG", b"CLO"}
                    and len(raw_message) >= 12
                    else 0
                )
                try:
                    message = parse_opcua_tcp(
                        raw_message,
                        security_policy_none=(connection, channel_id) in none_channels,
                    )
                except OpcUaParseError:
                    continue
                if (
                    message.message_type == "OPN"
                    and message.security_policy_uri
                    == "http://opcfoundation.org/UA/SecurityPolicy#None"
                    and message.secure_channel_id is not None
                ):
                    none_channels.add((connection, message.secure_channel_id))
                yield {
                    "sensor_id": sensor_id,
                    "site_id": site_id,
                    "observed_at": datetime.fromtimestamp(
                        float(packet.time), UTC
                    ).isoformat(),
                    "source_ip": network.src,
                    "destination_ip": network.dst,
                    "source_port": tcp.sport,
                    "destination_port": tcp.dport,
                    "source_mac": packet[Ether].src if Ether in packet else None,
                    "destination_mac": packet[Ether].dst if Ether in packet else None,
                    "message_type": message.message_type,
                    "chunk_type": message.chunk_type,
                    "endpoint_url": message.endpoint_url,
                    "security_policy_uri": message.security_policy_uri,
                    "secure_channel_id": message.secure_channel_id,
                    "token_id": message.token_id,
                    "sequence_number": message.sequence_number,
                    "request_id": message.request_id,
                    "service_node_id": message.service_node_id,
                    "service_name": message.service_name,
                    "fields": message.fields,
                    "byte_count": len(raw_message),
                    "payload_sha256": message.payload_sha256,
                }
