from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ModbusObservationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID | None = None
    sensor_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(default="default", min_length=1, max_length=128)
    observed_at: datetime
    source_ip: IPv4Address | IPv6Address
    destination_ip: IPv4Address | IPv6Address
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    source_mac: str | None = Field(
        default=None, pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    )
    destination_mac: str | None = Field(
        default=None, pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    )
    transaction_id: int = Field(ge=0, le=65535)
    unit_id: int = Field(ge=0, le=255)
    function_code: int = Field(ge=0, le=255)
    is_exception: bool = False
    fields: dict[str, Any] = Field(default_factory=dict)
    byte_count: int = Field(ge=0)
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class IngestResult(BaseModel):
    asset_id: str
    observation_id: int
    protocol_event_id: int
    created_asset: bool


class Dnp3ObservationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID | None = None
    sensor_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(default="default", min_length=1, max_length=128)
    observed_at: datetime
    source_ip: IPv4Address | IPv6Address
    destination_ip: IPv4Address | IPv6Address
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    source_mac: str | None = Field(
        default=None, pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    )
    destination_mac: str | None = Field(
        default=None, pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    )
    link_source_address: int = Field(ge=0, le=65535)
    link_destination_address: int = Field(ge=0, le=65535)
    direction_from_master: bool
    link_function: int = Field(ge=0, le=15)
    transport_sequence: int | None = Field(default=None, ge=0, le=63)
    application_function: int | None = Field(default=None, ge=0, le=255)
    application_function_name: str | None = Field(default=None, max_length=128)
    application_sequence: int | None = Field(default=None, ge=0, le=15)
    internal_indications: int | None = Field(default=None, ge=0, le=65535)
    fields: dict[str, Any] = Field(default_factory=dict)
    byte_count: int = Field(ge=0)
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("observed_at")
    @classmethod
    def dnp3_observed_at_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class S7ObservationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID | None = None
    sensor_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(default="default", min_length=1, max_length=128)
    observed_at: datetime
    source_ip: IPv4Address | IPv6Address
    destination_ip: IPv4Address | IPv6Address
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    source_mac: str | None = Field(
        default=None, pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    )
    destination_mac: str | None = Field(
        default=None, pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    )
    cotp_type: str = Field(min_length=1, max_length=64)
    pdu_reference: int | None = Field(default=None, ge=0, le=65535)
    rosctr: int | None = Field(default=None, ge=0, le=255)
    rosctr_name: str | None = Field(default=None, max_length=64)
    function_code: int | None = Field(default=None, ge=0, le=255)
    function_name: str | None = Field(default=None, max_length=128)
    error_class: int | None = Field(default=None, ge=0, le=255)
    error_code: int | None = Field(default=None, ge=0, le=255)
    source_tsap: str | None = Field(default=None, pattern=r"^[0-9a-f]{4}$")
    destination_tsap: str | None = Field(default=None, pattern=r"^[0-9a-f]{4}$")
    rack: int | None = Field(default=None, ge=0, le=7)
    slot: int | None = Field(default=None, ge=0, le=31)
    fields: dict[str, Any] = Field(default_factory=dict)
    byte_count: int = Field(ge=0)
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("observed_at")
    @classmethod
    def s7_observed_at_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class OpcUaObservationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID | None = None
    sensor_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(default="default", min_length=1, max_length=128)
    observed_at: datetime
    source_ip: IPv4Address | IPv6Address
    destination_ip: IPv4Address | IPv6Address
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    source_mac: str | None = Field(
        default=None, pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    )
    destination_mac: str | None = Field(
        default=None, pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    )
    message_type: str = Field(pattern=r"^(HEL|ACK|ERR|RHE|OPN|MSG|CLO)$")
    chunk_type: str = Field(pattern=r"^[FCA]$")
    endpoint_url: str | None = Field(default=None, max_length=4096)
    security_policy_uri: str | None = Field(default=None, max_length=2048)
    secure_channel_id: int | None = Field(default=None, ge=0, le=4294967295)
    token_id: int | None = Field(default=None, ge=0, le=4294967295)
    sequence_number: int | None = Field(default=None, ge=0, le=4294967295)
    request_id: int | None = Field(default=None, ge=0, le=4294967295)
    service_node_id: int | None = Field(default=None, ge=0, le=4294967295)
    service_name: str | None = Field(default=None, max_length=128)
    fields: dict[str, Any] = Field(default_factory=dict)
    byte_count: int = Field(ge=0)
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("observed_at")
    @classmethod
    def opcua_observed_at_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value
