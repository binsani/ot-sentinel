import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class UserRole(enum.StrEnum):
    VIEWER = "viewer"
    ADMIN = "admin"


class MatchStatus(enum.StrEnum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subject: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), unique=True)
    display_name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", values_callable=lambda e: [x.value for x in e]),
        default=UserRole.VIEWER,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("last_seen >= first_seen", name="ck_assets_seen_order"),
        CheckConstraint("criticality BETWEEN 1 AND 5", name="ck_assets_criticality"),
        UniqueConstraint("site_id", "ip_address", name="uq_assets_site_ip"),
        Index("ix_assets_last_seen", "last_seen"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    site_id: Mapped[str] = mapped_column(String(128), default="default", nullable=False)
    ip_address: Mapped[Any] = mapped_column(INET, nullable=False)
    mac_address: Mapped[Any | None] = mapped_column(MACADDR)
    hostname: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(255))
    model: Mapped[str | None] = mapped_column(String(255))
    firmware_version: Mapped[str | None] = mapped_column(String(255))
    firmware_baseline: Mapped[str | None] = mapped_column(String(255))
    firmware_baseline_set_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    firmware_baseline_set_by: Mapped[str | None] = mapped_column(String(255))
    firmware_drift_detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    protocols: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    fingerprint: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    criticality: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    observations: Mapped[list["Observation"]] = relationship(back_populates="asset")
    protocol_events: Mapped[list["ProtocolEvent"]] = relationship(back_populates="asset")
    cve_matches: Mapped[list["CveMatch"]] = relationship(back_populates="asset")


class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (
        CheckConstraint(
            "(source_port IS NULL OR source_port BETWEEN 0 AND 65535) AND "
            "(destination_port IS NULL OR destination_port BETWEEN 0 AND 65535)",
            name="ck_observation_ports",
        ),
        CheckConstraint(
            "packet_count > 0 AND byte_count >= 0", name="ck_observation_counts"
        ),
        Index("ix_observations_asset_observed", "asset_id", "observed_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    sensor_event_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), unique=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    sensor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip: Mapped[Any] = mapped_column(INET, nullable=False)
    destination_ip: Mapped[Any] = mapped_column(INET, nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(64), nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    byte_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )

    asset: Mapped[Asset] = relationship(back_populates="observations")


class ProtocolEvent(Base):
    __tablename__ = "protocol_events"
    __table_args__ = (
        CheckConstraint(
            "payload_digest IS NULL OR octet_length(payload_digest) = 32",
            name="ck_protocol_event_digest",
        ),
        Index("ix_protocol_events_asset_time", "asset_id", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    observation_id: Mapped[int | None] = mapped_column(
        ForeignKey("observations.id", ondelete="SET NULL")
    )
    protocol: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fields: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    payload_digest: Mapped[bytes | None] = mapped_column(LargeBinary(32))

    asset: Mapped[Asset] = relationship(back_populates="protocol_events")


class CveMatch(Base):
    __tablename__ = "cve_matches"
    __table_args__ = (
        UniqueConstraint("asset_id", "cve_id", name="uq_cve_matches_asset_cve"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_cve_confidence"),
        CheckConstraint(
            "cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10", name="ck_cve_cvss"
        ),
        Index("ix_cve_matches_cve_id", "cve_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[MatchStatus] = mapped_column(
        Enum(MatchStatus, name="match_status", values_callable=lambda e: [x.value for x in e]),
        default=MatchStatus.CANDIDATE,
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(nullable=False)
    cvss_score: Mapped[float | None]
    severity: Mapped[str | None] = mapped_column(String(32))
    exploitable: Mapped[bool | None]
    patch_available: Mapped[bool | None]
    matched_on: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    advisory: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    first_matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="cve_matches")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        CheckConstraint(
            "cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10",
            name="ck_vulnerability_cvss",
        ),
        Index("ix_vulnerabilities_modified_at", "modified_at"),
    )

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source_identifier: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_score: Mapped[float | None]
    severity: Mapped[str | None] = mapped_column(String(32))
    cpe_matches: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint(
            "entry_hash ~ '^[0-9a-f]{64}$' AND "
            "(previous_hash IS NULL OR previous_hash ~ '^[0-9a-f]{64}$')",
            name="ck_audit_hashes",
        ),
        Index("ix_audit_log_occurred_at", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    actor_subject: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    object_type: Mapped[str] = mapped_column(String(128), nullable=False)
    object_id: Mapped[str | None] = mapped_column(String(255))
    request_id: Mapped[str | None] = mapped_column(String(128))
    source_ip: Mapped[Any | None] = mapped_column(INET)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class AlertRule(Base):
    __tablename__ = "alert_rules"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('firmware_drift', 'vulnerability_match')",
            name="ck_alert_rules_event_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    site_id: Mapped[str | None] = mapped_column(String(128))
    webhook_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class AlertDelivery(Base):
    __tablename__ = "alert_deliveries"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'retrying', 'delivered', 'failed')",
            name="ck_alert_deliveries_status",
        ),
        Index("ix_alert_deliveries_pending", "status", "next_attempt_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alert_rules.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    response_status: Mapped[int | None] = mapped_column(Integer)
    last_error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ProbePolicy(Base):
    __tablename__ = "probe_policies"
    __table_args__ = (
        CheckConstraint("max_targets BETWEEN 1 AND 1000", name="ck_probe_max_targets"),
        CheckConstraint("rate_per_minute BETWEEN 1 AND 60", name="ck_probe_rate"),
        CheckConstraint(
            "maintenance_start_hour BETWEEN 0 AND 23 AND maintenance_end_hour BETWEEN 0 AND 23",
            name="ck_probe_maintenance_hours",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allowed_cidrs: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    protocols: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    max_targets: Mapped[int] = mapped_column(Integer, default=16, nullable=False)
    rate_per_minute: Mapped[int] = mapped_column(Integer, default=6, nullable=False)
    maintenance_start_hour: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    maintenance_end_hour: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approval_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class SiemDestination(Base):
    __tablename__ = "siem_destinations"
    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_siem_destination_port"),
        CheckConstraint(
            "minimum_severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_siem_minimum_severity",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=6514, nullable=False)
    minimum_severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class SiemDelivery(Base):
    __tablename__ = "siem_deliveries"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'retrying', 'delivered', 'failed')",
            name="ck_siem_delivery_status",
        ),
        Index("ix_siem_deliveries_pending", "status", "next_attempt_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    destination_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("siem_destinations.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
