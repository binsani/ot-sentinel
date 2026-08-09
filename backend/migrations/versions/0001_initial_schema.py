"""Create the initial OT-Sentinel data model.

Revision ID: 0001
Revises: None
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE TYPE user_role AS ENUM ('viewer', 'admin')")
    op.execute("CREATE TYPE match_status AS ENUM ('candidate', 'confirmed', 'rejected')")
    op.execute(
        """
        CREATE TABLE users (
            id UUID PRIMARY KEY,
            subject VARCHAR(255) NOT NULL UNIQUE,
            email VARCHAR(320) UNIQUE,
            display_name VARCHAR(255),
            role user_role NOT NULL DEFAULT 'viewer',
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE assets (
            id UUID PRIMARY KEY,
            site_id VARCHAR(128) NOT NULL DEFAULT 'default',
            ip_address INET NOT NULL,
            mac_address MACADDR,
            hostname VARCHAR(255),
            vendor VARCHAR(255),
            model VARCHAR(255),
            firmware_version VARCHAR(255),
            protocols JSONB NOT NULL DEFAULT '[]'::jsonb,
            fingerprint JSONB NOT NULL DEFAULT '{}'::jsonb,
            criticality INTEGER NOT NULL DEFAULT 1,
            first_seen TIMESTAMPTZ NOT NULL,
            last_seen TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_assets_seen_order CHECK (last_seen >= first_seen),
            CONSTRAINT ck_assets_criticality CHECK (criticality BETWEEN 1 AND 5),
            CONSTRAINT uq_assets_site_ip UNIQUE (site_id, ip_address)
        )
        """
    )
    op.execute("CREATE INDEX ix_assets_last_seen ON assets (last_seen)")
    op.execute(
        """
        CREATE TABLE observations (
            id BIGSERIAL PRIMARY KEY,
            asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            sensor_id VARCHAR(128) NOT NULL,
            observed_at TIMESTAMPTZ NOT NULL,
            source_ip INET NOT NULL,
            destination_ip INET NOT NULL,
            source_port INTEGER,
            destination_port INTEGER,
            protocol VARCHAR(64) NOT NULL,
            packet_count INTEGER NOT NULL DEFAULT 1,
            byte_count BIGINT NOT NULL DEFAULT 0,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            CONSTRAINT ck_observation_ports CHECK (
                (source_port IS NULL OR source_port BETWEEN 0 AND 65535) AND
                (destination_port IS NULL OR destination_port BETWEEN 0 AND 65535)
            ),
            CONSTRAINT ck_observation_counts CHECK (packet_count > 0 AND byte_count >= 0)
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_observations_asset_observed ON observations (asset_id, observed_at)"
    )
    op.execute(
        """
        CREATE TABLE protocol_events (
            id BIGSERIAL PRIMARY KEY,
            asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            observation_id BIGINT REFERENCES observations(id) ON DELETE SET NULL,
            protocol VARCHAR(64) NOT NULL,
            event_type VARCHAR(128) NOT NULL,
            occurred_at TIMESTAMPTZ NOT NULL,
            fields JSONB NOT NULL DEFAULT '{}'::jsonb,
            payload_digest BYTEA,
            CONSTRAINT ck_protocol_event_digest CHECK (
                payload_digest IS NULL OR octet_length(payload_digest) = 32
            )
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_protocol_events_asset_time ON protocol_events (asset_id, occurred_at)"
    )
    op.execute(
        """
        CREATE TABLE cve_matches (
            id UUID PRIMARY KEY,
            asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            cve_id VARCHAR(32) NOT NULL,
            source VARCHAR(64) NOT NULL,
            status match_status NOT NULL DEFAULT 'candidate',
            confidence DOUBLE PRECISION NOT NULL,
            cvss_score DOUBLE PRECISION,
            severity VARCHAR(32),
            exploitable BOOLEAN,
            patch_available BOOLEAN,
            matched_on JSONB NOT NULL DEFAULT '{}'::jsonb,
            advisory JSONB NOT NULL DEFAULT '{}'::jsonb,
            first_matched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_evaluated_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT uq_cve_matches_asset_cve UNIQUE (asset_id, cve_id),
            CONSTRAINT ck_cve_confidence CHECK (confidence BETWEEN 0 AND 1),
            CONSTRAINT ck_cve_cvss CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10)
        )
        """
    )
    op.execute("CREATE INDEX ix_cve_matches_cve_id ON cve_matches (cve_id)")
    op.execute(
        """
        CREATE TABLE audit_log (
            id BIGSERIAL PRIMARY KEY,
            occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            actor_subject VARCHAR(255),
            action VARCHAR(128) NOT NULL,
            object_type VARCHAR(128) NOT NULL,
            object_id VARCHAR(255),
            request_id VARCHAR(128),
            source_ip INET,
            details JSONB NOT NULL DEFAULT '{}'::jsonb,
            previous_hash VARCHAR(64),
            entry_hash VARCHAR(64) NOT NULL,
            CONSTRAINT ck_audit_hashes CHECK (
                entry_hash ~ '^[0-9a-f]{64}$' AND
                (previous_hash IS NULL OR previous_hash ~ '^[0-9a-f]{64}$')
            )
        )
        """
    )
    op.execute("CREATE INDEX ix_audit_log_occurred_at ON audit_log (occurred_at)")
    op.execute(
        """
        CREATE FUNCTION reject_audit_log_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update_or_delete
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION reject_audit_log_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update_or_delete ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS reject_audit_log_mutation")
    op.execute("DROP TABLE IF EXISTS audit_log")
    op.execute("DROP TABLE IF EXISTS cve_matches")
    op.execute("DROP TABLE IF EXISTS protocol_events")
    op.execute("DROP TABLE IF EXISTS observations")
    op.execute("DROP TABLE IF EXISTS assets")
    op.execute("DROP TABLE IF EXISTS users")
    op.execute("DROP TYPE IF EXISTS match_status")
    op.execute("DROP TYPE IF EXISTS user_role")
