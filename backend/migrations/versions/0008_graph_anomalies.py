"""Add communication baselines and new-edge anomalies.

Revision ID: 0008
Revises: 0007
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "graph_baselines",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("site_id", sa.String(128), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("captured_by", sa.String(255), nullable=False),
        sa.Column("edge_count", sa.Integer(), nullable=False),
    )
    op.create_index("ix_graph_baseline_active_site", "graph_baselines", ["site_id", "active"])
    op.create_table(
        "graph_baseline_edges",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "baseline_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("graph_baselines.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_ip", postgresql.INET(), nullable=False),
        sa.Column("destination_ip", postgresql.INET(), nullable=False),
        sa.Column("protocol", sa.String(64), nullable=False),
        sa.UniqueConstraint(
            "baseline_id", "source_ip", "destination_ip", "protocol", name="uq_baseline_edge"
        ),
    )
    op.create_table(
        "graph_anomalies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "baseline_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("graph_baselines.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("site_id", sa.String(128), nullable=False),
        sa.Column("source_ip", postgresql.INET(), nullable=False),
        sa.Column("destination_ip", postgresql.INET(), nullable=False),
        sa.Column("protocol", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_by", sa.String(255)),
        sa.UniqueConstraint(
            "baseline_id", "source_ip", "destination_ip", "protocol", name="uq_graph_anomaly"
        ),
        sa.CheckConstraint("status IN ('open', 'acknowledged')", name="ck_graph_anomaly_status"),
    )
    op.create_index("ix_graph_anomaly_status", "graph_anomalies", ["status", "last_seen"])
    op.drop_constraint("ck_alert_rules_event_type", "alert_rules", type_="check")
    op.create_check_constraint(
        "ck_alert_rules_event_type",
        "alert_rules",
        "event_type IN ('firmware_drift', 'vulnerability_match', 'communication_anomaly')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_alert_rules_event_type", "alert_rules", type_="check")
    op.create_check_constraint(
        "ck_alert_rules_event_type",
        "alert_rules",
        "event_type IN ('firmware_drift', 'vulnerability_match')",
    )
    op.drop_table("graph_anomalies")
    op.drop_table("graph_baseline_edges")
    op.drop_table("graph_baselines")
