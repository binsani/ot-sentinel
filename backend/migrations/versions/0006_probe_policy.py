"""Add fail-closed active probing policies.

Revision ID: 0006
Revises: 0005
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "probe_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("site_id", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("allowed_cidrs", postgresql.JSONB(), nullable=False),
        sa.Column("protocols", postgresql.JSONB(), nullable=False),
        sa.Column("max_targets", sa.Integer(), nullable=False, server_default="16"),
        sa.Column("rate_per_minute", sa.Integer(), nullable=False, server_default="6"),
        sa.Column("maintenance_start_hour", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("maintenance_end_hour", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("approved_by", sa.String(255)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("approval_expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("max_targets BETWEEN 1 AND 1000", name="ck_probe_max_targets"),
        sa.CheckConstraint("rate_per_minute BETWEEN 1 AND 60", name="ck_probe_rate"),
        sa.CheckConstraint(
            "maintenance_start_hour BETWEEN 0 AND 23 AND maintenance_end_hour BETWEEN 0 AND 23",
            name="ck_probe_maintenance_hours",
        ),
    )


def downgrade() -> None:
    op.drop_table("probe_policies")
