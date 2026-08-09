"""Add firmware baseline and drift state.

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("firmware_baseline", sa.String(255)))
    op.add_column("assets", sa.Column("firmware_baseline_set_at", sa.DateTime(timezone=True)))
    op.add_column("assets", sa.Column("firmware_baseline_set_by", sa.String(255)))
    op.add_column("assets", sa.Column("firmware_drift_detected_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("assets", "firmware_drift_detected_at")
    op.drop_column("assets", "firmware_baseline_set_by")
    op.drop_column("assets", "firmware_baseline_set_at")
    op.drop_column("assets", "firmware_baseline")
