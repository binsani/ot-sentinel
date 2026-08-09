"""Add retry-safe sensor event identifiers.

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "observations",
        sa.Column("sensor_event_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_unique_constraint(
        "uq_observations_sensor_event_id", "observations", ["sensor_event_id"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_observations_sensor_event_id", "observations", type_="unique")
    op.drop_column("observations", "sensor_event_id")
