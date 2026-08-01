"""create worker heartbeat fact

Revision ID: 20260730_0001
Revises:
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260730_0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "worker_heartbeats",
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("worker_id"),
        sa.CheckConstraint(
            "status IN ('READY', 'BLOCKED_RUNTIME', 'DRAINING', 'STOPPED')",
            name="ck_worker_heartbeats_status",
        ),
    )


def downgrade() -> None:
    op.drop_table("worker_heartbeats")
