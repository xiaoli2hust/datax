"""create local lifecycle control fact

Revision ID: 20260730_0002
Revises: 20260730_0001
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260730_0002"
down_revision: str | Sequence[str] | None = "20260730_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "system_control",
        sa.Column("singleton_id", sa.SmallInteger(), nullable=False),
        sa.Column("draining", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("singleton_id"),
        sa.CheckConstraint("singleton_id = 1", name="ck_system_control_singleton"),
    )
    op.execute(
        """
        INSERT INTO system_control (singleton_id, draining, reason, updated_at)
        VALUES (1, true, 'STARTUP_RECONCILIATION_REQUIRED', CURRENT_TIMESTAMP)
        """
    )


def downgrade() -> None:
    op.drop_table("system_control")
