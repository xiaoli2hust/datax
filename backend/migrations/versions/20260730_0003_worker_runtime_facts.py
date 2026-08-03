"""add worker runtime attestation facts

Revision ID: 20260730_0003
Revises: 20260730_0002
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260730_0003"
down_revision: str | Sequence[str] | None = "20260730_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "worker_heartbeats",
        sa.Column(
            "runtime_code",
            sa.String(length=64),
            nullable=False,
            server_default="RUNTIME_UNKNOWN",
        ),
    )
    op.add_column(
        "worker_heartbeats",
        sa.Column(
            "oracle_code",
            sa.String(length=64),
            nullable=False,
            server_default="ORACLE_UNKNOWN",
        ),
    )
    op.alter_column("worker_heartbeats", "runtime_code", server_default=None)
    op.alter_column("worker_heartbeats", "oracle_code", server_default=None)


def downgrade() -> None:
    op.drop_column("worker_heartbeats", "oracle_code")
    op.drop_column("worker_heartbeats", "runtime_code")
