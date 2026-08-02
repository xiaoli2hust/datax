"""add datasource usage grant generation

Revision ID: 20260802_0019
Revises: 20260802_0018
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0019"
down_revision: str | Sequence[str] | None = "20260802_0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "datasource_usage_grants",
        sa.Column("row_version", sa.BigInteger(), nullable=False, server_default="1"),
    )
    op.create_check_constraint(
        "ck_dsug_row_version",
        "datasource_usage_grants",
        "row_version >= 1",
    )
    op.alter_column("datasource_usage_grants", "row_version", server_default=None)


def downgrade() -> None:
    op.drop_constraint("ck_dsug_row_version", "datasource_usage_grants", type_="check")
    op.drop_column("datasource_usage_grants", "row_version")
