"""add durable retention holds

Revision ID: 20260731_0014
Revises: 20260731_0013
Create Date: 2026-07-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260731_0014"
down_revision: str | Sequence[str] | None = "20260731_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "retention_holds",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_type", sa.String(length=24), nullable=False),
        sa.Column("scope_id", sa.Uuid(), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column(
            "created_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "released_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "scope_type IN ('ORGANIZATION','PROJECT','EXECUTION','AUDIT_EVENT')",
            name="ck_retention_holds_scope_type",
        ),
        sa.CheckConstraint(
            "(released_at IS NULL AND released_by IS NULL) "
            "OR (released_at IS NOT NULL AND released_by IS NOT NULL)",
            name="ck_retention_holds_release_pair",
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name="ck_retention_holds_expiry",
        ),
    )
    op.create_index(
        "ix_retention_holds_scope_active",
        "retention_holds",
        [
            "organization_id",
            "scope_type",
            "scope_id",
            "released_at",
            "expires_at",
        ],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_retention_holds_scope_active",
        table_name="retention_holds",
    )
    op.drop_table("retention_holds")
