"""add durable work termination requests

Revision ID: 20260802_0015
Revises: 20260731_0014
Create Date: 2026-08-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0015"
down_revision: str | Sequence[str] | None = "20260731_0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "work_termination_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("work_kind", sa.String(length=24), nullable=False),
        sa.Column("work_id", sa.Uuid(), nullable=False),
        sa.Column(
            "credential_secret_id",
            sa.Uuid(),
            sa.ForeignKey("credential_secrets.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "work_kind IN ('EXECUTION','RECOVERY_PROBE')",
            name="ck_work_termination_requests_work_kind",
        ),
        sa.CheckConstraint(
            "reason_code IN "
            "('TARGET_EXCLUSIVITY_REVOKED','TARGET_EXCLUSIVITY_EXPIRED',"
            "'SECRET_REVOKED','SECRET_COMPROMISED')",
            name="ck_work_termination_requests_reason",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING','ACKNOWLEDGED','COMPLETED')",
            name="ck_work_termination_requests_status",
        ),
        sa.CheckConstraint(
            "(status = 'PENDING' AND acknowledged_at IS NULL AND completed_at IS NULL) "
            "OR (status = 'ACKNOWLEDGED' AND acknowledged_at IS NOT NULL "
            "AND completed_at IS NULL) "
            "OR (status = 'COMPLETED' AND acknowledged_at IS NOT NULL "
            "AND completed_at IS NOT NULL)",
            name="ck_work_termination_requests_lifecycle",
        ),
        sa.CheckConstraint(
            "(reason_code IN ('SECRET_REVOKED','SECRET_COMPROMISED') "
            "AND credential_secret_id IS NOT NULL) "
            "OR (reason_code IN ('TARGET_EXCLUSIVITY_REVOKED',"
            "'TARGET_EXCLUSIVITY_EXPIRED') AND credential_secret_id IS NULL "
            "AND work_kind = 'EXECUTION')",
            name="ck_work_termination_requests_secret_reason",
        ),
    )
    op.create_index(
        "uq_work_termination_requests_active_target",
        "work_termination_requests",
        ["work_kind", "work_id", "reason_code"],
        unique=True,
        sqlite_where=sa.text(
            "status IN ('PENDING','ACKNOWLEDGED') AND credential_secret_id IS NULL"
        ),
        postgresql_where=sa.text(
            "status IN ('PENDING','ACKNOWLEDGED') AND credential_secret_id IS NULL"
        ),
    )
    op.create_index(
        "uq_work_termination_requests_active_secret",
        "work_termination_requests",
        ["work_kind", "work_id", "reason_code", "credential_secret_id"],
        unique=True,
        sqlite_where=sa.text(
            "status IN ('PENDING','ACKNOWLEDGED') AND credential_secret_id IS NOT NULL"
        ),
        postgresql_where=sa.text(
            "status IN ('PENDING','ACKNOWLEDGED') AND credential_secret_id IS NOT NULL"
        ),
    )
    op.create_index(
        "ix_work_termination_requests_pending",
        "work_termination_requests",
        ["status", "requested_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_work_termination_requests_pending",
        table_name="work_termination_requests",
    )
    op.drop_index(
        "uq_work_termination_requests_active_secret",
        table_name="work_termination_requests",
    )
    op.drop_index(
        "uq_work_termination_requests_active_target",
        table_name="work_termination_requests",
    )
    op.drop_table("work_termination_requests")
