"""persist audit-chain readiness watermarks

Revision ID: 20260802_0018
Revises: 20260802_0017
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0018"
down_revision: str | Sequence[str] | None = "20260802_0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_chain_watermarks",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("head_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("head_hash", sa.String(length=64), nullable=True),
        sa.Column("verified_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("verified_hash", sa.String(length=64), nullable=True),
        sa.Column("full_replay_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("full_replay_hash", sa.String(length=64), nullable=True),
        sa.Column("full_replay_finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("integrity_status", sa.String(length=16), nullable=False, server_default="PENDING"),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_sequence", sa.BigInteger(), nullable=True),
        sa.Column("mutation_epoch", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("head_sequence >= 0", name="ck_audit_watermark_head_sequence"),
        sa.CheckConstraint(
            "(head_sequence = 0 AND head_hash IS NULL) "
            "OR (head_sequence > 0 AND head_hash IS NOT NULL)",
            name="ck_audit_watermark_head_hash",
        ),
        sa.CheckConstraint(
            "verified_sequence >= 0 AND verified_sequence <= head_sequence",
            name="ck_audit_watermark_verified_sequence",
        ),
        sa.CheckConstraint(
            "(verified_sequence = 0 AND verified_hash IS NULL) "
            "OR (verified_sequence > 0 AND verified_hash IS NOT NULL)",
            name="ck_audit_watermark_verified_hash",
        ),
        sa.CheckConstraint(
            "full_replay_sequence >= 0 AND full_replay_sequence <= verified_sequence",
            name="ck_audit_watermark_full_replay_sequence",
        ),
        sa.CheckConstraint(
            "(full_replay_sequence = 0 AND full_replay_hash IS NULL) "
            "OR (full_replay_sequence > 0 AND full_replay_hash IS NOT NULL)",
            name="ck_audit_watermark_full_replay_hash",
        ),
        sa.CheckConstraint(
            "integrity_status IN ('PENDING', 'PASSED', 'FAILED')",
            name="ck_audit_watermark_integrity_status",
        ),
        sa.CheckConstraint("mutation_epoch >= 0", name="ck_audit_watermark_mutation_epoch"),
        sa.CheckConstraint(
            "failure_sequence IS NULL OR "
            "(failure_sequence > 0 AND failure_sequence <= head_sequence)",
            name="ck_audit_watermark_failure_sequence",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("organization_id"),
    )

    bind = op.get_bind()
    now = datetime.now(UTC)
    organization_ids = bind.execute(sa.text("SELECT id FROM organizations")).scalars()
    for organization_id in organization_ids:
        head = bind.execute(
            sa.text(
                """
                SELECT organization_sequence, event_hash
                FROM audit_events
                WHERE organization_id = :organization_id
                ORDER BY organization_sequence DESC
                LIMIT 1
                """
            ),
            {"organization_id": organization_id},
        ).mappings().one_or_none()
        bind.execute(
            sa.text(
                """
                INSERT INTO audit_chain_watermarks (
                    organization_id, head_sequence, head_hash,
                    verified_sequence, verified_hash,
                    full_replay_sequence, full_replay_hash,
                    full_replay_finished_at, integrity_status,
                    failure_code, failure_sequence, mutation_epoch, updated_at
                ) VALUES (
                    :organization_id, :head_sequence, :head_hash,
                    0, NULL, 0, NULL, NULL, 'PENDING', NULL, NULL, 0, :updated_at
                )
                """
            ),
            {
                "organization_id": organization_id,
                "head_sequence": int(head["organization_sequence"]) if head else 0,
                "head_hash": str(head["event_hash"]) if head else None,
                "updated_at": now,
            },
        )


def downgrade() -> None:
    op.drop_table("audit_chain_watermarks")
