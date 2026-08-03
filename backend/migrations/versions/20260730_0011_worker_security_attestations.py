"""persist Worker egress and storage attestations

Revision ID: 20260730_0011
Revises: 20260730_0010
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260730_0011"
down_revision: str | Sequence[str] | None = "20260730_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NEW_HASH_COLUMNS = (
    "log_mount_identity_hash",
    "workspace_mount_identity_hash",
    "egress_policy_set_hash",
    "egress_ruleset_hash",
    "egress_evidence_hash",
)


def upgrade() -> None:
    op.drop_constraint(
        "ck_worker_heartbeats_ready_attested",
        "worker_heartbeats",
        type_="check",
    )
    op.drop_constraint(
        "ck_worker_heartbeats_status",
        "worker_heartbeats",
        type_="check",
    )
    op.create_check_constraint(
        "ck_worker_heartbeats_status",
        "worker_heartbeats",
        "status IN ("
        "'READY','BLOCKED_RUNTIME','BLOCKED_EGRESS','BLOCKED_STORAGE',"
        "'DRAINING','STOPPED')",
    )
    op.add_column(
        "worker_heartbeats",
        sa.Column(
            "storage_code",
            sa.String(length=64),
            nullable=False,
            server_default="STORAGE_UNKNOWN",
        ),
    )
    for column_name in _NEW_HASH_COLUMNS:
        op.add_column(
            "worker_heartbeats",
            sa.Column(column_name, sa.String(length=64), nullable=True),
        )
        op.create_check_constraint(
            f"ck_worker_hb_{column_name}_sha256",
            "worker_heartbeats",
            f"{column_name} IS NULL OR {column_name} ~ '^[a-f0-9]{{64}}$'",
        )
    op.add_column(
        "worker_heartbeats",
        sa.Column("log_free_bytes", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "worker_heartbeats",
        sa.Column("workspace_free_bytes", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "worker_heartbeats",
        sa.Column(
            "storage_checked_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "worker_heartbeats",
        sa.Column(
            "egress_checked_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.create_check_constraint(
        "ck_worker_hb_log_free_bytes",
        "worker_heartbeats",
        "log_free_bytes IS NULL OR log_free_bytes >= 0",
    )
    op.create_check_constraint(
        "ck_worker_hb_workspace_free_bytes",
        "worker_heartbeats",
        "workspace_free_bytes IS NULL OR workspace_free_bytes >= 0",
    )
    op.execute(
        """
        UPDATE worker_heartbeats
        SET status = 'BLOCKED_STORAGE',
            code = 'STORAGE_ATTESTATION_REQUIRED'
        WHERE status = 'READY'
        """
    )
    op.alter_column(
        "worker_heartbeats",
        "storage_code",
        server_default=None,
    )
    op.create_check_constraint(
        "ck_worker_heartbeats_ready_attested",
        "worker_heartbeats",
        "status <> 'READY' OR ("
        "code = 'WORKER_READY' "
        "AND runtime_code = 'RUNTIME_OK' "
        "AND oracle_code = 'ORACLE_OK' "
        "AND datax_release = 'datax_v202309' "
        "AND runtime_sha256 IS NOT NULL "
        "AND mysqlreader_plugin_sha256 IS NOT NULL "
        "AND postgresqlreader_plugin_sha256 IS NOT NULL "
        "AND mysqlwriter_plugin_sha256 IS NOT NULL "
        "AND postgresqlwriter_plugin_sha256 IS NOT NULL "
        "AND oracle_sha256 IS NOT NULL "
        "AND host_boot_id IS NOT NULL "
        "AND reconcile_epoch IS NOT NULL "
        "AND reconciled_at IS NOT NULL "
        "AND storage_code = 'STORAGE_OK' "
        "AND log_mount_identity_hash IS NOT NULL "
        "AND workspace_mount_identity_hash IS NOT NULL "
        "AND log_mount_identity_hash <> workspace_mount_identity_hash "
        "AND log_free_bytes IS NOT NULL "
        "AND workspace_free_bytes IS NOT NULL "
        "AND storage_checked_at IS NOT NULL "
        "AND storage_checked_at >= checked_at - INTERVAL '30 seconds' "
        "AND storage_checked_at <= checked_at + INTERVAL '2 seconds' "
        "AND egress_policy_set_hash IS NOT NULL "
        "AND egress_ruleset_hash IS NOT NULL "
        "AND egress_evidence_hash IS NOT NULL "
        "AND egress_checked_at IS NOT NULL "
        "AND egress_checked_at >= checked_at - INTERVAL '30 seconds' "
        "AND egress_checked_at <= checked_at + INTERVAL '2 seconds')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_worker_heartbeats_ready_attested",
        "worker_heartbeats",
        type_="check",
    )
    op.execute(
        """
        UPDATE worker_heartbeats
        SET status = 'BLOCKED_RUNTIME',
            code = 'STORAGE_ATTESTATION_NOT_SUPPORTED'
        WHERE status = 'BLOCKED_STORAGE'
        """
    )
    op.drop_constraint(
        "ck_worker_heartbeats_status",
        "worker_heartbeats",
        type_="check",
    )
    op.create_check_constraint(
        "ck_worker_heartbeats_status",
        "worker_heartbeats",
        "status IN ("
        "'READY','BLOCKED_RUNTIME','BLOCKED_EGRESS','DRAINING','STOPPED')",
    )
    op.drop_constraint(
        "ck_worker_hb_workspace_free_bytes",
        "worker_heartbeats",
        type_="check",
    )
    op.drop_constraint(
        "ck_worker_hb_log_free_bytes",
        "worker_heartbeats",
        type_="check",
    )
    for column_name in reversed(_NEW_HASH_COLUMNS):
        op.drop_constraint(
            f"ck_worker_hb_{column_name}_sha256",
            "worker_heartbeats",
            type_="check",
        )
    for column_name in (
        "egress_checked_at",
        "storage_checked_at",
        "workspace_free_bytes",
        "log_free_bytes",
        *_NEW_HASH_COLUMNS,
        "storage_code",
    ):
        op.drop_column("worker_heartbeats", column_name)
    op.create_check_constraint(
        "ck_worker_heartbeats_ready_attested",
        "worker_heartbeats",
        "status <> 'READY' OR ("
        "datax_release = 'datax_v202309' AND runtime_sha256 IS NOT NULL "
        "AND mysqlreader_plugin_sha256 IS NOT NULL "
        "AND postgresqlreader_plugin_sha256 IS NOT NULL "
        "AND mysqlwriter_plugin_sha256 IS NOT NULL "
        "AND postgresqlwriter_plugin_sha256 IS NOT NULL "
        "AND oracle_sha256 IS NOT NULL AND host_boot_id IS NOT NULL "
        "AND reconcile_epoch IS NOT NULL AND reconciled_at IS NOT NULL)",
    )
