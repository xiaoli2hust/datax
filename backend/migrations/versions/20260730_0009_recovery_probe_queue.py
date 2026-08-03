"""add recovery probes, Worker attestation, and persisted redacted logs

Revision ID: 20260730_0009
Revises: 20260730_0008
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260730_0009"
down_revision: str | Sequence[str] | None = "20260730_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid(name: str, *, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.Uuid(), nullable=nullable)


def _foreign_uuid(
    name: str,
    target: str,
    *,
    nullable: bool = False,
) -> sa.Column:
    return sa.Column(
        name,
        sa.Uuid(),
        sa.ForeignKey(target, ondelete="RESTRICT"),
        nullable=nullable,
    )


def upgrade() -> None:
    op.drop_constraint(
        "ck_worker_heartbeats_status",
        "worker_heartbeats",
        type_="check",
    )
    op.create_check_constraint(
        "ck_worker_heartbeats_status",
        "worker_heartbeats",
        "status IN ('READY','BLOCKED_RUNTIME','BLOCKED_EGRESS','DRAINING','STOPPED')",
    )
    for column in (
        sa.Column("datax_release", sa.String(length=32), nullable=True),
        sa.Column("runtime_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "mysqlreader_plugin_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "postgresqlreader_plugin_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "mysqlwriter_plugin_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "postgresqlwriter_plugin_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column("oracle_sha256", sa.String(length=64), nullable=True),
        sa.Column("host_boot_id", sa.String(length=128), nullable=True),
        sa.Column("reconcile_epoch", sa.Uuid(), nullable=True),
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=True),
    ):
        op.add_column("worker_heartbeats", column)
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
    op.add_column(
        "system_control",
        sa.Column("host_boot_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "system_control",
        sa.Column("reconcile_epoch", sa.Uuid(), nullable=True),
    )
    op.add_column(
        "system_control",
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "recovery_gates",
        _uuid("id"),
        _foreign_uuid("execution_id", "executions.id"),
        _foreign_uuid("project_id", "projects.id"),
        _foreign_uuid("target_namespace_id", "target_namespaces.id"),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("data_effect_at_open", sa.String(length=16), nullable=False),
        sa.Column("remediation_confirmation", sa.JSON(), nullable=True),
        sa.Column("target_empty_evidence", sa.JSON(), nullable=True),
        _uuid("latest_recovery_probe_id", nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("execution_id", name="uq_recovery_gates_execution"),
        sa.CheckConstraint(
            "status IN ('OPEN','REMEDIATION_SUBMITTED','VERIFIED','REJECTED')",
            name="ck_recovery_gates_status",
        ),
        sa.CheckConstraint(
            "data_effect_at_open IN ('NONE','POSSIBLE','CONFIRMED','UNKNOWN')",
            name="ck_recovery_gates_data_effect",
        ),
    )
    op.create_index(
        "ix_recovery_gates_namespace_status",
        "recovery_gates",
        ["target_namespace_id", "status"],
    )

    op.create_table(
        "recovery_probes",
        _uuid("id"),
        _foreign_uuid("project_id", "projects.id"),
        _foreign_uuid("recovery_gate_id", "recovery_gates.id"),
        _foreign_uuid("target_namespace_id", "target_namespaces.id"),
        _foreign_uuid(
            "target_datasource_revision_id",
            "datasource_revisions.id",
        ),
        _foreign_uuid(
            "target_endpoint_policy_revision_id",
            "endpoint_policy_revisions.id",
        ),
        _uuid("target_secret_id", nullable=True),
        _uuid("target_secret_envelope_id", nullable=True),
        sa.Column("target_secret_version", sa.Integer(), nullable=True),
        sa.Column("process_state", sa.String(length=16), nullable=False),
        sa.Column("result", sa.String(length=16), nullable=False),
        sa.Column("fence_epoch", sa.BigInteger(), nullable=False),
        _uuid("active_attempt_id", nullable=True),
        sa.Column("service_reservation_seconds", sa.Integer(), nullable=False),
        sa.Column("queue_eligibility_state", sa.String(length=16), nullable=False),
        sa.Column("queue_block_reason", sa.String(length=64), nullable=True),
        sa.Column(
            "queue_state_changed_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "eligible_wait_milliseconds",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        _uuid("target_connection_evidence_id", nullable=True),
        sa.Column("target_empty_evidence", sa.JSON(), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "process_state IN "
            "('QUEUED','STARTING','RUNNING','SUCCEEDED','FAILED','CANCELED','LOST')",
            name="ck_recovery_probes_process_state",
        ),
        sa.CheckConstraint(
            "result IN ('NOT_STARTED','EMPTY','NONEMPTY','INCONCLUSIVE')",
            name="ck_recovery_probes_result",
        ),
        sa.CheckConstraint("fence_epoch >= 0", name="ck_recovery_probes_fence"),
        sa.CheckConstraint(
            "target_secret_version IS NULL OR target_secret_version >= 1",
            name="ck_recovery_probes_secret_version",
        ),
        sa.CheckConstraint(
            "queue_eligibility_state IN ('ELIGIBLE','BLOCKED')",
            name="ck_recovery_probes_queue_eligibility",
        ),
        sa.CheckConstraint(
            "eligible_wait_milliseconds >= 0",
            name="ck_recovery_probes_wait_nonnegative",
        ),
    )
    op.create_index(
        "ix_recovery_probes_queue",
        "recovery_probes",
        ["process_state", "queued_at", "id"],
    )
    op.create_index(
        "uq_recovery_probes_gate_active",
        "recovery_probes",
        ["recovery_gate_id"],
        unique=True,
        postgresql_where=sa.text("process_state IN ('QUEUED','STARTING','RUNNING')"),
    )

    op.create_table(
        "recovery_probe_attempts",
        _uuid("id"),
        _foreign_uuid("recovery_probe_id", "recovery_probes.id"),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("lease_token_hash", sa.String(length=64), nullable=False),
        sa.Column("fence_epoch", sa.BigInteger(), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("host_boot_id", sa.String(length=128), nullable=False),
        sa.Column("cgroup_identity", sa.String(length=256), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("termination_reason", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "recovery_probe_id",
            "attempt_no",
            name="uq_recovery_probe_attempts_number",
        ),
        sa.UniqueConstraint(
            "recovery_probe_id",
            "fence_epoch",
            name="uq_recovery_probe_attempts_fence",
        ),
        sa.CheckConstraint(
            "attempt_no >= 1",
            name="ck_recovery_probe_attempts_number",
        ),
        sa.CheckConstraint(
            "fence_epoch >= 1",
            name="ck_recovery_probe_attempts_fence",
        ),
    )
    op.create_foreign_key(
        "fk_recovery_gates_latest_probe",
        "recovery_gates",
        "recovery_probes",
        ["latest_recovery_probe_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_recovery_probes_active_attempt",
        "recovery_probes",
        "recovery_probe_attempts",
        ["active_attempt_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_endpoint_evidence_recovery_probe",
        "endpoint_connection_evidences",
        "recovery_probes",
        ["recovery_probe_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_table(
        "execution_log_chunks",
        _uuid("id"),
        _foreign_uuid("execution_id", "executions.id"),
        _foreign_uuid("attempt_id", "execution_attempts.id"),
        sa.Column("chunk_no", sa.Integer(), nullable=False),
        sa.Column("first_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_sequence", sa.BigInteger(), nullable=False),
        sa.Column("storage_key", sa.String(length=500), nullable=False),
        sa.Column("byte_size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "redaction_rules_version",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "contains_truncated_line",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column("raw_received_bytes", sa.BigInteger(), nullable=False),
        sa.Column(
            "redacted_received_bytes",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column("stored_bytes", sa.BigInteger(), nullable=False),
        sa.Column("dropped_bytes", sa.BigInteger(), nullable=False),
        sa.Column("body_available", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "execution_id",
            "attempt_id",
            "chunk_no",
            name="uq_execution_log_chunks_attempt_number",
        ),
        sa.CheckConstraint(
            "chunk_no >= 1 AND first_sequence >= 1 AND last_sequence >= first_sequence",
            name="ck_execution_log_chunks_sequence",
        ),
        sa.CheckConstraint(
            "byte_size >= 0 AND raw_received_bytes >= 0 "
            "AND redacted_received_bytes >= 0 AND stored_bytes >= 0 "
            "AND dropped_bytes >= 0",
            name="ck_execution_log_chunks_nonnegative",
        ),
        sa.CheckConstraint(
            "byte_size = stored_bytes AND dropped_bytes = redacted_received_bytes - stored_bytes",
            name="ck_execution_log_chunks_accounting",
        ),
        sa.CheckConstraint(
            "(body_available AND deleted_at IS NULL) "
            "OR (NOT body_available AND deleted_at IS NOT NULL)",
            name="ck_execution_log_chunks_body_lifecycle",
        ),
    )
    op.create_index(
        "ix_execution_log_chunks_execution_sequence",
        "execution_log_chunks",
        ["execution_id", "first_sequence", "last_sequence"],
    )
    op.create_table(
        "execution_log_gaps",
        _uuid("id"),
        _foreign_uuid("execution_id", "executions.id"),
        _foreign_uuid("attempt_id", "execution_attempts.id"),
        sa.Column("gap_no", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=32), nullable=False),
        sa.Column("after_sequence", sa.BigInteger(), nullable=True),
        sa.Column("before_sequence", sa.BigInteger(), nullable=True),
        sa.Column("raw_received_bytes", sa.BigInteger(), nullable=False),
        sa.Column(
            "redacted_received_bytes",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column("stored_bytes", sa.BigInteger(), nullable=False),
        sa.Column("dropped_bytes", sa.BigInteger(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "execution_id",
            "attempt_id",
            "gap_no",
            name="uq_execution_log_gaps_attempt_number",
        ),
        sa.CheckConstraint(
            "gap_no >= 1",
            name="ck_execution_log_gaps_number",
        ),
        sa.CheckConstraint(
            "reason IN "
            "('LINE_LIMIT','EXECUTION_LIMIT','RING_EVICTION','SOURCE_READ_ERROR',"
            "'DECODE_ERROR','REDACTION_FAILURE','STORAGE_FAILURE','FENCE_LOST')",
            name="ck_execution_log_gaps_reason",
        ),
        sa.CheckConstraint(
            "(after_sequence IS NULL OR after_sequence >= 1) "
            "AND (before_sequence IS NULL OR before_sequence >= 1)",
            name="ck_execution_log_gaps_boundaries",
        ),
        sa.CheckConstraint(
            "raw_received_bytes >= 0 AND redacted_received_bytes >= 0 "
            "AND stored_bytes >= 0 AND dropped_bytes >= 0",
            name="ck_execution_log_gaps_nonnegative",
        ),
        sa.CheckConstraint(
            "dropped_bytes = redacted_received_bytes - stored_bytes",
            name="ck_execution_log_gaps_accounting",
        ),
    )
    op.create_index(
        "ix_execution_log_gaps_execution_number",
        "execution_log_gaps",
        ["execution_id", "gap_no"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_execution_log_gaps_execution_number",
        table_name="execution_log_gaps",
    )
    op.drop_table("execution_log_gaps")
    op.drop_index(
        "ix_execution_log_chunks_execution_sequence",
        table_name="execution_log_chunks",
    )
    op.drop_table("execution_log_chunks")
    op.drop_constraint(
        "fk_endpoint_evidence_recovery_probe",
        "endpoint_connection_evidences",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_recovery_probes_active_attempt",
        "recovery_probes",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_recovery_gates_latest_probe",
        "recovery_gates",
        type_="foreignkey",
    )
    op.drop_table("recovery_probe_attempts")
    op.drop_index(
        "uq_recovery_probes_gate_active",
        table_name="recovery_probes",
    )
    op.drop_index("ix_recovery_probes_queue", table_name="recovery_probes")
    op.drop_table("recovery_probes")
    op.drop_index(
        "ix_recovery_gates_namespace_status",
        table_name="recovery_gates",
    )
    op.drop_table("recovery_gates")
    op.drop_column("system_control", "reconciled_at")
    op.drop_column("system_control", "reconcile_epoch")
    op.drop_column("system_control", "host_boot_id")
    op.drop_constraint(
        "ck_worker_heartbeats_ready_attested",
        "worker_heartbeats",
        type_="check",
    )
    for column_name in (
        "reconciled_at",
        "reconcile_epoch",
        "host_boot_id",
        "oracle_sha256",
        "postgresqlwriter_plugin_sha256",
        "mysqlwriter_plugin_sha256",
        "postgresqlreader_plugin_sha256",
        "mysqlreader_plugin_sha256",
        "runtime_sha256",
        "datax_release",
    ):
        op.drop_column("worker_heartbeats", column_name)
    op.drop_constraint(
        "ck_worker_heartbeats_status",
        "worker_heartbeats",
        type_="check",
    )
    op.create_check_constraint(
        "ck_worker_heartbeats_status",
        "worker_heartbeats",
        "status IN ('READY','BLOCKED_RUNTIME','DRAINING','STOPPED')",
    )
