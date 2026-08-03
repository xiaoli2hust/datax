from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from datax_studio.auth.db import Base


class RecoveryGate(Base):
    __tablename__ = "recovery_gates"
    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN','REMEDIATION_SUBMITTED','VERIFIED','REJECTED')",
            name="ck_recovery_gates_status",
        ),
        CheckConstraint(
            "data_effect_at_open IN ('NONE','POSSIBLE','CONFIRMED','UNKNOWN')",
            name="ck_recovery_gates_data_effect",
        ),
        UniqueConstraint("execution_id", name="uq_recovery_gates_execution"),
        Index("ix_recovery_gates_namespace_status", "target_namespace_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("executions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    project_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_namespace_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("target_namespaces.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    data_effect_at_open: Mapped[str] = mapped_column(String(16), nullable=False)
    remediation_confirmation: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    target_empty_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    latest_recovery_probe_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reason_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RecoveryProbe(Base):
    __tablename__ = "recovery_probes"
    __table_args__ = (
        CheckConstraint(
            "process_state IN "
            "('QUEUED','STARTING','RUNNING','SUCCEEDED','FAILED','CANCELED','LOST')",
            name="ck_recovery_probes_process_state",
        ),
        CheckConstraint(
            "result IN ('NOT_STARTED','EMPTY','NONEMPTY','INCONCLUSIVE')",
            name="ck_recovery_probes_result",
        ),
        CheckConstraint("fence_epoch >= 0", name="ck_recovery_probes_fence"),
        CheckConstraint(
            "target_secret_version IS NULL OR target_secret_version >= 1",
            name="ck_recovery_probes_secret_version",
        ),
        CheckConstraint(
            "queue_eligibility_state IN ('ELIGIBLE','BLOCKED')",
            name="ck_recovery_probes_queue_eligibility",
        ),
        CheckConstraint(
            "eligible_wait_milliseconds >= 0",
            name="ck_recovery_probes_wait_nonnegative",
        ),
        Index(
            "ix_recovery_probes_queue",
            "process_state",
            "queued_at",
            "id",
        ),
        Index(
            "uq_recovery_probes_gate_active",
            "recovery_gate_id",
            unique=True,
            sqlite_where=text("process_state IN ('QUEUED','STARTING','RUNNING')"),
            postgresql_where=text("process_state IN ('QUEUED','STARTING','RUNNING')"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    recovery_gate_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("recovery_gates.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_namespace_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("target_namespaces.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_datasource_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasource_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_endpoint_policy_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("endpoint_policy_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_secret_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    target_secret_envelope_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    target_secret_version: Mapped[int | None] = mapped_column(Integer)
    process_state: Mapped[str] = mapped_column(String(16), nullable=False)
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    fence_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    active_attempt_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    service_reservation_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=360,
    )
    queue_eligibility_state: Mapped[str] = mapped_column(String(16), nullable=False)
    queue_block_reason: Mapped[str | None] = mapped_column(String(64))
    queue_state_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    eligible_wait_milliseconds: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    target_connection_evidence_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    target_empty_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    failure_code: Mapped[str | None] = mapped_column(String(64))


class RecoveryProbeAttempt(Base):
    __tablename__ = "recovery_probe_attempts"
    __table_args__ = (
        CheckConstraint("attempt_no >= 1", name="ck_recovery_probe_attempts_number"),
        CheckConstraint("fence_epoch >= 1", name="ck_recovery_probe_attempts_fence"),
        UniqueConstraint(
            "recovery_probe_id",
            "attempt_no",
            name="uq_recovery_probe_attempts_number",
        ),
        UniqueConstraint(
            "recovery_probe_id",
            "fence_epoch",
            name="uq_recovery_probe_attempts_fence",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    recovery_probe_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("recovery_probes.id", ondelete="RESTRICT"),
        nullable=False,
    )
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False)
    lease_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    fence_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    host_boot_id: Mapped[str] = mapped_column(String(128), nullable=False)
    cgroup_identity: Mapped[str] = mapped_column(String(256), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    termination_reason: Mapped[str | None] = mapped_column(String(64))
