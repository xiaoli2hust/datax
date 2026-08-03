from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from datax_studio.auth.db import Base


class ExecutionLogChunk(Base):
    __tablename__ = "execution_log_chunks"
    __table_args__ = (
        CheckConstraint(
            "chunk_no >= 1 AND first_sequence >= 1 AND last_sequence >= first_sequence",
            name="ck_execution_log_chunks_sequence",
        ),
        CheckConstraint(
            "byte_size >= 0 AND raw_received_bytes >= 0 "
            "AND redacted_received_bytes >= 0 AND stored_bytes >= 0 "
            "AND dropped_bytes >= 0",
            name="ck_execution_log_chunks_nonnegative",
        ),
        CheckConstraint(
            "byte_size = stored_bytes AND dropped_bytes = redacted_received_bytes - stored_bytes",
            name="ck_execution_log_chunks_accounting",
        ),
        CheckConstraint(
            "(body_available AND deleted_at IS NULL) "
            "OR (NOT body_available AND deleted_at IS NOT NULL)",
            name="ck_execution_log_chunks_body_lifecycle",
        ),
        UniqueConstraint(
            "execution_id",
            "attempt_id",
            "chunk_no",
            name="uq_execution_log_chunks_attempt_number",
        ),
        Index(
            "ix_execution_log_chunks_execution_sequence",
            "execution_id",
            "first_sequence",
            "last_sequence",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    execution_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("executions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    attempt_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("execution_attempts.id", ondelete="RESTRICT"),
        nullable=False,
    )
    chunk_no: Mapped[int] = mapped_column(Integer, nullable=False)
    first_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    redaction_rules_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    contains_truncated_line: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )
    raw_received_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    redacted_received_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    stored_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    dropped_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    body_available: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ExecutionLogGap(Base):
    __tablename__ = "execution_log_gaps"
    __table_args__ = (
        CheckConstraint("gap_no >= 1", name="ck_execution_log_gaps_number"),
        CheckConstraint(
            "reason IN "
            "('LINE_LIMIT','EXECUTION_LIMIT','RING_EVICTION','SOURCE_READ_ERROR',"
            "'DECODE_ERROR','REDACTION_FAILURE','STORAGE_FAILURE','FENCE_LOST')",
            name="ck_execution_log_gaps_reason",
        ),
        CheckConstraint(
            "(after_sequence IS NULL OR after_sequence >= 1) "
            "AND (before_sequence IS NULL OR before_sequence >= 1)",
            name="ck_execution_log_gaps_boundaries",
        ),
        CheckConstraint(
            "raw_received_bytes >= 0 AND redacted_received_bytes >= 0 "
            "AND stored_bytes >= 0 AND dropped_bytes >= 0",
            name="ck_execution_log_gaps_nonnegative",
        ),
        CheckConstraint(
            "dropped_bytes = redacted_received_bytes - stored_bytes",
            name="ck_execution_log_gaps_accounting",
        ),
        UniqueConstraint(
            "execution_id",
            "attempt_id",
            "gap_no",
            name="uq_execution_log_gaps_attempt_number",
        ),
        Index(
            "ix_execution_log_gaps_execution_number",
            "execution_id",
            "gap_no",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    execution_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("executions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    attempt_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("execution_attempts.id", ondelete="RESTRICT"),
        nullable=False,
    )
    gap_no: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    after_sequence: Mapped[int | None] = mapped_column(BigInteger)
    before_sequence: Mapped[int | None] = mapped_column(BigInteger)
    raw_received_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    redacted_received_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    stored_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    dropped_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
