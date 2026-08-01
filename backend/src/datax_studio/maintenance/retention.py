from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID, uuid4

import rfc8785
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from datax_studio.auth.db import (
    AuditEvent,
    IdempotencyRecord,
    Organization,
    OrganizationMember,
)
from datax_studio.auth.security import ensure_aware
from datax_studio.core.db import (
    Execution,
    ExecutionAttempt,
    ExecutionCancelRequest,
    ExecutionEvent,
    Project,
    SystemControl,
    TargetCopyLock,
)
from datax_studio.credentials.db import EndpointConnectionEvidence
from datax_studio.logs.db import ExecutionLogChunk, ExecutionLogGap
from datax_studio.maintenance.db import RetentionHold
from datax_studio.recovery.db import RecoveryGate
from datax_studio.settings import Settings, get_settings

_TERMINAL_EXECUTION_STATES = frozenset({"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED", "LOST"})
_OPEN_RECOVERY_GATE_STATES = frozenset({"OPEN", "REMEDIATION_SUBMITTED", "REJECTED"})
_ACTIVE_CANCEL_REQUEST_STATES = frozenset({"PENDING", "ACKNOWLEDGED"})
_REASON_PATTERN = re.compile(r"^[A-Z0-9_]{1,64}$")
_AUDIT_DOMAIN = "DXAUDITv1"
_QUARANTINE_DIRECTORY = ".retention-quarantine"


class RetentionMaintenanceError(RuntimeError):
    def __init__(self, code: str) -> None:
        if _REASON_PATTERN.fullmatch(code) is None:
            raise ValueError("retention error code is invalid")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RetentionResult:
    run_id: str
    status: str
    checked_at: str
    log_retention_days: int
    execution_retention_days: int
    audit_retention_days: int
    idempotency_retention_hours: int
    log_bodies_deleted: int
    log_bodies_blocked: int
    executions_deleted: int
    executions_blocked: int
    execution_events_deleted: int
    idempotency_records_deleted: int
    idempotency_records_blocked: int
    audit_events_expired: int
    audit_events_blocked: int
    quarantine_files_reconciled: int
    audit_chain_verified: bool
    external_worm_anchor_available: bool
    block_reasons: tuple[str, ...]


@dataclass(frozen=True)
class _MovedLogBody:
    original: Path
    quarantine: Path


@dataclass
class _MutableCounts:
    log_bodies_deleted: int = 0
    log_bodies_blocked: int = 0
    executions_deleted: int = 0
    executions_blocked: int = 0
    execution_events_deleted: int = 0
    idempotency_records_deleted: int = 0
    idempotency_records_blocked: int = 0
    audit_events_expired: int = 0
    audit_events_blocked: int = 0
    quarantine_files_reconciled: int = 0

    @property
    def deleted_total(self) -> int:
        return self.log_bodies_deleted + self.executions_deleted + self.idempotency_records_deleted

    @property
    def blocked_total(self) -> int:
        return (
            self.log_bodies_blocked
            + self.executions_blocked
            + self.idempotency_records_blocked
            + self.audit_events_blocked
        )


class RetentionMaintenanceService:
    """Apply fixed minimum retention without deleting unresolved evidence.

    AuditEvent deletion is deliberately unavailable until an independently
    verifiable database-external WORM checkpoint/export capability exists.
    Expired audit events are counted and reported as blocked instead of being
    removed from the current append-only chain.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        sessions: sessionmaker[Session],
    ) -> None:
        self.settings = settings
        self.sessions = sessions

    def run(self, *, now: datetime | None = None) -> RetentionResult:
        checked_at = _as_utc(now) if now is not None else None
        run_id = uuid4()
        moved: list[_MovedLogBody] = []
        organization_ids: list[UUID] = []
        counts = _MutableCounts()
        reasons: set[str] = set()
        try:
            with self.sessions.begin() as session:
                effective_now = checked_at or self._database_now(session)
                self._lock_maintenance(session)
                organizations = list(
                    session.scalars(
                        select(Organization).order_by(Organization.id).with_for_update()
                    )
                )
                if not organizations:
                    raise RetentionMaintenanceError("RETENTION_ORGANIZATION_MISSING")
                organization_ids = [organization.id for organization in organizations]
                self._verify_audit_chains(session, organization_ids)
                for organization in organizations:
                    self._append_audit(
                        session,
                        organization=organization,
                        run_id=run_id,
                        action="RETENTION_MAINTENANCE_STARTED",
                        outcome="SUCCEEDED",
                        reason_code=None,
                        occurred_at=effective_now,
                        metadata=self._policy_metadata(),
                    )

                reconciled, reconcile_reasons = self._reconcile_quarantine(
                    session,
                )
                counts.quarantine_files_reconciled += reconciled
                reasons.update(reconcile_reasons)
                self._purge_idempotency(
                    session,
                    now=effective_now,
                    counts=counts,
                    reasons=reasons,
                )
                self._purge_log_bodies(
                    session,
                    now=effective_now,
                    run_id=run_id,
                    moved=moved,
                    counts=counts,
                    reasons=reasons,
                )
                self._purge_executions(
                    session,
                    now=effective_now,
                    counts=counts,
                    reasons=reasons,
                )
                self._inspect_expired_audit_events(
                    session,
                    now=effective_now,
                    counts=counts,
                    reasons=reasons,
                )
                result = self._result(
                    run_id=run_id,
                    now=effective_now,
                    counts=counts,
                    reasons=reasons,
                )
                completed_outcome = "SUCCEEDED" if result.status != "BLOCKED" else "DENIED"
                completed_reason = (
                    None if result.status == "SUCCEEDED" else "RETENTION_ITEMS_BLOCKED"
                )
                for organization in organizations:
                    self._append_audit(
                        session,
                        organization=organization,
                        run_id=run_id,
                        action="RETENTION_MAINTENANCE_COMPLETED",
                        outcome=completed_outcome,
                        reason_code=completed_reason,
                        occurred_at=effective_now,
                        metadata=self._result_metadata(result),
                    )
                session.flush()
                self._verify_audit_chains(session, organization_ids)
        except BaseException as exc:
            self._restore_moved(moved)
            self._append_failure_audit_safely(
                organization_ids=organization_ids,
                run_id=run_id,
                now=checked_at or datetime.now(UTC),
                code=(
                    exc.code
                    if isinstance(exc, RetentionMaintenanceError)
                    else "RETENTION_MAINTENANCE_FAILED"
                ),
            )
            raise

        failed_quarantine_deletes = self._finalize_moved(moved)
        if failed_quarantine_deletes:
            reasons.add("LOG_QUARANTINE_DELETE_FAILED")
            self._append_failure_audit_safely(
                organization_ids=organization_ids,
                run_id=run_id,
                now=checked_at or datetime.now(UTC),
                code="LOG_QUARANTINE_DELETE_FAILED",
                metadata={"failed_file_count": str(failed_quarantine_deletes)},
            )
            result = self._result(
                run_id=run_id,
                now=_as_utc_string_to_datetime(result.checked_at),
                counts=counts,
                reasons=reasons,
            )
        return result

    def _purge_idempotency(
        self,
        session: Session,
        *,
        now: datetime,
        counts: _MutableCounts,
        reasons: set[str],
    ) -> None:
        cutoff = now - timedelta(hours=self.settings.idempotency_retention_hours)
        records = list(
            session.scalars(
                select(IdempotencyRecord)
                .where(
                    IdempotencyRecord.expires_at <= now,
                    IdempotencyRecord.created_at <= cutoff,
                )
                .order_by(IdempotencyRecord.expires_at, IdempotencyRecord.id)
                .limit(self.settings.retention_batch_size)
            )
        )
        for record in records:
            organization_ids = set(
                session.scalars(
                    select(OrganizationMember.organization_id).where(
                        OrganizationMember.user_id == record.actor_id
                    )
                )
            )
            if not organization_ids:
                counts.idempotency_records_blocked += 1
                reasons.add("IDEMPOTENCY_ORGANIZATION_UNRESOLVED")
                continue
            if any(
                self._organization_has_any_hold(
                    session,
                    organization_id=organization_id,
                    now=now,
                )
                for organization_id in organization_ids
            ):
                counts.idempotency_records_blocked += 1
                reasons.add("RETENTION_HOLD_ACTIVE")
                continue
            session.delete(record)
            counts.idempotency_records_deleted += 1
        session.flush()

    def _purge_log_bodies(
        self,
        session: Session,
        *,
        now: datetime,
        run_id: UUID,
        moved: list[_MovedLogBody],
        counts: _MutableCounts,
        reasons: set[str],
    ) -> None:
        cutoff = now - timedelta(days=self.settings.log_retention_days)
        rows = list(
            session.execute(
                select(
                    ExecutionLogChunk,
                    Execution,
                    Project.organization_id,
                )
                .join(
                    Execution,
                    Execution.id == ExecutionLogChunk.execution_id,
                )
                .join(Project, Project.id == Execution.project_id)
                .where(
                    ExecutionLogChunk.body_available.is_(True),
                    ExecutionLogChunk.expires_at <= now,
                    ExecutionLogChunk.created_at <= cutoff,
                )
                .order_by(
                    ExecutionLogChunk.expires_at,
                    ExecutionLogChunk.id,
                )
                .limit(self.settings.retention_batch_size)
            )
        )
        for chunk, execution, organization_id in rows:
            if (
                execution.process_state not in _TERMINAL_EXECUTION_STATES
                or execution.finished_at is None
                or execution.active_attempt_id is not None
            ):
                counts.log_bodies_blocked += 1
                reasons.add("EXECUTION_NOT_SAFELY_TERMINAL")
                continue
            if self._execution_has_hold(
                session,
                organization_id=organization_id,
                project_id=execution.project_id,
                execution_id=execution.id,
                now=now,
            ):
                counts.log_bodies_blocked += 1
                reasons.add("RETENTION_HOLD_ACTIVE")
                continue
            unresolved_gate = session.scalar(
                select(RecoveryGate.id).where(
                    RecoveryGate.execution_id == execution.id,
                    RecoveryGate.status.in_(_OPEN_RECOVERY_GATE_STATES),
                )
            )
            if unresolved_gate is not None:
                counts.log_bodies_blocked += 1
                reasons.add("RECOVERY_GATE_UNRESOLVED")
                continue
            locks = list(
                session.scalars(
                    select(TargetCopyLock).where(TargetCopyLock.execution_id == execution.id)
                )
            )
            if len(locks) != 1 or locks[0].state != "RELEASED":
                counts.log_bodies_blocked += 1
                reasons.add("TARGET_COPY_LOCK_NOT_RELEASED")
                continue
            try:
                moved_body = self._quarantine_log_body(
                    chunk,
                    run_id=run_id,
                )
            except RetentionMaintenanceError as exc:
                counts.log_bodies_blocked += 1
                reasons.add(exc.code)
                continue
            moved.append(moved_body)
            chunk.body_available = False
            chunk.deleted_at = now
            counts.log_bodies_deleted += 1
        session.flush()

    def _purge_executions(
        self,
        session: Session,
        *,
        now: datetime,
        counts: _MutableCounts,
        reasons: set[str],
    ) -> None:
        cutoff = now - timedelta(days=self.settings.execution_retention_days)
        rows = list(
            session.execute(
                select(Execution, Project.organization_id)
                .join(Project, Project.id == Execution.project_id)
                .where(
                    Execution.process_state.in_(_TERMINAL_EXECUTION_STATES),
                    Execution.finished_at.is_not(None),
                    Execution.finished_at <= cutoff,
                )
                .order_by(Execution.finished_at.desc(), Execution.id)
                .limit(self.settings.retention_batch_size)
            )
        )
        for execution, organization_id in rows:
            block_reason = self._execution_delete_block_reason(
                session,
                execution=execution,
                organization_id=organization_id,
                now=now,
            )
            if block_reason is not None:
                counts.executions_blocked += 1
                reasons.add(block_reason)
                continue
            deleted_events = 0
            try:
                with session.begin_nested():
                    session.execute(
                        delete(EndpointConnectionEvidence).where(
                            EndpointConnectionEvidence.execution_id == execution.id
                        )
                    )
                    session.execute(
                        delete(ExecutionLogGap).where(ExecutionLogGap.execution_id == execution.id)
                    )
                    session.execute(
                        delete(ExecutionLogChunk).where(
                            ExecutionLogChunk.execution_id == execution.id
                        )
                    )
                    event_result = session.execute(
                        delete(ExecutionEvent).where(ExecutionEvent.execution_id == execution.id)
                    )
                    deleted_events = _rowcount(event_result.rowcount)
                    session.execute(
                        delete(ExecutionCancelRequest).where(
                            ExecutionCancelRequest.execution_id == execution.id
                        )
                    )
                    session.execute(
                        delete(TargetCopyLock).where(TargetCopyLock.execution_id == execution.id)
                    )
                    session.execute(
                        delete(ExecutionAttempt).where(
                            ExecutionAttempt.execution_id == execution.id
                        )
                    )
                    deleted_execution = session.execute(
                        delete(Execution).where(Execution.id == execution.id)
                    )
                    if _rowcount(deleted_execution.rowcount) != 1:
                        raise RetentionMaintenanceError("EXECUTION_DELETE_CONFLICT")
                    session.flush()
            except (IntegrityError, RetentionMaintenanceError):
                counts.executions_blocked += 1
                reasons.add("EXECUTION_REFERENCE_RESTRICTED")
                continue
            counts.executions_deleted += 1
            counts.execution_events_deleted += deleted_events

    def _execution_delete_block_reason(
        self,
        session: Session,
        *,
        execution: Execution,
        organization_id: UUID,
        now: datetime,
    ) -> str | None:
        if (
            execution.process_state not in _TERMINAL_EXECUTION_STATES
            or execution.finished_at is None
            or execution.active_attempt_id is not None
        ):
            return "EXECUTION_NOT_SAFELY_TERMINAL"
        if self._execution_has_hold(
            session,
            organization_id=organization_id,
            project_id=execution.project_id,
            execution_id=execution.id,
            now=now,
        ):
            return "RETENTION_HOLD_ACTIVE"
        if (
            session.scalar(select(RecoveryGate.id).where(RecoveryGate.execution_id == execution.id))
            is not None
        ):
            return "RECOVERY_GATE_PRESERVED"
        if (
            session.scalar(
                select(Execution.id).where(Execution.rerun_of_execution_id == execution.id)
            )
            is not None
        ):
            return "EXECUTION_RERUN_REFERENCE_ACTIVE"
        if (
            session.scalar(
                select(ExecutionAttempt.id).where(
                    ExecutionAttempt.execution_id == execution.id,
                    ExecutionAttempt.finished_at.is_(None),
                )
            )
            is not None
        ):
            return "EXECUTION_ATTEMPT_UNFINISHED"
        if (
            session.scalar(
                select(ExecutionCancelRequest.id).where(
                    ExecutionCancelRequest.execution_id == execution.id,
                    ExecutionCancelRequest.status.in_(_ACTIVE_CANCEL_REQUEST_STATES),
                )
            )
            is not None
        ):
            return "EXECUTION_CANCEL_REQUEST_ACTIVE"
        locks = list(
            session.scalars(
                select(TargetCopyLock).where(TargetCopyLock.execution_id == execution.id)
            )
        )
        if len(locks) != 1 or locks[0].state != "RELEASED":
            return "TARGET_COPY_LOCK_NOT_RELEASED"
        if (
            session.scalar(
                select(ExecutionLogChunk.id).where(
                    ExecutionLogChunk.execution_id == execution.id,
                    ExecutionLogChunk.body_available.is_(True),
                )
            )
            is not None
        ):
            return "LOG_BODY_RETENTION_NOT_COMPLETED"
        if (
            session.scalar(
                select(IdempotencyRecord.id).where(
                    IdempotencyRecord.resource_type == "EXECUTION",
                    IdempotencyRecord.resource_id == execution.id,
                    IdempotencyRecord.expires_at > now,
                )
            )
            is not None
        ):
            return "IDEMPOTENCY_REFERENCE_ACTIVE"
        return None

    def _inspect_expired_audit_events(
        self,
        session: Session,
        *,
        now: datetime,
        counts: _MutableCounts,
        reasons: set[str],
    ) -> None:
        cutoff = now - timedelta(days=self.settings.audit_retention_days)
        expired = int(
            session.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.expires_at <= now,
                    AuditEvent.occurred_at <= cutoff,
                )
            )
            or 0
        )
        counts.audit_events_expired = expired
        counts.audit_events_blocked = expired
        if expired:
            reasons.add("AUDIT_WORM_ANCHOR_UNAVAILABLE")
            held = session.scalar(
                select(RetentionHold.id)
                .join(
                    AuditEvent,
                    or_(
                        (RetentionHold.scope_type == "ORGANIZATION")
                        & (RetentionHold.scope_id == AuditEvent.organization_id),
                        (RetentionHold.scope_type == "PROJECT")
                        & (RetentionHold.scope_id == AuditEvent.project_id),
                        (RetentionHold.scope_type == "AUDIT_EVENT")
                        & (RetentionHold.scope_id == AuditEvent.id),
                    ),
                )
                .where(
                    AuditEvent.expires_at <= now,
                    AuditEvent.occurred_at <= cutoff,
                    RetentionHold.organization_id == AuditEvent.organization_id,
                    self._active_hold_predicate(now),
                )
                .limit(1)
            )
            if held is not None:
                reasons.add("RETENTION_HOLD_ACTIVE")

    def _execution_has_hold(
        self,
        session: Session,
        *,
        organization_id: UUID,
        project_id: UUID,
        execution_id: UUID,
        now: datetime,
    ) -> bool:
        return (
            session.scalar(
                select(RetentionHold.id)
                .where(
                    RetentionHold.organization_id == organization_id,
                    self._active_hold_predicate(now),
                    or_(
                        (RetentionHold.scope_type == "ORGANIZATION")
                        & (RetentionHold.scope_id == organization_id),
                        (RetentionHold.scope_type == "PROJECT")
                        & (RetentionHold.scope_id == project_id),
                        (RetentionHold.scope_type == "EXECUTION")
                        & (RetentionHold.scope_id == execution_id),
                    ),
                )
                .limit(1)
            )
            is not None
        )

    def _organization_has_any_hold(
        self,
        session: Session,
        *,
        organization_id: UUID,
        now: datetime,
    ) -> bool:
        return (
            session.scalar(
                select(RetentionHold.id)
                .where(
                    RetentionHold.organization_id == organization_id,
                    self._active_hold_predicate(now),
                )
                .limit(1)
            )
            is not None
        )

    @staticmethod
    def _active_hold_predicate(now: datetime) -> Any:
        return RetentionHold.released_at.is_(None) & or_(
            RetentionHold.expires_at.is_(None),
            RetentionHold.expires_at > now,
        )

    def _quarantine_log_body(
        self,
        chunk: ExecutionLogChunk,
        *,
        run_id: UUID,
    ) -> _MovedLogBody:
        key = _safe_storage_key(chunk.storage_key)
        root = self.settings.log_volume_path
        if root.is_symlink():
            raise RetentionMaintenanceError("LOG_STORAGE_PATH_UNSAFE")
        try:
            resolved_root = root.resolve(strict=True)
        except OSError as exc:
            raise RetentionMaintenanceError("LOG_STORAGE_PATH_UNAVAILABLE") from exc
        source = resolved_root.joinpath(*key.parts)
        _assert_safe_existing_file(source, root=resolved_root)
        byte_size, digest = _file_size_and_sha256(source)
        if byte_size != chunk.byte_size or digest != chunk.sha256:
            raise RetentionMaintenanceError("LOG_BODY_INTEGRITY_INVALID")

        quarantine_root = resolved_root / _QUARANTINE_DIRECTORY / str(run_id)
        target_parent = _secure_directory_chain(
            resolved_root,
            (
                _QUARANTINE_DIRECTORY,
                str(run_id),
                *key.parts[:-1],
            ),
        )
        target = target_parent / key.name
        if target.exists() or target.is_symlink():
            raise RetentionMaintenanceError("LOG_QUARANTINE_CONFLICT")
        try:
            os.replace(source, target)
        except OSError as exc:
            raise RetentionMaintenanceError("LOG_BODY_DELETE_FAILED") from exc
        if not target.is_relative_to(quarantine_root):
            raise RetentionMaintenanceError("LOG_QUARANTINE_PATH_UNSAFE")
        return _MovedLogBody(original=source, quarantine=target)

    def _reconcile_quarantine(
        self,
        session: Session,
    ) -> tuple[int, set[str]]:
        root = self.settings.log_volume_path
        quarantine_root = root / _QUARANTINE_DIRECTORY
        if not quarantine_root.exists():
            return 0, set()
        if root.is_symlink() or quarantine_root.is_symlink():
            return 0, {"LOG_QUARANTINE_PATH_UNSAFE"}
        try:
            resolved_root = root.resolve(strict=True)
            resolved_quarantine = quarantine_root.resolve(strict=True)
            resolved_quarantine.relative_to(resolved_root)
        except (OSError, ValueError):
            return 0, {"LOG_QUARANTINE_PATH_UNSAFE"}
        reconciled = 0
        reasons: set[str] = set()
        for candidate in sorted(resolved_quarantine.rglob("*")):
            if candidate.is_symlink():
                reasons.add("LOG_QUARANTINE_PATH_UNSAFE")
                continue
            if not candidate.is_file():
                continue
            try:
                relative = candidate.relative_to(resolved_quarantine)
            except ValueError:
                reasons.add("LOG_QUARANTINE_PATH_UNSAFE")
                continue
            if len(relative.parts) < 3:
                reasons.add("LOG_QUARANTINE_ORPHAN_UNRESOLVED")
                continue
            storage_key = PurePosixPath(*relative.parts[1:]).as_posix()
            chunk = session.scalar(
                select(ExecutionLogChunk).where(ExecutionLogChunk.storage_key == storage_key)
            )
            if chunk is None:
                reasons.add("LOG_QUARANTINE_ORPHAN_UNRESOLVED")
                continue
            if chunk.body_available:
                try:
                    original = resolved_root.joinpath(*_safe_storage_key(storage_key).parts)
                    if original.exists() or original.is_symlink():
                        reasons.add("LOG_QUARANTINE_CONFLICT")
                        continue
                    _secure_directory_chain(
                        resolved_root,
                        _safe_storage_key(storage_key).parts[:-1],
                    )
                    os.replace(candidate, original)
                    reconciled += 1
                except (OSError, RetentionMaintenanceError):
                    reasons.add("LOG_QUARANTINE_RESTORE_FAILED")
                continue
            try:
                candidate.unlink()
                reconciled += 1
            except OSError:
                reasons.add("LOG_QUARANTINE_DELETE_FAILED")
        _prune_empty_directories(resolved_quarantine, stop=resolved_root)
        return reconciled, reasons

    @staticmethod
    def _restore_moved(moved: list[_MovedLogBody]) -> None:
        failures = 0
        for entry in reversed(moved):
            if not entry.quarantine.exists():
                continue
            if entry.original.exists() or entry.original.is_symlink():
                failures += 1
                continue
            try:
                os.replace(entry.quarantine, entry.original)
            except OSError:
                failures += 1
        if failures:
            raise RetentionMaintenanceError("LOG_QUARANTINE_RESTORE_FAILED")

    @staticmethod
    def _finalize_moved(moved: list[_MovedLogBody]) -> int:
        failures = 0
        prune_roots: set[tuple[Path, Path]] = set()
        for entry in moved:
            quarantine_root = next(
                (
                    candidate
                    for candidate in (
                        entry.quarantine.parent,
                        *entry.quarantine.parents,
                    )
                    if candidate.name == _QUARANTINE_DIRECTORY
                ),
                None,
            )
            if quarantine_root is not None:
                prune_roots.add((entry.quarantine.parent, quarantine_root.parent))
            try:
                entry.quarantine.unlink(missing_ok=True)
            except OSError:
                failures += 1
        for start, stop in prune_roots:
            _prune_empty_directories(start, stop=stop)
        return failures

    @staticmethod
    def _lock_maintenance(session: Session) -> None:
        control = session.scalar(
            select(SystemControl).where(SystemControl.singleton_id == 1).with_for_update()
        )
        if control is None:
            raise RetentionMaintenanceError("RETENTION_SYSTEM_CONTROL_MISSING")

    @staticmethod
    def _database_now(session: Session) -> datetime:
        value = session.scalar(select(func.current_timestamp()))
        if not isinstance(value, datetime):
            raise RetentionMaintenanceError("RETENTION_DATABASE_TIME_INVALID")
        return _as_utc(value)

    def _append_audit(
        self,
        session: Session,
        *,
        organization: Organization,
        run_id: UUID,
        action: str,
        outcome: str,
        reason_code: str | None,
        occurred_at: datetime,
        metadata: dict[str, Any],
    ) -> None:
        session.execute(
            select(Organization.id).where(Organization.id == organization.id).with_for_update()
        ).scalar_one()
        previous = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization.id)
            .order_by(AuditEvent.organization_sequence.desc())
            .limit(1)
        )
        sequence = previous.organization_sequence + 1 if previous else 1
        previous_hash = previous.event_hash if previous else None
        event_id = uuid4()
        event: dict[str, Any] = {
            "schema_version": "1.0",
            "event_id": str(event_id),
            "organization_id": str(organization.id),
            "sequence": sequence,
            "project_id": None,
            "occurred_at": _rfc3339(occurred_at),
            "action": action,
            "actor": {
                "kind": "SYSTEM",
                "user_id": None,
                "display_name": None,
            },
            "target": {
                "type": "RETENTION_MAINTENANCE",
                "id": str(run_id),
                "name": None,
            },
            "request": {
                "request_id": str(run_id),
                "source_ip": None,
                "user_agent": None,
            },
            "outcome": outcome,
            "reason_code": reason_code,
            "changes": {
                "before_hash": None,
                "after_hash": None,
                "changed_fields": [],
            },
            "metadata": metadata,
            "integrity": {
                "algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "chain_scope": "ORGANIZATION_SEQUENCE",
                "previous_hash": previous_hash,
            },
        }
        prefix = (
            f"{_AUDIT_DOMAIN}\n"
            f"{str(organization.id).lower()}\n"
            f"{sequence}\n"
            f"{previous_hash or ('0' * 64)}\n"
        ).encode()
        event_hash = hashlib.sha256(prefix + rfc8785.dumps(event)).hexdigest()
        event["integrity"]["event_hash"] = event_hash
        session.add(
            AuditEvent(
                id=event_id,
                organization_id=organization.id,
                organization_sequence=sequence,
                project_id=None,
                event_json=event,
                canonicalization_version="RFC8785-v1",
                previous_hash=previous_hash,
                event_hash=event_hash,
                occurred_at=occurred_at,
                expires_at=occurred_at + timedelta(days=self.settings.audit_retention_days),
            )
        )
        session.flush()

    def _append_failure_audit_safely(
        self,
        *,
        organization_ids: list[UUID],
        run_id: UUID,
        now: datetime,
        code: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if _REASON_PATTERN.fullmatch(code) is None:
            code = "RETENTION_MAINTENANCE_FAILED"
        for organization_id in organization_ids:
            try:
                with self.sessions.begin() as session:
                    organization = session.get(Organization, organization_id)
                    if organization is None:
                        continue
                    self._verify_audit_chains(session, [organization_id])
                    self._append_audit(
                        session,
                        organization=organization,
                        run_id=run_id,
                        action="RETENTION_MAINTENANCE_FAILED",
                        outcome="FAILED",
                        reason_code=code,
                        occurred_at=_as_utc(now),
                        metadata=metadata or {},
                    )
                    self._verify_audit_chains(session, [organization_id])
            except (SQLAlchemyError, OSError, TypeError, ValueError, RuntimeError):
                continue

    @staticmethod
    def _verify_audit_chains(
        session: Session,
        organization_ids: list[UUID],
    ) -> None:
        for organization_id in organization_ids:
            rows = list(
                session.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.organization_id == organization_id)
                    .order_by(AuditEvent.organization_sequence)
                )
            )
            expected_sequence = 1
            expected_previous: str | None = None
            for row in rows:
                event = copy.deepcopy(row.event_json)
                integrity = event.get("integrity") if isinstance(event, dict) else None
                if (
                    row.organization_sequence != expected_sequence
                    or row.canonicalization_version != "RFC8785-v1"
                    or row.previous_hash != expected_previous
                    or not isinstance(integrity, dict)
                    or event.get("event_id") != str(row.id)
                    or event.get("organization_id") != str(organization_id)
                    or event.get("sequence") != expected_sequence
                    or integrity.get("algorithm") != "SHA-256"
                    or integrity.get("canonicalization") != "RFC8785"
                    or integrity.get("chain_scope") != "ORGANIZATION_SEQUENCE"
                    or integrity.get("previous_hash") != expected_previous
                    or integrity.get("event_hash") != row.event_hash
                ):
                    raise RetentionMaintenanceError("AUDIT_CHAIN_INTEGRITY_INVALID")
                event_hash = integrity.pop("event_hash")
                prefix = (
                    f"{_AUDIT_DOMAIN}\n"
                    f"{str(organization_id).lower()}\n"
                    f"{expected_sequence}\n"
                    f"{expected_previous or ('0' * 64)}\n"
                ).encode()
                calculated = hashlib.sha256(prefix + rfc8785.dumps(event)).hexdigest()
                if calculated != event_hash:
                    raise RetentionMaintenanceError("AUDIT_CHAIN_INTEGRITY_INVALID")
                expected_previous = calculated
                expected_sequence += 1

    def _policy_metadata(self) -> dict[str, Any]:
        return {
            "log_retention_days": str(self.settings.log_retention_days),
            "execution_retention_days": str(self.settings.execution_retention_days),
            "audit_retention_days": str(self.settings.audit_retention_days),
            "idempotency_retention_hours": str(self.settings.idempotency_retention_hours),
            "batch_size": str(self.settings.retention_batch_size),
            "external_worm_anchor_available": False,
        }

    @staticmethod
    def _result_metadata(result: RetentionResult) -> dict[str, Any]:
        return {
            "status": result.status,
            "log_bodies_deleted": str(result.log_bodies_deleted),
            "log_bodies_blocked": str(result.log_bodies_blocked),
            "executions_deleted": str(result.executions_deleted),
            "executions_blocked": str(result.executions_blocked),
            "execution_events_deleted": str(result.execution_events_deleted),
            "idempotency_records_deleted": str(result.idempotency_records_deleted),
            "idempotency_records_blocked": str(result.idempotency_records_blocked),
            "audit_events_expired": str(result.audit_events_expired),
            "audit_events_blocked": str(result.audit_events_blocked),
            "quarantine_files_reconciled": str(result.quarantine_files_reconciled),
            "block_reasons": list(result.block_reasons),
            "audit_chain_verified": result.audit_chain_verified,
            "external_worm_anchor_available": (result.external_worm_anchor_available),
        }

    def _result(
        self,
        *,
        run_id: UUID,
        now: datetime,
        counts: _MutableCounts,
        reasons: set[str],
    ) -> RetentionResult:
        if counts.blocked_total or reasons:
            status = "PARTIAL" if counts.deleted_total else "BLOCKED"
        else:
            status = "SUCCEEDED"
        return RetentionResult(
            run_id=str(run_id),
            status=status,
            checked_at=_rfc3339(now),
            log_retention_days=self.settings.log_retention_days,
            execution_retention_days=self.settings.execution_retention_days,
            audit_retention_days=self.settings.audit_retention_days,
            idempotency_retention_hours=(self.settings.idempotency_retention_hours),
            log_bodies_deleted=counts.log_bodies_deleted,
            log_bodies_blocked=counts.log_bodies_blocked,
            executions_deleted=counts.executions_deleted,
            executions_blocked=counts.executions_blocked,
            execution_events_deleted=counts.execution_events_deleted,
            idempotency_records_deleted=counts.idempotency_records_deleted,
            idempotency_records_blocked=counts.idempotency_records_blocked,
            audit_events_expired=counts.audit_events_expired,
            audit_events_blocked=counts.audit_events_blocked,
            quarantine_files_reconciled=counts.quarantine_files_reconciled,
            audit_chain_verified=True,
            external_worm_anchor_available=False,
            block_reasons=tuple(sorted(reasons)),
        )


def _safe_storage_key(raw: str) -> PurePosixPath:
    key = PurePosixPath(raw)
    if (
        key.is_absolute()
        or not key.parts
        or key.parts[0] == _QUARANTINE_DIRECTORY
        or any(part in {"", ".", ".."} or "\\" in part for part in key.parts)
    ):
        raise RetentionMaintenanceError("LOG_STORAGE_PATH_UNSAFE")
    return key


def _assert_safe_existing_file(path: Path, *, root: Path) -> None:
    try:
        path.relative_to(root)
        current = path.parent
        while current != root:
            if current.is_symlink():
                raise RetentionMaintenanceError("LOG_STORAGE_PATH_UNSAFE")
            current = current.parent
        metadata = path.lstat()
    except (OSError, ValueError) as exc:
        raise RetentionMaintenanceError("LOG_BODY_MISSING") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RetentionMaintenanceError("LOG_STORAGE_PATH_UNSAFE")


def _file_size_and_sha256(path: Path) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RetentionMaintenanceError("LOG_BODY_MISSING") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RetentionMaintenanceError("LOG_STORAGE_PATH_UNSAFE")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(block)
                digest.update(block)
    finally:
        os.close(descriptor)
    return size, digest.hexdigest()


def _secure_directory_chain(root: Path, parts: tuple[str, ...]) -> Path:
    current = root
    for part in parts:
        if part in {"", ".", ".."} or "/" in part or "\\" in part:
            raise RetentionMaintenanceError("LOG_QUARANTINE_PATH_UNSAFE")
        current = current / part
        if current.exists():
            if current.is_symlink() or not current.is_dir():
                raise RetentionMaintenanceError("LOG_QUARANTINE_PATH_UNSAFE")
            continue
        try:
            current.mkdir(mode=0o700)
        except OSError as exc:
            raise RetentionMaintenanceError("LOG_QUARANTINE_PATH_UNSAFE") from exc
    return current


def _prune_empty_directories(start: Path, *, stop: Path) -> None:
    current = start
    while current != stop and current.is_relative_to(stop):
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def _as_utc(value: datetime) -> datetime:
    return ensure_aware(value).astimezone(UTC)


def _as_utc_string_to_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _rfc3339(value: datetime) -> str:
    return (
        _as_utc(value)
        .isoformat(timespec="microseconds")
        .replace(
            "+00:00",
            "Z",
        )
    )


def _rowcount(value: int | None) -> int:
    return value if value is not None and value > 0 else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="datax-studio-retention-maintenance")
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run")
    run.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main() -> None:
    _parser().parse_args()
    settings = get_settings()
    from sqlalchemy import create_engine

    engine = create_engine(settings.database_url, pool_pre_ping=True)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        result = RetentionMaintenanceService(
            settings=settings,
            sessions=sessions,
        ).run()
        output = asdict(result)
        print(json.dumps(output, separators=(",", ":"), sort_keys=True))
        raise SystemExit(0 if result.status == "SUCCEEDED" else 3)
    except (
        OSError,
        SQLAlchemyError,
        RetentionMaintenanceError,
        TypeError,
        ValueError,
    ) as exc:
        code = (
            exc.code
            if isinstance(exc, RetentionMaintenanceError)
            else "RETENTION_MAINTENANCE_FAILED"
        )
        print(
            json.dumps(
                {
                    "status": "FAILED",
                    "code": code,
                    "detail": type(exc).__name__,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        raise SystemExit(4) from None
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
