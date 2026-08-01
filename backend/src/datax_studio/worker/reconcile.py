from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from datax_studio.api.problems import ProblemException
from datax_studio.auth.security import ensure_aware
from datax_studio.core.db import (
    Execution,
    ExecutionAttempt,
    ExecutionCancelRequest,
    SystemControl,
    TargetCopyLock,
)
from datax_studio.core.schemas import ClaimedExecution
from datax_studio.core.service import ControlService
from datax_studio.logs.service import append_reconciler_fence_gap
from datax_studio.recovery.db import RecoveryProbe, RecoveryProbeAttempt
from datax_studio.recovery.service import RecoveryService
from datax_studio.worker.process import (
    ProcessAction,
    ProcessIdentity,
    terminate_recorded_process_group,
)

_ACTIVE_EXECUTION_STATES = {
    "STARTING",
    "RUNNING",
    "VERIFYING",
    "CANCEL_REQUESTED",
}


@dataclass(frozen=True)
class RuntimeIdentity:
    host_boot_id: str
    cgroup_identity: str

    @classmethod
    def current(cls) -> RuntimeIdentity:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        cgroup = Path("/proc/self/cgroup").read_bytes()
        if not boot_id or not cgroup:
            raise RuntimeError("worker Linux runtime identity is unavailable")
        return cls(
            host_boot_id=boot_id,
            cgroup_identity=hashlib.sha256(b"DXCGROUPIDENTITYv1\n" + cgroup).hexdigest(),
        )


@dataclass(frozen=True)
class ReconcileResult:
    queued_cancellations: int
    lost_executions: int
    lost_recovery_probes: int


class WorkerReconciler:
    def __init__(
        self,
        *,
        control: ControlService,
        sessions: sessionmaker[Session],
    ) -> None:
        self.control = control
        self.sessions = sessions

    def reconcile_startup(
        self,
        *,
        identity: RuntimeIdentity,
        reconcile_epoch: UUID,
        accepting: bool,
        completion_reason: str,
    ) -> ReconcileResult:
        """Drain, reconcile every prior active fact, then publish the epoch."""

        self._begin_epoch(identity=identity, reconcile_epoch=reconcile_epoch)
        queued = self._reconcile_queued_cancellations()
        execution_ids = self._active_execution_ids()
        lost_executions = sum(
            self._mark_execution_lost(
                execution_id,
                identity=identity,
                require_expired=False,
                reason_code="WORKER_STARTUP_RECONCILIATION",
            )
            for execution_id in execution_ids
        )
        probe_ids = self._active_probe_ids()
        lost_probes = sum(
            self._mark_probe_lost(
                probe_id,
                require_expired=False,
                reason_code="WORKER_STARTUP_RECONCILIATION",
            )
            for probe_id in probe_ids
        )
        self._complete_epoch(
            identity=identity,
            reconcile_epoch=reconcile_epoch,
            accepting=accepting,
            completion_reason=completion_reason,
        )
        return ReconcileResult(
            queued_cancellations=queued,
            lost_executions=lost_executions,
            lost_recovery_probes=lost_probes,
        )

    def reconcile_expired_leases(
        self,
        *,
        identity: RuntimeIdentity,
    ) -> ReconcileResult:
        queued = self._reconcile_queued_cancellations()
        lost_executions = sum(
            self._mark_execution_lost(
                execution_id,
                identity=identity,
                require_expired=True,
                reason_code="EXECUTION_LEASE_EXPIRED",
            )
            for execution_id in self._active_execution_ids()
        )
        lost_probes = sum(
            self._mark_probe_lost(
                probe_id,
                require_expired=True,
                reason_code="RECOVERY_PROBE_LEASE_EXPIRED",
            )
            for probe_id in self._active_probe_ids()
        )
        return ReconcileResult(
            queued_cancellations=queued,
            lost_executions=lost_executions,
            lost_recovery_probes=lost_probes,
        )

    def poll_claim_action(self, claim: ClaimedExecution) -> ProcessAction:
        with self.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            try:
                execution, attempt = self.control._current_fenced_attempt(  # noqa: SLF001
                    session,
                    claim=claim,
                    now=now,
                    lock=True,
                )
            except ProblemException:
                return ProcessAction.FENCE_LOST
            cancel = session.scalar(
                select(ExecutionCancelRequest)
                .where(
                    ExecutionCancelRequest.execution_id == execution.id,
                    ExecutionCancelRequest.status == "PENDING",
                )
                .with_for_update()
            )
            if cancel is None:
                return ProcessAction.CONTINUE
            from_state = execution.process_state
            if from_state not in {"STARTING", "RUNNING", "VERIFYING"}:
                return (
                    ProcessAction.CANCEL
                    if from_state == "CANCEL_REQUESTED"
                    else ProcessAction.FENCE_LOST
                )
            execution.process_state = "CANCEL_REQUESTED"
            execution.state_version += 1
            cancel.status = "ACKNOWLEDGED"
            cancel.acknowledged_at = now
            self.control._append_execution_event(  # noqa: SLF001
                session,
                execution,
                event_type="EXECUTION_CANCEL_ACKNOWLEDGED",
                from_state=from_state,
                to_state="CANCEL_REQUESTED",
                attempt_id=attempt.id,
                payload={"cancel_request_id": str(cancel.id)},
                now=now,
            )
            return ProcessAction.CANCEL

    def complete_claimed_cancel(
        self,
        *,
        claim: ClaimedExecution,
        oracle_started: bool,
    ) -> None:
        verification_state = "INCONCLUSIVE" if oracle_started else "NOT_STARTED"
        self.control.transition_claimed_execution(
            claim=claim,
            expected_state="CANCEL_REQUESTED",
            new_state="CANCELED",
            data_effect="UNKNOWN",
            verification_state=verification_state,
            failure_code="OPERATOR_CANCELED",
            failure_message="Execution was canceled after Worker acknowledgement.",
        )
        with self.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            execution = session.scalar(
                select(Execution).where(Execution.id == claim.execution_id).with_for_update()
            )
            cancel = session.scalar(
                select(ExecutionCancelRequest)
                .where(
                    ExecutionCancelRequest.execution_id == claim.execution_id,
                    ExecutionCancelRequest.status == "ACKNOWLEDGED",
                )
                .with_for_update()
            )
            if execution is None or execution.process_state != "CANCELED":
                return
            if cancel is not None:
                cancel.status = "COMPLETED"
                cancel.completed_at = now
            RecoveryService.ensure_gate(
                session,
                execution=execution,
                now=now,
            )

    def ensure_terminal_gate(self, execution_id: UUID) -> bool:
        with self.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            execution = session.scalar(
                select(Execution).where(Execution.id == execution_id).with_for_update()
            )
            if execution is None:
                return False
            return (
                RecoveryService.ensure_gate(
                    session,
                    execution=execution,
                    now=now,
                )
                is not None
            )

    def record_process_identity(
        self,
        *,
        claim: ClaimedExecution,
        identity: ProcessIdentity,
        workspace_path_hash: str,
    ) -> None:
        with self.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            _execution, attempt = self.control._current_fenced_attempt(  # noqa: SLF001
                session,
                claim=claim,
                now=now,
                lock=True,
            )
            attempt.pid = identity.pid
            attempt.pid_start_time = identity.pid_start_time
            attempt.process_group_id = identity.process_group_id
            attempt.workspace_path_hash = workspace_path_hash

    def _reconcile_queued_cancellations(self) -> int:
        with self.sessions() as session:
            execution_ids = list(
                session.scalars(
                    select(ExecutionCancelRequest.execution_id)
                    .join(
                        Execution,
                        Execution.id == ExecutionCancelRequest.execution_id,
                    )
                    .where(
                        ExecutionCancelRequest.status == "PENDING",
                        Execution.process_state == "QUEUED",
                        Execution.active_attempt_id.is_(None),
                    )
                    .order_by(ExecutionCancelRequest.requested_at)
                )
            )
        return sum(
            self.control.reconcile_unclaimed_cancel(execution_id=execution_id)
            for execution_id in execution_ids
        )

    def _active_execution_ids(self) -> list[UUID]:
        with self.sessions() as session:
            return list(
                session.scalars(
                    select(Execution.id)
                    .where(Execution.process_state.in_(_ACTIVE_EXECUTION_STATES))
                    .order_by(Execution.id)
                )
            )

    def _active_probe_ids(self) -> list[UUID]:
        with self.sessions() as session:
            return list(
                session.scalars(
                    select(RecoveryProbe.id)
                    .where(RecoveryProbe.process_state.in_({"STARTING", "RUNNING"}))
                    .order_by(RecoveryProbe.id)
                )
            )

    def _mark_execution_lost(
        self,
        execution_id: UUID,
        *,
        identity: RuntimeIdentity,
        require_expired: bool,
        reason_code: str,
    ) -> bool:
        with self.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            execution = session.scalar(
                select(Execution).where(Execution.id == execution_id).with_for_update()
            )
            if (
                execution is None
                or execution.process_state not in _ACTIVE_EXECUTION_STATES
                or execution.active_attempt_id is None
            ):
                return False
            attempt = session.scalar(
                select(ExecutionAttempt)
                .where(ExecutionAttempt.id == execution.active_attempt_id)
                .with_for_update()
            )
            lock = session.scalar(
                select(TargetCopyLock)
                .where(TargetCopyLock.execution_id == execution.id)
                .with_for_update()
            )
            if attempt is None or lock is None:
                raise RuntimeError("active execution control facts are missing")
            if require_expired and ensure_aware(attempt.lease_expires_at) > now:
                return False
            if (
                attempt.host_boot_id == identity.host_boot_id
                and attempt.cgroup_identity == identity.cgroup_identity
                and attempt.pid is not None
                and attempt.pid_start_time is not None
                and attempt.process_group_id is not None
            ):
                terminate_recorded_process_group(
                    ProcessIdentity(
                        pid=attempt.pid,
                        pid_start_time=attempt.pid_start_time,
                        process_group_id=attempt.process_group_id,
                    )
                )
            from_state = execution.process_state
            oracle_started = (
                from_state == "VERIFYING" or execution.verification_state == "VERIFYING"
            )
            execution.process_state = "LOST"
            execution.data_effect = "UNKNOWN"
            execution.verification_state = "INCONCLUSIVE" if oracle_started else "NOT_STARTED"
            execution.failure_code = reason_code
            execution.failure_message = (
                "Worker ownership could not be safely retained; manual recovery is required."
            )
            append_reconciler_fence_gap(
                session,
                execution=execution,
                attempt_id=attempt.id,
                detected_at=now,
            )
            execution.finished_at = now
            execution.active_attempt_id = None
            execution.state_version += 1
            attempt.finished_at = now
            attempt.termination_reason = "LOST"
            lock.state = "RECOVERY_REQUIRED"
            cancel = session.scalar(
                select(ExecutionCancelRequest)
                .where(
                    ExecutionCancelRequest.execution_id == execution.id,
                    ExecutionCancelRequest.status.in_({"PENDING", "ACKNOWLEDGED"}),
                )
                .with_for_update()
            )
            if cancel is not None:
                cancel.status = "COMPLETED"
                cancel.acknowledged_at = cancel.acknowledged_at or now
                cancel.completed_at = now
            self.control._append_execution_event(  # noqa: SLF001
                session,
                execution,
                event_type="EXECUTION_LOST",
                from_state=from_state,
                to_state="LOST",
                attempt_id=attempt.id,
                payload={
                    "data_effect": "UNKNOWN",
                    "verification_state": execution.verification_state,
                    "reason_code": reason_code,
                },
                now=now,
            )
            RecoveryService.ensure_gate(
                session,
                execution=execution,
                now=now,
            )
            return True

    def _mark_probe_lost(
        self,
        probe_id: UUID,
        *,
        require_expired: bool,
        reason_code: str,
    ) -> bool:
        with self.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            probe = session.scalar(
                select(RecoveryProbe).where(RecoveryProbe.id == probe_id).with_for_update()
            )
            if (
                probe is None
                or probe.process_state not in {"STARTING", "RUNNING"}
                or probe.active_attempt_id is None
            ):
                return False
            attempt = session.scalar(
                select(RecoveryProbeAttempt)
                .where(RecoveryProbeAttempt.id == probe.active_attempt_id)
                .with_for_update()
            )
            if attempt is None:
                raise RuntimeError("active recovery probe attempt is missing")
            if require_expired and ensure_aware(attempt.lease_expires_at) > now:
                return False
            probe.process_state = "LOST"
            probe.result = "INCONCLUSIVE"
            probe.failure_code = reason_code
            probe.finished_at = now
            probe.active_attempt_id = None
            attempt.finished_at = now
            attempt.termination_reason = "LOST"
            return True

    def _begin_epoch(
        self,
        *,
        identity: RuntimeIdentity,
        reconcile_epoch: UUID,
    ) -> None:
        with self.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            control = session.scalar(
                select(SystemControl).where(SystemControl.singleton_id == 1).with_for_update()
            )
            if control is None:
                raise RuntimeError("system control fact is missing")
            control.draining = True
            control.reason = "WORKER_STARTUP_RECONCILIATION"
            control.host_boot_id = identity.host_boot_id
            control.reconcile_epoch = reconcile_epoch
            control.reconciled_at = None
            control.updated_at = now

    def _complete_epoch(
        self,
        *,
        identity: RuntimeIdentity,
        reconcile_epoch: UUID,
        accepting: bool,
        completion_reason: str,
    ) -> None:
        with self.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            control = session.scalar(
                select(SystemControl).where(SystemControl.singleton_id == 1).with_for_update()
            )
            if (
                control is None
                or control.reconcile_epoch != reconcile_epoch
                or control.host_boot_id != identity.host_boot_id
            ):
                raise RuntimeError("startup reconciliation epoch was superseded")
            control.draining = not accepting
            control.reason = completion_reason
            control.reconciled_at = now
            control.updated_at = now
