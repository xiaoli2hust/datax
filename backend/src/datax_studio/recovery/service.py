from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

import rfc8785
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from datax_studio.api.problems import ProblemException
from datax_studio.auth.db import Role
from datax_studio.auth.security import ensure_aware, utc_now
from datax_studio.auth.service import AuditContext, OperationResult, Principal
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    EndpointPolicy,
    EndpointPolicyRevision,
    Execution,
    ExecutionEvent,
    JobVersion,
    SyncJob,
    SystemControl,
    TargetCopyLock,
    TargetNamespace,
    TransferPolicy,
    WorkTerminationRequest,
)
from datax_studio.core.schemas import (
    CredentialBinding,
    ExecutionCreate,
    ExecutionResponse,
    JobSpecV1,
    TargetEmptyEvidence,
)
from datax_studio.core.service import ControlService
from datax_studio.credentials.db import CredentialSecret, EndpointConnectionEvidence
from datax_studio.recovery.db import (
    RecoveryGate,
    RecoveryProbe,
    RecoveryProbeAttempt,
)
from datax_studio.recovery.gates import ensure_recovery_gate
from datax_studio.recovery.schemas import (
    ExecutionRerunCreate,
    RecoveryGateResponse,
    RecoveryProbeAttemptResponse,
    RecoveryProbeResponse,
    RecoverySubmissionResponse,
    RemediationConfirmation,
)


@dataclass(frozen=True)
class ClaimedRecoveryProbe:
    recovery_probe_id: UUID
    attempt_id: UUID
    fence_epoch: int
    lease_token: str


class CredentialBindingSelector(Protocol):
    def __call__(
        self,
        session: Session,
        *,
        source_datasource_id: UUID,
        target_datasource_id: UUID,
    ) -> CredentialBinding: ...


_ACTIVE_WORK_TERMINATION_STATUSES = ("PENDING", "ACKNOWLEDGED")
_TERMINATION_REASON_PRIORITY = {
    "SECRET_COMPROMISED": 0,
    "SECRET_REVOKED": 1,
    "TARGET_EXCLUSIVITY_REVOKED": 2,
    "TARGET_EXCLUSIVITY_EXPIRED": 3,
}
_TERMINATION_FAILURE_CODES = {
    "SECRET_COMPROMISED": "CREDENTIAL_SECRET_COMPROMISED",
    "SECRET_REVOKED": "CREDENTIAL_SECRET_REVOKED",
    "TARGET_EXCLUSIVITY_REVOKED": "TARGET_EXCLUSIVITY_BROKEN",
    "TARGET_EXCLUSIVITY_EXPIRED": "TARGET_EXCLUSIVITY_BROKEN",
}


class RecoveryService:
    """Recovery APIs and the independent, non-DataX target-empty fact queue."""

    def __init__(self, control: ControlService) -> None:
        self.control = control

    def get_gate(
        self,
        *,
        principal: Principal,
        execution_id: UUID,
    ) -> RecoveryGateResponse:
        with self.control.sessions() as session:
            execution = self.control._visible_execution(  # noqa: SLF001
                session,
                principal,
                execution_id,
            )
            gate = session.scalar(
                select(RecoveryGate).where(RecoveryGate.execution_id == execution.id)
            )
            if gate is None:
                self._gate_not_applicable()
            return self._gate_response(gate)

    def submit_remediation(
        self,
        *,
        principal: Principal,
        execution_id: UUID,
        request: RemediationConfirmation,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[RecoverySubmissionResponse]:
        now = utc_now()
        with self.control.sessions.begin() as session:
            execution = self.control._visible_execution(  # noqa: SLF001
                session,
                principal,
                execution_id,
                lock=True,
            )
            self.control._require_project_role(  # noqa: SLF001
                principal,
                execution.project_id,
                {Role.OPERATOR},
            )
            organization = self.control._lock_organization(  # noqa: SLF001
                session,
                principal.organization_id,
            )
            replay = self.control._claim_idempotency(  # noqa: SLF001
                session,
                actor_id=principal.user_id,
                scope="POST /executions/{execution_id}/recovery",
                key=idempotency_key,
                body=request.model_dump(mode="json"),
                now=now,
            )
            if replay is not None:
                return OperationResult(
                    RecoverySubmissionResponse.model_validate(replay.response_body),
                    replayed=True,
                )
            gate = session.scalar(
                select(RecoveryGate)
                .where(RecoveryGate.execution_id == execution.id)
                .with_for_update()
            )
            lock = session.scalar(
                select(TargetCopyLock)
                .where(TargetCopyLock.execution_id == execution.id)
                .with_for_update()
            )
            if (
                gate is None
                or lock is None
                or execution.attempt_count < 1
                or execution.process_state not in {"FAILED", "TIMED_OUT", "CANCELED", "LOST"}
                or lock.state != "RECOVERY_REQUIRED"
            ):
                self._gate_not_applicable()
            if gate.status not in {"OPEN", "REJECTED"}:
                raise ProblemException(
                    status=409,
                    code="RECOVERY_GATE_STATE_CONFLICT",
                    title="恢复门禁状态不允许重新提交",
                    detail="已提交或已通过的处置确认不可被覆盖。",
                )
            if request.confirmed_at > now + timedelta(minutes=5):
                raise ProblemException(
                    status=422,
                    code="VALIDATION_ERROR",
                    title="处置确认时间无效",
                    detail="confirmed_at 不能显著晚于服务端当前时间。",
                )
            # Serialize with current-secret emergency status transitions
            # before writing a new queue intention.  If revocation wins, the
            # datasource is DISABLED and no RecoveryProbe/Gate transition is
            # persisted.  If this submission wins, it commits while holding
            # the datasource row and the revocation's non-locking post-gate
            # scan records a durable WorkTerminationRequest for the probe.
            target_revision = session.get(
                DatasourceRevision,
                execution.target_datasource_revision_id,
            )
            target_datasource = (
                session.scalar(
                    select(Datasource)
                    .where(
                        Datasource.id == target_revision.datasource_id,
                        Datasource.project_id == execution.project_id,
                    )
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                if target_revision is not None
                else None
            )
            target_secret = (
                session.scalar(
                    select(CredentialSecret)
                    .where(
                        CredentialSecret.id == target_datasource.current_secret_id,
                        CredentialSecret.datasource_id == target_datasource.id,
                    )
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                if (
                    target_datasource is not None
                    and target_datasource.current_secret_id is not None
                )
                else None
            )
            if (
                target_revision is None
                or target_datasource is None
                or target_datasource.status != "ACTIVE"
                or target_secret is None
                or target_secret.status != "ACTIVE"
            ):
                raise ProblemException(
                    status=409,
                    code="CREDENTIAL_BINDING_NOT_ACTIVE",
                    title="目标数据源当前凭据不可用",
                    detail="恢复空表复检只会为 ACTIVE 数据源及其当前凭据创建队列。",
                )
            active_probe = session.scalar(
                select(RecoveryProbe.id).where(
                    RecoveryProbe.recovery_gate_id == gate.id,
                    RecoveryProbe.process_state.in_({"QUEUED", "STARTING", "RUNNING"}),
                )
            )
            if active_probe is not None:
                raise ProblemException(
                    status=409,
                    code="RECOVERY_PROBE_ALREADY_ACTIVE",
                    title="恢复空表复检已在进行",
                    detail="请等待当前 RecoveryProbe 完成后再提交新的处置确认。",
                )
            probe = RecoveryProbe(
                id=uuid4(),
                project_id=execution.project_id,
                recovery_gate_id=gate.id,
                target_namespace_id=execution.target_namespace_id,
                target_datasource_revision_id=(execution.target_datasource_revision_id),
                target_endpoint_policy_revision_id=(execution.target_endpoint_policy_revision_id),
                process_state="QUEUED",
                result="NOT_STARTED",
                fence_epoch=0,
                active_attempt_id=None,
                service_reservation_seconds=360,
                queue_eligibility_state="ELIGIBLE",
                queue_block_reason=None,
                queue_state_changed_at=now,
                eligible_wait_milliseconds=0,
                queued_at=now,
            )
            session.add(probe)
            session.flush()
            gate.status = "REMEDIATION_SUBMITTED"
            gate.remediation_confirmation = request.model_dump(mode="json")
            gate.target_empty_evidence = None
            gate.latest_recovery_probe_id = probe.id
            gate.submitted_at = now
            gate.verified_at = None
            gate.reason_code = None
            response = RecoverySubmissionResponse(
                recovery_gate=self._gate_response(gate),
                recovery_probe=self._probe_response(probe, None),
            )
            self.control._append_audit(  # noqa: SLF001
                session,
                organization=organization,
                project_id=execution.project_id,
                action="EXECUTION_REMEDIATION_SUBMITTED",
                actor_id=principal.user_id,
                target_type="RECOVERY_GATE",
                target_id=gate.id,
                target_name=None,
                changed_fields=[
                    "remediation_confirmation",
                    "recovery_probe",
                    "status",
                ],
                audit=audit,
                metadata={
                    "execution_id": str(execution.id),
                    "recovery_probe_id": str(probe.id),
                    "action": request.action,
                    "cleanup_performed": request.cleanup_performed,
                },
            )
            self.control._complete_idempotency(  # noqa: SLF001
                session,
                actor_id=principal.user_id,
                scope="POST /executions/{execution_id}/recovery",
                key=idempotency_key,
                status=202,
                body=response.model_dump(mode="json"),
                resource_type="RECOVERY_PROBE",
                resource_id=probe.id,
            )
            return OperationResult(response)

    def get_probe(
        self,
        *,
        principal: Principal,
        recovery_probe_id: UUID,
    ) -> RecoveryProbeResponse:
        with self.control.sessions() as session:
            probe = session.get(RecoveryProbe, recovery_probe_id)
            if probe is None:
                self.control._not_found()  # noqa: SLF001
            self.control._visible_project(  # noqa: SLF001
                session,
                principal,
                probe.project_id,
            )
            attempt = (
                session.get(RecoveryProbeAttempt, probe.active_attempt_id)
                if probe.active_attempt_id
                else None
            )
            return self._probe_response(probe, attempt)

    def rerun(
        self,
        *,
        principal: Principal,
        execution_id: UUID,
        request: ExecutionRerunCreate,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[ExecutionResponse]:
        now = utc_now()
        with self.control.sessions.begin() as session:
            original = self.control._visible_execution(  # noqa: SLF001
                session,
                principal,
                execution_id,
                lock=True,
            )
            self.control._require_project_role(  # noqa: SLF001
                principal,
                original.project_id,
                {Role.OPERATOR},
            )
            organization = self.control._lock_organization(  # noqa: SLF001
                session,
                principal.organization_id,
            )
            replay = self.control._claim_idempotency(  # noqa: SLF001
                session,
                actor_id=principal.user_id,
                scope="POST /executions/{execution_id}/rerun",
                key=idempotency_key,
                body=request.model_dump(mode="json"),
                now=now,
            )
            if replay is not None:
                return OperationResult(
                    ExecutionResponse.model_validate(replay.response_body),
                    replayed=True,
                )
            self.control._require_accepting_new_executions(session)  # noqa: SLF001
            gate = session.scalar(
                select(RecoveryGate)
                .where(RecoveryGate.id == request.recovery_gate_id)
                .with_for_update()
            )
            old_lock = session.scalar(
                select(TargetCopyLock)
                .where(TargetCopyLock.execution_id == original.id)
                .with_for_update()
            )
            if (
                gate is None
                or gate.execution_id != original.id
                or gate.status != "VERIFIED"
                or gate.target_empty_evidence is None
                or original.attempt_count < 1
                or original.process_state not in {"FAILED", "TIMED_OUT", "CANCELED", "LOST"}
                or old_lock is None
                or old_lock.state != "RECOVERY_REQUIRED"
            ):
                raise ProblemException(
                    status=409,
                    code="RECOVERY_GATE_NOT_VERIFIED",
                    title="恢复门禁尚未通过",
                    detail="必须先提交真实处置确认，并由 Worker 独立复检目标为空。",
                )
            target_empty = TargetEmptyEvidence.model_validate(gate.target_empty_evidence)
            namespace = session.get(TargetNamespace, original.target_namespace_id)
            version = session.get(JobVersion, original.job_version_id)
            job = session.get(SyncJob, original.job_id)
            if (
                namespace is None
                or version is None
                or job is None
                or target_empty.target_namespace_id != namespace.id
                or target_empty.physical_table_identity_hash
                != namespace.physical_table_identity_hash
            ):
                raise ProblemException(
                    status=409,
                    code="RECOVERY_TARGET_BINDING_MISMATCH",
                    title="恢复证据与原目标不匹配",
                    detail="不会使用不匹配的空表证据再次执行。",
                )
            self.control.require_job_version_plugin_certification(
                version=version,
                now=now,
            )
            execution_request = ExecutionCreate(
                job_version_id=version.id,
                source_quiescence_confirmation=(request.source_quiescence_confirmation),
                target_exclusivity_confirmation=(request.target_exclusivity_confirmation),
            )
            self.control._validate_execution_confirmations(  # noqa: SLF001
                execution_request,
                now,
            )
            spec = JobSpecV1.model_validate(version.spec_json)
            self.control._check_job_spec_resources(  # noqa: SLF001
                session,
                job.project_id,
                spec,
                lock_datasources=True,
            )
            policy = session.get(TransferPolicy, version.transfer_policy_id)
            if (
                job.status != "PUBLISHED"
                or policy is None
                or policy.status != "ACTIVE"
                or policy.scope_hash != version.transfer_policy_scope_hash
            ):
                raise ProblemException(
                    status=409,
                    code="JOB_NOT_PUBLISHED",
                    title="原任务版本已不可执行",
                    detail="恢复再次执行仍要求原 JobVersion 及传输授权有效。",
                )
            self.control._assert_policy_covers_spec(  # noqa: SLF001
                session,
                policy,
                spec,
            )
            self.control._require_datasource_grants(  # noqa: SLF001
                session,
                principal=principal,
                source_revision_id=version.source_datasource_revision_id,
                target_revision_id=version.target_datasource_revision_id,
            )
            queued_count = session.scalar(
                select(func.count(Execution.id)).where(Execution.process_state == "QUEUED")
            )
            if (queued_count or 0) >= 200:
                raise ProblemException(
                    status=503,
                    code="CAPACITY_ADMISSION_BLOCKED",
                    title="当前队列已达到安全上限",
                    detail="请等待现有工作完成后重试。",
                    retryable=True,
                )
            old_lock.state = "RELEASED"
            old_lock.released_at = now
            new_execution = self._new_rerun_execution(
                original=original,
                requested_by=principal.user_id,
                request=execution_request,
                spec=spec,
                now=now,
            )
            session.add(new_execution)
            session.flush()
            new_lock = TargetCopyLock(
                id=uuid4(),
                target_namespace_id=namespace.id,
                physical_table_identity_hash=(namespace.physical_table_identity_hash),
                execution_id=new_execution.id,
                state="RESERVED",
                reserved_at=now,
            )
            session.add(new_lock)
            session.add(
                ExecutionEvent(
                    id=uuid4(),
                    execution_id=new_execution.id,
                    sequence_no=1,
                    event_type="EXECUTION_RERUN_QUEUED",
                    from_state=None,
                    to_state="QUEUED",
                    payload={
                        "rerun_of_execution_id": str(original.id),
                        "recovery_gate_id": str(gate.id),
                        "target_lock_state": "RESERVED",
                    },
                    occurred_at=now,
                )
            )
            response = self.control._execution_response(  # noqa: SLF001
                new_execution,
                new_lock,
                version,
            )
            self.control._append_audit(  # noqa: SLF001
                session,
                organization=organization,
                project_id=original.project_id,
                action="EXECUTION_RERUN_CREATED",
                actor_id=principal.user_id,
                target_type="EXECUTION",
                target_id=new_execution.id,
                target_name=None,
                changed_fields=[
                    "execution",
                    "target_copy_lock",
                    "recovery_gate_id",
                ],
                audit=audit,
                metadata={
                    "original_execution_id": str(original.id),
                    "recovery_gate_id": str(gate.id),
                },
            )
            self.control._complete_idempotency(  # noqa: SLF001
                session,
                actor_id=principal.user_id,
                scope="POST /executions/{execution_id}/rerun",
                key=idempotency_key,
                status=202,
                body=response.model_dump(mode="json"),
                resource_type="EXECUTION",
                resource_id=new_execution.id,
            )
            return OperationResult(response)

    def claim_next_probe(
        self,
        *,
        worker_id: str,
        host_boot_id: str,
        cgroup_identity: str,
        credential_selector: CredentialBindingSelector,
        lease_seconds: int = 30,
    ) -> ClaimedRecoveryProbe | None:
        if not 5 <= lease_seconds <= 300:
            raise ValueError("lease_seconds must be between 5 and 300")
        with self.control.sessions.begin() as session:
            control = session.get(SystemControl, 1)
            if control is None or control.draining:
                raise ProblemException(
                    status=503,
                    code="SERVICE_DRAINING",
                    title="服务正在对账或停止",
                    detail="完成 Worker 对账前不会领取 RecoveryProbe。",
                    retryable=True,
                )
            now = self.control._database_now(session)  # noqa: SLF001
            pending_termination = (
                select(WorkTerminationRequest.id)
                .where(
                    WorkTerminationRequest.work_kind == "RECOVERY_PROBE",
                    WorkTerminationRequest.work_id == RecoveryProbe.id,
                    WorkTerminationRequest.status.in_(_ACTIVE_WORK_TERMINATION_STATUSES),
                )
                .exists()
            )
            probe = session.scalar(
                select(RecoveryProbe)
                .where(
                    RecoveryProbe.process_state == "QUEUED",
                    RecoveryProbe.active_attempt_id.is_(None),
                    RecoveryProbe.queue_eligibility_state == "ELIGIBLE",
                    ~pending_termination,
                )
                .order_by(RecoveryProbe.queued_at, RecoveryProbe.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if probe is None:
                return None
            gate = session.scalar(
                select(RecoveryGate)
                .where(RecoveryGate.id == probe.recovery_gate_id)
                .with_for_update()
            )
            execution = session.get(Execution, gate.execution_id) if gate is not None else None
            target_lock = (
                session.scalar(
                    select(TargetCopyLock)
                    .where(TargetCopyLock.execution_id == execution.id)
                    .with_for_update()
                )
                if execution is not None
                else None
            )
            revision = session.get(
                DatasourceRevision,
                probe.target_datasource_revision_id,
            )
            policy_revision = session.get(
                EndpointPolicyRevision,
                probe.target_endpoint_policy_revision_id,
            )
            datasource = (
                session.scalar(
                    select(Datasource)
                    .where(Datasource.id == revision.datasource_id)
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                if revision is not None
                else None
            )
            policy = (
                session.get(EndpointPolicy, policy_revision.endpoint_policy_id)
                if policy_revision is not None
                else None
            )
            # The initial selection happened before this transaction waited
            # for the datasource/credential gate.  A current-secret emergency
            # may have committed a durable stop during that wait.  Preserve
            # the request for the reconciler instead of converting the probe
            # into a generic blocked queue row and stranding its gate.
            if self._active_probe_termination_requests(
                session,
                recovery_probe_id=probe.id,
                lock=False,
            ):
                return None
            if (
                gate is None
                or gate.status != "REMEDIATION_SUBMITTED"
                or gate.latest_recovery_probe_id != probe.id
                or execution is None
                or target_lock is None
                or target_lock.state != "RECOVERY_REQUIRED"
                or revision is None
                or policy_revision is None
                or datasource is None
                or datasource.status != "ACTIVE"
                or policy is None
                or policy.status != "ACTIVE"
                or policy.current_revision_id != policy_revision.id
            ):
                probe.queue_eligibility_state = "BLOCKED"
                probe.queue_block_reason = "RECOVERY_BINDING_NOT_ACTIVE"
                probe.queue_state_changed_at = now
                return None
            try:
                binding = credential_selector(
                    session,
                    source_datasource_id=datasource.id,
                    target_datasource_id=datasource.id,
                )
            except ProblemException as exc:
                if exc.code != "CREDENTIAL_BINDING_NOT_ACTIVE":
                    raise
                if self._active_probe_termination_requests(
                    session,
                    recovery_probe_id=probe.id,
                    lock=False,
                ):
                    return None
                probe.queue_eligibility_state = "BLOCKED"
                probe.queue_block_reason = exc.code
                probe.queue_state_changed_at = now
                return None
            if self._active_probe_termination_requests(
                session,
                recovery_probe_id=probe.id,
                lock=False,
            ):
                return None
            token = secrets.token_urlsafe(32)
            next_fence = probe.fence_epoch + 1
            attempt = RecoveryProbeAttempt(
                id=uuid4(),
                recovery_probe_id=probe.id,
                attempt_no=next_fence,
                worker_id=worker_id,
                lease_token_hash=hashlib.sha256(token.encode("ascii")).hexdigest(),
                fence_epoch=next_fence,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                heartbeat_at=now,
                host_boot_id=host_boot_id,
                cgroup_identity=cgroup_identity,
                started_at=now,
            )
            session.add(attempt)
            session.flush()
            probe.fence_epoch = next_fence
            probe.active_attempt_id = attempt.id
            probe.process_state = "STARTING"
            probe.target_secret_id = binding.target_secret_id
            probe.target_secret_envelope_id = binding.target_secret_envelope_id
            probe.target_secret_version = binding.target_secret_version
            probe.eligible_wait_milliseconds += max(
                0,
                int((now - ensure_aware(probe.queue_state_changed_at)).total_seconds() * 1000),
            )
            return ClaimedRecoveryProbe(
                recovery_probe_id=probe.id,
                attempt_id=attempt.id,
                fence_epoch=next_fence,
                lease_token=token,
            )

    def start_claimed_probe(self, claim: ClaimedRecoveryProbe) -> None:
        termination_pending = False
        with self.control.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            probe, _attempt = self._current_probe_attempt(
                session,
                claim,
                now,
            )
            if probe.process_state != "STARTING":
                self._probe_fence_lost()
            termination_pending = bool(
                self._acknowledge_probe_termination_requests(
                    session,
                    recovery_probe_id=probe.id,
                    now=now,
                )
            )
            if not termination_pending:
                probe.process_state = "RUNNING"
        if termination_pending:
            raise ProblemException(
                status=409,
                code="RECOVERY_PROBE_TERMINATION_PENDING",
                title="恢复探针收到安全终止请求",
                detail="Worker 必须停止探针，不能发布空表核验结论。",
            )

    def heartbeat_probe(
        self,
        claim: ClaimedRecoveryProbe,
        *,
        lease_seconds: int = 30,
    ) -> datetime:
        termination_pending = False
        with self.control.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            probe, attempt = self._current_probe_attempt(session, claim, now)
            termination_pending = bool(
                self._acknowledge_probe_termination_requests(
                    session,
                    recovery_probe_id=probe.id,
                    now=now,
                )
            )
            if not termination_pending:
                attempt.heartbeat_at = now
                attempt.lease_expires_at = now + timedelta(seconds=lease_seconds)
                lease_expires_at = ensure_aware(attempt.lease_expires_at)
            else:
                lease_expires_at = ensure_aware(attempt.lease_expires_at)
        if termination_pending:
            raise ProblemException(
                status=409,
                code="RECOVERY_PROBE_TERMINATION_PENDING",
                title="恢复探针收到安全终止请求",
                detail="Worker 必须停止探针，不能发布空表核验结论。",
            )
        return lease_expires_at

    def poll_claimed_probe_termination(self, claim: ClaimedRecoveryProbe) -> bool:
        """Acknowledge an emergency stop at a bounded probe control point."""

        with self.control.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            probe, _attempt = self._current_probe_attempt(session, claim, now)
            return bool(
                self._acknowledge_probe_termination_requests(
                    session,
                    recovery_probe_id=probe.id,
                    now=now,
                )
            )

    def complete_claimed_probe_termination(self, claim: ClaimedRecoveryProbe) -> bool:
        """Fail a fenced probe closed so it cannot verify a recovery gate."""

        with self.control.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            probe, attempt = self._current_probe_attempt(session, claim, now)
            requests = self._acknowledge_probe_termination_requests(
                session,
                recovery_probe_id=probe.id,
                now=now,
            )
            if not requests:
                return False
            self._complete_probe_termination(
                session,
                probe=probe,
                attempt=attempt,
                requests=requests,
                now=now,
            )
            return True

    def reconcile_unclaimed_probe_termination(
        self,
        *,
        recovery_probe_id: UUID,
    ) -> bool:
        """Worker-only convergence for a queued RecoveryProbe safety stop.

        Unlike a claimed probe, a queued probe has no attempt or secret
        binding.  A durable WorkTerminationRequest created when its current
        datasource secret becomes terminal must still reject the gate, so an
        Operator can submit a fresh independently fenced remediation probe.
        """

        with self.control.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            probe = session.scalar(
                select(RecoveryProbe)
                .where(RecoveryProbe.id == recovery_probe_id)
                .with_for_update()
            )
            if (
                probe is None
                or probe.process_state != "QUEUED"
                or probe.active_attempt_id is not None
            ):
                return False
            requests = self._acknowledge_probe_termination_requests(
                session,
                recovery_probe_id=probe.id,
                now=now,
            )
            if not requests:
                return False
            self._complete_probe_termination(
                session,
                probe=probe,
                attempt=None,
                requests=requests,
                now=now,
            )
            return True

    def complete_probe(
        self,
        *,
        claim: ClaimedRecoveryProbe,
        result: str,
        target_connection_evidence_id: UUID | None = None,
        target_empty_evidence: dict | None = None,
        failure_code: str | None = None,
    ) -> None:
        if result not in {"EMPTY", "NONEMPTY", "INCONCLUSIVE"}:
            raise ValueError("invalid recovery probe result")
        with self.control.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            probe, attempt = self._current_probe_attempt(session, claim, now)
            if probe.process_state not in {"STARTING", "RUNNING"}:
                self._probe_fence_lost()
            requests = self._acknowledge_probe_termination_requests(
                session,
                recovery_probe_id=probe.id,
                now=now,
            )
            if requests:
                self._complete_probe_termination(
                    session,
                    probe=probe,
                    attempt=attempt,
                    requests=requests,
                    now=now,
                )
                return
            gate = session.scalar(
                select(RecoveryGate)
                .where(RecoveryGate.id == probe.recovery_gate_id)
                .with_for_update()
            )
            if gate is None or gate.latest_recovery_probe_id != probe.id:
                self._probe_fence_lost()
            process_state = "FAILED"
            connection = (
                session.get(
                    EndpointConnectionEvidence,
                    target_connection_evidence_id,
                )
                if target_connection_evidence_id is not None
                else None
            )
            if result in {"EMPTY", "NONEMPTY"} and (
                connection is None
                or connection.operation_kind != "RECOVERY_PROBE"
                or connection.decision != "ALLOWED"
                or connection.egress_enforcement_status != "VERIFIED"
                or connection.recovery_probe_id != probe.id
                or connection.attempt_id != attempt.id
                or connection.fence_epoch != claim.fence_epoch
                or connection.datasource_revision_id != probe.target_datasource_revision_id
                or connection.endpoint_policy_revision_id
                != probe.target_endpoint_policy_revision_id
            ):
                raise ProblemException(
                    status=409,
                    code="RECOVERY_PROBE_EVIDENCE_INVALID",
                    title="恢复探针连接证据无效",
                    detail="当前 fenced RecoveryProbe 缺少匹配的真实连接证据。",
                )
            if result == "EMPTY":
                evidence = TargetEmptyEvidence.model_validate(target_empty_evidence)
                evidence_document = evidence.model_dump(mode="json")
                claimed_hash = evidence_document.pop("evidence_hash")
                expected_hash = self._domain_hash(
                    "DXTARGETEMPTYv1",
                    evidence_document,
                )
                namespace = session.get(
                    TargetNamespace,
                    probe.target_namespace_id,
                )
                if (
                    not hmac.compare_digest(claimed_hash, expected_hash)
                    or connection.id != evidence.connection_evidence_id
                    or evidence.target_datasource_revision_id != probe.target_datasource_revision_id
                    or evidence.target_endpoint_policy_revision_id
                    != probe.target_endpoint_policy_revision_id
                    or evidence.target_namespace_id != probe.target_namespace_id
                    or namespace is None
                    or evidence.physical_table_identity_hash
                    != namespace.physical_table_identity_hash
                    or evidence.checked_at < ensure_aware(connection.observed_at)
                    or evidence.checked_at > now + timedelta(seconds=5)
                ):
                    raise ProblemException(
                        status=409,
                        code="RECOVERY_PROBE_EVIDENCE_INVALID",
                        title="恢复空表证据无效",
                        detail="只有当前 fenced RecoveryProbe 的真实连接证据可通过门禁。",
                    )
                process_state = "SUCCEEDED"
                gate.status = "VERIFIED"
                gate.target_empty_evidence = evidence.model_dump(mode="json")
                gate.verified_at = now
                gate.reason_code = None
            else:
                gate.status = "REJECTED"
                gate.target_empty_evidence = None
                gate.verified_at = None
                gate.reason_code = (
                    "TARGET_NONEMPTY"
                    if result == "NONEMPTY"
                    else failure_code or "RECOVERY_PROBE_INCONCLUSIVE"
                )
            probe.process_state = process_state
            probe.result = result
            probe.target_connection_evidence_id = target_connection_evidence_id
            probe.target_empty_evidence = target_empty_evidence
            probe.failure_code = failure_code
            probe.finished_at = now
            probe.active_attempt_id = None
            attempt.finished_at = now
            attempt.termination_reason = process_state

    @staticmethod
    def _active_probe_termination_requests(
        session: Session,
        *,
        recovery_probe_id: UUID,
        lock: bool,
    ) -> list[WorkTerminationRequest]:
        statement = (
            select(WorkTerminationRequest)
            .where(
                WorkTerminationRequest.work_kind == "RECOVERY_PROBE",
                WorkTerminationRequest.work_id == recovery_probe_id,
                WorkTerminationRequest.status.in_(_ACTIVE_WORK_TERMINATION_STATUSES),
            )
            .order_by(WorkTerminationRequest.requested_at, WorkTerminationRequest.id)
        )
        if lock:
            statement = statement.with_for_update()
        return list(session.scalars(statement))

    def _acknowledge_probe_termination_requests(
        self,
        session: Session,
        *,
        recovery_probe_id: UUID,
        now: datetime,
    ) -> list[WorkTerminationRequest]:
        requests = self._active_probe_termination_requests(
            session,
            recovery_probe_id=recovery_probe_id,
            lock=True,
        )
        for request in requests:
            if request.status == "PENDING":
                request.status = "ACKNOWLEDGED"
                request.acknowledged_at = now
        return requests

    def _complete_probe_termination(
        self,
        session: Session,
        *,
        probe: RecoveryProbe,
        attempt: RecoveryProbeAttempt | None,
        requests: list[WorkTerminationRequest],
        now: datetime,
    ) -> None:
        gate = session.scalar(
            select(RecoveryGate)
            .where(RecoveryGate.id == probe.recovery_gate_id)
            .with_for_update()
        )
        if gate is None or gate.latest_recovery_probe_id != probe.id:
            self._probe_fence_lost()
        primary = min(
            requests,
            key=lambda item: _TERMINATION_REASON_PRIORITY[item.reason_code],
        )
        failure_code = _TERMINATION_FAILURE_CODES[primary.reason_code]
        probe.process_state = "FAILED"
        probe.result = "INCONCLUSIVE"
        probe.target_empty_evidence = None
        probe.failure_code = failure_code
        probe.finished_at = now
        probe.active_attempt_id = None
        if attempt is not None:
            attempt.finished_at = now
            attempt.termination_reason = primary.reason_code
        else:
            probe.queue_eligibility_state = "BLOCKED"
            probe.queue_block_reason = failure_code
            probe.queue_state_changed_at = now
        gate.status = "REJECTED"
        gate.target_empty_evidence = None
        gate.verified_at = None
        gate.reason_code = failure_code
        for request in requests:
            request.status = "COMPLETED"
            request.acknowledged_at = request.acknowledged_at or now
            request.completed_at = now

    @staticmethod
    def ensure_gate(
        session: Session,
        *,
        execution: Execution,
        now: datetime,
    ) -> RecoveryGate | None:
        return ensure_recovery_gate(session, execution=execution, now=now)

    def _current_probe_attempt(
        self,
        session: Session,
        claim: ClaimedRecoveryProbe,
        now: datetime,
    ) -> tuple[RecoveryProbe, RecoveryProbeAttempt]:
        probe = session.scalar(
            select(RecoveryProbe)
            .where(RecoveryProbe.id == claim.recovery_probe_id)
            .with_for_update()
        )
        attempt = session.scalar(
            select(RecoveryProbeAttempt)
            .where(RecoveryProbeAttempt.id == claim.attempt_id)
            .with_for_update()
        )
        token_hash = hashlib.sha256(claim.lease_token.encode("ascii")).hexdigest()
        if (
            probe is None
            or attempt is None
            or probe.active_attempt_id != attempt.id
            or probe.fence_epoch != claim.fence_epoch
            or attempt.recovery_probe_id != probe.id
            or attempt.fence_epoch != claim.fence_epoch
            or not hmac.compare_digest(attempt.lease_token_hash, token_hash)
            or ensure_aware(attempt.lease_expires_at) <= now
        ):
            self._probe_fence_lost()
        return probe, attempt

    @staticmethod
    def _new_rerun_execution(
        *,
        original: Execution,
        requested_by: UUID,
        request: ExecutionCreate,
        spec: JobSpecV1,
        now: datetime,
    ) -> Execution:
        return Execution(
            id=uuid4(),
            project_id=original.project_id,
            job_id=original.job_id,
            job_version_id=original.job_version_id,
            rerun_of_execution_id=original.id,
            trigger_type="MANUAL",
            requested_by=requested_by,
            process_state="QUEUED",
            data_effect="NONE",
            verification_state="NOT_STARTED",
            state_version=1,
            fence_epoch=0,
            active_attempt_id=None,
            queue_priority=0,
            capacity_profile="LARGE",
            service_reservation_seconds=3600,
            log_reservation_bytes=0,
            workspace_reservation_bytes=0,
            queue_eligibility_state="ELIGIBLE",
            queue_block_reason=None,
            queue_state_changed_at=now,
            eligible_wait_milliseconds=0,
            queued_at=now,
            timeout_seconds=spec.execution_policy.timeout_seconds,
            source_datasource_revision_id=original.source_datasource_revision_id,
            target_datasource_revision_id=original.target_datasource_revision_id,
            source_endpoint_policy_revision_id=(original.source_endpoint_policy_revision_id),
            target_endpoint_policy_revision_id=(original.target_endpoint_policy_revision_id),
            target_namespace_id=original.target_namespace_id,
            source_quiescence_confirmation=(
                request.source_quiescence_confirmation.model_dump(mode="json")
            ),
            target_exclusivity_confirmation=(
                request.target_exclusivity_confirmation.model_dump(mode="json")
            ),
            target_exclusivity_status="ACTIVE",
            attempt_count=0,
            summary_parse_status="PENDING",
            log_truncated=False,
            log_incomplete=False,
            log_raw_received_bytes=0,
            log_redacted_received_bytes=0,
            log_stored_bytes=0,
            log_dropped_bytes=0,
            created_at=now,
        )

    @staticmethod
    def _gate_response(gate: RecoveryGate) -> RecoveryGateResponse:
        return RecoveryGateResponse(
            id=gate.id,
            execution_id=gate.execution_id,
            target_namespace_id=gate.target_namespace_id,
            status=gate.status,
            data_effect_at_open=gate.data_effect_at_open,
            remediation_confirmation=gate.remediation_confirmation,
            target_empty_evidence=gate.target_empty_evidence,
            latest_recovery_probe_id=gate.latest_recovery_probe_id,
            submitted_at=gate.submitted_at,
            verified_at=gate.verified_at,
            reason_code=gate.reason_code,
        )

    @staticmethod
    def _probe_response(
        probe: RecoveryProbe,
        attempt: RecoveryProbeAttempt | None,
    ) -> RecoveryProbeResponse:
        active_attempt = (
            RecoveryProbeAttemptResponse(
                id=attempt.id,
                recovery_probe_id=attempt.recovery_probe_id,
                attempt_no=attempt.attempt_no,
                fence_epoch=attempt.fence_epoch,
                started_at=attempt.started_at,
                finished_at=attempt.finished_at,
                termination_reason=attempt.termination_reason,
            )
            if attempt is not None
            else None
        )
        return RecoveryProbeResponse(
            id=probe.id,
            project_id=probe.project_id,
            recovery_gate_id=probe.recovery_gate_id,
            target_namespace_id=probe.target_namespace_id,
            target_datasource_revision_id=(probe.target_datasource_revision_id),
            target_endpoint_policy_revision_id=(probe.target_endpoint_policy_revision_id),
            process_state=probe.process_state,
            result=probe.result,
            fence_epoch=probe.fence_epoch,
            active_attempt=active_attempt,
            service_reservation_seconds=probe.service_reservation_seconds,
            queue_eligibility_state=probe.queue_eligibility_state,
            queue_block_reason=probe.queue_block_reason,
            queue_state_changed_at=probe.queue_state_changed_at,
            eligible_wait_milliseconds=probe.eligible_wait_milliseconds,
            queued_at=probe.queued_at,
            finished_at=probe.finished_at,
            target_connection_evidence_id=(probe.target_connection_evidence_id),
            target_empty_evidence=probe.target_empty_evidence,
            failure_code=probe.failure_code,
        )

    @staticmethod
    def _domain_hash(domain: str, value: object) -> str:
        return hashlib.sha256(domain.encode("ascii") + b"\n" + rfc8785.dumps(value)).hexdigest()

    @staticmethod
    def _gate_not_applicable() -> None:
        raise ProblemException(
            status=409,
            code="RECOVERY_GATE_NOT_APPLICABLE",
            title="该执行不适用恢复门禁",
            detail="只有已领取且未成功完成的执行才需要人工处置与空表复检。",
        )

    @staticmethod
    def _probe_fence_lost() -> None:
        raise ProblemException(
            status=409,
            code="RECOVERY_PROBE_FENCE_LOST",
            title="恢复探针租约或围栏已失效",
            detail="旧 Worker 不得继续写入 RecoveryProbe 事实。",
        )
