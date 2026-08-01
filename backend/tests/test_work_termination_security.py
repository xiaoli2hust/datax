from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select
from test_core_control_plane import (
    CoreStack,
    PublishedJob,
    _credential_selector,
    _execution_request,
    _seed_published_job,
    core_stack,
)

from datax_studio.api.problems import ProblemException
from datax_studio.auth.service import AuditContext
from datax_studio.core.db import Datasource, Execution, TargetCopyLock, WorkTerminationRequest
from datax_studio.core.schemas import ClaimedExecution, CredentialBinding
from datax_studio.core.service import ControlService
from datax_studio.credentials.connectors import DatabaseConnector
from datax_studio.credentials.db import CredentialSecret
from datax_studio.credentials.keyring import KekKeyring
from datax_studio.credentials.network import EndpointPolicyGuard
from datax_studio.credentials.schemas import CredentialSecretStatusChange
from datax_studio.credentials.service import CredentialService
from datax_studio.recovery.db import RecoveryGate, RecoveryProbe, RecoveryProbeAttempt
from datax_studio.recovery.service import ClaimedRecoveryProbe, RecoveryService
from datax_studio.worker.reconcile import RuntimeIdentity, WorkerReconciler

__all__ = ["core_stack"]


def _credential_service(
    core_stack: CoreStack,
    *,
    keyring_root: Path,
) -> CredentialService:
    guard = EndpointPolicyGuard(
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        connect_timeout_seconds=1,
    )
    return CredentialService(
        sessions=core_stack.sessions,
        keyring=KekKeyring(keyring_root),
        active_kek_version="v1",
        integrity_hmac_key=b"work-termination-test-hmac-key-1",
        guard=guard,
        connector=DatabaseConnector(
            guard=guard,
            connect_timeout_seconds=1,
            query_timeout_seconds=1,
        ),
    )


def _claim_execution(
    core_stack: CoreStack,
    *,
    suffix: str,
) -> tuple[PublishedJob, UUID, ClaimedExecution]:
    published = _seed_published_job(core_stack, suffix)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"termination-{suffix}-execution"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 202, created.text
    execution_id = UUID(created.json()["id"])
    claim = core_stack.service.claim_next_execution(
        worker_id=f"worker-{suffix}",
        host_boot_id=f"boot-{suffix}",
        cgroup_identity=f"container:{suffix}",
        credential_selector=_credential_selector(
            published,
            CredentialBinding(
                source_secret_id=published.source_secret_id,
                target_secret_id=published.target_secret_id,
                source_secret_envelope_id=uuid4(),
                target_secret_envelope_id=uuid4(),
                source_secret_version=1,
                target_secret_version=1,
            ),
        ),
    )
    assert claim is not None
    return published, execution_id, claim


def _persist_active_secret(
    core_stack: CoreStack,
    *,
    datasource_id: UUID,
    secret_id: UUID,
) -> None:
    now = datetime.now(UTC)
    with core_stack.sessions.begin() as session:
        existing = session.get(CredentialSecret, secret_id)
        if existing is not None:
            assert existing.datasource_id == datasource_id
            assert existing.status == "ACTIVE"
            return
        session.add(
            CredentialSecret(
                id=secret_id,
                datasource_id=datasource_id,
                secret_version=1,
                ciphertext=b"opaque-test-ciphertext",
                nonce=b"n" * 12,
                data_algorithm="AES-256-GCM",
                aad_schema_version="1.0",
                status="ACTIVE",
                status_reason_code=None,
                created_by=core_stack.principal.user_id,
                created_at=now,
                status_changed_at=now,
            )
        )


def _persist_active_target_secret(
    core_stack: CoreStack,
    *,
    published: PublishedJob,
) -> None:
    _persist_active_secret(
        core_stack,
        datasource_id=published.target_datasource_id,
        secret_id=published.target_secret_id,
    )


def _persist_active_source_secret(
    core_stack: CoreStack,
    *,
    published: PublishedJob,
) -> None:
    _persist_active_secret(
        core_stack,
        datasource_id=published.source_datasource_id,
        secret_id=published.source_secret_id,
    )


def _rotate_target_current_secret_for_test(
    core_stack: CoreStack,
    *,
    published: PublishedJob,
) -> UUID:
    """Install a replacement current secret without rewriting an old binding."""

    replacement_secret_id = uuid4()
    now = datetime.now(UTC)
    with core_stack.sessions.begin() as session:
        datasource = session.get(Datasource, published.target_datasource_id)
        assert datasource is not None
        session.add(
            CredentialSecret(
                id=replacement_secret_id,
                datasource_id=datasource.id,
                secret_version=2,
                ciphertext=b"opaque-rotated-test-ciphertext",
                nonce=b"r" * 12,
                data_algorithm="AES-256-GCM",
                aad_schema_version="1.0",
                status="ACTIVE",
                status_reason_code=None,
                created_by=core_stack.principal.user_id,
                created_at=now,
                status_changed_at=now,
            )
        )
        datasource.current_secret_id = replacement_secret_id
        datasource.row_version += 1
        datasource.updated_at = now
    return replacement_secret_id


def _change_target_secret_status(
    core_stack: CoreStack,
    *,
    service: CredentialService,
    published: PublishedJob,
    status: str,
    suffix: str,
    datasource_id: UUID | None = None,
) -> None:
    result = service.change_secret_status(
        principal=core_stack.principal,
        datasource_id=datasource_id or published.target_datasource_id,
        secret_version=1,
        request=CredentialSecretStatusChange(
            status=status,  # type: ignore[arg-type]
            reason_code=f"TEST_{status}",
        ),
        idempotency_key=f"termination-{suffix}-{status.lower()}",
        audit=AuditContext(
            request_id=uuid4(),
            source_ip="127.0.0.1",
            user_agent="work-termination-security-test",
        ),
    )
    assert result.value.status == status


def _claim_recovery_probe(
    core_stack: CoreStack,
    *,
    published: PublishedJob,
    execution_id: UUID,
    execution_claim: ClaimedExecution,
    suffix: str,
) -> tuple[RecoveryService, UUID, ClaimedRecoveryProbe]:
    core_stack.service.transition_claimed_execution(
        claim=execution_claim,
        expected_state="STARTING",
        new_state="FAILED",
        data_effect="NONE",
        verification_state="NOT_STARTED",
        failure_code="PREFLIGHT_FAILED",
        failure_message="prepare a recovery probe for termination testing",
    )
    remediation = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/recovery",
        headers={"Idempotency-Key": f"termination-{suffix}-remediation"},
        json={
            "action": "NO_CLEANUP_REQUIRED",
            "cleanup_performed": False,
            "reason": "DataX did not start; independently prove the target is empty.",
            "confirmed_at": datetime.now(UTC).isoformat(),
        },
    )
    assert remediation.status_code == 202, remediation.text
    probe_id = UUID(remediation.json()["recovery_probe"]["id"])
    recovery = RecoveryService(core_stack.service)
    probe_claim = recovery.claim_next_probe(
        worker_id=f"worker-probe-{suffix}",
        host_boot_id=f"boot-probe-{suffix}",
        cgroup_identity=f"container:probe-{suffix}",
        credential_selector=lambda _session, **_kwargs: CredentialBinding(
            source_secret_id=published.target_secret_id,
            target_secret_id=published.target_secret_id,
            source_secret_envelope_id=uuid4(),
            target_secret_envelope_id=uuid4(),
            source_secret_version=1,
            target_secret_version=1,
        ),
    )
    assert probe_claim is not None
    assert probe_claim.recovery_probe_id == probe_id
    return recovery, probe_id, probe_claim


def _queue_recovery_probe(
    core_stack: CoreStack,
    *,
    published: PublishedJob,
    execution_id: UUID,
    execution_claim: ClaimedExecution,
    suffix: str,
) -> UUID:
    core_stack.service.transition_claimed_execution(
        claim=execution_claim,
        expected_state="STARTING",
        new_state="FAILED",
        data_effect="NONE",
        verification_state="NOT_STARTED",
        failure_code="PREFLIGHT_FAILED",
        failure_message="prepare a queued recovery probe for termination testing",
    )
    remediation = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/recovery",
        headers={"Idempotency-Key": f"termination-{suffix}-queued-remediation"},
        json={
            "action": "NO_CLEANUP_REQUIRED",
            "cleanup_performed": False,
            "reason": "DataX did not start; independently prove the target is empty.",
            "confirmed_at": datetime.now(UTC).isoformat(),
        },
    )
    assert remediation.status_code == 202, remediation.text
    return UUID(remediation.json()["recovery_probe"]["id"])


@pytest.mark.parametrize("status", ["REVOKED", "COMPROMISED"])
@pytest.mark.parametrize("work_kind", ["EXECUTION", "RECOVERY_PROBE"])
def test_emergency_secret_status_creates_bound_work_termination_request(
    core_stack: CoreStack,
    tmp_path: Path,
    status: str,
    work_kind: str,
) -> None:
    suffix = f"{work_kind.lower()}-{status.lower()}"
    published, execution_id, execution_claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    _persist_active_target_secret(core_stack, published=published)
    work_id = execution_id
    if work_kind == "RECOVERY_PROBE":
        _recovery, work_id, _probe_claim = _claim_recovery_probe(
            core_stack,
            published=published,
            execution_id=execution_id,
            execution_claim=execution_claim,
            suffix=suffix,
        )

    _change_target_secret_status(
        core_stack,
        service=_credential_service(core_stack, keyring_root=tmp_path),
        published=published,
        status=status,
        suffix=suffix,
    )

    with core_stack.sessions() as session:
        requests = list(
            session.scalars(
                select(WorkTerminationRequest).where(
                    WorkTerminationRequest.credential_secret_id == published.target_secret_id
                )
            )
        )
        assert len(requests) == 1
        request = requests[0]
        assert request.work_kind == work_kind
        assert request.work_id == work_id
        assert request.reason_code == f"SECRET_{status}"
        assert request.status == "PENDING"
        assert request.acknowledged_at is None
        assert request.completed_at is None


@pytest.mark.parametrize("work_kind", ["EXECUTION", "RECOVERY_PROBE"])
def test_retired_secret_does_not_terminate_already_bound_work(
    core_stack: CoreStack,
    tmp_path: Path,
    work_kind: str,
) -> None:
    suffix = f"{work_kind.lower()}-retired"
    published, execution_id, execution_claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    _persist_active_target_secret(core_stack, published=published)
    if work_kind == "RECOVERY_PROBE":
        _claim_recovery_probe(
            core_stack,
            published=published,
            execution_id=execution_id,
            execution_claim=execution_claim,
            suffix=suffix,
        )
    _rotate_target_current_secret_for_test(core_stack, published=published)

    _change_target_secret_status(
        core_stack,
        service=_credential_service(core_stack, keyring_root=tmp_path),
        published=published,
        status="RETIRED",
        suffix=suffix,
    )

    with core_stack.sessions() as session:
        assert (
            session.scalar(
                select(func.count(WorkTerminationRequest.id)).where(
                    WorkTerminationRequest.credential_secret_id == published.target_secret_id
                )
            )
            == 0
        )


def test_retired_secret_can_escalate_to_compromised_and_stop_bound_execution(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    suffix = "execution-retired-escalation"
    published, _execution_id, _claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    _persist_active_target_secret(core_stack, published=published)
    _rotate_target_current_secret_for_test(core_stack, published=published)
    service = _credential_service(core_stack, keyring_root=tmp_path)
    _change_target_secret_status(
        core_stack,
        service=service,
        published=published,
        status="RETIRED",
        suffix=suffix,
    )
    _change_target_secret_status(
        core_stack,
        service=service,
        published=published,
        status="COMPROMISED",
        suffix=f"{suffix}-compromised",
    )

    with core_stack.sessions() as session:
        secret = session.get(CredentialSecret, published.target_secret_id)
        requests = list(
            session.scalars(
                select(WorkTerminationRequest).where(
                    WorkTerminationRequest.credential_secret_id
                    == published.target_secret_id
                )
            )
        )
        assert secret is not None and secret.status == "COMPROMISED"
        assert len(requests) == 1
        assert requests[0].reason_code == "SECRET_COMPROMISED"
        assert requests[0].status == "PENDING"


def test_current_secret_retirement_is_rejected_before_queued_work_is_stranded(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    suffix = "current-secret-retirement-rejected"
    published = _seed_published_job(core_stack, suffix)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"termination-{suffix}-execution"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 202, created.text
    service = _credential_service(core_stack, keyring_root=tmp_path)

    with pytest.raises(ProblemException) as blocked:
        service.change_secret_status(
            principal=core_stack.principal,
            datasource_id=published.target_datasource_id,
            secret_version=1,
            request=CredentialSecretStatusChange(
                status="RETIRED",
                reason_code="TEST_CURRENT_RETIRE",
            ),
            idempotency_key=f"termination-{suffix}-retire",
            audit=AuditContext(
                request_id=uuid4(),
                source_ip="127.0.0.1",
                user_agent="work-termination-security-test",
            ),
        )
    assert blocked.value.code == "CREDENTIAL_STATUS_CONFLICT"

    claim = core_stack.service.claim_next_execution(
        worker_id="current-secret-retirement-worker",
        host_boot_id="current-secret-retirement-boot",
        cgroup_identity="container:current-secret-retirement",
        credential_selector=_credential_selector(
            published,
            CredentialBinding(
                source_secret_id=published.source_secret_id,
                target_secret_id=published.target_secret_id,
                source_secret_envelope_id=uuid4(),
                target_secret_envelope_id=uuid4(),
                source_secret_version=1,
                target_secret_version=1,
            ),
        ),
    )
    assert claim is not None
    with core_stack.sessions() as session:
        secret = session.get(CredentialSecret, published.target_secret_id)
        datasource = session.get(Datasource, published.target_datasource_id)
        assert secret is not None and secret.status == "ACTIVE"
        assert datasource is not None and datasource.status == "ACTIVE"


@pytest.mark.parametrize("status", ["REVOKED", "COMPROMISED"])
@pytest.mark.parametrize("is_source", [False, True], ids=["target", "source"])
def test_current_secret_emergency_terminates_queued_execution_and_releases_reservation(
    core_stack: CoreStack,
    tmp_path: Path,
    status: str,
    is_source: bool,
) -> None:
    side = "source" if is_source else "target"
    suffix = f"queued-execution-{side}-current-{status.lower()}"
    published = _seed_published_job(core_stack, suffix)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"termination-{suffix}-execution"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 202, created.text
    execution_id = UUID(created.json()["id"])
    datasource_id = (
        published.source_datasource_id if is_source else published.target_datasource_id
    )
    secret_id = published.source_secret_id if is_source else published.target_secret_id
    if is_source:
        _persist_active_source_secret(core_stack, published=published)
    else:
        _persist_active_target_secret(core_stack, published=published)

    _change_target_secret_status(
        core_stack,
        service=_credential_service(core_stack, keyring_root=tmp_path),
        published=published,
        status=status,
        suffix=suffix,
        datasource_id=datasource_id,
    )

    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        request = session.scalar(
            select(WorkTerminationRequest).where(
                WorkTerminationRequest.work_kind == "EXECUTION",
                WorkTerminationRequest.work_id == execution_id,
                WorkTerminationRequest.credential_secret_id == secret_id,
            )
        )
        target_lock = session.scalar(
            select(TargetCopyLock).where(TargetCopyLock.execution_id == execution_id)
        )
        assert execution is not None
        assert execution.process_state == "QUEUED"
        assert execution.source_secret_id is None
        assert execution.target_secret_id is None
        assert request is not None
        assert request.reason_code == f"SECRET_{status}"
        assert request.status == "PENDING"
        assert target_lock is not None and target_lock.state == "RESERVED"

    reconciler = WorkerReconciler(
        control=core_stack.service,
        sessions=core_stack.sessions,
    )
    assert reconciler.reconcile_pending_work_terminations(
        identity=RuntimeIdentity(
            host_boot_id="queued-execution-stop",
            cgroup_identity="queued-execution-stop",
        )
    ) == 1

    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        request = session.scalar(
            select(WorkTerminationRequest).where(
                WorkTerminationRequest.work_kind == "EXECUTION",
                WorkTerminationRequest.work_id == execution_id,
            )
        )
        target_lock = session.scalar(
            select(TargetCopyLock).where(TargetCopyLock.execution_id == execution_id)
        )
        assert execution is not None
        assert execution.process_state == "CANCELED"
        assert execution.data_effect == "NONE"
        assert execution.verification_state == "NOT_STARTED"
        assert execution.failure_code == f"CREDENTIAL_SECRET_{status}"
        assert target_lock is not None and target_lock.state == "RELEASED"
        assert request is not None and request.status == "COMPLETED"
        assert request.acknowledged_at is not None
        assert request.completed_at is not None


@pytest.mark.parametrize("status", ["REVOKED", "COMPROMISED"])
def test_current_secret_emergency_terminates_queued_probe_and_rejects_gate(
    core_stack: CoreStack,
    tmp_path: Path,
    status: str,
) -> None:
    suffix = f"queued-probe-current-{status.lower()}"
    published, execution_id, execution_claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    probe_id = _queue_recovery_probe(
        core_stack,
        published=published,
        execution_id=execution_id,
        execution_claim=execution_claim,
        suffix=suffix,
    )
    _persist_active_target_secret(core_stack, published=published)

    _change_target_secret_status(
        core_stack,
        service=_credential_service(core_stack, keyring_root=tmp_path),
        published=published,
        status=status,
        suffix=suffix,
    )

    with core_stack.sessions() as session:
        probe = session.get(RecoveryProbe, probe_id)
        request = session.scalar(
            select(WorkTerminationRequest).where(
                WorkTerminationRequest.work_kind == "RECOVERY_PROBE",
                WorkTerminationRequest.work_id == probe_id,
                WorkTerminationRequest.credential_secret_id == published.target_secret_id,
            )
        )
        assert probe is not None
        assert probe.process_state == "QUEUED"
        assert probe.target_secret_id is None
        assert request is not None
        assert request.reason_code == f"SECRET_{status}"
        assert request.status == "PENDING"

    reconciler = WorkerReconciler(
        control=core_stack.service,
        sessions=core_stack.sessions,
    )
    assert reconciler.reconcile_pending_work_terminations(
        identity=RuntimeIdentity(
            host_boot_id="queued-probe-stop",
            cgroup_identity="queued-probe-stop",
        )
    ) == 1

    with core_stack.sessions() as session:
        probe = session.get(RecoveryProbe, probe_id)
        gate = session.scalar(select(RecoveryGate).where(RecoveryGate.execution_id == execution_id))
        request = session.scalar(
            select(WorkTerminationRequest).where(
                WorkTerminationRequest.work_kind == "RECOVERY_PROBE",
                WorkTerminationRequest.work_id == probe_id,
            )
        )
        assert probe is not None
        assert probe.process_state == "FAILED"
        assert probe.result == "INCONCLUSIVE"
        assert probe.active_attempt_id is None
        assert probe.failure_code == f"CREDENTIAL_SECRET_{status}"
        assert probe.queue_eligibility_state == "BLOCKED"
        assert probe.queue_block_reason == f"CREDENTIAL_SECRET_{status}"
        assert gate is not None
        assert gate.status == "REJECTED"
        assert gate.latest_recovery_probe_id == probe_id
        assert gate.target_empty_evidence is None
        assert gate.verified_at is None
        assert gate.reason_code == f"CREDENTIAL_SECRET_{status}"
        assert request is not None and request.status == "COMPLETED"
        assert request.acknowledged_at is not None
        assert request.completed_at is not None


def test_current_secret_emergency_post_gate_rescan_covers_first_scan_omission(
    core_stack: CoreStack,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A queue row that slips past the first scan still gets a durable stop.

    This models the only unsafe interleaving: an execution producer wins before
    the status transition acquires the datasource gate, but the initial
    Work-row scan did not observe it.  The post-gate scan must create the WTR;
    the reconciler then releases the otherwise RESERVED target lock.
    """

    suffix = "post-gate-rescan-first-scan-omission"
    published = _seed_published_job(core_stack, suffix)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"termination-{suffix}-execution"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 202, created.text
    execution_id = UUID(created.json()["id"])
    _persist_active_target_secret(core_stack, published=published)

    monkeypatch.setattr(
        CredentialService,
        "_lock_potential_work_for_secret_status",
        staticmethod(lambda *_args, **_kwargs: ([], [])),
    )
    _change_target_secret_status(
        core_stack,
        service=_credential_service(core_stack, keyring_root=tmp_path),
        published=published,
        status="REVOKED",
        suffix=suffix,
    )

    with core_stack.sessions() as session:
        termination = session.scalar(
            select(WorkTerminationRequest).where(
                WorkTerminationRequest.work_kind == "EXECUTION",
                WorkTerminationRequest.work_id == execution_id,
                WorkTerminationRequest.reason_code == "SECRET_REVOKED",
            )
        )
        assert termination is not None and termination.status == "PENDING"

    reconciler = WorkerReconciler(
        control=core_stack.service,
        sessions=core_stack.sessions,
    )
    assert reconciler.reconcile_pending_work_terminations(
        identity=RuntimeIdentity(
            host_boot_id="post-gate-rescan",
            cgroup_identity="post-gate-rescan",
        )
    ) == 1
    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(TargetCopyLock.execution_id == execution_id)
        )
        assert execution is not None and execution.process_state == "CANCELED"
        assert target_lock is not None and target_lock.state == "RELEASED"


def test_new_execution_rejects_after_current_secret_revocation_disables_datasource(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    suffix = "create-after-current-secret-revocation"
    published = _seed_published_job(core_stack, suffix)
    _persist_active_target_secret(core_stack, published=published)
    _change_target_secret_status(
        core_stack,
        service=_credential_service(core_stack, keyring_root=tmp_path),
        published=published,
        status="COMPROMISED",
        suffix=suffix,
    )

    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"termination-{suffix}-execution"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 409, created.text
    assert created.json()["code"] == "DATASOURCE_DISABLED"
    with core_stack.sessions() as session:
        assert (
            session.scalar(
                select(func.count(Execution.id)).where(
                    Execution.job_id == published.job_id
                )
            )
            == 0
        )


def test_recovery_submission_rejects_revoked_current_binding_without_wedging_gate(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    suffix = "recovery-submit-after-current-secret-revocation"
    published, execution_id, execution_claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    core_stack.service.transition_claimed_execution(
        claim=execution_claim,
        expected_state="STARTING",
        new_state="FAILED",
        data_effect="NONE",
        verification_state="NOT_STARTED",
        failure_code="PREFLIGHT_FAILED",
        failure_message="open a recovery gate before revoking the target credential",
    )
    _persist_active_target_secret(core_stack, published=published)
    _change_target_secret_status(
        core_stack,
        service=_credential_service(core_stack, keyring_root=tmp_path),
        published=published,
        status="REVOKED",
        suffix=suffix,
    )

    submitted = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/recovery",
        headers={"Idempotency-Key": f"termination-{suffix}-remediation"},
        json={
            "action": "NO_CLEANUP_REQUIRED",
            "cleanup_performed": False,
            "reason": "The target credential is disabled; do not enqueue a probe.",
            "confirmed_at": datetime.now(UTC).isoformat(),
        },
    )
    assert submitted.status_code == 409, submitted.text
    assert submitted.json()["code"] == "CREDENTIAL_BINDING_NOT_ACTIVE"
    with core_stack.sessions() as session:
        gate = session.scalar(
            select(RecoveryGate).where(RecoveryGate.execution_id == execution_id)
        )
        assert gate is not None
        probe_count = session.scalar(
            select(func.count(RecoveryProbe.id)).where(
                RecoveryProbe.recovery_gate_id == gate.id
            )
        )
        assert gate.status == "OPEN"
        assert probe_count == 0


def test_execution_claim_rechecks_termination_after_credential_gate(
    core_stack: CoreStack,
) -> None:
    suffix = "execution-claim-post-credential-termination"
    published = _seed_published_job(core_stack, suffix)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"termination-{suffix}-execution"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 202, created.text
    execution_id = UUID(created.json()["id"])
    _persist_active_target_secret(core_stack, published=published)

    def select_then_create_termination(session, **_kwargs) -> CredentialBinding:
        ControlService._ensure_work_termination_request(  # noqa: SLF001
            session,
            work_kind="EXECUTION",
            work_id=execution_id,
            reason_code="SECRET_REVOKED",
            credential_secret_id=published.target_secret_id,
            now=datetime.now(UTC),
        )
        return CredentialBinding(
            source_secret_id=published.source_secret_id,
            target_secret_id=published.target_secret_id,
            source_secret_envelope_id=uuid4(),
            target_secret_envelope_id=uuid4(),
            source_secret_version=1,
            target_secret_version=1,
        )

    claim = core_stack.service.claim_next_execution(
        worker_id="post-credential-stop-worker",
        host_boot_id="post-credential-stop-boot",
        cgroup_identity="container:post-credential-stop",
        credential_selector=select_then_create_termination,
    )
    assert claim is None
    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(TargetCopyLock.execution_id == execution_id)
        )
        assert execution is not None and execution.process_state == "QUEUED"
        assert execution.queue_eligibility_state == "ELIGIBLE"
        assert target_lock is not None and target_lock.state == "RESERVED"
    reconciler = WorkerReconciler(
        control=core_stack.service,
        sessions=core_stack.sessions,
    )
    assert reconciler.reconcile_pending_work_terminations(
        identity=RuntimeIdentity(
            host_boot_id="post-credential-stop",
            cgroup_identity="post-credential-stop",
        )
    ) == 1
    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(TargetCopyLock.execution_id == execution_id)
        )
        assert execution is not None and execution.process_state == "CANCELED"
        assert target_lock is not None and target_lock.state == "RELEASED"


def test_probe_claim_rechecks_termination_after_credential_gate(
    core_stack: CoreStack,
) -> None:
    suffix = "probe-claim-post-credential-termination"
    published, execution_id, execution_claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    _persist_active_target_secret(core_stack, published=published)
    probe_id = _queue_recovery_probe(
        core_stack,
        published=published,
        execution_id=execution_id,
        execution_claim=execution_claim,
        suffix=suffix,
    )
    recovery = RecoveryService(core_stack.service)

    def select_then_create_termination(session, **_kwargs) -> CredentialBinding:
        ControlService._ensure_work_termination_request(  # noqa: SLF001
            session,
            work_kind="RECOVERY_PROBE",
            work_id=probe_id,
            reason_code="SECRET_COMPROMISED",
            credential_secret_id=published.target_secret_id,
            now=datetime.now(UTC),
        )
        return CredentialBinding(
            source_secret_id=published.target_secret_id,
            target_secret_id=published.target_secret_id,
            source_secret_envelope_id=uuid4(),
            target_secret_envelope_id=uuid4(),
            source_secret_version=1,
            target_secret_version=1,
        )

    claim = recovery.claim_next_probe(
        worker_id="post-credential-probe-worker",
        host_boot_id="post-credential-probe-boot",
        cgroup_identity="container:post-credential-probe",
        credential_selector=select_then_create_termination,
    )
    assert claim is None
    with core_stack.sessions() as session:
        probe = session.get(RecoveryProbe, probe_id)
        gate = session.scalar(
            select(RecoveryGate).where(RecoveryGate.execution_id == execution_id)
        )
        assert probe is not None and probe.process_state == "QUEUED"
        assert probe.queue_eligibility_state == "ELIGIBLE"
        assert gate is not None and gate.status == "REMEDIATION_SUBMITTED"
    reconciler = WorkerReconciler(
        control=core_stack.service,
        sessions=core_stack.sessions,
    )
    assert reconciler.reconcile_pending_work_terminations(
        identity=RuntimeIdentity(
            host_boot_id="post-credential-probe",
            cgroup_identity="post-credential-probe",
        )
    ) == 1
    with core_stack.sessions() as session:
        probe = session.get(RecoveryProbe, probe_id)
        gate = session.scalar(
            select(RecoveryGate).where(RecoveryGate.execution_id == execution_id)
        )
        assert probe is not None and probe.process_state == "FAILED"
        assert gate is not None and gate.status == "REJECTED"


def test_retired_noncurrent_secret_does_not_terminate_queued_work(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    suffix = "queued-execution-retired-noncurrent"
    published = _seed_published_job(core_stack, suffix)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"termination-{suffix}-execution"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 202, created.text
    execution_id = UUID(created.json()["id"])
    retired_secret_id = uuid4()
    now = datetime.now(UTC)
    with core_stack.sessions.begin() as session:
        session.add(
            CredentialSecret(
                id=retired_secret_id,
                datasource_id=published.target_datasource_id,
                secret_version=2,
                ciphertext=b"opaque-retired-test-ciphertext",
                nonce=b"r" * 12,
                data_algorithm="AES-256-GCM",
                aad_schema_version="1.0",
                status="RETIRED",
                status_reason_code="ROTATED",
                created_by=core_stack.principal.user_id,
                created_at=now,
                status_changed_at=now,
                retired_at=now,
            )
        )

    result = _credential_service(
        core_stack,
        keyring_root=tmp_path,
    ).change_secret_status(
        principal=core_stack.principal,
        datasource_id=published.target_datasource_id,
        secret_version=2,
        request=CredentialSecretStatusChange(
            status="REVOKED",
            reason_code="TEST_RETIRED_NONCURRENT",
        ),
        idempotency_key=f"termination-{suffix}-revoke",
        audit=AuditContext(
            request_id=uuid4(),
            source_ip="127.0.0.1",
            user_agent="work-termination-security-test",
        ),
    )
    assert result.value.status == "REVOKED"

    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        datasource = session.get(Datasource, published.target_datasource_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(TargetCopyLock.execution_id == execution_id)
        )
        request_count = session.scalar(
            select(func.count(WorkTerminationRequest.id)).where(
                WorkTerminationRequest.work_kind == "EXECUTION",
                WorkTerminationRequest.work_id == execution_id,
            )
        )
        assert execution is not None
        assert execution.process_state == "QUEUED"
        assert datasource is not None
        assert datasource.status == "ACTIVE"
        assert datasource.current_secret_id == published.target_secret_id
        assert target_lock is not None and target_lock.state == "RESERVED"
        assert request_count == 0


def test_retired_noncurrent_secret_does_not_terminate_queued_probe(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    suffix = "queued-probe-retired-noncurrent"
    published, execution_id, execution_claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    probe_id = _queue_recovery_probe(
        core_stack,
        published=published,
        execution_id=execution_id,
        execution_claim=execution_claim,
        suffix=suffix,
    )
    retired_secret_id = uuid4()
    now = datetime.now(UTC)
    with core_stack.sessions.begin() as session:
        session.add(
            CredentialSecret(
                id=retired_secret_id,
                datasource_id=published.target_datasource_id,
                secret_version=2,
                ciphertext=b"opaque-retired-probe-test-ciphertext",
                nonce=b"r" * 12,
                data_algorithm="AES-256-GCM",
                aad_schema_version="1.0",
                status="RETIRED",
                status_reason_code="ROTATED",
                created_by=core_stack.principal.user_id,
                created_at=now,
                status_changed_at=now,
                retired_at=now,
            )
        )

    result = _credential_service(
        core_stack,
        keyring_root=tmp_path,
    ).change_secret_status(
        principal=core_stack.principal,
        datasource_id=published.target_datasource_id,
        secret_version=2,
        request=CredentialSecretStatusChange(
            status="COMPROMISED",
            reason_code="TEST_RETIRED_NONCURRENT_PROBE",
        ),
        idempotency_key=f"termination-{suffix}-compromise",
        audit=AuditContext(
            request_id=uuid4(),
            source_ip="127.0.0.1",
            user_agent="work-termination-security-test",
        ),
    )
    assert result.value.status == "COMPROMISED"

    with core_stack.sessions() as session:
        probe = session.get(RecoveryProbe, probe_id)
        gate = session.scalar(select(RecoveryGate).where(RecoveryGate.execution_id == execution_id))
        request_count = session.scalar(
            select(func.count(WorkTerminationRequest.id)).where(
                WorkTerminationRequest.work_kind == "RECOVERY_PROBE",
                WorkTerminationRequest.work_id == probe_id,
            )
        )
        assert probe is not None
        assert probe.process_state == "QUEUED"
        assert probe.target_secret_id is None
        assert gate is not None and gate.status == "REMEDIATION_SUBMITTED"
        assert request_count == 0


def test_each_bound_secret_keeps_its_own_durable_termination_fact(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    suffix = "execution-two-secret-revocations"
    published, execution_id, _claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    _persist_active_source_secret(core_stack, published=published)
    _persist_active_target_secret(core_stack, published=published)
    service = _credential_service(core_stack, keyring_root=tmp_path)
    _change_target_secret_status(
        core_stack,
        service=service,
        published=published,
        datasource_id=published.source_datasource_id,
        status="REVOKED",
        suffix=f"{suffix}-source",
    )
    _change_target_secret_status(
        core_stack,
        service=service,
        published=published,
        status="REVOKED",
        suffix=f"{suffix}-target",
    )

    with core_stack.sessions() as session:
        requests = list(
            session.scalars(
                select(WorkTerminationRequest)
                .where(
                    WorkTerminationRequest.work_kind == "EXECUTION",
                    WorkTerminationRequest.work_id == execution_id,
                    WorkTerminationRequest.reason_code == "SECRET_REVOKED",
                )
                .order_by(WorkTerminationRequest.credential_secret_id)
            )
        )
        assert [item.credential_secret_id for item in requests] == sorted(
            [published.source_secret_id, published.target_secret_id],
            key=str,
        )
        assert all(item.status == "PENDING" for item in requests)


def test_probe_empty_completion_cannot_verify_gate_after_secret_revocation(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    suffix = "probe-empty-revoke-race"
    published, execution_id, execution_claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    _persist_active_target_secret(core_stack, published=published)
    recovery, probe_id, probe_claim = _claim_recovery_probe(
        core_stack,
        published=published,
        execution_id=execution_id,
        execution_claim=execution_claim,
        suffix=suffix,
    )
    _change_target_secret_status(
        core_stack,
        service=_credential_service(core_stack, keyring_root=tmp_path),
        published=published,
        status="REVOKED",
        suffix=suffix,
    )

    # Simulate a late EMPTY result racing the committed security stop. The
    # durable termination fact must win before any evidence can verify the gate.
    recovery.complete_probe(
        claim=probe_claim,
        result="EMPTY",
        target_connection_evidence_id=uuid4(),
        target_empty_evidence={},
    )

    with core_stack.sessions() as session:
        probe = session.get(RecoveryProbe, probe_id)
        attempt = session.get(RecoveryProbeAttempt, probe_claim.attempt_id)
        gate = session.scalar(select(RecoveryGate).where(RecoveryGate.execution_id == execution_id))
        request = session.scalar(
            select(WorkTerminationRequest).where(
                WorkTerminationRequest.work_kind == "RECOVERY_PROBE",
                WorkTerminationRequest.work_id == probe_id,
            )
        )
        assert probe is not None
        assert probe.process_state == "FAILED"
        assert probe.result == "INCONCLUSIVE"
        assert attempt is not None and attempt.termination_reason == "SECRET_REVOKED"
        assert probe.failure_code == "CREDENTIAL_SECRET_REVOKED"
        assert probe.target_empty_evidence is None
        assert gate is not None
        assert gate.status == "REJECTED"
        assert gate.target_empty_evidence is None
        assert gate.verified_at is None
        assert gate.reason_code == "CREDENTIAL_SECRET_REVOKED"
        assert request is not None
        assert request.status == "COMPLETED"
        assert request.acknowledged_at is not None
        assert request.completed_at is not None


def test_expired_terminated_probe_preserves_safety_reason_and_blocks_revoked_binding(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    suffix = "probe-lease-expired-after-revoke"
    published, execution_id, execution_claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    _persist_active_target_secret(core_stack, published=published)
    _recovery, probe_id, probe_claim = _claim_recovery_probe(
        core_stack,
        published=published,
        execution_id=execution_id,
        execution_claim=execution_claim,
        suffix=suffix,
    )
    _change_target_secret_status(
        core_stack,
        service=_credential_service(core_stack, keyring_root=tmp_path),
        published=published,
        status="REVOKED",
        suffix=suffix,
    )
    with core_stack.sessions.begin() as session:
        attempt = session.get(RecoveryProbeAttempt, probe_claim.attempt_id)
        assert attempt is not None
        attempt.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)

    reconciler = WorkerReconciler(
        control=core_stack.service,
        sessions=core_stack.sessions,
    )
    assert (
        reconciler.reconcile_pending_work_terminations(
            identity=RuntimeIdentity(
                host_boot_id="different-boot",
                cgroup_identity="different-cgroup",
            )
        )
        == 1
    )

    with core_stack.sessions() as session:
        probe = session.get(RecoveryProbe, probe_id)
        attempt = session.get(RecoveryProbeAttempt, probe_claim.attempt_id)
        gate = session.scalar(select(RecoveryGate).where(RecoveryGate.execution_id == execution_id))
        request = session.scalar(
            select(WorkTerminationRequest).where(
                WorkTerminationRequest.work_kind == "RECOVERY_PROBE",
                WorkTerminationRequest.work_id == probe_id,
            )
        )
        assert probe is not None and probe.process_state == "LOST"
        assert probe.result == "INCONCLUSIVE"
        assert probe.target_empty_evidence is None
        assert gate is not None
        assert gate.status == "REJECTED"
        assert gate.target_empty_evidence is None
        assert gate.verified_at is None
        assert probe.failure_code == "CREDENTIAL_SECRET_REVOKED"
        assert attempt is not None and attempt.termination_reason == "SECRET_REVOKED"
        assert gate.reason_code == "CREDENTIAL_SECRET_REVOKED"
        assert request is not None and request.status == "COMPLETED"

    retry = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/recovery",
        headers={"Idempotency-Key": f"termination-{suffix}-retry"},
        json={
            "action": "NO_CLEANUP_REQUIRED",
            "cleanup_performed": False,
            "reason": "The terminated probe was inconclusive; create a fresh probe.",
            "confirmed_at": datetime.now(UTC).isoformat(),
        },
    )
    assert retry.status_code == 409, retry.text
    assert retry.json()["code"] == "CREDENTIAL_BINDING_NOT_ACTIVE"
    with core_stack.sessions() as session:
        gate = session.scalar(select(RecoveryGate).where(RecoveryGate.execution_id == execution_id))
        assert gate is not None
        probe_count = session.scalar(
            select(func.count(RecoveryProbe.id)).where(
                RecoveryProbe.recovery_gate_id == gate.id
            )
        )
        assert gate.status == "REJECTED"
        assert gate.latest_recovery_probe_id == probe_id
        assert gate.reason_code == "CREDENTIAL_SECRET_REVOKED"
        assert probe_count == 1
