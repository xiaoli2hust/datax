from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
import rfc8785
from sqlalchemy import func, select
from sqlalchemy.orm import object_session
from test_core_control_plane import (
    CoreStack,
    PublishedJob,
    _credential_selector,
    _execution_request,
    _explicit_test_plugin_certification,
    _preflight_evidence_validator,
    _runtime_preflight,
    _seed_published_job,
    _test_plugin_certification_with_override,
    core_stack,
)

from datax_studio.core import service as core_service_module
from datax_studio.core.db import Execution, JobVersion, TargetCopyLock
from datax_studio.core.schemas import ClaimedExecution, CredentialBinding
from datax_studio.core.service import ControlService
from datax_studio.credentials.db import EndpointConnectionEvidence
from datax_studio.recovery.db import RecoveryGate, RecoveryProbe
from datax_studio.recovery.service import RecoveryService
from datax_studio.worker.process import ProcessAction
from datax_studio.worker.reconcile import WorkerReconciler

__all__ = ["core_stack"]


def _claim_execution(
    core_stack: CoreStack,
    *,
    suffix: str,
) -> tuple[PublishedJob, UUID, ClaimedExecution]:
    published = _seed_published_job(core_stack, suffix)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"recovery-terminal-{suffix}-001"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 202, created.text
    binding = CredentialBinding(
        source_secret_id=published.source_secret_id,
        target_secret_id=published.target_secret_id,
        source_secret_envelope_id=uuid4(),
        target_secret_envelope_id=uuid4(),
        source_secret_version=1,
        target_secret_version=1,
    )
    claim = core_stack.service.claim_next_execution(
        worker_id=f"worker-recovery-{suffix}",
        host_boot_id=f"boot-recovery-{suffix}",
        cgroup_identity=f"container:recovery-{suffix}",
        credential_selector=_credential_selector(published, binding),
    )
    assert claim is not None
    return published, UUID(created.json()["id"]), claim


def _prepare_verified_rerun(
    core_stack: CoreStack,
    *,
    suffix: str,
) -> tuple[PublishedJob, UUID, UUID]:
    published, execution_id, claim = _claim_execution(core_stack, suffix=suffix)
    core_stack.service.transition_claimed_execution(
        claim=claim,
        expected_state="STARTING",
        new_state="FAILED",
        data_effect="NONE",
        verification_state="NOT_STARTED",
        failure_code="PREFLIGHT_FAILED",
        failure_message="safe failure before the recovery rerun fixture",
    )
    checked_at = datetime.now(UTC)
    target_empty: dict[str, object] = {
        "result": "EMPTY",
        "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
        "observed_row_count": 0,
        "target_datasource_revision_id": str(
            published.target_datasource_revision_id
        ),
        "target_endpoint_policy_revision_id": str(
            published.target_endpoint_policy_revision_id
        ),
        "target_namespace_id": str(published.target_namespace_id),
        "physical_table_identity_hash": published.target_table_identity_hash,
        "connection_evidence_id": str(uuid4()),
    }
    target_empty["evidence_hash"] = hashlib.sha256(
        b"DXTARGETEMPTYv1\n" + rfc8785.dumps(target_empty)
    ).hexdigest()
    with core_stack.sessions.begin() as session:
        gate = session.scalar(
            select(RecoveryGate).where(RecoveryGate.execution_id == execution_id)
        )
        assert gate is not None
        gate.status = "VERIFIED"
        gate.target_empty_evidence = target_empty
        gate.verified_at = checked_at
        gate.reason_code = None
        gate_id = gate.id
    return published, execution_id, gate_id


def _row_snapshot(row: Any) -> dict[str, object]:
    return {
        column.key: deepcopy(getattr(row, column.key))
        for column in row.__table__.columns
    }


def _rerun_state_snapshot(
    core_stack: CoreStack,
    *,
    execution_id: UUID,
) -> dict[str, object]:
    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        gate = session.scalar(
            select(RecoveryGate).where(RecoveryGate.execution_id == execution_id)
        )
        target_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == execution_id
            )
        )
        assert execution is not None
        assert gate is not None
        assert target_lock is not None
        return {
            "execution_count": session.scalar(select(func.count(Execution.id))) or 0,
            "recovery_gate_count": session.scalar(select(func.count(RecoveryGate.id)))
            or 0,
            "target_copy_lock_count": session.scalar(
                select(func.count(TargetCopyLock.id))
            )
            or 0,
            "execution": _row_snapshot(execution),
            "recovery_gate": _row_snapshot(gate),
            "target_copy_lock": _row_snapshot(target_lock),
        }


@pytest.mark.parametrize(
    "terminal_state",
    ["FAILED", "TIMED_OUT", "CANCELED", "LOST"],
)
def test_claimed_recovery_terminal_commits_lock_and_gate_together(
    core_stack: CoreStack,
    terminal_state: str,
) -> None:
    suffix = terminal_state.lower()
    published, execution_id, claim = _claim_execution(
        core_stack,
        suffix=suffix,
    )
    expected_state = "STARTING"
    transition: dict[str, Any] = {
        "new_state": terminal_state,
        "data_effect": "NONE" if terminal_state == "FAILED" else "UNKNOWN",
        "verification_state": "NOT_STARTED",
        "failure_code": f"TEST_{terminal_state}",
        "failure_message": "safe terminal fixture",
    }
    if terminal_state == "TIMED_OUT":
        runtime_preflight = _runtime_preflight(published)
        core_stack.service.record_claimed_preflight(
            claim=claim,
            runtime_preflight=runtime_preflight,
            evidence_validator=_preflight_evidence_validator(
                published,
                claim,
                runtime_preflight,
            ),
        )
        core_stack.service.transition_claimed_execution(
            claim=claim,
            expected_state="STARTING",
            new_state="RUNNING",
            data_effect="NONE",
            verification_state="NOT_STARTED",
        )
        expected_state = "RUNNING"
        transition["summary_parse_status"] = "FAILED"
    elif terminal_state in {"CANCELED", "LOST"}:
        cancel = core_stack.client.post(
            f"/api/v1/executions/{execution_id}/cancel",
            headers={"Idempotency-Key": f"recovery-terminal-cancel-{suffix}"},
            json={"reason": "terminal recovery gate fixture"},
        )
        assert cancel.status_code == 202, cancel.text
        reconciler = WorkerReconciler(
            control=core_stack.service,
            sessions=core_stack.sessions,
        )
        assert reconciler.poll_claim_action(claim) == ProcessAction.CANCEL
        expected_state = "CANCEL_REQUESTED"

    core_stack.service.transition_claimed_execution(
        claim=claim,
        expected_state=expected_state,
        **transition,
    )

    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == execution_id
            )
        )
        gates = list(
            session.scalars(
                select(RecoveryGate).where(
                    RecoveryGate.execution_id == execution_id
                )
            )
        )
        assert execution is not None
        assert execution.process_state == terminal_state
        assert target_lock is not None
        assert target_lock.state == "RECOVERY_REQUIRED"
        assert len(gates) == 1
        assert gates[0].status == "OPEN"
        assert gates[0].data_effect_at_open == execution.data_effect
        assert gates[0].reason_code == execution.failure_code


def test_recovery_gate_survives_crash_immediately_after_terminal_commit(
    core_stack: CoreStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _published, execution_id, claim = _claim_execution(
        core_stack,
        suffix="post-commit-crash",
    )
    reconciler = WorkerReconciler(
        control=core_stack.service,
        sessions=core_stack.sessions,
    )

    def fail_legacy_gate_hook(_execution_id: UUID) -> bool:
        raise RuntimeError("simulated process failure after terminal commit")

    monkeypatch.setattr(
        reconciler,
        "ensure_terminal_gate",
        fail_legacy_gate_hook,
    )

    def transition_then_crash() -> None:
        core_stack.service.transition_claimed_execution(
            claim=claim,
            expected_state="STARTING",
            new_state="FAILED",
            data_effect="NONE",
            verification_state="NOT_STARTED",
            failure_code="SIMULATED_POST_COMMIT_CRASH",
        )
        # This is the former gap where Worker called ensure_terminal_gate in a
        # second transaction. A process failure here must not affect the gate.
        reconciler.ensure_terminal_gate(execution_id)

    with pytest.raises(RuntimeError, match="simulated process failure"):
        transition_then_crash()

    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == execution_id
            )
        )
        gate = session.scalar(
            select(RecoveryGate).where(
                RecoveryGate.execution_id == execution_id
            )
        )
        assert execution is not None and execution.process_state == "FAILED"
        assert target_lock is not None and target_lock.state == "RECOVERY_REQUIRED"
        assert gate is not None and gate.status == "OPEN"


def test_gate_creation_failure_rolls_back_terminal_and_lock_together(
    core_stack: CoreStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _published, execution_id, claim = _claim_execution(
        core_stack,
        suffix="gate-write-failure",
    )

    def fail_gate_write(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated recovery gate write failure")

    monkeypatch.setattr(
        core_service_module,
        "ensure_recovery_gate",
        fail_gate_write,
    )
    with pytest.raises(RuntimeError, match="simulated recovery gate write failure"):
        core_stack.service.transition_claimed_execution(
            claim=claim,
            expected_state="STARTING",
            new_state="FAILED",
            data_effect="NONE",
            verification_state="NOT_STARTED",
            failure_code="SIMULATED_GATE_WRITE_FAILURE",
        )

    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == execution_id
            )
        )
        gate_count = session.scalar(
            select(func.count(RecoveryGate.id)).where(
                RecoveryGate.execution_id == execution_id
            )
        )
        assert execution is not None and execution.process_state == "STARTING"
        assert execution.active_attempt_id == claim.attempt_id
        assert target_lock is not None and target_lock.state == "ACTIVE"
        assert gate_count == 0


def test_claimed_failure_requires_real_recovery_probe_before_rerun(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "recovery")
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": "recovery-execution-001"},
        json=_execution_request(published.job_version_id),
    )
    execution_id = UUID(created.json()["id"])
    binding = CredentialBinding(
        source_secret_id=published.source_secret_id,
        target_secret_id=published.target_secret_id,
        source_secret_envelope_id=uuid4(),
        target_secret_envelope_id=uuid4(),
        source_secret_version=1,
        target_secret_version=1,
    )
    claim = core_stack.service.claim_next_execution(
        worker_id="worker-1",
        host_boot_id="boot-1",
        cgroup_identity="container:test",
        credential_selector=_credential_selector(published, binding),
    )
    assert claim is not None
    core_stack.service.transition_claimed_execution(
        claim=claim,
        expected_state="STARTING",
        new_state="FAILED",
        data_effect="NONE",
        verification_state="NOT_STARTED",
        failure_code="PREFLIGHT_FAILED",
        failure_message="safe failure",
    )
    recovery = RecoveryService(core_stack.service)
    with core_stack.sessions.begin() as session:
        execution = session.get(Execution, execution_id)
        assert execution is not None
        gate_at_terminal_commit = session.scalar(
            select(RecoveryGate).where(
                RecoveryGate.execution_id == execution_id
            )
        )
        assert gate_at_terminal_commit is not None
        gate = recovery.ensure_gate(
            session,
            execution=execution,
            now=datetime.now(UTC),
        )
        assert gate is not None
        gate_again = recovery.ensure_gate(
            session,
            execution=execution,
            now=datetime.now(UTC),
        )
        assert gate_again is not None
        assert gate.id == gate_again.id == gate_at_terminal_commit.id
        assert (
            session.scalar(
                select(func.count(RecoveryGate.id)).where(
                    RecoveryGate.execution_id == execution_id
                )
            )
            == 1
        )

    gate_response = core_stack.client.get(
        f"/api/v1/executions/{execution_id}/recovery"
    )
    assert gate_response.status_code == 200, gate_response.text
    assert gate_response.json()["status"] == "OPEN"
    remediation = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/recovery",
        headers={"Idempotency-Key": "recovery-remediation-001"},
        json={
            "action": "NO_CLEANUP_REQUIRED",
            "cleanup_performed": False,
            "reason": "DataX never started; Worker must still prove target empty.",
            "confirmed_at": datetime.now(UTC).isoformat(),
        },
    )
    assert remediation.status_code == 202, remediation.text
    probe_id = UUID(remediation.json()["recovery_probe"]["id"])
    probe_claim = recovery.claim_next_probe(
        worker_id="worker-1",
        host_boot_id="boot-1",
        cgroup_identity="container:test",
        credential_selector=lambda _session, **_kwargs: CredentialBinding(
            source_secret_id=published.target_secret_id,
            target_secret_id=published.target_secret_id,
            source_secret_envelope_id=uuid4(),
            target_secret_envelope_id=uuid4(),
            source_secret_version=2,
            target_secret_version=2,
        ),
    )
    assert probe_claim is not None
    assert probe_claim.recovery_probe_id == probe_id
    recovery.start_claimed_probe(probe_claim)

    observed_at = datetime.now(UTC)
    connection_evidence_id = uuid4()
    with core_stack.sessions.begin() as session:
        session.add(
            EndpointConnectionEvidence(
                id=connection_evidence_id,
                operation_kind="RECOVERY_PROBE",
                datasource_revision_id=(
                    published.target_datasource_revision_id
                ),
                endpoint_policy_revision_id=(
                    published.target_endpoint_policy_revision_id
                ),
                execution_id=None,
                recovery_probe_id=probe_id,
                attempt_id=probe_claim.attempt_id,
                fence_epoch=probe_claim.fence_epoch,
                resolver_policy_version="resolver-v1",
                cname_chain=[],
                resolved_ips=["10.20.0.42"],
                selected_ip="10.20.0.42",
                dns_valid_until=observed_at + timedelta(minutes=1),
                egress_policy_version="egress-v1",
                egress_enforcement_status="VERIFIED",
                egress_evidence_hash="a" * 64,
                peer_ip="10.20.0.42",
                tls_peer_spki_sha256=None,
                decision="ALLOWED",
                evidence_hash="b" * 64,
                observed_at=observed_at,
            )
        )
    target_empty = {
        "result": "EMPTY",
        "checked_at": (
            (observed_at + timedelta(milliseconds=1))
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "observed_row_count": 0,
        "target_datasource_revision_id": str(
            published.target_datasource_revision_id
        ),
        "target_endpoint_policy_revision_id": str(
            published.target_endpoint_policy_revision_id
        ),
        "target_namespace_id": str(published.target_namespace_id),
        "physical_table_identity_hash": (
            published.target_table_identity_hash
        ),
        "connection_evidence_id": str(connection_evidence_id),
    }
    target_empty["evidence_hash"] = hashlib.sha256(
        b"DXTARGETEMPTYv1\n" + rfc8785.dumps(target_empty)
    ).hexdigest()
    recovery.complete_probe(
        claim=probe_claim,
        result="EMPTY",
        target_connection_evidence_id=connection_evidence_id,
        target_empty_evidence=target_empty,
    )
    probe_response = core_stack.client.get(
        f"/api/v1/recovery-probes/{probe_id}"
    )
    assert probe_response.status_code == 200
    assert probe_response.json()["process_state"] == "SUCCEEDED"
    assert probe_response.json()["result"] == "EMPTY"

    rerun_body = _execution_request(published.job_version_id)
    rerun_body.pop("job_version_id")
    rerun_body["recovery_gate_id"] = gate_response.json()["id"]
    rerun = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/rerun",
        headers={"Idempotency-Key": "recovery-rerun-001"},
        json=rerun_body,
    )
    assert rerun.status_code == 202, rerun.text
    assert rerun.json()["rerun_of_execution_id"] == str(execution_id)
    assert rerun.json()["process_state"] == "QUEUED"
    assert rerun.json()["target_copy_lock"]["state"] == "RESERVED"
    with core_stack.sessions() as session:
        old_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == execution_id
            )
        )
        new_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == UUID(rerun.json()["id"])
            )
        )
        gate = session.scalar(
            select(RecoveryGate).where(
                RecoveryGate.execution_id == execution_id
            )
        )
        probe = session.get(RecoveryProbe, probe_id)
        assert old_lock is not None and old_lock.state == "RELEASED"
        assert new_lock is not None and new_lock.state == "RESERVED"
        assert gate is not None and gate.status == "VERIFIED"
        assert probe is not None and probe.result == "EMPTY"


@pytest.mark.parametrize(
    ("certification_case", "expected_reason"),
    [
        ("default_deny", "WINDOWS_E4_EVIDENCE_MISSING"),
        ("expired", "EVIDENCE_EXPIRED"),
        ("invalid", "PLUGIN_HASH_MISMATCH"),
    ],
)
def test_recovery_rerun_rechecks_e4_before_mutating_recovery_state(
    core_stack: CoreStack,
    monkeypatch: pytest.MonkeyPatch,
    certification_case: str,
    expected_reason: str,
) -> None:
    published, execution_id, gate_id = _prepare_verified_rerun(
        core_stack,
        suffix=f"rerun_e4_{certification_case}",
    )
    before = _rerun_state_snapshot(core_stack, execution_id=execution_id)
    execution_before = before["execution"]
    gate_before = before["recovery_gate"]
    lock_before = before["target_copy_lock"]
    assert isinstance(execution_before, dict)
    assert isinstance(gate_before, dict)
    assert isinstance(lock_before, dict)
    assert execution_before["process_state"] == "FAILED"
    assert gate_before["status"] == "VERIFIED"
    assert lock_before["state"] == "RECOVERY_REQUIRED"
    assert lock_before["released_at"] is None
    certification_source = None
    if certification_case == "expired":
        certification_source = _explicit_test_plugin_certification(
            valid_until=datetime.now(UTC) - timedelta(seconds=1)
        )
    elif certification_case == "invalid":
        certification_source = _test_plugin_certification_with_override(
            "mysqlreader",
            plugin_sha256="0" * 64,
        )
    if certification_source is None:
        blocked_service = ControlService(
            sessions=core_stack.sessions,
            integrity_hmac_key=b"recovery-rerun-certification-test-key",
        )
    else:
        blocked_service = ControlService(
            sessions=core_stack.sessions,
            integrity_hmac_key=b"recovery-rerun-certification-test-key",
            plugin_certification_source=certification_source,
        )
    certification_gate = blocked_service.require_job_version_plugin_certification

    def assert_state_is_pristine_then_require_e4(
        *,
        version: JobVersion,
        now: datetime | None = None,
    ) -> None:
        session = object_session(version)
        assert session is not None
        domain_changes = [
            row
            for row in (*session.new, *session.dirty)
            if isinstance(row, (Execution, RecoveryGate, TargetCopyLock))
        ]
        assert domain_changes == []
        original = session.get(Execution, execution_id)
        gate = session.get(RecoveryGate, gate_id)
        old_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == execution_id
            )
        )
        assert original is not None
        assert gate is not None
        assert old_lock is not None
        assert _row_snapshot(original) == before["execution"]
        assert _row_snapshot(gate) == before["recovery_gate"]
        assert _row_snapshot(old_lock) == before["target_copy_lock"]
        certification_gate(version=version, now=now)

    monkeypatch.setattr(
        blocked_service,
        "require_job_version_plugin_certification",
        assert_state_is_pristine_then_require_e4,
    )
    rerun_body = _execution_request(published.job_version_id)
    rerun_body.pop("job_version_id")
    rerun_body["recovery_gate_id"] = str(gate_id)
    idempotency_key = f"recovery-rerun-e4-{certification_case}"
    original_service = core_stack.client.app.state.control_service
    core_stack.client.app.state.control_service = blocked_service
    try:
        blocked = core_stack.client.post(
            f"/api/v1/executions/{execution_id}/rerun",
            headers={"Idempotency-Key": idempotency_key},
            json=rerun_body,
        )
    finally:
        core_stack.client.app.state.control_service = original_service

    assert blocked.status_code == 409, blocked.text
    assert blocked.json()["code"] == "PLUGIN_WINDOWS_E4_CERTIFICATION_REQUIRED"
    assert blocked.json()["details"]["block_reasons"] == [expected_reason]
    assert _rerun_state_snapshot(core_stack, execution_id=execution_id) == before

    accepted = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/rerun",
        headers={"Idempotency-Key": idempotency_key},
        json=rerun_body,
    )
    assert accepted.status_code == 202, accepted.text
    assert accepted.headers.get("Idempotency-Replayed") is None
    assert accepted.json()["rerun_of_execution_id"] == str(execution_id)


def test_unclaimed_cancellation_has_no_recovery_gate(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "no-gate")
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": "no-gate-execution-001"},
        json=_execution_request(published.job_version_id),
    )
    execution_id = UUID(created.json()["id"])
    canceled = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/cancel",
        headers={"Idempotency-Key": "no-gate-cancel-001"},
    )
    assert canceled.status_code == 202
    assert core_stack.service.reconcile_unclaimed_cancel(
        execution_id=execution_id
    )
    response = core_stack.client.get(
        f"/api/v1/executions/{execution_id}/recovery"
    )
    assert response.status_code == 409
    assert response.json()["code"] == "RECOVERY_GATE_NOT_APPLICABLE"
