from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import rfc8785
from sqlalchemy import select
from test_core_control_plane import (
    CoreStack,
    _credential_selector,
    _execution_request,
    _seed_published_job,
    core_stack,
)

from datax_studio.core.db import Execution, TargetCopyLock
from datax_studio.core.schemas import CredentialBinding
from datax_studio.credentials.db import EndpointConnectionEvidence
from datax_studio.recovery.db import RecoveryGate, RecoveryProbe
from datax_studio.recovery.service import RecoveryService

__all__ = ["core_stack"]


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
        gate = recovery.ensure_gate(
            session,
            execution=execution,
            now=datetime.now(UTC),
        )
        assert gate is not None

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
