from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import rfc8785
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from datax_studio.api.app import create_app
from datax_studio.api.problems import ProblemException
from datax_studio.auth.db import (
    AuditEvent,
    Base,
    Organization,
    OrganizationMember,
    Role,
    ScopeType,
    User,
)
from datax_studio.auth.routes import business_principal
from datax_studio.auth.schemas import ScopedRoles
from datax_studio.auth.service import AuditContext, Principal
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    DatasourceUsageGrant,
    EndpointPolicy,
    EndpointPolicyRevision,
    Execution,
    ExecutionAttempt,
    ExecutionCancelRequest,
    JobVersion,
    PhysicalEndpointIdentity,
    Project,
    ProjectQueueServiceCursor,
    QueueSchedulerState,
    SyncJob,
    SystemControl,
    TargetCopyLock,
    TargetNamespace,
    TransferPolicy,
)
from datax_studio.core.schemas import ClaimedExecution, CredentialBinding
from datax_studio.core.service import (
    ControlService,
    ValidationMaterial,
    _filtered_cursor_scope,
)
from datax_studio.credentials.routes import get_credential_service
from datax_studio.recovery.db import RecoveryGate
from datax_studio.schema_snapshot import schema_snapshot_hash
from datax_studio.settings import Settings
from datax_studio.worker.process import ProcessAction
from datax_studio.worker.reconcile import WorkerReconciler


@dataclass(frozen=True)
class CoreStack:
    client: TestClient
    service: ControlService
    sessions: sessionmaker
    principal: Principal
    member_id: UUID


@dataclass(frozen=True)
class PublishedJob:
    project_id: UUID
    job_id: UUID
    job_version_id: UUID
    source_datasource_id: UUID
    target_datasource_id: UUID
    source_secret_id: UUID
    target_secret_id: UUID
    target_namespace_id: UUID
    target_datasource_revision_id: UUID
    target_endpoint_policy_revision_id: UUID
    target_table_identity_hash: str


@pytest.fixture
def core_stack() -> CoreStack:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(UTC)
    organization_id = uuid4()
    user_id = uuid4()
    member_id = uuid4()
    with sessions.begin() as session:
        session.add_all(
            [
                Organization(
                    id=organization_id,
                    name="Test Organization",
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                User(
                    id=user_id,
                    email="admin@example.com",
                    display_name="Local Admin",
                    password_hash="not-used-by-core-tests",
                    must_change_password=False,
                    password_changed_at=now,
                    status="ACTIVE",
                    failed_login_count=0,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                OrganizationMember(
                    id=member_id,
                    organization_id=organization_id,
                    user_id=user_id,
                    status="ACTIVE",
                    joined_at=now,
                ),
                SystemControl(
                    singleton_id=1,
                    draining=False,
                    reason="READY",
                    updated_at=now,
                ),
                QueueSchedulerState(
                    singleton_id=1,
                    next_service_sequence=1,
                    updated_at=now,
                ),
            ]
        )
    principal = Principal(
        user_id=user_id,
        organization_id=organization_id,
        session_id=uuid4(),
        email="admin@example.com",
        display_name="Local Admin",
        must_change_password=False,
        role_assignments=(
            ScopedRoles(
                scope_type=ScopeType.ORGANIZATION,
                scope_id=organization_id,
                roles=[Role.ADMIN],
            ),
        ),
    )
    service = ControlService(
        sessions=sessions,
        integrity_hmac_key=b"core-control-plane-test-key-0001",
    )
    app = create_app(
        settings=Settings(app_version="test", trusted_host="testserver"),
        control_service=service,
    )
    app.dependency_overrides[business_principal] = lambda: principal
    app.dependency_overrides[get_credential_service] = lambda: object()
    with TestClient(app) as client:
        yield CoreStack(
            client=client,
            service=service,
            sessions=sessions,
            principal=principal,
            member_id=member_id,
        )


def test_project_idempotency_etag_archive_and_endpoint_normalization(
    core_stack: CoreStack,
) -> None:
    headers = {"Idempotency-Key": "create-project-001"}
    body = {
        "name": "Finance Migration",
        "slug": "finance-migration",
        "description": "One-time offline copy",
    }

    created = core_stack.client.post("/api/v1/projects", headers=headers, json=body)
    replay = core_stack.client.post("/api/v1/projects", headers=headers, json=body)
    conflict = core_stack.client.post(
        "/api/v1/projects",
        headers=headers,
        json={**body, "name": "Different intent"},
    )

    assert created.status_code == 201, created.text
    assert created.headers["etag"] == 'W/"1"'
    assert replay.status_code == 201
    assert replay.headers["idempotency-replayed"] == "true"
    assert replay.json()["id"] == created.json()["id"]
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"

    archived = core_stack.client.patch(
        f"/api/v1/projects/{created.json()['id']}",
        headers={"If-Match": 'W/"1"'},
        json={"status": "ARCHIVED"},
    )
    stale = core_stack.client.patch(
        f"/api/v1/projects/{created.json()['id']}",
        headers={"If-Match": 'W/"1"'},
        json={"description": "stale update"},
    )
    assert archived.status_code == 200
    assert archived.json()["status"] == "ARCHIVED"
    assert archived.headers["etag"] == 'W/"2"'
    assert stale.status_code == 409
    assert stale.json()["code"] == "VERSION_CONFLICT"

    policy = core_stack.client.post(
        "/api/v1/endpoint-policies",
        headers={"Idempotency-Key": "endpoint-policy-001"},
        json={
            "name": "Approved PostgreSQL target",
            "engine": "POSTGRESQL_15",
            "host_kind": "EXACT_FQDN",
            "host_value": "DB.Example.COM.",
            "allowed_cidrs": ["10.0.0.42/24", "10.0.0.0/24"],
            "allowed_ports": [5432, 5432],
            "tls_required": True,
            "dns_ttl_ceiling_seconds": 60,
        },
    )
    assert policy.status_code == 201, policy.text
    revision = policy.json()["current_revision"]
    assert revision["host_value"] == "db.example.com"
    assert revision["allowed_cidrs"] == ["10.0.0.0/24"]
    assert revision["allowed_ports"] == [5432]
    assert revision["resolver_policy_version"] == "des-system-dns-v1"
    assert revision["egress_policy_version"] == "des-nftables-egress-v1"
    assert len(revision["policy_hash"]) == 64
    policy_id = policy.json()["id"]
    listed_policies = core_stack.client.get("/api/v1/endpoint-policies")
    fetched_policy = core_stack.client.get(
        f"/api/v1/endpoint-policies/{policy_id}"
    )
    assert listed_policies.status_code == 200
    assert [item["id"] for item in listed_policies.json()["items"]] == [policy_id]
    assert fetched_policy.status_code == 200
    assert fetched_policy.json() == policy.json()
    assert fetched_policy.headers["etag"] == 'W/"1"'

    with core_stack.sessions() as session:
        actions = [
            event.event_json["action"]
            for event in session.scalars(
                select(AuditEvent).order_by(AuditEvent.organization_sequence)
            )
        ]
    assert actions == [
        "PROJECT_CREATED",
        "PROJECT_ARCHIVED",
        "ENDPOINT_POLICY_CREATED",
    ]


def test_project_dashboard_has_fixed_window_complete_zero_counts_and_drilldowns(
    core_stack: CoreStack,
) -> None:
    created = core_stack.client.post(
        "/api/v1/projects",
        headers={"Idempotency-Key": "dashboard-project-001"},
        json={
            "name": "Dashboard Project",
            "slug": "dashboard-project",
            "description": None,
        },
    )
    assert created.status_code == 201
    window_to = datetime.now(UTC)
    window_from = window_to - timedelta(hours=2)
    dashboard = core_stack.client.get(
        f"/api/v1/projects/{created.json()['id']}/dashboard",
        params={
            "from": window_from.isoformat(),
            "to": window_to.isoformat(),
        },
    )
    assert dashboard.status_code == 200, dashboard.text
    payload = dashboard.json()
    assert payload["window"] == {
        "from": window_from.isoformat().replace("+00:00", "Z"),
        "to": window_to.isoformat().replace("+00:00", "Z"),
    }
    assert payload["job_counts"] == {
        "total": 0,
        "draft": 0,
        "valid": 0,
        "published": 0,
        "archived": 0,
        "executable": 0,
    }
    assert payload["execution_total"] == 0
    assert all(value == 0 for value in payload["execution_state_counts"].values())
    assert all(value == 0 for value in payload["verification_state_counts"].values())
    assert all(value == 0 for value in payload["data_effect_counts"].values())
    assert payload["success_rate"] == {
        "numerator": 0,
        "denominator": 0,
        "ratio": None,
    }
    assert payload["verified_records"] == {
        "value": 0,
        "complete": True,
        "missing_verification_count": 0,
    }
    assert payload["runtime"] == {
        "worker_online": False,
        "runtime_ready": False,
        "oracle_ready": False,
        "datax_release": None,
        "version_match": False,
    }
    assert len(payload["trend"]) == 1
    assert len(payload["drilldowns"]) == 10

    overlong = core_stack.client.get(
        f"/api/v1/projects/{created.json()['id']}/dashboard",
        params={
            "from": (window_to - timedelta(days=32)).isoformat(),
            "to": window_to.isoformat(),
        },
    )
    assert overlong.status_code == 422
    assert overlong.json()["code"] == "VALIDATION_ERROR"


def test_execution_api_only_queues_reserves_and_records_cancel_or_revoke(
    core_stack: CoreStack,
) -> None:
    queued_job = _seed_published_job(core_stack, "queued")
    request_body = _execution_request(queued_job.job_version_id)
    headers = {"Idempotency-Key": "execution-queued-001"}

    created = core_stack.client.post(
        f"/api/v1/jobs/{queued_job.job_id}/executions",
        headers=headers,
        json=request_body,
    )
    replay = core_stack.client.post(
        f"/api/v1/jobs/{queued_job.job_id}/executions",
        headers=headers,
        json=request_body,
    )
    assert created.status_code == 202, created.text
    assert replay.status_code == 202
    assert replay.headers["idempotency-replayed"] == "true"
    execution_id = UUID(created.json()["id"])
    assert created.json()["process_state"] == "QUEUED"
    assert created.json()["data_effect"] == "NONE"
    assert created.json()["verification_state"] == "NOT_STARTED"
    assert created.json()["target_copy_lock"]["state"] == "RESERVED"
    assert created.json()["source_secret_version"] is None
    assert created.json()["runtime_snapshot"] is None
    matching_filter = core_stack.client.get(
        f"/api/v1/projects/{queued_job.project_id}/executions",
        params={
            "verification_state": "NOT_STARTED",
            "job_id": str(queued_job.job_id),
            "data_effect": "NONE",
        },
    )
    nonmatching_filter = core_stack.client.get(
        f"/api/v1/projects/{queued_job.project_id}/executions",
        params={"job_id": str(uuid4())},
    )
    invalid_time_filter = core_stack.client.get(
        f"/api/v1/projects/{queued_job.project_id}/executions",
        params={"from": "2026-07-30T10:00:00"},
    )
    assert matching_filter.status_code == 200
    assert [item["id"] for item in matching_filter.json()["items"]] == [
        str(execution_id)
    ]
    assert nonmatching_filter.status_code == 200
    assert nonmatching_filter.json()["items"] == []
    assert invalid_time_filter.status_code == 422

    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == execution_id
            )
        )
        attempts = list(
            session.scalars(
                select(ExecutionAttempt).where(
                    ExecutionAttempt.execution_id == execution_id
                )
            )
        )
        assert execution is not None and execution.fence_epoch == 0
        assert execution.active_attempt_id is None
        assert target_lock is not None and target_lock.state == "RESERVED"
        assert attempts == []

    cancel = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/cancel",
        headers={"Idempotency-Key": "cancel-queued-001"},
        json={"reason": "operator canceled before claim"},
    )
    before_reconcile = core_stack.client.get(f"/api/v1/executions/{execution_id}")
    assert cancel.status_code == 202
    assert cancel.json()["status"] == "PENDING"
    assert before_reconcile.json()["process_state"] == "QUEUED"
    assert core_stack.service.reconcile_unclaimed_cancel(execution_id=execution_id)
    after_reconcile = core_stack.client.get(f"/api/v1/executions/{execution_id}")
    assert after_reconcile.json()["process_state"] == "CANCELED"
    assert after_reconcile.json()["data_effect"] == "NONE"
    assert after_reconcile.json()["verification_state"] == "NOT_STARTED"
    assert after_reconcile.json()["target_copy_lock"]["state"] == "RELEASED"

    revoked_job = _seed_published_job(core_stack, "revoked")
    revoked_created = core_stack.client.post(
        f"/api/v1/jobs/{revoked_job.job_id}/executions",
        headers={"Idempotency-Key": "execution-revoked-001"},
        json=_execution_request(revoked_job.job_version_id),
    )
    revoked_id = revoked_created.json()["id"]
    revoke = core_stack.client.post(
        f"/api/v1/executions/{revoked_id}/target-exclusivity/revoke",
        headers={"Idempotency-Key": "revoke-target-001"},
        json={
            "statement_version": "1.0",
            "responsible_party": "DBA",
            "reason": "EXTERNAL_DML_DDL_REPORTED",
            "reported_at": datetime.now(UTC).isoformat(),
            "note": "A DBA reported an external write.",
        },
    )
    assert revoke.status_code == 202, revoke.text
    assert revoke.json()["target_exclusivity_status"] == "REVOKED"
    assert revoke.json()["process_state"] == "QUEUED"
    assert revoke.json()["data_effect"] == "NONE"
    assert revoke.json()["verification_state"] == "NOT_STARTED"
    assert revoke.json()["target_copy_lock"]["state"] == "RESERVED"
    assert core_stack.service.reconcile_unclaimed_target_exclusivity(
        execution_id=UUID(revoked_id)
    )
    revoked_reconciled = core_stack.client.get(
        f"/api/v1/executions/{revoked_id}"
    ).json()
    assert revoked_reconciled["process_state"] == "CANCELED"
    assert revoked_reconciled["data_effect"] == "NONE"
    assert revoked_reconciled["verification_state"] == "NOT_STARTED"
    assert revoked_reconciled["target_copy_lock"]["state"] == "RELEASED"
    assert (
        revoked_reconciled["failure_code"]
        == "TARGET_EXCLUSIVITY_REVOKED"
    )

    with core_stack.sessions.begin() as session:
        control = session.get(SystemControl, 1)
        assert control is not None
        control.draining = True
        control.reason = "ORDERLY_STOP"
    replay_while_draining = core_stack.client.post(
        f"/api/v1/jobs/{queued_job.job_id}/executions",
        headers=headers,
        json=request_body,
    )
    assert replay_while_draining.status_code == 202
    assert replay_while_draining.headers["idempotency-replayed"] == "true"
    assert replay_while_draining.json() == created.json()
    _assert_audit_contract(core_stack)


def test_worker_claim_fence_and_independent_verification_gate(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "worker")
    execution_request = _execution_request(published.job_version_id)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": "execution-worker-001"},
        json=execution_request,
    )
    assert created.status_code == 202, created.text
    execution_id = UUID(created.json()["id"])
    binding = CredentialBinding(
        source_secret_id=published.source_secret_id,
        target_secret_id=published.target_secret_id,
        source_secret_envelope_id=uuid4(),
        target_secret_envelope_id=uuid4(),
        source_secret_version=3,
        target_secret_version=7,
    )

    claim = core_stack.service.claim_next_execution(
        worker_id="worker-1",
        host_boot_id="boot-1",
        cgroup_identity="container:test",
        credential_selector=_credential_selector(published, binding),
    )
    assert claim is not None
    assert claim.execution_id == execution_id
    assert claim.fence_epoch == 1
    assert len(claim.lease_token) >= 32
    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        attempt = session.get(ExecutionAttempt, claim.attempt_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == execution_id
            )
        )
        assert execution is not None and execution.process_state == "STARTING"
        assert execution.runtime_snapshot is None
        assert execution.source_connection_evidence_id is None
        assert execution.target_connection_evidence_id is None
        assert attempt is not None
        assert attempt.lease_token_hash == hashlib.sha256(
            claim.lease_token.encode("ascii")
        ).hexdigest()
        assert attempt.lease_token_hash != claim.lease_token
        assert target_lock is not None and target_lock.state == "ACTIVE"
        assert target_lock.fence_epoch == 1

    with pytest.raises(ValueError, match="completed fenced preflight"):
        core_stack.service.transition_claimed_execution(
            claim=claim,
            expected_state="STARTING",
            new_state="RUNNING",
            data_effect="NONE",
            verification_state="NOT_STARTED",
        )

    runtime_preflight = _runtime_preflight(published)
    evidence_validator = _preflight_evidence_validator(
        published,
        claim,
        runtime_preflight,
    )
    with pytest.raises(ValueError, match="secret material"):
        core_stack.service.record_claimed_preflight(
            claim=claim,
            runtime_preflight={"password": "must-never-be-persisted"},
            evidence_validator=evidence_validator,
        )

    tampered_preflight = json.loads(json.dumps(runtime_preflight))
    tampered_preflight["target_empty_evidence"][
        "physical_table_identity_hash"
    ] = "0" * 64
    with pytest.raises(ProblemException) as invalid_target_empty_hash:
        core_stack.service.record_claimed_preflight(
            claim=claim,
            runtime_preflight=tampered_preflight,
            evidence_validator=evidence_validator,
        )
    assert (
        invalid_target_empty_hash.value.code
        == "TARGET_EMPTY_EVIDENCE_HASH_MISMATCH"
    )
    snapshot = core_stack.service.record_claimed_preflight(
        claim=claim,
        runtime_preflight=runtime_preflight,
        evidence_validator=evidence_validator,
    )
    assert snapshot.target_fence_epoch == claim.fence_epoch
    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        assert execution is not None
        assert execution.runtime_snapshot is not None
        assert claim.lease_token not in str(execution.runtime_snapshot)
        assert execution.source_connection_evidence_id == UUID(
            runtime_preflight["source_connection_evidence_id"]
        )
        assert execution.target_connection_evidence_id == UUID(
            runtime_preflight["target_connection_evidence_id"]
        )

    stale = ClaimedExecution(
        execution_id=claim.execution_id,
        attempt_id=claim.attempt_id,
        fence_epoch=claim.fence_epoch,
        lease_token="x" * 43,
    )
    with pytest.raises(ProblemException) as fence_lost:
        core_stack.service.heartbeat_execution(claim=stale)
    assert fence_lost.value.code == "EXECUTION_FENCE_LOST"

    core_stack.service.transition_claimed_execution(
        claim=claim,
        expected_state="STARTING",
        new_state="RUNNING",
        data_effect="NONE",
        verification_state="NOT_STARTED",
    )
    core_stack.service.transition_claimed_execution(
        claim=claim,
        expected_state="RUNNING",
        new_state="VERIFYING",
        data_effect="POSSIBLE",
        verification_state="NOT_STARTED",
        exit_code=0,
        summary_parse_status="FAILED",
    )
    before_oracle = core_stack.client.get(
        f"/api/v1/executions/{execution_id}"
    ).json()
    assert before_oracle["process_state"] == "VERIFYING"
    assert before_oracle["verification_state"] == "NOT_STARTED"

    core_stack.service.mark_claimed_oracle_started(claim=claim)
    during_verification = core_stack.client.get(
        f"/api/v1/executions/{execution_id}"
    ).json()
    assert during_verification["process_state"] == "VERIFYING"
    assert during_verification["verification_state"] == "VERIFYING"
    assert during_verification["target_copy_lock"]["state"] == "ACTIVE"
    with pytest.raises(ProblemException) as duplicate_oracle_start:
        core_stack.service.mark_claimed_oracle_started(claim=claim)
    assert duplicate_oracle_start.value.code == "ORACLE_START_STATE_CONFLICT"

    oracle_report = _passed_oracle_report(
        execution_response=created.json(),
        claimed_response=core_stack.client.get(
            f"/api/v1/executions/{execution_id}"
        ).json(),
        claim=claim,
        published=published,
        runtime_preflight=runtime_preflight,
        source_confirmed_at=execution_request[
            "source_quiescence_confirmation"
        ]["confirmed_at"],
    )
    core_stack.service.transition_claimed_execution(
        claim=claim,
        expected_state="VERIFYING",
        new_state="SUCCEEDED",
        data_effect="CONFIRMED",
        verification_state="PASSED",
        exit_code=0,
        verification_report=oracle_report,
        verification_evidence_hash=oracle_report["artifact_sha256"],
    )
    succeeded = core_stack.client.get(f"/api/v1/executions/{execution_id}").json()
    assert succeeded["process_state"] == "SUCCEEDED"
    assert succeeded["data_effect"] == "CONFIRMED"
    assert succeeded["verification_state"] == "PASSED"
    assert succeeded["target_copy_lock"]["state"] == "RELEASED"
    assert succeeded["verification_summary"]["result"] == "PASSED"
    assert succeeded["summary_parse_status"] == "FAILED"
    assert succeeded["run_summary"] is None


def test_success_transition_refuses_accepted_cancel_and_worker_finishes_canceled(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "verify-cancel")
    execution_request = _execution_request(published.job_version_id)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": "execution-verify-cancel-001"},
        json=execution_request,
    )
    assert created.status_code == 202, created.text
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
        worker_id="worker-verify-cancel",
        host_boot_id="boot-verify-cancel",
        cgroup_identity="container:verify-cancel",
        credential_selector=_credential_selector(published, binding),
    )
    assert claim is not None
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
    core_stack.service.transition_claimed_execution(
        claim=claim,
        expected_state="RUNNING",
        new_state="VERIFYING",
        data_effect="POSSIBLE",
        verification_state="NOT_STARTED",
        exit_code=0,
        summary_parse_status="FAILED",
    )
    core_stack.service.mark_claimed_oracle_started(claim=claim)
    oracle_report = _passed_oracle_report(
        execution_response=created.json(),
        claimed_response=core_stack.client.get(
            f"/api/v1/executions/{execution_id}"
        ).json(),
        claim=claim,
        published=published,
        runtime_preflight=runtime_preflight,
        source_confirmed_at=execution_request[
            "source_quiescence_confirmation"
        ]["confirmed_at"],
    )

    cancel = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/cancel",
        headers={"Idempotency-Key": "cancel-verifying-001"},
        json={"reason": "operator canceled during oracle"},
    )
    assert cancel.status_code == 202, cancel.text
    with pytest.raises(ProblemException) as blocked_success:
        core_stack.service.transition_claimed_execution(
            claim=claim,
            expected_state="VERIFYING",
            new_state="SUCCEEDED",
            data_effect="CONFIRMED",
            verification_state="PASSED",
            exit_code=0,
            verification_report=oracle_report,
            verification_evidence_hash=oracle_report["artifact_sha256"],
        )
    assert blocked_success.value.code == "EXECUTION_CANCEL_PENDING"

    reconciler = WorkerReconciler(
        control=core_stack.service,
        sessions=core_stack.sessions,
    )
    assert reconciler.poll_claim_action(claim) == ProcessAction.CANCEL
    reconciler.complete_claimed_cancel(claim=claim, oracle_started=True)

    canceled = core_stack.client.get(
        f"/api/v1/executions/{execution_id}"
    ).json()
    assert canceled["process_state"] == "CANCELED"
    assert canceled["data_effect"] == "UNKNOWN"
    assert canceled["verification_state"] == "INCONCLUSIVE"
    assert canceled["target_copy_lock"]["state"] == "RECOVERY_REQUIRED"
    with core_stack.sessions() as session:
        cancel_request = session.scalar(
            select(ExecutionCancelRequest).where(
                ExecutionCancelRequest.execution_id == execution_id
            )
        )
        assert cancel_request is not None
        assert cancel_request.status == "COMPLETED"


@pytest.mark.parametrize(
    "broken_kind",
    ["REVOKED", "EXPIRED_BOUNDARY", "EXPIRED_TERMINAL"],
)
def test_verification_exclusivity_break_fails_closed_into_recovery_gate(
    core_stack: CoreStack,
    broken_kind: str,
) -> None:
    published = _seed_published_job(core_stack, f"verify-{broken_kind.lower()}")
    execution_request = _execution_request(published.job_version_id)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"execution-{broken_kind.lower()}-001"},
        json=execution_request,
    )
    assert created.status_code == 202, created.text
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
        worker_id=f"worker-{broken_kind.lower()}",
        host_boot_id=f"boot-{broken_kind.lower()}",
        cgroup_identity=f"container:{broken_kind.lower()}",
        credential_selector=_credential_selector(published, binding),
    )
    assert claim is not None
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
    core_stack.service.transition_claimed_execution(
        claim=claim,
        expected_state="RUNNING",
        new_state="VERIFYING",
        data_effect="POSSIBLE",
        verification_state="NOT_STARTED",
        exit_code=0,
        summary_parse_status="FAILED",
    )
    core_stack.service.mark_claimed_oracle_started(claim=claim)
    oracle_report = _passed_oracle_report(
        execution_response=created.json(),
        claimed_response=core_stack.client.get(
            f"/api/v1/executions/{execution_id}"
        ).json(),
        claim=claim,
        published=published,
        runtime_preflight=runtime_preflight,
        source_confirmed_at=execution_request[
            "source_quiescence_confirmation"
        ]["confirmed_at"],
    )

    with core_stack.sessions.begin() as session:
        execution = session.get(Execution, execution_id)
        assert execution is not None
        if broken_kind == "REVOKED":
            execution.target_exclusivity_status = "REVOKED"
            execution.target_exclusivity_revoked_at = datetime.now(UTC)
            execution.target_exclusivity_revocation_reason = "DBA_REVOKED"
        else:
            confirmation = dict(execution.target_exclusivity_confirmation)
            confirmation["valid_until"] = (
                datetime.now(UTC) - timedelta(seconds=1)
            ).isoformat()
            execution.target_exclusivity_confirmation = confirmation

    if broken_kind != "EXPIRED_TERMINAL":
        with pytest.raises(ProblemException) as boundary_broken:
            core_stack.service.assert_claimed_verification_exclusivity(
                claim=claim
            )
        assert boundary_broken.value.code == "TARGET_EXCLUSIVITY_BROKEN"

    # Even if revoke/expiry wins after the final callback, the SUCCEEDED row
    # lock atomically commits the safe failed terminal result and returns the
    # same stable code. EXPIRED_TERMINAL exercises expiry first observed here.
    with pytest.raises(ProblemException) as terminal_broken:
        core_stack.service.transition_claimed_execution(
            claim=claim,
            expected_state="VERIFYING",
            new_state="SUCCEEDED",
            data_effect="CONFIRMED",
            verification_state="PASSED",
            exit_code=0,
            verification_report=oracle_report,
            verification_evidence_hash=oracle_report["artifact_sha256"],
        )
    assert terminal_broken.value.code == "TARGET_EXCLUSIVITY_BROKEN"
    failed = core_stack.client.get(f"/api/v1/executions/{execution_id}").json()
    assert failed["process_state"] == "FAILED"
    assert failed["data_effect"] == "UNKNOWN"
    assert failed["verification_state"] == "INCONCLUSIVE"
    assert failed["failure_code"] == "TARGET_EXCLUSIVITY_BROKEN"
    assert failed["target_copy_lock"]["state"] == "RECOVERY_REQUIRED"
    assert failed["target_exclusivity_status"] == (
        "REVOKED" if broken_kind == "REVOKED" else "EXPIRED"
    )
    with core_stack.sessions() as session:
        gate = session.scalar(
            select(RecoveryGate).where(
                RecoveryGate.execution_id == execution_id,
            )
        )
        assert gate is not None
        assert gate.status == "OPEN"
        assert gate.data_effect_at_open == "UNKNOWN"
        assert gate.reason_code == "TARGET_EXCLUSIVITY_BROKEN"


@pytest.mark.parametrize(
    ("verification_state", "data_effect", "failure_code"),
    [
        ("FAILED", "POSSIBLE", "ORACLE_MISMATCH"),
        ("INCONCLUSIVE", "UNKNOWN", "ORACLE_READ_FAILED"),
    ],
)
def test_verification_failure_transition_yields_to_accepted_cancel(
    core_stack: CoreStack,
    verification_state: str,
    data_effect: str,
    failure_code: str,
) -> None:
    label = verification_state.lower()
    published = _seed_published_job(core_stack, f"verify-cancel-{label}")
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"execution-cancel-{label}-001"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 202, created.text
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
        worker_id=f"worker-cancel-{label}",
        host_boot_id=f"boot-cancel-{label}",
        cgroup_identity=f"container:cancel-{label}",
        credential_selector=_credential_selector(published, binding),
    )
    assert claim is not None
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
    core_stack.service.transition_claimed_execution(
        claim=claim,
        expected_state="RUNNING",
        new_state="VERIFYING",
        data_effect="POSSIBLE",
        verification_state="NOT_STARTED",
        exit_code=0,
        summary_parse_status="FAILED",
    )
    core_stack.service.mark_claimed_oracle_started(claim=claim)

    cancel = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/cancel",
        headers={"Idempotency-Key": f"cancel-{label}-001"},
        json={"reason": f"operator canceled before {label} terminal write"},
    )
    assert cancel.status_code == 202, cancel.text
    with pytest.raises(ProblemException) as blocked_terminal:
        core_stack.service.transition_claimed_execution(
            claim=claim,
            expected_state="VERIFYING",
            new_state="FAILED",
            data_effect=data_effect,
            verification_state=verification_state,
            exit_code=0,
            failure_code=failure_code,
            failure_message="safe failure",
        )
    assert blocked_terminal.value.code == "EXECUTION_CANCEL_PENDING"

    reconciler = WorkerReconciler(
        control=core_stack.service,
        sessions=core_stack.sessions,
    )
    assert reconciler.poll_claim_action(claim) == ProcessAction.CANCEL
    # An acknowledged request remains actionable, which makes retry after a
    # Worker interruption safe before the atomic CANCELED transition.
    assert reconciler.poll_claim_action(claim) == ProcessAction.CANCEL
    reconciler.complete_claimed_cancel(claim=claim, oracle_started=True)

    canceled = core_stack.client.get(
        f"/api/v1/executions/{execution_id}"
    ).json()
    assert canceled["process_state"] == "CANCELED"
    assert canceled["verification_state"] == "INCONCLUSIVE"
    assert canceled["target_copy_lock"]["state"] == "RECOVERY_REQUIRED"
    with core_stack.sessions() as session:
        cancel_request = session.scalar(
            select(ExecutionCancelRequest).where(
                ExecutionCancelRequest.execution_id == execution_id
            )
        )
        assert cancel_request is not None
        assert cancel_request.status == "COMPLETED"
        assert cancel_request.acknowledged_at is not None
        assert cancel_request.completed_at is not None


def test_claim_next_execution_advances_persisted_fairness_only_on_claim(
    core_stack: CoreStack,
) -> None:
    older_cursor = _seed_published_job(core_stack, "fair-old")
    least_served = _seed_published_job(core_stack, "fair-next")
    for sequence, published in enumerate((older_cursor, least_served), start=1):
        created = core_stack.client.post(
            f"/api/v1/jobs/{published.job_id}/executions",
            headers={"Idempotency-Key": f"execution-fair-{sequence:03d}"},
            json=_execution_request(published.job_version_id),
        )
        assert created.status_code == 202
    with core_stack.sessions.begin() as session:
        first_cursor = session.get(
            ProjectQueueServiceCursor,
            older_cursor.project_id,
        )
        second_cursor = session.get(
            ProjectQueueServiceCursor,
            least_served.project_id,
        )
        scheduler = session.get(QueueSchedulerState, 1)
        assert first_cursor is not None and second_cursor is not None
        assert scheduler is not None
        first_cursor.last_service_sequence = 10
        second_cursor.last_service_sequence = 0
        scheduler.next_service_sequence = 11

    bindings = {
        item.source_datasource_id: (
            item,
            CredentialBinding(
                source_secret_id=item.source_secret_id,
                target_secret_id=item.target_secret_id,
                source_secret_envelope_id=uuid4(),
                target_secret_envelope_id=uuid4(),
                source_secret_version=1,
                target_secret_version=1,
            ),
        )
        for item in (older_cursor, least_served)
    }

    def select_binding(
        session,
        *,
        source_datasource_id: UUID,
        target_datasource_id: UUID,
    ) -> CredentialBinding:
        assert session.in_transaction()
        published, binding = bindings[source_datasource_id]
        assert target_datasource_id == published.target_datasource_id
        return binding

    first_claim = core_stack.service.claim_next_execution(
        worker_id="worker-fair",
        host_boot_id="boot-fair",
        cgroup_identity="container:fair",
        credential_selector=select_binding,
    )
    assert first_claim is not None
    with core_stack.sessions() as session:
        first_execution = session.get(Execution, first_claim.execution_id)
        first_cursor = session.get(
            ProjectQueueServiceCursor,
            older_cursor.project_id,
        )
        second_cursor = session.get(
            ProjectQueueServiceCursor,
            least_served.project_id,
        )
        scheduler = session.get(QueueSchedulerState, 1)
        assert first_execution is not None
        assert first_execution.project_id == least_served.project_id
        assert first_cursor is not None and first_cursor.last_service_sequence == 10
        assert second_cursor is not None
        assert second_cursor.last_service_sequence == 11
        assert second_cursor.served_execution_count == 1
        assert scheduler is not None and scheduler.next_service_sequence == 12

    second_claim = core_stack.service.claim_next_execution(
        worker_id="worker-fair",
        host_boot_id="boot-fair",
        cgroup_identity="container:fair",
        credential_selector=select_binding,
    )
    assert second_claim is not None
    with core_stack.sessions() as session:
        second_execution = session.get(Execution, second_claim.execution_id)
        first_cursor = session.get(
            ProjectQueueServiceCursor,
            older_cursor.project_id,
        )
        scheduler = session.get(QueueSchedulerState, 1)
        assert second_execution is not None
        assert second_execution.project_id == older_cursor.project_id
        assert first_cursor is not None and first_cursor.last_service_sequence == 12
        assert scheduler is not None and scheduler.next_service_sequence == 13


def test_publish_and_read_immutable_job_version_route(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "publish")
    with core_stack.sessions.begin() as session:
        existing_version = session.get(JobVersion, published.job_version_id)
        job = session.get(SyncJob, published.job_id)
        assert existing_version is not None and job is not None
        source_snapshot = existing_version.source_schema_snapshot
        target_snapshot = existing_version.target_schema_snapshot
        source_schema_hash = existing_version.source_schema_hash
        target_schema_hash = existing_version.target_schema_hash
        source_table_identity_hash = (
            existing_version.source_physical_table_identity_hash
        )
        session.delete(existing_version)
        job.status = "VALID"
        job.latest_published_version_id = None
        job.row_version = 2
        job.validation_report = {
            "valid": True,
            "draft_spec_hash": "b" * 64,
            "source_schema_snapshot": source_snapshot,
            "target_schema_snapshot": target_snapshot,
            "source_schema_hash": source_schema_hash,
            "target_schema_hash": target_schema_hash,
            "source_physical_table_identity_hash": source_table_identity_hash,
            "target_namespace_id": str(published.target_namespace_id),
            "transfer_policy_id": str(
                session.scalar(
                    select(TransferPolicy.id).where(
                        TransferPolicy.project_id == published.project_id
                    )
                )
            ),
            "transfer_policy_scope_hash": "a" * 64,
            "runtime_sha256": "d" * 64,
            "reader_plugin_sha256": "b" * 64,
            "writer_plugin_sha256": "c" * 64,
            "errors": [],
            "warnings": [],
        }

    headers = {
        "Idempotency-Key": "publish-job-version-001",
        "If-Match": 'W/"2"',
    }
    body = {"expected_draft_spec_hash": "b" * 64}
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/versions",
        headers=headers,
        json=body,
    )
    replay = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/versions",
        headers=headers,
        json=body,
    )
    assert created.status_code == 201, created.text
    assert created.json()["version_no"] == 1
    assert created.json()["spec_hash"] == "b" * 64
    assert replay.status_code == 201
    assert replay.headers["idempotency-replayed"] == "true"
    assert replay.json() == created.json()

    version_id = created.json()["id"]
    listed = core_stack.client.get(
        f"/api/v1/jobs/{published.job_id}/versions"
    )
    fetched = core_stack.client.get(
        f"/api/v1/jobs/{published.job_id}/versions/{version_id}"
    )
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["items"]] == [version_id]
    assert fetched.status_code == 200
    assert fetched.json() == created.json()


def test_validation_material_requires_bound_canonical_schema_snapshots(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "schema")
    with core_stack.sessions() as session:
        version = session.get(JobVersion, published.job_version_id)
        assert version is not None
        material = ValidationMaterial(
            source_schema_snapshot=version.source_schema_snapshot,
            target_schema_snapshot=version.target_schema_snapshot,
            source_schema_hash=version.source_schema_hash,
            target_schema_hash=version.target_schema_hash,
            source_physical_table_identity_hash=(
                version.source_physical_table_identity_hash
            ),
            target_namespace_id=version.target_namespace_id,
            transfer_policy_id=version.transfer_policy_id,
            transfer_policy_scope_hash=version.transfer_policy_scope_hash,
            runtime_sha256=version.runtime_sha256,
            reader_plugin_sha256=version.reader_plugin_sha256,
            writer_plugin_sha256=version.writer_plugin_sha256,
        )
    audit = AuditContext(
        request_id=uuid4(),
        source_ip="127.0.0.1",
        user_agent="core-test",
    )
    with pytest.raises(ProblemException) as invalid_shape:
        core_stack.service.accept_validation_material(
            principal=core_stack.principal,
            job_id=published.job_id,
            material=replace(
                material,
                source_schema_snapshot={"columns": [{"name": "id"}]},
            ),
            audit=audit,
        )
    assert invalid_shape.value.code == "SCHEMA_SNAPSHOT_INVALID"
    with pytest.raises(ProblemException) as invalid_hash:
        core_stack.service.accept_validation_material(
            principal=core_stack.principal,
            job_id=published.job_id,
            material=replace(material, source_schema_hash="0" * 64),
            audit=audit,
        )
    assert invalid_hash.value.code == "SCHEMA_SNAPSHOT_HASH_MISMATCH"

    validated = core_stack.service.accept_validation_material(
        principal=core_stack.principal,
        job_id=published.job_id,
        material=material,
        audit=audit,
    )
    assert validated.status == "VALID"
    with core_stack.sessions() as session:
        job = session.get(SyncJob, published.job_id)
        assert job is not None
        assert (
            job.validation_report["source_schema_hash"]
            == schema_snapshot_hash(job.validation_report["source_schema_snapshot"])
        )
        assert (
            job.validation_report["target_schema_hash"]
            == schema_snapshot_hash(job.validation_report["target_schema_snapshot"])
        )


def test_job_preview_is_redacted_and_explicitly_not_executable(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "preview")
    preview = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/preview"
    )
    assert preview.status_code == 200, preview.text
    payload = preview.json()
    assert payload["draft_spec_hash"] == "b" * 64
    assert payload["executable"] is False
    encoded = json.dumps(payload["redacted_datax_json"], sort_keys=True)
    assert "${SECRET}" in encoded
    assert "mysql-preview.example.test" not in encoded
    assert "postgres-preview.example.test" not in encoded
    assert '"preSql"' not in encoded
    assert '"postSql"' not in encoded
    assert '"transformer"' not in encoded


def test_job_validation_fails_closed_without_current_worker_attestation(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "validate-runtime")
    validation = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/validate"
    )
    assert validation.status_code == 503
    assert validation.json()["code"] == "RUNTIME_ATTESTATION_UNAVAILABLE"
    assert validation.json()["retryable"] is True


def test_service_draining_blocks_new_execution_before_target_admission(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "draining")
    with core_stack.sessions.begin() as session:
        control = session.get(SystemControl, 1)
        assert control is not None
        control.draining = True
        control.reason = "STARTUP_RECONCILIATION_REQUIRED"

    response = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": "execution-draining-001"},
        json=_execution_request(published.job_version_id),
    )
    assert response.status_code == 503
    assert response.json()["code"] == "SERVICE_DRAINING"


def test_claim_persists_expired_exclusivity_as_a_queue_block(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "expired")
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": "execution-expired-001"},
        json=_execution_request(published.job_version_id),
    )
    execution_id = UUID(created.json()["id"])
    with core_stack.sessions.begin() as session:
        execution = session.get(Execution, execution_id)
        assert execution is not None
        confirmation = dict(execution.target_exclusivity_confirmation)
        confirmation["valid_until"] = (
            datetime.now(UTC) - timedelta(seconds=1)
        ).isoformat()
        execution.target_exclusivity_confirmation = confirmation

    expired_claim = core_stack.service.claim_next_execution(
        worker_id="worker-1",
        host_boot_id="boot-1",
        cgroup_identity="container:test",
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
    assert expired_claim is None
    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == execution_id
            )
        )
        assert execution is not None
        assert execution.target_exclusivity_status == "EXPIRED"
        assert (
            execution.target_exclusivity_revocation_reason
            == "VALIDITY_WINDOW_EXPIRED"
        )
        assert execution.queue_eligibility_state == "BLOCKED"
        assert execution.queue_block_reason == "TARGET_EXCLUSIVITY_EXPIRED"
        assert execution.active_attempt_id is None
        assert target_lock is not None and target_lock.state == "RESERVED"
    assert core_stack.service.reconcile_unclaimed_target_exclusivity(
        execution_id=execution_id
    )
    reconciled = core_stack.client.get(f"/api/v1/executions/{execution_id}").json()
    assert reconciled["process_state"] == "CANCELED"
    assert reconciled["data_effect"] == "NONE"
    assert reconciled["verification_state"] == "NOT_STARTED"
    assert reconciled["target_copy_lock"]["state"] == "RELEASED"


def _execution_request(job_version_id: UUID) -> dict:
    now = datetime.now(UTC)
    return {
        "job_version_id": str(job_version_id),
        "source_quiescence_confirmation": {
            "confirmed": True,
            "confirmed_at": (now - timedelta(minutes=1)).isoformat(),
            "note": "Operator confirms source silence.",
        },
        "target_exclusivity_confirmation": {
            "statement_version": "1.0",
            "confirmed": True,
            "confirmed_at": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(hours=1)).isoformat(),
            "responsible_party": "DBA",
            "note": "DBA owns the external exclusivity window.",
        },
    }


def _runtime_preflight(published: PublishedJob) -> dict:
    target_connection_evidence_id = uuid4()
    target_empty_document = {
        "result": "EMPTY",
        "checked_at": (
            datetime.now(UTC).isoformat().replace("+00:00", "Z")
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
        "connection_evidence_id": str(target_connection_evidence_id),
    }
    return {
        "datax_release": "datax_v202309",
        "runtime_sha256": "d" * 64,
        "reader_plugin_sha256": "b" * 64,
        "writer_plugin_sha256": "c" * 64,
        "resolved_config_hash": hashlib.sha256(
            f"{published.job_version_id}:resolved".encode()
        ).hexdigest(),
        "source_connection_evidence_id": str(uuid4()),
        "target_connection_evidence_id": str(target_connection_evidence_id),
        "target_empty_evidence": {
            **target_empty_document,
            "evidence_hash": hashlib.sha256(
                b"DXTARGETEMPTYv1\n" + rfc8785.dumps(target_empty_document)
            ).hexdigest(),
        },
    }


def _passed_oracle_report(
    *,
    execution_response: dict,
    claimed_response: dict,
    claim: ClaimedExecution,
    published: PublishedJob,
    runtime_preflight: dict,
    source_confirmed_at: str,
) -> dict:
    target_empty_checked_at = datetime.fromisoformat(
        runtime_preflight["target_empty_evidence"]["checked_at"]
    )
    report_started_at = target_empty_checked_at - timedelta(seconds=1)
    snapshot_started_at = target_empty_checked_at + timedelta(seconds=1)
    read_started_at = snapshot_started_at + timedelta(seconds=1)
    read_finished_at = read_started_at + timedelta(seconds=1)
    snapshot_finished_at = read_finished_at + timedelta(seconds=1)
    report_finished_at = snapshot_finished_at
    multiset_hash = "1" * 64
    source_fingerprint = "2" * 64
    target_confirmation = execution_response["target_exclusivity_confirmation"]
    runtime = claimed_response["runtime_snapshot"]
    report = {
        "schema_version": "1.0",
        "oracle_version": "oracle-v1.0",
        "execution_id": execution_response["id"],
        "job_version_id": str(published.job_version_id),
        "started_at": report_started_at.isoformat(),
        "finished_at": report_finished_at.isoformat(),
        "source_quiescence": {
            "mode": "OPERATOR_QUIESCED",
            "operator_confirmed_at": source_confirmed_at,
            "preflight_fingerprint": source_fingerprint,
            "post_verification_fingerprint": source_fingerprint,
            "unchanged": True,
        },
        "target_lock": {
            "lock_key_hash": published.target_table_identity_hash,
            "fence_epoch": claim.fence_epoch,
            "held_through_verification": True,
        },
        "target_exclusivity": {
            "mode": "OPERATOR_OR_DBA_CONFIRMED",
            "statement_version": "1.0",
            "responsible_party": target_confirmation["responsible_party"],
            "confirmed_at": target_confirmation["confirmed_at"],
            "valid_until": target_confirmation["valid_until"],
            "status": "ACTIVE",
            "revoked_at": None,
            "revocation_reason": None,
            "target_empty_checked_at": target_empty_checked_at.isoformat(),
            "target_snapshot_id": "independent-oracle-snapshot",
            "valid_through_target_snapshot": True,
            "confirmation_evidence_sha256": runtime[
                "target_exclusivity_confirmation_sha256"
            ],
        },
        "normalization": {
            "row_algorithm": "SHA-256",
            "row_preimage": "DOMAIN_NUL_FIELD_COUNT_U32_BE_FIELDS",
            "field_encoding": "TAG_LENGTH_U16_BE_TAG_VALUE_LENGTH_U64_BE_VALUE",
            "collection_semantics": "MULTISET_WITH_COUNTS",
            "stable_order": "ROW_DIGEST_ASC_THEN_COUNT",
            "multiset_preimage": "DOMAIN_NUL_ROW_DIGEST_RAW32_COUNT_U64_BE",
            "null_encoding": "TYPE_TAGGED_NULL",
            "text_encoding": "UTF-8",
            "unicode_normalization": "NFC",
            "trim_text": False,
            "decimal_encoding": (
                "CANONICAL_BASE10_NO_EXPONENT_NO_INSIGNIFICANT_ZERO"
            ),
            "negative_zero": "NORMALIZE_TO_ZERO",
            "session_timezone": "UTC",
            "timestamp_encoding": "RFC3339_UTC_MICROSECONDS",
            "boolean_encoding": "LOWERCASE_TRUE_FALSE",
            "binary_encoding": "BASE64_RFC4648",
            "field_separator": "LENGTH_PREFIXED",
        },
        "mapping_order": [
            {
                "ordinal": 1,
                "source_column": "id",
                "target_column": "id",
                "logical_type": "INTEGER",
            }
        ],
        "source_result": {
            "row_count": 1,
            "distinct_row_digest_count": 1,
            "multiset_sha256": multiset_hash,
            "read_started_at": report_started_at.isoformat(),
            "read_finished_at": target_empty_checked_at.isoformat(),
        },
        "target_result": {
            "row_count": 1,
            "distinct_row_digest_count": 1,
            "multiset_sha256": multiset_hash,
            "read_started_at": read_started_at.isoformat(),
            "read_finished_at": read_finished_at.isoformat(),
            "snapshot_mode": "SINGLE_CONSISTENT_READ_TRANSACTION",
            "snapshot_id": "independent-oracle-snapshot",
            "snapshot_started_at": snapshot_started_at.isoformat(),
            "snapshot_finished_at": snapshot_finished_at.isoformat(),
        },
        "difference": {
            "missing_row_count": 0,
            "unexpected_row_count": 0,
            "row_count_equal": True,
            "multiset_sha256_equal": True,
            "sample_digest_pairs": [],
        },
        "result": "PASSED",
    }
    report["artifact_sha256"] = hashlib.sha256(rfc8785.dumps(report)).hexdigest()
    return report


def _assert_audit_contract(core_stack: CoreStack) -> None:
    schema_path = (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "contracts"
        / "audit-event.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )
    with core_stack.sessions() as session:
        events = list(session.scalars(select(AuditEvent)))
    assert events
    for event in events:
        errors = sorted(
            validator.iter_errors(event.event_json),
            key=lambda item: list(item.absolute_path),
        )
        assert errors == [], [
            {
                "path": ".".join(str(part) for part in error.absolute_path),
                "message": error.message,
            }
            for error in errors
        ]


def test_job_patch_immutable_identity_and_audit_reads(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "patch-audit")

    renamed = core_stack.client.patch(
        f"/api/v1/jobs/{published.job_id}",
        headers={"If-Match": 'W/"3"'},
        json={"name": "Renamed copy"},
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"] == "Renamed copy"
    assert renamed.headers["etag"] == 'W/"4"'
    assert renamed.json()["status"] == "PUBLISHED"

    draft_spec = renamed.json()["draft_spec"]
    draft_spec["execution_policy"]["timeout_seconds"] = 7200
    updated = core_stack.client.patch(
        f"/api/v1/jobs/{published.job_id}",
        headers={"If-Match": 'W/"4"'},
        json={"draft_spec": draft_spec},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["status"] == "DRAFT"
    assert updated.json()["validated_spec_hash"] is None
    assert updated.json()["draft_spec_hash"] != "b" * 64
    assert updated.headers["etag"] == 'W/"5"'

    with core_stack.sessions() as session:
        stored_namespace = session.get(
            TargetNamespace,
            published.target_namespace_id,
        )
        assert stored_namespace is not None
        identity_id = stored_namespace.physical_endpoint_identity_id
    identity = core_stack.client.get(
        f"/api/v1/physical-endpoint-identities/{identity_id}"
    )
    assert identity.status_code == 200, identity.text
    assert identity.json()["id"] == str(identity_id)
    assert "verification_evidence" not in identity.json()

    namespace = core_stack.client.get(
        f"/api/v1/target-namespaces/{published.target_namespace_id}"
    )
    assert namespace.status_code == 200, namespace.text
    assert namespace.json()["target_namespace_id"] == str(
        published.target_namespace_id
    )

    project_audit = core_stack.client.get(
        f"/api/v1/projects/{published.project_id}/audit-events",
        params={"action": "JOB_DRAFT_UPDATED"},
    )
    assert project_audit.status_code == 200, project_audit.text
    assert len(project_audit.json()["items"]) == 2
    assert all(
        item["action"] == "JOB_DRAFT_UPDATED"
        for item in project_audit.json()["items"]
    )
    organization_audit = core_stack.client.get(
        "/api/v1/audit-events",
        params={"project_id": str(published.project_id)},
    )
    assert organization_audit.status_code == 200
    assert len(organization_audit.json()["items"]) == 2


def test_job_list_filters_cursor_scope_and_archive_gate(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "job-list")
    now = datetime.now(UTC)
    with core_stack.sessions.begin() as session:
        original = session.get(SyncJob, published.job_id)
        assert original is not None
        second_id = uuid4()
        third_id = uuid4()
        session.add_all(
            [
                SyncJob(
                    id=second_id,
                    project_id=published.project_id,
                    name="Orders staging draft",
                    status="DRAFT",
                    draft_spec_json=original.draft_spec_json,
                    draft_spec_hash="1" * 64,
                    validated_spec_hash=None,
                    validation_report=None,
                    latest_published_version_id=None,
                    created_by=core_stack.principal.user_id,
                    created_at=now + timedelta(seconds=2),
                    updated_at=now + timedelta(seconds=2),
                    row_version=1,
                ),
                SyncJob(
                    id=third_id,
                    project_id=published.project_id,
                    name="Archive candidate",
                    status="VALID",
                    draft_spec_json=original.draft_spec_json,
                    draft_spec_hash="2" * 64,
                    validated_spec_hash="2" * 64,
                    validation_report={"valid": True},
                    latest_published_version_id=None,
                    created_by=core_stack.principal.user_id,
                    created_at=now + timedelta(seconds=1),
                    updated_at=now + timedelta(seconds=1),
                    row_version=1,
                ),
            ]
        )

    first = core_stack.client.get(
        f"/api/v1/projects/{published.project_id}/jobs",
        params={"limit": 1},
    )
    assert first.status_code == 200, first.text
    assert first.json()["has_more"] is True
    cursor = first.json()["next_cursor"]
    second = core_stack.client.get(
        f"/api/v1/projects/{published.project_id}/jobs",
        params={"limit": 1, "cursor": cursor},
    )
    assert second.status_code == 200, second.text
    assert second.json()["items"][0]["id"] != first.json()["items"][0]["id"]

    changed_filter = core_stack.client.get(
        f"/api/v1/projects/{published.project_id}/jobs",
        params={"limit": 1, "cursor": cursor, "status": "DRAFT"},
    )
    assert changed_filter.status_code == 400
    assert changed_filter.json()["code"] == "CURSOR_INVALID"

    searched = core_stack.client.get(
        f"/api/v1/projects/{published.project_id}/jobs",
        params={"q": "SOURCE_TABLE_JOB-LIST"},
    )
    assert searched.status_code == 200, searched.text
    assert len(searched.json()["items"]) == 3
    reader_filtered = core_stack.client.get(
        f"/api/v1/projects/{published.project_id}/jobs",
        params={"reader_plugin": "postgresqlreader"},
    )
    assert reader_filtered.status_code == 200
    assert reader_filtered.json()["items"] == []

    archived = core_stack.client.patch(
        f"/api/v1/jobs/{third_id}",
        headers={"If-Match": 'W/"1"'},
        json={"status": "ARCHIVED"},
    )
    assert archived.status_code == 200, archived.text
    assert archived.json()["status"] == "ARCHIVED"
    with core_stack.sessions() as session:
        stored = session.get(SyncJob, third_id)
        assert stored is not None
        assert stored.archived_by == core_stack.principal.user_id
        assert stored.archived_at is not None

    queued = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": "job-archive-gate-001"},
        json=_execution_request(published.job_version_id),
    )
    assert queued.status_code == 202, queued.text
    latest_execution = core_stack.client.get(
        f"/api/v1/projects/{published.project_id}/jobs",
        params={"latest_execution_state": "QUEUED"},
    )
    assert latest_execution.status_code == 200, latest_execution.text
    assert [item["id"] for item in latest_execution.json()["items"]] == [
        str(published.job_id)
    ]
    summary = latest_execution.json()["items"][0]
    assert summary["latest_published_version_no"] == 1
    assert summary["latest_execution_process_state"] == "QUEUED"
    assert summary["latest_execution_at"] is not None
    blocked_archive = core_stack.client.patch(
        f"/api/v1/jobs/{published.job_id}",
        headers={"If-Match": 'W/"3"'},
        json={"status": "ARCHIVED"},
    )
    assert blocked_archive.status_code == 409
    assert blocked_archive.json()["code"] == "JOB_ACTIVE_EXECUTION"


def test_execution_cursor_is_bound_to_all_filters(
    core_stack: CoreStack,
) -> None:
    published = _seed_published_job(core_stack, "execution-cursor")
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": "execution-filter-cursor-001"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 202, created.text
    execution_id = UUID(created.json()["id"])
    with core_stack.sessions() as session:
        execution = session.get(Execution, execution_id)
        assert execution is not None
        queued_at = execution.queued_at

    route = f"GET /projects/{published.project_id}/executions"
    scope = _filtered_cursor_scope(
        route,
        {
            "q": None,
            "process_state": [],
            "data_effect": [],
            "verification_state": [],
            "target_exclusivity_status": [],
            "job_id": None,
            "job_version_id": None,
            "requested_by": None,
            "from": None,
            "to": None,
            "is_rerun": None,
            "unresolved_failure": None,
        },
    )
    cursor = core_stack.service._encode_cursor(
        actor_id=core_stack.principal.user_id,
        scope=scope,
        created_at=queued_at,
        resource_id=execution_id,
    )
    changed_filter = core_stack.client.get(
        f"/api/v1/projects/{published.project_id}/executions",
        params={"cursor": cursor, "process_state": "FAILED"},
    )
    assert changed_filter.status_code == 400
    assert changed_filter.json()["code"] == "CURSOR_INVALID"

    matching = core_stack.client.get(
        f"/api/v1/projects/{published.project_id}/executions",
        params={
            "q": "Copy execution-cursor",
            "target_exclusivity_status": "ACTIVE",
            "job_version_id": str(published.job_version_id),
            "requested_by": str(core_stack.principal.user_id),
            "is_rerun": "false",
        },
    )
    assert matching.status_code == 200, matching.text
    assert [item["id"] for item in matching.json()["items"]] == [
        str(execution_id)
    ]


def test_plugins_are_derived_from_current_worker_attestation(
    core_stack: CoreStack,
) -> None:
    now = datetime.now(UTC)
    reconcile_epoch = uuid4()
    with core_stack.sessions.begin() as session:
        control = session.get(SystemControl, 1)
        assert control is not None
        control.host_boot_id = "boot-test"
        control.reconcile_epoch = reconcile_epoch
        control.reconciled_at = now
        session.execute(
            text(
                """
                CREATE TABLE worker_heartbeats (
                    worker_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    runtime_code TEXT NOT NULL,
                    oracle_code TEXT NOT NULL,
                    datax_release TEXT,
                    mysqlreader_plugin_sha256 TEXT,
                    postgresqlreader_plugin_sha256 TEXT,
                    mysqlwriter_plugin_sha256 TEXT,
                    postgresqlwriter_plugin_sha256 TEXT,
                    host_boot_id TEXT,
                    reconcile_epoch CHAR(32),
                    reconciled_at DATETIME,
                    updated_at DATETIME NOT NULL
                )
                """
            )
        )
        session.execute(
            text(
                """
                INSERT INTO worker_heartbeats (
                    worker_id,
                    status,
                    runtime_code,
                    oracle_code,
                    datax_release,
                    mysqlreader_plugin_sha256,
                    postgresqlreader_plugin_sha256,
                    mysqlwriter_plugin_sha256,
                    postgresqlwriter_plugin_sha256,
                    host_boot_id,
                    reconcile_epoch,
                    reconciled_at,
                    updated_at
                ) VALUES (
                    'worker-1',
                    'READY',
                    'RUNTIME_OK',
                    'ORACLE_OK',
                    'datax_v202309',
                    :mysqlreader,
                    :postgresqlreader,
                    :mysqlwriter,
                    :postgresqlwriter,
                    'boot-test',
                    :reconcile_epoch,
                    :reconciled_at,
                    :updated_at
                )
                """
            ),
            {
                "mysqlreader": "1" * 64,
                "postgresqlreader": "2" * 64,
                "mysqlwriter": "3" * 64,
                "postgresqlwriter": "4" * 64,
                "reconcile_epoch": reconcile_epoch.hex,
                "reconciled_at": now,
                "updated_at": now,
            },
        )

    response = core_stack.client.get("/api/v1/plugins")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert [
        item["datax_plugin_name"] for item in payload["items"]
    ] == [
        "mysqlreader",
        "mysqlwriter",
        "postgresqlreader",
        "postgresqlwriter",
    ]
    schema = json.loads(
        (
            Path(__file__).parents[2]
            / "docs/contracts/plugin-manifest.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )
    for item in payload["items"]:
        assert list(validator.iter_errors(item)) == []


def _seed_published_job(core_stack: CoreStack, label: str) -> PublishedJob:
    now = datetime.now(UTC)
    project_id = uuid4()
    source_policy_id = uuid4()
    target_policy_id = uuid4()
    source_policy_revision_id = uuid4()
    target_policy_revision_id = uuid4()
    source_identity_id = uuid4()
    target_identity_id = uuid4()
    source_datasource_id = uuid4()
    target_datasource_id = uuid4()
    source_revision_id = uuid4()
    target_revision_id = uuid4()
    source_secret_id = uuid4()
    target_secret_id = uuid4()
    target_namespace_id = uuid4()
    transfer_policy_id = uuid4()
    job_id = uuid4()
    job_version_id = uuid4()
    source_catalog = f"source_{label}"
    target_catalog = f"target_{label}"
    source_table = f"source_table_{label}"
    target_table = f"target_table_{label}"
    source_identity_hash = hashlib.sha256(
        f"{label}:source-identity".encode()
    ).hexdigest()
    target_identity_hash = hashlib.sha256(
        f"{label}:target-identity".encode()
    ).hexdigest()
    target_table_hash = hashlib.sha256(
        f"{label}:target-table".encode()
    ).hexdigest()
    source_table_hash = hashlib.sha256(
        f"{label}:source-table".encode()
    ).hexdigest()
    spec = {
        "schema_version": "1.0",
        "source": {
            "datasource_id": str(source_datasource_id),
            "datasource_revision_id": str(source_revision_id),
            "plugin_name": "mysqlreader",
            "table": {
                "schema_name": source_catalog,
                "table_name": source_table,
            },
        },
        "target": {
            "datasource_id": str(target_datasource_id),
            "datasource_revision_id": str(target_revision_id),
            "plugin_name": "postgresqlwriter",
            "table": {"schema_name": "public", "table_name": target_table},
        },
        "selection_mode": "ALL_COLUMNS",
        "mappings": [
            {
                "source_column": "id",
                "source_ordinal": 1,
                "source_type": "BIGINT",
                "source_nullable": False,
                "target_column": "id",
                "target_ordinal": 1,
                "target_type": "BIGINT",
                "target_nullable": False,
                "compatibility": "EXACT",
                "oracle_logical_type": "INTEGER",
            }
        ],
        "source_consistency_mode": "OPERATOR_QUIESCED",
        "target_precondition": "EMPTY_AND_VERIFIABLE",
        "write_semantics": "INSERT_ONLY_ONCE",
        "duplicate_policy": "REJECT_NONEMPTY_TARGET",
        "partial_write_policy": "MANUAL_REMEDIATE",
        "write_policy": {
            "mode": "INSERT",
            "target_table_must_exist": True,
            "target_table_must_be_empty": True,
            "platform_may_mutate_target_before_run": False,
        },
        "execution_policy": {
            "channel": 1,
            "timeout_seconds": 3600,
            "dirty_data_limit": {"record_count": 0, "percentage": 0},
        },
    }
    source_snapshot = _single_integer_schema_snapshot(
        engine="MYSQL_8",
        physical_endpoint_identity_id=source_identity_id,
        physical_table_identity_hash=source_table_hash,
        catalog_name=source_catalog,
        schema_name="",
        table_name=source_table,
    )
    target_snapshot = _single_integer_schema_snapshot(
        engine="POSTGRESQL_15",
        physical_endpoint_identity_id=target_identity_id,
        physical_table_identity_hash=target_table_hash,
        catalog_name=target_catalog,
        schema_name="public",
        table_name=target_table,
    )
    scope = {
        "schema_version": "1.0",
        "source": {
            "catalog": source_catalog,
            "schema": source_catalog,
            "table": source_table,
            "allowed_columns": ["id"],
        },
        "target": {
            "catalog": target_catalog,
            "schema": "public",
            "table": target_table,
            "allowed_columns": ["id"],
        },
    }
    with core_stack.sessions.begin() as session:
        session.add_all(
            [
                Project(
                    id=project_id,
                    organization_id=core_stack.principal.organization_id,
                    name=f"Project {label}",
                    slug=f"project-{label}",
                    status="ACTIVE",
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                ProjectQueueServiceCursor(
                    project_id=project_id,
                    last_service_sequence=0,
                    served_execution_count=0,
                    served_recovery_probe_count=0,
                    row_version=1,
                    updated_at=now,
                ),
                EndpointPolicy(
                    id=source_policy_id,
                    organization_id=core_stack.principal.organization_id,
                    name=f"Source policy {label}",
                    current_revision_id=source_policy_revision_id,
                    status="ACTIVE",
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                EndpointPolicy(
                    id=target_policy_id,
                    organization_id=core_stack.principal.organization_id,
                    name=f"Target policy {label}",
                    current_revision_id=target_policy_revision_id,
                    status="ACTIVE",
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                EndpointPolicyRevision(
                    id=source_policy_revision_id,
                    endpoint_policy_id=source_policy_id,
                    revision_no=1,
                    engine="MYSQL_8",
                    host_kind="EXACT_FQDN",
                    host_value=f"mysql-{label}.example.test",
                    allowed_cidrs=["10.10.0.0/24"],
                    allowed_ports=[3306],
                    tls_required=True,
                    dns_ttl_ceiling_seconds=60,
                    resolver_policy_version="resolver-v1",
                    egress_policy_version="egress-v1",
                    policy_hash="1" * 64,
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                ),
                EndpointPolicyRevision(
                    id=target_policy_revision_id,
                    endpoint_policy_id=target_policy_id,
                    revision_no=1,
                    engine="POSTGRESQL_15",
                    host_kind="EXACT_FQDN",
                    host_value=f"postgres-{label}.example.test",
                    allowed_cidrs=["10.20.0.0/24"],
                    allowed_ports=[5432],
                    tls_required=True,
                    dns_ttl_ceiling_seconds=60,
                    resolver_policy_version="resolver-v1",
                    egress_policy_version="egress-v1",
                    policy_hash="2" * 64,
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                ),
                PhysicalEndpointIdentity(
                    id=source_identity_id,
                    organization_id=core_stack.principal.organization_id,
                    engine="MYSQL_8",
                    identity_scheme="MYSQL_SERVER_UUID",
                    server_identity_hash=source_identity_hash,
                    verification_evidence={"probe": "real-validator-boundary"},
                    verification_evidence_hash="4" * 64,
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                ),
                PhysicalEndpointIdentity(
                    id=target_identity_id,
                    organization_id=core_stack.principal.organization_id,
                    engine="POSTGRESQL_15",
                    identity_scheme="POSTGRES_SYSTEM_IDENTIFIER",
                    server_identity_hash=target_identity_hash,
                    verification_evidence={"probe": "real-validator-boundary"},
                    verification_evidence_hash="6" * 64,
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                ),
                Datasource(
                    id=source_datasource_id,
                    project_id=project_id,
                    name=f"Source {label}",
                    current_revision_id=source_revision_id,
                    current_secret_id=source_secret_id,
                    status="ACTIVE",
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                Datasource(
                    id=target_datasource_id,
                    project_id=project_id,
                    name=f"Target {label}",
                    current_revision_id=target_revision_id,
                    current_secret_id=target_secret_id,
                    status="ACTIVE",
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                DatasourceRevision(
                    id=source_revision_id,
                    datasource_id=source_datasource_id,
                    revision_no=1,
                    endpoint_policy_revision_id=source_policy_revision_id,
                    physical_endpoint_identity_id=source_identity_id,
                    engine="MYSQL_8",
                    host=f"mysql-{label}.example.test",
                    port=3306,
                    database_name=source_catalog,
                    default_schema=source_catalog,
                    username="reader",
                    ssl_mode="VERIFY_FULL",
                    connection_options={},
                    config_hash="7" * 64,
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                ),
                DatasourceRevision(
                    id=target_revision_id,
                    datasource_id=target_datasource_id,
                    revision_no=1,
                    endpoint_policy_revision_id=target_policy_revision_id,
                    physical_endpoint_identity_id=target_identity_id,
                    engine="POSTGRESQL_15",
                    host=f"postgres-{label}.example.test",
                    port=5432,
                    database_name=target_catalog,
                    default_schema="public",
                    username="writer",
                    ssl_mode="VERIFY_FULL",
                    connection_options={},
                    config_hash="8" * 64,
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                ),
                DatasourceUsageGrant(
                    id=uuid4(),
                    datasource_id=source_datasource_id,
                    organization_member_id=core_stack.member_id,
                    usage="SOURCE_USE",
                    status="ACTIVE",
                    granted_by=core_stack.principal.user_id,
                    granted_at=now,
                ),
                DatasourceUsageGrant(
                    id=uuid4(),
                    datasource_id=target_datasource_id,
                    organization_member_id=core_stack.member_id,
                    usage="TARGET_USE",
                    status="ACTIVE",
                    granted_by=core_stack.principal.user_id,
                    granted_at=now,
                ),
                TargetNamespace(
                    id=target_namespace_id,
                    physical_endpoint_identity_id=target_identity_id,
                    engine="POSTGRESQL_15",
                    normalized_catalog_name=target_catalog,
                    normalized_schema_name="public",
                    normalized_table_name=target_table,
                    normalization_version="1.0",
                    physical_table_identity_hash=target_table_hash,
                    created_at=now,
                ),
                TransferPolicy(
                    id=transfer_policy_id,
                    project_id=project_id,
                    source_datasource_revision_id=source_revision_id,
                    target_datasource_revision_id=target_revision_id,
                    source_physical_endpoint_identity_id=source_identity_id,
                    target_physical_endpoint_identity_id=target_identity_id,
                    scope_json=scope,
                    scope_hash="a" * 64,
                    classification="STANDARD",
                    status="ACTIVE",
                    requested_by=core_stack.principal.user_id,
                    activated_at=now,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                SyncJob(
                    id=job_id,
                    project_id=project_id,
                    name=f"Copy {label}",
                    status="PUBLISHED",
                    draft_spec_json=spec,
                    draft_spec_hash="b" * 64,
                    validated_spec_hash="b" * 64,
                    validation_report={"valid": True},
                    latest_published_version_id=job_version_id,
                    created_by=core_stack.principal.user_id,
                    created_at=now,
                    updated_at=now,
                    row_version=3,
                ),
                JobVersion(
                    id=job_version_id,
                    job_id=job_id,
                    version_no=1,
                    job_spec_schema_version="1.0",
                    spec_json=spec,
                    spec_hash="b" * 64,
                    source_datasource_revision_id=source_revision_id,
                    target_datasource_revision_id=target_revision_id,
                    source_endpoint_policy_revision_id=source_policy_revision_id,
                    target_endpoint_policy_revision_id=target_policy_revision_id,
                    source_physical_table_identity_hash=source_table_hash,
                    target_namespace_id=target_namespace_id,
                    transfer_policy_id=transfer_policy_id,
                    transfer_policy_scope_hash="a" * 64,
                    source_schema_snapshot=source_snapshot,
                    target_schema_snapshot=target_snapshot,
                    source_schema_hash=schema_snapshot_hash(source_snapshot),
                    target_schema_hash=schema_snapshot_hash(target_snapshot),
                    reader_plugin_name="mysqlreader",
                    reader_plugin_sha256="b" * 64,
                    writer_plugin_name="postgresqlwriter",
                    writer_plugin_sha256="c" * 64,
                    datax_release="datax_v202309",
                    runtime_sha256="d" * 64,
                    version_artifact_hash="f" * 64,
                    published_by=core_stack.principal.user_id,
                    published_at=now,
                ),
            ]
        )
    return PublishedJob(
        project_id=project_id,
        job_id=job_id,
        job_version_id=job_version_id,
        source_datasource_id=source_datasource_id,
        target_datasource_id=target_datasource_id,
        source_secret_id=source_secret_id,
        target_secret_id=target_secret_id,
        target_namespace_id=target_namespace_id,
        target_datasource_revision_id=target_revision_id,
        target_endpoint_policy_revision_id=target_policy_revision_id,
        target_table_identity_hash=target_table_hash,
    )


def _credential_selector(
    published: PublishedJob,
    binding: CredentialBinding,
):
    def select_binding(
        session,
        *,
        source_datasource_id: UUID,
        target_datasource_id: UUID,
    ) -> CredentialBinding:
        assert session.in_transaction()
        assert source_datasource_id == published.source_datasource_id
        assert target_datasource_id == published.target_datasource_id
        return binding

    return select_binding


def _preflight_evidence_validator(
    published: PublishedJob,
    expected_claim: ClaimedExecution,
    runtime_preflight: dict,
):
    def validate(
        session,
        *,
        claim: ClaimedExecution,
        source_evidence_id: UUID,
        target_evidence_id: UUID,
        source_revision_id: UUID,
        target_revision_id: UUID,
        source_policy_revision_id: UUID,
        target_policy_revision_id: UUID,
    ) -> None:
        assert session.in_transaction()
        assert claim == expected_claim
        assert source_evidence_id == UUID(
            runtime_preflight["source_connection_evidence_id"]
        )
        assert target_evidence_id == UUID(
            runtime_preflight["target_connection_evidence_id"]
        )
        assert source_revision_id != target_revision_id
        assert target_revision_id == published.target_datasource_revision_id
        assert source_policy_revision_id != target_policy_revision_id
        assert (
            target_policy_revision_id
            == published.target_endpoint_policy_revision_id
        )

    return validate


def _single_integer_schema_snapshot(
    *,
    engine: str,
    physical_endpoint_identity_id: UUID,
    physical_table_identity_hash: str,
    catalog_name: str,
    schema_name: str,
    table_name: str,
) -> dict:
    return {
        "schema_version": "1.0",
        "normalization_version": "1.0",
        "engine": engine,
        "physical_endpoint_identity_id": str(physical_endpoint_identity_id),
        "physical_table_identity_hash": physical_table_identity_hash,
        "identifier_case_mode": (
            "MYSQL_LOWER_CASE_TABLE_NAMES_1"
            if engine == "MYSQL_8"
            else "POSTGRESQL_FOLDED_OR_QUOTED"
        ),
        "catalog_name": catalog_name,
        "schema_name": schema_name,
        "table_name": table_name,
        "table_kind": "BASE_TABLE",
        "columns": [
            {
                "ordinal_position": 1,
                "name": "id",
                "native_type": "bigint",
                "logical_type": "INTEGER",
                "nullable": False,
                "unsigned": False,
                "generated": False,
                "identity": False,
                "character_maximum_length": None,
                "numeric_precision": 64,
                "numeric_scale": 0,
                "datetime_precision": None,
                "character_set_name": None,
                "collation_name": None,
                "default_present": False,
                "default_expression_sha256": None,
            }
        ],
        "constraints": [],
        "triggers": [],
        "table_options": {
            "partitioned": False,
            "row_security_enabled": None if engine == "MYSQL_8" else False,
        },
    }
