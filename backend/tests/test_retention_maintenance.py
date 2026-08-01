from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy import func, select
from test_core_control_plane import (
    CoreStack,
    _execution_request,
    _seed_published_job,
    core_stack,
)
from test_execution_logs import _persist_redacted_log

from datax_studio.auth.db import AuditEvent, IdempotencyRecord
from datax_studio.core.db import (
    Execution,
    ExecutionEvent,
    TargetCopyLock,
)
from datax_studio.logs.db import ExecutionLogChunk
from datax_studio.maintenance.db import RetentionHold
from datax_studio.maintenance.retention import (
    RetentionMaintenanceError,
    RetentionMaintenanceService,
)
from datax_studio.recovery.db import RecoveryGate

__all__ = ["core_stack"]


def _service(
    core_stack: CoreStack,
    tmp_path: Path,
) -> RetentionMaintenanceService:
    settings = core_stack.client.app.state.settings.model_copy(
        update={"log_volume_path": tmp_path / "logs"}
    )
    core_stack.client.app.state.settings = settings
    return RetentionMaintenanceService(
        settings=settings,
        sessions=core_stack.sessions,
    )


def _create_canceled_execution(
    core_stack: CoreStack,
    *,
    suffix: str,
) -> UUID:
    published = _seed_published_job(core_stack, suffix)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"retention-execution-{suffix}"},
        json=_execution_request(published.job_version_id),
    )
    assert created.status_code == 202, created.text
    execution_id = UUID(created.json()["id"])
    canceled = core_stack.client.post(
        f"/api/v1/executions/{execution_id}/cancel",
        headers={"Idempotency-Key": f"retention-cancel-{suffix}"},
        json={"reason": "retention fixture cancellation"},
    )
    assert canceled.status_code == 202, canceled.text
    assert core_stack.service.reconcile_unclaimed_cancel(execution_id=execution_id)
    return execution_id


def _validate_retention_audits(
    core_stack: CoreStack,
    *,
    run_id: str,
) -> list[AuditEvent]:
    schema = json.loads(
        (Path(__file__).parents[2] / "docs" / "contracts" / "audit-event.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )
    with core_stack.sessions() as session:
        events = list(
            session.scalars(
                select(AuditEvent)
                .where(AuditEvent.event_json["target"]["id"].as_string() == run_id)
                .order_by(AuditEvent.organization_sequence)
            )
        )
    assert events
    for event in events:
        validator.validate(event.event_json)
    return events


def test_retention_deletes_expired_idempotency_and_safe_execution_group(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    execution_id = _create_canceled_execution(
        core_stack,
        suffix="safe-delete",
    )
    before = datetime.now(UTC)
    with core_stack.sessions() as session:
        event_count = int(
            session.scalar(
                select(func.count(ExecutionEvent.id)).where(
                    ExecutionEvent.execution_id == execution_id
                )
            )
            or 0
        )
        assert event_count > 0

    result = _service(core_stack, tmp_path).run(now=before + timedelta(days=366))

    assert result.status == "SUCCEEDED"
    assert result.executions_deleted == 1
    assert result.execution_events_deleted == event_count
    assert result.idempotency_records_deleted >= 2
    assert result.audit_events_expired == 0
    assert result.external_worm_anchor_available is False
    with core_stack.sessions() as session:
        assert session.get(Execution, execution_id) is None
        assert (
            session.scalar(
                select(func.count(ExecutionEvent.id)).where(
                    ExecutionEvent.execution_id == execution_id
                )
            )
            == 0
        )
        assert session.scalar(select(func.count(IdempotencyRecord.id))) == 0
    audits = _validate_retention_audits(
        core_stack,
        run_id=result.run_id,
    )
    assert [event.event_json["action"] for event in audits] == [
        "RETENTION_MAINTENANCE_STARTED",
        "RETENTION_MAINTENANCE_COMPLETED",
    ]
    assert audits[-1].event_json["outcome"] == "SUCCEEDED"


def test_active_hold_blocks_related_cleanup_until_explicit_release(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    execution_id = _create_canceled_execution(
        core_stack,
        suffix="held",
    )
    now = datetime.now(UTC)
    hold_id = uuid4()
    with core_stack.sessions.begin() as session:
        session.add(
            RetentionHold(
                id=hold_id,
                organization_id=core_stack.principal.organization_id,
                scope_type="EXECUTION",
                scope_id=execution_id,
                reason_code="INCIDENT_INVESTIGATION",
                created_by=core_stack.principal.user_id,
                created_at=now,
                expires_at=None,
                released_by=None,
                released_at=None,
            )
        )

    first = _service(core_stack, tmp_path).run(now=now + timedelta(days=366))

    assert first.status == "BLOCKED"
    assert first.executions_blocked == 1
    assert first.idempotency_records_blocked > 0
    assert "RETENTION_HOLD_ACTIVE" in first.block_reasons
    with core_stack.sessions() as session:
        assert session.get(Execution, execution_id) is not None
        assert session.get(RetentionHold, hold_id) is not None

    released_at = now + timedelta(days=366, minutes=1)
    with core_stack.sessions.begin() as session:
        hold = session.get(RetentionHold, hold_id)
        assert hold is not None
        hold.released_by = core_stack.principal.user_id
        hold.released_at = released_at

    second = _service(core_stack, tmp_path).run(now=released_at + timedelta(minutes=1))

    assert second.status == "SUCCEEDED"
    assert second.executions_deleted == 1
    with core_stack.sessions() as session:
        assert session.get(Execution, execution_id) is None
        hold = session.get(RetentionHold, hold_id)
        assert hold is not None
        assert hold.released_at is not None


def test_log_body_is_deleted_after_30_days_but_summary_and_gate_survive(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    claim, log_path = _persist_redacted_log(
        core_stack,
        tmp_path,
        suffix="retention-log",
        content=b"INFO redacted retention body\n",
    )
    core_stack.service.transition_claimed_execution(
        claim=claim,
        expected_state="STARTING",
        new_state="FAILED",
        data_effect="NONE",
        verification_state="NOT_STARTED",
        failure_code="TEST_PRE_DATA_FAILURE",
    )
    now = datetime.now(UTC)
    with core_stack.sessions.begin() as session:
        execution = session.get(Execution, claim.execution_id)
        lock = session.scalar(
            select(TargetCopyLock).where(TargetCopyLock.execution_id == claim.execution_id)
        )
        gate = session.scalar(
            select(RecoveryGate).where(
                RecoveryGate.execution_id == claim.execution_id
            )
        )
        assert execution is not None
        assert lock is not None
        assert gate is not None
        gate_id = gate.id
        lock.state = "RELEASED"
        lock.released_at = now
        gate.status = "VERIFIED"
        gate.remediation_confirmation = {
            "action": "NO_CLEANUP_REQUIRED",
            "target_was_mutated": False,
            "reason": "pre-data failure",
        }
        gate.target_empty_evidence = {"result": "EMPTY"}
        gate.submitted_at = now
        gate.verified_at = now
        gate.reason_code = None

    result = _service(core_stack, tmp_path).run(now=now + timedelta(days=31))

    assert result.status == "SUCCEEDED"
    assert result.log_bodies_deleted == 1
    assert result.executions_deleted == 0
    assert not log_path.exists()
    with core_stack.sessions() as session:
        chunk = session.scalar(
            select(ExecutionLogChunk).where(ExecutionLogChunk.execution_id == claim.execution_id)
        )
        execution = session.get(Execution, claim.execution_id)
        gate = session.get(RecoveryGate, gate_id)
        assert chunk is not None
        assert chunk.body_available is False
        assert chunk.deleted_at is not None
        assert execution is not None
        assert execution.log_stored_bytes > 0
        assert gate is not None and gate.status == "VERIFIED"


def test_recovery_gate_blocks_execution_deletion(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    execution_id = _create_canceled_execution(
        core_stack,
        suffix="gate-preserved",
    )
    now = datetime.now(UTC)
    with core_stack.sessions.begin() as session:
        execution = session.get(Execution, execution_id)
        assert execution is not None
        session.add(
            RecoveryGate(
                id=uuid4(),
                execution_id=execution.id,
                project_id=execution.project_id,
                target_namespace_id=execution.target_namespace_id,
                status="VERIFIED",
                data_effect_at_open="NONE",
                remediation_confirmation={
                    "action": "NO_CLEANUP_REQUIRED",
                    "target_was_mutated": False,
                    "reason": "verified fixture",
                },
                target_empty_evidence={"result": "EMPTY"},
                latest_recovery_probe_id=None,
                submitted_at=now,
                verified_at=now,
                reason_code=None,
                created_at=now,
            )
        )

    result = _service(core_stack, tmp_path).run(now=now + timedelta(days=366))

    assert result.status == "PARTIAL"
    assert result.executions_blocked == 1
    assert "RECOVERY_GATE_PRESERVED" in result.block_reasons
    with core_stack.sessions() as session:
        assert session.get(Execution, execution_id) is not None
        assert (
            session.scalar(
                select(func.count(RecoveryGate.id)).where(RecoveryGate.execution_id == execution_id)
            )
            == 1
        )


def test_expired_audit_is_reported_blocked_without_worm_or_chain_mutation(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    created = core_stack.client.post(
        "/api/v1/projects",
        headers={"Idempotency-Key": "retention-audit-project"},
        json={
            "name": "Retention audit evidence",
            "slug": "retention-audit-evidence",
            "description": None,
        },
    )
    assert created.status_code == 201, created.text
    with core_stack.sessions.begin() as session:
        session.query(IdempotencyRecord).delete()
    with core_stack.sessions() as session:
        original_ids = set(session.scalars(select(AuditEvent.id)))
        assert original_ids
    now = datetime.now(UTC)

    result = _service(core_stack, tmp_path).run(now=now + timedelta(days=731))

    assert result.status == "BLOCKED"
    assert result.audit_events_expired == len(original_ids)
    assert result.audit_events_blocked == len(original_ids)
    assert "AUDIT_WORM_ANCHOR_UNAVAILABLE" in result.block_reasons
    assert result.external_worm_anchor_available is False
    with core_stack.sessions() as session:
        after_ids = set(session.scalars(select(AuditEvent.id)))
        assert original_ids <= after_ids
        assert len(after_ids) == len(original_ids) + 2
    audits = _validate_retention_audits(
        core_stack,
        run_id=result.run_id,
    )
    assert audits[-1].event_json["outcome"] == "DENIED"
    assert audits[-1].event_json["reason_code"] == "RETENTION_ITEMS_BLOCKED"


def test_broken_audit_chain_fails_closed_before_any_cleanup(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    created = core_stack.client.post(
        "/api/v1/projects",
        headers={"Idempotency-Key": "retention-broken-chain"},
        json={
            "name": "Broken chain fixture",
            "slug": "broken-chain-fixture",
            "description": None,
        },
    )
    assert created.status_code == 201, created.text
    with core_stack.sessions.begin() as session:
        event = session.scalar(select(AuditEvent).order_by(AuditEvent.organization_sequence.desc()))
        assert event is not None
        event.event_hash = "f" * 64
    before_idempotency = 0
    with core_stack.sessions() as session:
        before_idempotency = int(session.scalar(select(func.count(IdempotencyRecord.id))) or 0)

    with pytest.raises(
        RetentionMaintenanceError,
        match="AUDIT_CHAIN_INTEGRITY_INVALID",
    ):
        _service(core_stack, tmp_path).run(now=datetime.now(UTC) + timedelta(days=2))

    with core_stack.sessions() as session:
        assert (
            int(session.scalar(select(func.count(IdempotencyRecord.id))) or 0) == before_idempotency
        )
