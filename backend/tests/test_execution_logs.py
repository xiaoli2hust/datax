from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy import select
from test_core_control_plane import (
    CoreStack,
    _credential_selector,
    _execution_request,
    _seed_published_job,
    core_stack,
)

from datax_studio.auth.db import AuditEvent
from datax_studio.core.db import Execution, ExecutionAttempt, TargetCopyLock
from datax_studio.core.schemas import ClaimedExecution, CredentialBinding
from datax_studio.logs.db import ExecutionLogChunk, ExecutionLogGap
from datax_studio.logs.service import ExecutionLogService
from datax_studio.recovery.db import RecoveryGate
from datax_studio.worker.process import BoundedRedactedLog
from datax_studio.worker.reconcile import RuntimeIdentity, WorkerReconciler

__all__ = ["core_stack"]


def _claimed_execution(core_stack: CoreStack, suffix: str) -> ClaimedExecution:
    published = _seed_published_job(core_stack, suffix)
    created = core_stack.client.post(
        f"/api/v1/jobs/{published.job_id}/executions",
        headers={"Idempotency-Key": f"log-execution-{suffix}-001"},
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
        worker_id="worker-log-test",
        host_boot_id="boot-log-test",
        cgroup_identity="container:log-test",
        credential_selector=_credential_selector(published, binding),
    )
    assert claim is not None
    assert claim.execution_id == UUID(created.json()["id"])
    return claim


def _persist_redacted_log(
    core_stack: CoreStack,
    tmp_path: Path,
    *,
    suffix: str,
    content: bytes,
    maximum_bytes: int = 4096,
    maximum_line_bytes: int = 1024,
    export_limit_bytes: int = 100 * 1024 * 1024,
) -> tuple[ClaimedExecution, Path]:
    settings = core_stack.client.app.state.settings.model_copy(
        update={
            "log_volume_path": tmp_path / "logs",
            "log_export_limit_bytes": export_limit_bytes,
        }
    )
    core_stack.client.app.state.settings = settings
    claim = _claimed_execution(core_stack, suffix)
    path = settings.log_volume_path / str(claim.execution_id) / f"{claim.attempt_id}.log"
    capture = BoundedRedactedLog(
        path,
        secrets=[b"database-secret"],
        maximum_bytes=maximum_bytes,
        maximum_line_bytes=maximum_line_bytes,
    )
    capture.write_raw(content)
    result = capture.close()
    ExecutionLogService(
        settings=settings,
        control=core_stack.service,
    ).persist_claimed_process_log(
        claim=claim,
        result=result,
    )
    return claim, path


def test_redacted_log_cursor_and_download_use_only_persisted_content(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    claim, path = _persist_redacted_log(
        core_stack,
        tmp_path,
        suffix="read-download",
        content=(b"2026-07-30 INFO password=database-secret\n2026-07-30 WARN safe second line\n"),
    )
    persisted = path.read_bytes()
    assert b"database-secret" not in persisted
    assert b"[REDACTED]" in persisted

    first = core_stack.client.get(
        f"/api/v1/executions/{claim.execution_id}/logs",
        params={"limit": 1},
    )
    assert first.status_code == 200, first.text
    page = first.json()
    assert len(page["items"]) == 1
    assert page["items"][0]["stream"] == "SYSTEM"
    assert page["items"][0]["level"] == "INFO"
    assert "database-secret" not in page["items"][0]["message"]
    assert page["eof"] is False
    assert page["incomplete"] is False
    assert page["truncated"] is False

    second = core_stack.client.get(
        f"/api/v1/executions/{claim.execution_id}/logs",
        params={"limit": 1, "cursor": page["next_cursor"]},
    )
    assert second.status_code == 200
    assert second.json()["items"][0]["sequence"] == 2
    assert second.json()["eof"] is True

    cursor = page["next_cursor"]
    tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
    invalid = core_stack.client.get(
        f"/api/v1/executions/{claim.execution_id}/logs",
        params={"cursor": tampered},
    )
    assert invalid.status_code == 400
    assert invalid.json()["code"] == "CURSOR_INVALID"

    download = core_stack.client.get(f"/api/v1/executions/{claim.execution_id}/logs/download")
    assert download.status_code == 200, download.text
    assert download.content == persisted
    assert b"database-secret" not in download.content
    assert download.headers["x-content-sha256"] == hashlib.sha256(persisted).hexdigest()
    assert download.headers["x-log-incomplete"] == "false"
    with core_stack.sessions() as session:
        audit = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.organization_id == core_stack.principal.organization_id)
            .order_by(AuditEvent.organization_sequence.desc())
        )
        assert audit is not None
        assert audit.event_json["action"] == "EXECUTION_LOG_EXPORTED"
        assert audit.event_json["outcome"] == "SUCCEEDED"
        assert (
            audit.event_json["metadata"]["content_sha256"] == download.headers["x-content-sha256"]
        )
        audit_schema = json.loads(
            (
                Path(__file__).resolve().parents[2]
                / "docs"
                / "contracts"
                / "audit-event.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(
            audit_schema,
            format_checker=FormatChecker(),
        ).validate(audit.event_json)


def test_truncation_gaps_survive_cursor_and_download(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    claim, _path = _persist_redacted_log(
        core_stack,
        tmp_path,
        suffix="truncated",
        content=b"x" * 5000 + b"\n" + b"safe line\n" * 500,
        maximum_bytes=1024,
        maximum_line_bytes=128,
    )
    response = core_stack.client.get(f"/api/v1/executions/{claim.execution_id}/logs")
    assert response.status_code == 200
    page = response.json()
    reasons = {gap["reason"] for gap in page["gaps"]}
    assert reasons == {"LINE_LIMIT", "RING_EVICTION"}
    assert page["truncated"] is True
    assert page["incomplete"] is True
    assert page["dropped_bytes"] == (page["redacted_received_bytes"] - page["stored_bytes"])
    assert page["first_truncated_sequence"] == 1

    download = core_stack.client.get(f"/api/v1/executions/{claim.execution_id}/logs/download")
    assert download.status_code == 200
    assert download.headers["x-log-truncated"] == "true"
    assert download.headers["x-log-incomplete"] == "true"
    assert download.headers["x-log-gap-count"] == "2"
    assert download.headers["x-log-truncation-reason"] == "LINE_LIMIT"


def test_storage_tamper_becomes_explicit_gap_and_is_never_exported(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    claim, path = _persist_redacted_log(
        core_stack,
        tmp_path,
        suffix="tamper",
        content=b"INFO safe persisted line\n",
    )
    path.write_bytes(b"tampered replacement")
    response = core_stack.client.get(f"/api/v1/executions/{claim.execution_id}/logs")
    assert response.status_code == 200
    page = response.json()
    assert page["items"] == []
    assert page["incomplete"] is True
    assert page["stored_bytes"] == 0
    assert page["dropped_bytes"] == page["redacted_received_bytes"]
    assert {gap["reason"] for gap in page["gaps"]} == {"STORAGE_FAILURE"}
    assert not path.exists()
    with core_stack.sessions() as session:
        chunk = session.scalar(
            select(ExecutionLogChunk).where(ExecutionLogChunk.execution_id == claim.execution_id)
        )
        gap = session.scalar(
            select(ExecutionLogGap).where(ExecutionLogGap.execution_id == claim.execution_id)
        )
        assert chunk is not None and chunk.body_available is False
        assert chunk.deleted_at is not None
        assert gap is not None and gap.reason == "STORAGE_FAILURE"

    download = core_stack.client.get(f"/api/v1/executions/{claim.execution_id}/logs/download")
    assert download.status_code == 200
    assert download.content == b""
    assert download.headers["x-log-incomplete"] == "true"


def test_expired_and_oversized_downloads_are_denied_and_audited(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    oversized_claim, _path = _persist_redacted_log(
        core_stack,
        tmp_path,
        suffix="too-large",
        content=(b"safe output line\n" * 100),
        export_limit_bytes=1024,
    )
    too_large = core_stack.client.get(
        f"/api/v1/executions/{oversized_claim.execution_id}/logs/download"
    )
    assert too_large.status_code == 413
    assert too_large.json()["code"] == "LOG_EXPORT_TOO_LARGE"

    expired_claim, _path = _persist_redacted_log(
        core_stack,
        tmp_path,
        suffix="expired",
        content=b"INFO expires\n",
    )
    with core_stack.sessions.begin() as session:
        chunk = session.scalar(
            select(ExecutionLogChunk).where(
                ExecutionLogChunk.execution_id == expired_claim.execution_id
            )
        )
        assert chunk is not None
        chunk.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    expired = core_stack.client.get(
        f"/api/v1/executions/{expired_claim.execution_id}/logs/download"
    )
    assert expired.status_code == 410
    assert expired.json()["code"] == "LOG_EXPIRED"
    with core_stack.sessions() as session:
        audits = list(
            session.scalars(
                select(AuditEvent)
                .where(AuditEvent.event_json["action"].as_string() == "EXECUTION_LOG_EXPORTED")
                .order_by(AuditEvent.organization_sequence.desc())
                .limit(2)
            )
        )
        assert [audit.event_json["outcome"] for audit in audits] == [
            "DENIED",
            "DENIED",
        ]
        assert {audit.event_json["reason_code"] for audit in audits} == {
            "LOG_EXPIRED",
            "LOG_EXPORT_TOO_LARGE",
        }


def test_reconciler_records_fence_lost_gap_without_stale_worker_write(
    core_stack: CoreStack,
) -> None:
    claim = _claimed_execution(core_stack, "fence-gap")
    with core_stack.sessions.begin() as session:
        attempt = session.get(ExecutionAttempt, claim.attempt_id)
        assert attempt is not None
        attempt.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    reconciler = WorkerReconciler(
        control=core_stack.service,
        sessions=core_stack.sessions,
    )
    result = reconciler.reconcile_expired_leases(
        identity=RuntimeIdentity(
            host_boot_id="different-boot",
            cgroup_identity="different-cgroup",
        )
    )
    assert result.lost_executions == 1
    with core_stack.sessions() as session:
        execution = session.get(Execution, claim.execution_id)
        target_lock = session.scalar(
            select(TargetCopyLock).where(
                TargetCopyLock.execution_id == claim.execution_id
            )
        )
        gate = session.scalar(
            select(RecoveryGate).where(
                RecoveryGate.execution_id == claim.execution_id
            )
        )
        gap = session.scalar(
            select(ExecutionLogGap).where(
                ExecutionLogGap.execution_id == claim.execution_id,
                ExecutionLogGap.reason == "FENCE_LOST",
            )
        )
        assert execution is not None and execution.process_state == "LOST"
        assert target_lock is not None and target_lock.state == "RECOVERY_REQUIRED"
        assert gate is not None and gate.status == "OPEN"
        assert gate.reason_code == "EXECUTION_LEASE_EXPIRED"
        assert gap is not None
        assert gap.raw_received_bytes == 0
        assert gap.redacted_received_bytes == 0
        assert gap.stored_bytes == 0
        assert gap.dropped_bytes == 0
