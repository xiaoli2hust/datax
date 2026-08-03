from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from datax_studio.core.schemas import (
    SourceQuiescenceConfirmation,
    TargetExclusivityConfirmation,
)
from datax_studio.qualification.execution_lifecycle import (
    PhaseAPrivateExecutionIssuer,
)
from datax_studio.qualification.ledger import PhaseAGrantRef, PhaseALedgerError

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)


class _FakeMappingsResult:
    def __init__(self, row: dict[str, object]) -> None:
        self._row = row

    def mappings(self) -> _FakeMappingsResult:
        return self

    def one(self) -> dict[str, object]:
        return self._row


class _FakeConnection:
    def __init__(self, *, row_overrides: dict[str, object] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self._row_overrides = row_overrides or {}

    def execute(self, statement: object, parameters: dict[str, object]) -> _FakeMappingsResult:
        rendered = str(statement)
        self.calls.append((rendered, dict(parameters)))
        assert "des_create_authorize_reserve_phase_a_execution" in rendered
        row = {
            "execution_id": parameters["execution_id"],
            "authorization_id": parameters["authorization_id"],
            "grant_id": parameters["grant_id"],
            "lock_id": parameters["lock_id"],
            "job_id": uuid4(),
            "job_version_id": parameters["job_version_id"],
            "target_namespace_id": uuid4(),
            "checkpoint": "LOCK_RESERVED",
            "execution_process_state": "QUEUED",
            "queue_eligibility_state": "BLOCKED",
            "queue_block_reason": "PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED",
            "target_lock_state": "RESERVED",
            "occurred_at": NOW,
        }
        row.update(self._row_overrides)
        return _FakeMappingsResult(row)


class _FakeTransaction:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def __enter__(self) -> _FakeConnection:
        return self._connection

    def __exit__(self, *_arguments: object) -> bool:
        return False


class _FakeEngine:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def begin(self) -> _FakeTransaction:
        return _FakeTransaction(self._connection)


def _confirmations() -> tuple[SourceQuiescenceConfirmation, TargetExclusivityConfirmation]:
    return (
        SourceQuiescenceConfirmation(confirmed=True, confirmed_at=NOW, note="phase-a"),
        TargetExclusivityConfirmation(
            statement_version="1.0",
            confirmed=True,
            confirmed_at=NOW,
            valid_until=NOW + timedelta(minutes=15),
            responsible_party="OPERATOR",
            note="phase-a",
        ),
    )


def _assert_code(callback: object, expected: str) -> None:
    with pytest.raises(PhaseALedgerError) as raised:
        assert callable(callback)
        callback()
    assert raised.value.code == expected


def test_private_lifecycle_uses_one_final_security_definer_receipt() -> None:
    connection = _FakeConnection()
    issuer = PhaseAPrivateExecutionIssuer(_FakeEngine(connection))  # type: ignore[arg-type]
    grant = PhaseAGrantRef(grant_id=uuid4())
    requested_by = uuid4()
    job_version_id = uuid4()
    source_confirmation, target_confirmation = _confirmations()

    receipt = issuer.create_authorize_and_reserve(
        grant=grant,
        requested_by=requested_by,
        job_version_id=job_version_id,
        source_quiescence_confirmation=source_confirmation,
        target_exclusivity_confirmation=target_confirmation,
    )

    assert receipt.grant_id == grant.grant_id
    assert receipt.job_version_id == job_version_id
    assert receipt.checkpoint == "LOCK_RESERVED"
    assert receipt.execution_process_state == "QUEUED"
    assert receipt.queue_eligibility_state == "BLOCKED"
    assert receipt.queue_block_reason == "PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED"
    assert receipt.target_lock_state == "RESERVED"
    assert len(connection.calls) == 1
    query, parameters = connection.calls[0]
    assert "des_create_authorize_reserve_phase_a_execution" in query
    assert "public.executions" not in query
    assert "target_copy_locks" not in query
    assert parameters["grant_id"] == grant.grant_id
    assert parameters["requested_by"] == requested_by
    assert parameters["job_version_id"] == job_version_id
    assert parameters["source_quiescence_confirmation"] == {
        "confirmed": True,
        "confirmed_at": "2026-08-02T12:00:00Z",
        "note": "phase-a",
    }
    assert parameters["target_exclusivity_confirmation"] == {
        "statement_version": "1.0",
        "confirmed": True,
        "confirmed_at": "2026-08-02T12:00:00Z",
        "valid_until": "2026-08-02T12:15:00Z",
        "responsible_party": "OPERATOR",
        "note": "phase-a",
    }
    assert all("nonce" not in name and "credential" not in name for name in parameters)

    schema = json.loads(
        (
            Path(__file__).parents[2]
            / "docs"
            / "contracts"
            / "phase-a-execution-lifecycle.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    serialized = receipt.to_contract_v1()
    assert Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(serialized)
    assert set(serialized) == set(schema["required"])


def test_private_lifecycle_rejects_invalid_inputs_before_database_access() -> None:
    connection = _FakeConnection()
    issuer = PhaseAPrivateExecutionIssuer(_FakeEngine(connection))  # type: ignore[arg-type]
    source_confirmation, target_confirmation = _confirmations()

    _assert_code(
        lambda: issuer.create_authorize_and_reserve(
            grant=PhaseAGrantRef(grant_id=uuid4()),
            requested_by="not-a-uuid",  # type: ignore[arg-type]
            job_version_id=uuid4(),
            source_quiescence_confirmation=source_confirmation,
            target_exclusivity_confirmation=target_confirmation,
        ),
        "PHASE_A_PRIVATE_EXECUTION_INPUT_INVALID",
    )
    _assert_code(
        lambda: issuer.create_authorize_and_reserve(
            grant=PhaseAGrantRef(grant_id=uuid4()),
            requested_by=uuid4(),
            job_version_id=uuid4(),
            source_quiescence_confirmation={"confirmed": True},  # type: ignore[arg-type]
            target_exclusivity_confirmation=target_confirmation,
        ),
        "PHASE_A_PRIVATE_EXECUTION_INPUT_INVALID",
    )
    assert connection.calls == []


def test_private_lifecycle_rejects_malformed_or_unblocked_final_receipts() -> None:
    source_confirmation, target_confirmation = _confirmations()
    for row_overrides in (
        {"target_lock_state": "ACTIVE"},
        {"occurred_at": datetime(2026, 8, 2, 12, 0)},
    ):
        issuer = PhaseAPrivateExecutionIssuer(
            _FakeEngine(_FakeConnection(row_overrides=row_overrides))  # type: ignore[arg-type]
        )
        _assert_code(
            lambda current_issuer=issuer: current_issuer.create_authorize_and_reserve(
                grant=PhaseAGrantRef(grant_id=uuid4()),
                requested_by=uuid4(),
                job_version_id=uuid4(),
                source_quiescence_confirmation=source_confirmation,
                target_exclusivity_confirmation=target_confirmation,
            ),
            "PHASE_A_PRIVATE_EXECUTION_RESPONSE_INVALID",
        )
