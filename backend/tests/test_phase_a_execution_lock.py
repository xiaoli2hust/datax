from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from datax_studio.qualification.execution_lock import (
    PhaseAClaimedExecutionLock,
    PhaseAExecutionLockRef,
    PhaseAExecutionLockRunner,
)
from datax_studio.qualification.ledger import PhaseALedgerError

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class _FakeScalarResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one(self) -> object:
        return self._value


class _FakeMappingsResult:
    def __init__(self, row: dict[str, object] | None) -> None:
        self._row = row

    def mappings(self) -> _FakeMappingsResult:
        return self

    def one(self) -> dict[str, object]:
        assert self._row is not None
        return self._row

    def one_or_none(self) -> dict[str, object] | None:
        return self._row


class _FakeConnection:
    def __init__(self, *, read_row: dict[str, object] | None = None) -> None:
        self.read_row = read_row
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(self, statement: object, parameters: dict[str, object]) -> object:
        rendered = str(statement)
        values = dict(parameters)
        self.calls.append((rendered, values))
        if "des_reserve_phase_a_execution_lock" in rendered:
            return _FakeScalarResult(values["lock_id"])
        if "des_claim_phase_a_execution_lock" in rendered:
            return _FakeMappingsResult(
                {
                    "attempt_id": values["attempt_id"],
                    "fence_epoch": 1,
                    "lease_expires_at": NOW + timedelta(seconds=values["lease_seconds"]),
                }
            )
        if "des_heartbeat_phase_a_execution_lock" in rendered:
            return _FakeScalarResult(NOW + timedelta(seconds=values["lease_seconds"]))
        if "des_require_phase_a_execution_recovery" in rendered:
            return _FakeScalarResult(True)
        if "des_release_phase_a_execution_lock" in rendered:
            return _FakeScalarResult(True)
        if "des_read_phase_a_execution_lock" in rendered:
            return _FakeMappingsResult(self.read_row)
        raise AssertionError(f"unexpected private lock query: {rendered}")


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


def _reserved_row(ref: PhaseAExecutionLockRef) -> dict[str, object]:
    return {
        "lock_id": ref.lock_id,
        "execution_id": ref.execution_id,
        "target_namespace_id": uuid4(),
        "physical_table_identity_hash": _hash("target-table"),
        "lock_state": "RESERVED",
        "attempt_id": None,
        "fence_epoch": None,
        "worker_id": None,
        "host_boot_id": None,
        "cgroup_identity": None,
        "reserved_at": NOW,
        "acquired_at": None,
        "heartbeat_at": None,
        "lease_expires_at": None,
        "released_at": None,
    }


def _assert_code(callback: object, expected: str) -> None:
    with pytest.raises(PhaseALedgerError) as raised:
        assert callable(callback)
        callback()
    assert raised.value.code == expected


def test_private_lock_adapter_uses_only_security_definer_entrypoints() -> None:
    connection = _FakeConnection()
    runner = PhaseAExecutionLockRunner(_FakeEngine(connection))  # type: ignore[arg-type]
    execution_id = uuid4()

    lock = runner.reserve(execution_id=execution_id)
    claim = runner.claim(
        lock=lock,
        worker_id="phase-a-runner-01",
        host_boot_id="host-boot-01",
        cgroup_identity="/des/phase-a/runner-01",
    )
    assert runner.heartbeat(claim=claim) == NOW + timedelta(seconds=30)
    assert runner.require_recovery(claim=claim, reason="RUNNER_STOPPED") is True
    assert runner.release_recovery_lock(claim=claim, reason="RECOVERY_CONFIRMED") is True

    assert lock.execution_id == execution_id
    assert claim.fence_epoch == 1
    assert len(connection.calls) == 5
    queries = "\n".join(query for query, _parameters in connection.calls)
    for function in (
        "des_reserve_phase_a_execution_lock",
        "des_claim_phase_a_execution_lock",
        "des_heartbeat_phase_a_execution_lock",
        "des_require_phase_a_execution_recovery",
        "des_release_phase_a_execution_lock",
    ):
        assert function in queries
    assert "target_copy_locks" not in queries
    assert "execution_attempts" not in queries
    # The raw lease token stays in the private caller object; only its digest
    # reaches SQL and the adapter never serializes it through a read record.
    all_parameters = [parameters for _query, parameters in connection.calls]
    assert all(claim.lease_token not in parameters.values() for parameters in all_parameters)
    assert all(
        _hash(claim.lease_token) in parameters.values()
        for parameters in all_parameters[1:]
    )


def test_private_lock_reader_rejects_malformed_lifecycle_and_never_returns_token_hash() -> None:
    ref = PhaseAExecutionLockRef(lock_id=uuid4(), execution_id=uuid4())
    connection = _FakeConnection(read_row=_reserved_row(ref))
    runner = PhaseAExecutionLockRunner(_FakeEngine(connection))  # type: ignore[arg-type]

    snapshot = runner.read(execution_id=ref.execution_id)

    assert snapshot is not None
    assert snapshot.lock == ref
    assert snapshot.state == "RESERVED"
    assert not hasattr(snapshot, "lease_token_hash")
    read_query, read_parameters = connection.calls[-1]
    assert "des_read_phase_a_execution_lock" in read_query
    assert read_parameters == {"execution_id": ref.execution_id}

    malformed = _reserved_row(ref)
    malformed["fence_epoch"] = 1
    _assert_code(
        lambda: PhaseAExecutionLockRunner(
            _FakeEngine(_FakeConnection(read_row=malformed))  # type: ignore[arg-type]
        ).read(execution_id=ref.execution_id),
        "PHASE_A_EXECUTION_LOCK_RESPONSE_INVALID",
    )


def test_private_lock_adapter_rejects_invalid_references_before_database_access() -> None:
    connection = _FakeConnection()
    runner = PhaseAExecutionLockRunner(_FakeEngine(connection))  # type: ignore[arg-type]
    lock = PhaseAExecutionLockRef(lock_id=uuid4(), execution_id=uuid4())

    _assert_code(
        lambda: runner.reserve(execution_id="not-a-uuid"),  # type: ignore[arg-type]
        "PHASE_A_EXECUTION_REFERENCE_INVALID",
    )
    _assert_code(
        lambda: runner.claim(
            lock=lock,
            worker_id="invalid worker id with space",
            host_boot_id="host-boot-01",
            cgroup_identity="/des/phase-a/runner-01",
        ),
        "PHASE_A_EXECUTION_CLAIM_INPUT_INVALID",
    )
    forged = PhaseAClaimedExecutionLock(
        lock=lock,
        attempt_id=uuid4(),
        fence_epoch=0,
        lease_token="forged",
        lease_expires_at=NOW,
    )
    _assert_code(
        lambda: runner.heartbeat(claim=forged),
        "PHASE_A_EXECUTION_CLAIM_REFERENCE_INVALID",
    )
    non_ascii = PhaseAClaimedExecutionLock(
        lock=lock,
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="\u00e9",
        lease_expires_at=NOW,
    )
    _assert_code(
        lambda: runner.heartbeat(claim=non_ascii),
        "PHASE_A_EXECUTION_CLAIM_REFERENCE_INVALID",
    )
    assert connection.calls == []
