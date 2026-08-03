"""Private Phase-A target-lock/fence adapter.

The adapter has no Settings, API, Worker, Compose, or Launcher integration.
It is intentionally useful only to a future protected harness that injects a
dedicated ``datax_phase_a_runner`` Engine.  The database role is NOLOGIN in a
normal product installation, so constructing this class does not create a
private runner or make a PHASE_A_HARNESS execution runnable.

It reuses the product's public TargetCopyLock and ExecutionAttempt records on
purpose: their existing partial unique namespace index is the one global
target-write exclusion invariant across STANDARD and protected executions.
The private SQL functions are the only way this adapter can access such rows.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from datax_studio.qualification.ledger import PhaseALedgerError

_SCHEMA = "des_phase_a_qualification"
_RESERVE_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_reserve_phase_a_execution_lock(
        :lock_id,
        :execution_id
    ) AS lock_id
    """
)
_CLAIM_SQL = text(
    f"""
    SELECT *
    FROM {_SCHEMA}.des_claim_phase_a_execution_lock(
        :execution_id,
        :attempt_id,
        :worker_id,
        :lease_token_hash,
        :host_boot_id,
        :cgroup_identity,
        :lease_seconds
    )
    """
)
_HEARTBEAT_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_heartbeat_phase_a_execution_lock(
        :execution_id,
        :attempt_id,
        :fence_epoch,
        :lease_token_hash,
        :lease_seconds
    ) AS lease_expires_at
    """
)
_RECOVERY_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_require_phase_a_execution_recovery(
        :execution_id,
        :attempt_id,
        :fence_epoch,
        :lease_token_hash,
        :reason
    ) AS transitioned
    """
)
_RELEASE_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_release_phase_a_execution_lock(
        :execution_id,
        :attempt_id,
        :fence_epoch,
        :lease_token_hash,
        :reason
    ) AS released
    """
)
_READ_SQL = text(
    f"""
    SELECT *
    FROM {_SCHEMA}.des_read_phase_a_execution_lock(:execution_id)
    """
)

_WORKER_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_CGROUP_ID = re.compile(r"^[-A-Za-z0-9._:/@+]{1,255}[-A-Za-z0-9._:/@+]?$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_LOCK_STATES = frozenset({"RESERVED", "ACTIVE", "RECOVERY_REQUIRED", "RELEASED"})


@dataclass(frozen=True)
class PhaseAExecutionLockRef:
    """Opaque reference to the global lock held for one private execution."""

    lock_id: UUID
    execution_id: UUID


@dataclass(frozen=True)
class PhaseAClaimedExecutionLock:
    """Private fenced claim; raw lease token stays only in caller memory."""

    lock: PhaseAExecutionLockRef
    attempt_id: UUID
    fence_epoch: int
    lease_token: str
    lease_expires_at: datetime


@dataclass(frozen=True)
class PhaseAExecutionLockSnapshot:
    """Non-secret lifecycle/fence facts from the protected lock reader."""

    lock: PhaseAExecutionLockRef
    target_namespace_id: UUID
    physical_table_identity_hash: str
    state: str
    attempt_id: UUID | None
    fence_epoch: int | None
    worker_id: str | None
    host_boot_id: str | None
    cgroup_identity: str | None
    reserved_at: datetime
    acquired_at: datetime | None
    heartbeat_at: datetime | None
    lease_expires_at: datetime | None
    released_at: datetime | None


class PhaseAExecutionLockRunner:
    """Runner-role-only adapter for an unconnected private lock primitive.

    The caller must separately use the PEA consumer at future private
    checkpoints.  This class does not create executions, expose a queue,
    decrypt credentials, mutate ordinary work, call Popen, or invoke DataX.
    A later protected runner design must add its own confirmation, audit,
    credential, log, recovery-reconciliation, and process-start gates.
    """

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def reserve(self, *, execution_id: UUID) -> PhaseAExecutionLockRef:
        _execution_id(execution_id)
        lock_id = uuid4()
        try:
            with self._engine.begin() as connection:
                returned = connection.execute(
                    _RESERVE_SQL,
                    {"lock_id": lock_id, "execution_id": execution_id},
                ).scalar_one()
        except DBAPIError as error:
            raise _reserve_error(error) from None
        except SQLAlchemyError:
            # A commit error could have durably reserved the global namespace.
            # Never retry automatically and accidentally hide that condition.
            raise PhaseALedgerError("PHASE_A_EXECUTION_LOCK_RESERVATION_UNCERTAIN") from None
        if type(returned) is not UUID or returned != lock_id:
            raise PhaseALedgerError("PHASE_A_EXECUTION_LOCK_RESERVATION_UNCERTAIN")
        return PhaseAExecutionLockRef(lock_id=lock_id, execution_id=execution_id)

    def claim(
        self,
        *,
        lock: PhaseAExecutionLockRef,
        worker_id: str,
        host_boot_id: str,
        cgroup_identity: str,
        lease_seconds: int = 30,
    ) -> PhaseAClaimedExecutionLock:
        lock = _lock_ref(lock)
        _claim_identity(
            worker_id=worker_id,
            host_boot_id=host_boot_id,
            cgroup_identity=cgroup_identity,
            lease_seconds=lease_seconds,
        )
        attempt_id = uuid4()
        lease_token = secrets.token_urlsafe(32)
        lease_token_hash = _lease_token_hash(lease_token)
        try:
            with self._engine.begin() as connection:
                row = connection.execute(
                    _CLAIM_SQL,
                    {
                        "execution_id": lock.execution_id,
                        "attempt_id": attempt_id,
                        "worker_id": worker_id,
                        "lease_token_hash": lease_token_hash,
                        "host_boot_id": host_boot_id,
                        "cgroup_identity": cgroup_identity,
                        "lease_seconds": lease_seconds,
                    },
                ).mappings().one()
        except DBAPIError as error:
            raise _claim_error(error) from None
        except SQLAlchemyError:
            raise PhaseALedgerError("PHASE_A_EXECUTION_CLAIM_UNCERTAIN") from None
        try:
            returned_attempt_id = _uuid(row, "attempt_id")
            fence_epoch = _positive_int(row, "fence_epoch")
            lease_expires_at = _aware_datetime(row, "lease_expires_at")
        except (KeyError, TypeError, ValueError) as error:
            raise PhaseALedgerError("PHASE_A_EXECUTION_CLAIM_RESPONSE_INVALID") from error
        if returned_attempt_id != attempt_id:
            raise PhaseALedgerError("PHASE_A_EXECUTION_CLAIM_UNCERTAIN")
        return PhaseAClaimedExecutionLock(
            lock=lock,
            attempt_id=attempt_id,
            fence_epoch=fence_epoch,
            lease_token=lease_token,
            lease_expires_at=lease_expires_at,
        )

    def heartbeat(
        self,
        *,
        claim: PhaseAClaimedExecutionLock,
        lease_seconds: int = 30,
    ) -> datetime:
        claim = _claimed_lock(claim)
        _lease_seconds(lease_seconds)
        try:
            with self._engine.begin() as connection:
                returned = connection.execute(
                    _HEARTBEAT_SQL,
                    {
                        "execution_id": claim.lock.execution_id,
                        "attempt_id": claim.attempt_id,
                        "fence_epoch": claim.fence_epoch,
                        "lease_token_hash": _lease_token_hash(claim.lease_token),
                        "lease_seconds": lease_seconds,
                    },
                ).scalar_one()
        except DBAPIError as error:
            raise _heartbeat_error(error) from None
        except SQLAlchemyError:
            raise PhaseALedgerError("PHASE_A_EXECUTION_HEARTBEAT_UNCERTAIN") from None
        try:
            return _aware_datetime({"lease_expires_at": returned}, "lease_expires_at")
        except (KeyError, TypeError, ValueError) as error:
            raise PhaseALedgerError("PHASE_A_EXECUTION_HEARTBEAT_RESPONSE_INVALID") from error

    def require_recovery(
        self,
        *,
        claim: PhaseAClaimedExecutionLock,
        reason: str,
    ) -> bool:
        claim = _claimed_lock(claim)
        _reason(reason)
        try:
            with self._engine.begin() as connection:
                returned = connection.execute(
                    _RECOVERY_SQL,
                    _claim_parameters(claim=claim, reason=reason),
                ).scalar_one()
        except DBAPIError as error:
            raise _fenced_transition_error(error) from None
        except SQLAlchemyError:
            raise PhaseALedgerError("PHASE_A_EXECUTION_RECOVERY_UNCERTAIN") from None
        if type(returned) is not bool:
            raise PhaseALedgerError("PHASE_A_EXECUTION_RECOVERY_UNCERTAIN")
        return returned

    def release_recovery_lock(
        self,
        *,
        claim: PhaseAClaimedExecutionLock,
        reason: str,
    ) -> bool:
        claim = _claimed_lock(claim)
        _reason(reason)
        try:
            with self._engine.begin() as connection:
                returned = connection.execute(
                    _RELEASE_SQL,
                    _claim_parameters(claim=claim, reason=reason),
                ).scalar_one()
        except DBAPIError as error:
            raise _fenced_transition_error(error) from None
        except SQLAlchemyError:
            raise PhaseALedgerError("PHASE_A_EXECUTION_LOCK_RELEASE_UNCERTAIN") from None
        if type(returned) is not bool:
            raise PhaseALedgerError("PHASE_A_EXECUTION_LOCK_RELEASE_UNCERTAIN")
        return returned

    def read(self, *, execution_id: UUID) -> PhaseAExecutionLockSnapshot | None:
        _execution_id(execution_id)
        try:
            with self._engine.begin() as connection:
                row = connection.execute(
                    _READ_SQL,
                    {"execution_id": execution_id},
                ).mappings().one_or_none()
        except DBAPIError as error:
            raise _read_error(error) from None
        except SQLAlchemyError:
            raise PhaseALedgerError("PHASE_A_EXECUTION_LOCK_LOOKUP_UNAVAILABLE") from None
        if row is None:
            return None
        try:
            return _snapshot(row)
        except (KeyError, TypeError, ValueError) as error:
            raise PhaseALedgerError("PHASE_A_EXECUTION_LOCK_RESPONSE_INVALID") from error


def _execution_id(value: object) -> UUID:
    if type(value) is not UUID:
        raise PhaseALedgerError("PHASE_A_EXECUTION_REFERENCE_INVALID")
    return value


def _lock_ref(value: object) -> PhaseAExecutionLockRef:
    if type(value) is not PhaseAExecutionLockRef:
        raise PhaseALedgerError("PHASE_A_EXECUTION_LOCK_REFERENCE_INVALID")
    _execution_id(value.execution_id)
    if type(value.lock_id) is not UUID:
        raise PhaseALedgerError("PHASE_A_EXECUTION_LOCK_REFERENCE_INVALID")
    return value


def _claimed_lock(value: object) -> PhaseAClaimedExecutionLock:
    if type(value) is not PhaseAClaimedExecutionLock:
        raise PhaseALedgerError("PHASE_A_EXECUTION_CLAIM_REFERENCE_INVALID")
    _lock_ref(value.lock)
    if type(value.attempt_id) is not UUID or type(value.fence_epoch) is not int:
        raise PhaseALedgerError("PHASE_A_EXECUTION_CLAIM_REFERENCE_INVALID")
    if value.fence_epoch < 1 or type(value.lease_token) is not str or not value.lease_token:
        raise PhaseALedgerError("PHASE_A_EXECUTION_CLAIM_REFERENCE_INVALID")
    try:
        value.lease_token.encode("ascii")
    except UnicodeEncodeError:
        raise PhaseALedgerError("PHASE_A_EXECUTION_CLAIM_REFERENCE_INVALID") from None
    return value


def _claim_identity(
    *,
    worker_id: object,
    host_boot_id: object,
    cgroup_identity: object,
    lease_seconds: object,
) -> None:
    if (
        type(worker_id) is not str
        or _WORKER_ID.fullmatch(worker_id) is None
        or type(host_boot_id) is not str
        or _WORKER_ID.fullmatch(host_boot_id) is None
        or type(cgroup_identity) is not str
        or _CGROUP_ID.fullmatch(cgroup_identity) is None
    ):
        raise PhaseALedgerError("PHASE_A_EXECUTION_CLAIM_INPUT_INVALID")
    _lease_seconds(lease_seconds)


def _lease_seconds(value: object) -> int:
    if type(value) is not int or not 5 <= value <= 300:
        raise PhaseALedgerError("PHASE_A_EXECUTION_CLAIM_INPUT_INVALID")
    return value


def _reason(value: object) -> str:
    if type(value) is not str or _REASON.fullmatch(value) is None:
        raise PhaseALedgerError("PHASE_A_EXECUTION_LOCK_REASON_INVALID")
    return value


def _lease_token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _claim_parameters(
    *,
    claim: PhaseAClaimedExecutionLock,
    reason: str,
) -> dict[str, object]:
    return {
        "execution_id": claim.lock.execution_id,
        "attempt_id": claim.attempt_id,
        "fence_epoch": claim.fence_epoch,
        "lease_token_hash": _lease_token_hash(claim.lease_token),
        "reason": reason,
    }


def _snapshot(row: Mapping[str, object]) -> PhaseAExecutionLockSnapshot:
    lock_id = _uuid(row, "lock_id")
    execution_id = _uuid(row, "execution_id")
    state = _string(row, "lock_state")
    if state not in _LOCK_STATES:
        raise ValueError("lock_state is invalid")
    attempt_id = _optional_uuid(row, "attempt_id")
    fence_epoch = _optional_positive_int(row, "fence_epoch")
    snapshot = PhaseAExecutionLockSnapshot(
        lock=PhaseAExecutionLockRef(lock_id=lock_id, execution_id=execution_id),
        target_namespace_id=_uuid(row, "target_namespace_id"),
        physical_table_identity_hash=_sha256(row, "physical_table_identity_hash"),
        state=state,
        attempt_id=attempt_id,
        fence_epoch=fence_epoch,
        worker_id=_optional_string(row, "worker_id"),
        host_boot_id=_optional_string(row, "host_boot_id"),
        cgroup_identity=_optional_string(row, "cgroup_identity"),
        reserved_at=_aware_datetime(row, "reserved_at"),
        acquired_at=_optional_aware_datetime(row, "acquired_at"),
        heartbeat_at=_optional_aware_datetime(row, "heartbeat_at"),
        lease_expires_at=_optional_aware_datetime(row, "lease_expires_at"),
        released_at=_optional_aware_datetime(row, "released_at"),
    )
    _validate_snapshot_lifecycle(snapshot)
    return snapshot


def _validate_snapshot_lifecycle(snapshot: PhaseAExecutionLockSnapshot) -> None:
    active = snapshot.state in {"ACTIVE", "RECOVERY_REQUIRED"}
    if snapshot.state == "RESERVED":
        if any(
            value is not None
            for value in (
                snapshot.attempt_id,
                snapshot.fence_epoch,
                snapshot.worker_id,
                snapshot.host_boot_id,
                snapshot.cgroup_identity,
                snapshot.acquired_at,
                snapshot.heartbeat_at,
                snapshot.lease_expires_at,
                snapshot.released_at,
            )
        ):
            raise ValueError("reserved lock has active facts")
        return
    if active and (
        snapshot.attempt_id is None
        or snapshot.fence_epoch is None
        or snapshot.worker_id is None
        or snapshot.host_boot_id is None
        or snapshot.cgroup_identity is None
        or snapshot.acquired_at is None
        or snapshot.heartbeat_at is None
        or snapshot.lease_expires_at is None
        or snapshot.released_at is not None
    ):
        raise ValueError("active private lock has incomplete fenced facts")
    if snapshot.state == "RELEASED" and snapshot.released_at is None:
        raise ValueError("released private lock has no release time")


def _uuid(row: Mapping[str, object], name: str) -> UUID:
    value = row[name]
    if type(value) is not UUID:
        raise TypeError(f"{name} must be a UUID")
    return value


def _optional_uuid(row: Mapping[str, object], name: str) -> UUID | None:
    value = row[name]
    if value is None:
        return None
    if type(value) is not UUID:
        raise TypeError(f"{name} must be a UUID or null")
    return value


def _string(row: Mapping[str, object], name: str) -> str:
    value = row[name]
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    return value


def _optional_string(row: Mapping[str, object], name: str) -> str | None:
    value = row[name]
    if value is None:
        return None
    if type(value) is not str:
        raise TypeError(f"{name} must be a string or null")
    return value


def _sha256(row: Mapping[str, object], name: str) -> str:
    value = _string(row, name)
    if re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value


def _positive_int(row: Mapping[str, object], name: str) -> int:
    value = row[name]
    if type(value) is not int or value < 1:
        raise TypeError(f"{name} must be a positive integer")
    return value


def _optional_positive_int(row: Mapping[str, object], name: str) -> int | None:
    value = row[name]
    if value is None:
        return None
    if type(value) is not int or value < 1:
        raise TypeError(f"{name} must be a positive integer or null")
    return value


def _aware_datetime(row: Mapping[str, object], name: str) -> datetime:
    value = row[name]
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError(f"{name} must be an aware datetime")
    return value


def _optional_aware_datetime(row: Mapping[str, object], name: str) -> datetime | None:
    value = row[name]
    if value is None:
        return None
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError(f"{name} must be an aware datetime or null")
    return value


def _sqlstate(error: DBAPIError) -> str | None:
    value = getattr(error.orig, "sqlstate", None)
    return value if type(value) is str else None


def _reserve_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_RUNNER_UNAUTHORIZED",
            "23505": "PHASE_A_TARGET_NAMESPACE_BUSY",
            "22023": "PHASE_A_EXECUTION_LOCK_REJECTED",
            "P0001": "PHASE_A_EXECUTION_LOCK_REJECTED",
        }.get(_sqlstate(error), "PHASE_A_EXECUTION_LOCK_RESERVATION_UNCERTAIN")
    )


def _claim_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_RUNNER_UNAUTHORIZED",
            "23505": "PHASE_A_EXECUTION_CLAIM_REJECTED",
            "22023": "PHASE_A_EXECUTION_CLAIM_REJECTED",
            "P0001": "PHASE_A_EXECUTION_CLAIM_REJECTED",
        }.get(_sqlstate(error), "PHASE_A_EXECUTION_CLAIM_UNCERTAIN")
    )


def _heartbeat_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_RUNNER_UNAUTHORIZED",
            "22023": "PHASE_A_EXECUTION_FENCE_LOST",
            "P0001": "PHASE_A_EXECUTION_FENCE_LOST",
        }.get(_sqlstate(error), "PHASE_A_EXECUTION_HEARTBEAT_UNCERTAIN")
    )


def _fenced_transition_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_RUNNER_UNAUTHORIZED",
            "22023": "PHASE_A_EXECUTION_FENCE_LOST",
            "P0001": "PHASE_A_EXECUTION_FENCE_LOST",
        }.get(_sqlstate(error), "PHASE_A_EXECUTION_RECOVERY_UNCERTAIN")
    )


def _read_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_RUNNER_UNAUTHORIZED",
        }.get(_sqlstate(error), "PHASE_A_EXECUTION_LOCK_LOOKUP_UNAVAILABLE")
    )
