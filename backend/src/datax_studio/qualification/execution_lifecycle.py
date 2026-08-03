"""Private adapter for the atomic Phase-A execution lifecycle boundary.

This module is intentionally not wired into Settings, the normal API, Worker,
Compose, Launcher, or the public plugin manifest.  A future protected harness
must explicitly inject a dedicated ``datax_phase_a_issuer`` Engine.  The
ordinary product stays deny-all, and a successful call creates only a queued,
blocked private record; it does not claim work, decrypt credentials, spawn a
process, or invoke DataX.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import Engine, bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from datax_studio.core.schemas import (
    SourceQuiescenceConfirmation,
    TargetExclusivityConfirmation,
)
from datax_studio.qualification.ledger import PhaseAGrantRef, PhaseALedgerError

_SCHEMA = "des_phase_a_qualification"
_CREATE_SQL = text(
    f"""
    SELECT *
    FROM {_SCHEMA}.des_create_authorize_reserve_phase_a_execution(
        :execution_id,
        :authorization_id,
        :lock_id,
        :grant_id,
        :job_version_id,
        :requested_by,
        :source_quiescence_confirmation,
        :target_exclusivity_confirmation
    )
    """
).bindparams(
    bindparam("source_quiescence_confirmation", type_=JSONB),
    bindparam("target_exclusivity_confirmation", type_=JSONB),
)


@dataclass(frozen=True)
class PhaseAPrivateExecutionReceipt:
    """The non-secret final receipt from the private atomic DB function."""

    execution_id: UUID
    authorization_id: UUID
    grant_id: UUID
    lock_id: UUID
    job_id: UUID
    job_version_id: UUID
    target_namespace_id: UUID
    checkpoint: str
    execution_process_state: str
    queue_eligibility_state: str
    queue_block_reason: str
    target_lock_state: str
    occurred_at: datetime

    def to_contract_v1(self) -> dict[str, object]:
        """Serialize the fixed, non-public machine handoff receipt.

        This is deliberately an explicit projection rather than a generic
        dataclass serializer: the protected contract has a closed field set and
        must never gain grant/QH/credential/process material by accident.
        """

        return {
            "schema_version": "1.0",
            "artifact_kind": "PHASE_A_EXECUTION_LIFECYCLE_RECEIPT",
            "purpose": "PRIVATE_PHASE_A_EXECUTION_LIFECYCLE",
            "visibility": "PROTECTED_PRIVATE",
            "ordinary_path_authorized": False,
            "evidence_conclusion": "NOT_E3_OR_E4",
            "execution_id": str(self.execution_id),
            "authorization_id": str(self.authorization_id),
            "grant_id": str(self.grant_id),
            "lock_id": str(self.lock_id),
            "job_id": str(self.job_id),
            "job_version_id": str(self.job_version_id),
            "target_namespace_id": str(self.target_namespace_id),
            "checkpoint": self.checkpoint,
            "execution_process_state": self.execution_process_state,
            "queue_eligibility_state": self.queue_eligibility_state,
            "queue_block_reason": self.queue_block_reason,
            "target_lock_state": self.target_lock_state,
            "occurred_at": self.occurred_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        }


class PhaseAPrivateExecutionIssuer:
    """Issuer-only client for create -> PEA -> global lock reservation.

    The function is one database transaction.  If the commit outcome is
    uncertain this adapter never retries, because a retry could obscure a
    consumed grant or an existing global target reservation.
    """

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def create_authorize_and_reserve(
        self,
        *,
        grant: PhaseAGrantRef,
        requested_by: UUID,
        job_version_id: UUID,
        source_quiescence_confirmation: SourceQuiescenceConfirmation,
        target_exclusivity_confirmation: TargetExclusivityConfirmation,
    ) -> PhaseAPrivateExecutionReceipt:
        grant_id = _grant_id(grant)
        _uuid_input(requested_by, "requested_by")
        _uuid_input(job_version_id, "job_version_id")
        source_payload, target_payload = _confirmation_payloads(
            source_quiescence_confirmation=source_quiescence_confirmation,
            target_exclusivity_confirmation=target_exclusivity_confirmation,
        )
        execution_id = uuid4()
        authorization_id = uuid4()
        lock_id = uuid4()
        try:
            with self._engine.begin() as connection:
                row = (
                    connection.execute(
                        _CREATE_SQL,
                        {
                            "execution_id": execution_id,
                            "authorization_id": authorization_id,
                            "lock_id": lock_id,
                            "grant_id": grant_id,
                            "job_version_id": job_version_id,
                            "requested_by": requested_by,
                            "source_quiescence_confirmation": source_payload,
                            "target_exclusivity_confirmation": target_payload,
                        },
                    )
                    .mappings()
                    .one()
                )
        except DBAPIError as error:
            raise _creation_error(error) from None
        except SQLAlchemyError:
            raise PhaseALedgerError("PHASE_A_PRIVATE_EXECUTION_CREATION_UNCERTAIN") from None

        try:
            return _receipt_from_row(
                row=row,
                execution_id=execution_id,
                authorization_id=authorization_id,
                grant_id=grant_id,
                lock_id=lock_id,
                job_version_id=job_version_id,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PhaseALedgerError("PHASE_A_PRIVATE_EXECUTION_RESPONSE_INVALID") from error


def _grant_id(grant: PhaseAGrantRef) -> UUID:
    if type(grant) is not PhaseAGrantRef or type(grant.grant_id) is not UUID:
        raise PhaseALedgerError("PHASE_A_PRIVATE_EXECUTION_INPUT_INVALID")
    return grant.grant_id


def _uuid_input(value: UUID, name: str) -> None:
    if type(value) is not UUID:
        raise PhaseALedgerError("PHASE_A_PRIVATE_EXECUTION_INPUT_INVALID")


def _confirmation_payloads(
    *,
    source_quiescence_confirmation: SourceQuiescenceConfirmation,
    target_exclusivity_confirmation: TargetExclusivityConfirmation,
) -> tuple[dict[str, object], dict[str, object]]:
    if type(source_quiescence_confirmation) is not SourceQuiescenceConfirmation:
        raise PhaseALedgerError("PHASE_A_PRIVATE_EXECUTION_INPUT_INVALID")
    if type(target_exclusivity_confirmation) is not TargetExclusivityConfirmation:
        raise PhaseALedgerError("PHASE_A_PRIVATE_EXECUTION_INPUT_INVALID")
    source_payload = source_quiescence_confirmation.model_dump(mode="json")
    target_payload = target_exclusivity_confirmation.model_dump(mode="json")
    if type(source_payload) is not dict or type(target_payload) is not dict:
        raise PhaseALedgerError("PHASE_A_PRIVATE_EXECUTION_INPUT_INVALID")
    return source_payload, target_payload


def _receipt_from_row(
    *,
    row: Mapping[str, object],
    execution_id: UUID,
    authorization_id: UUID,
    grant_id: UUID,
    lock_id: UUID,
    job_version_id: UUID,
) -> PhaseAPrivateExecutionReceipt:
    if not isinstance(row, Mapping):
        raise TypeError("Phase-A private execution row is not a mapping")
    expected_ids = {
        "execution_id": execution_id,
        "authorization_id": authorization_id,
        "grant_id": grant_id,
        "lock_id": lock_id,
        "job_version_id": job_version_id,
    }
    for name, expected in expected_ids.items():
        if _uuid_field(row, name) != expected:
            raise ValueError(f"{name} does not match the private lifecycle request")
    checkpoint = _string_field(row, "checkpoint")
    if checkpoint != "LOCK_RESERVED":
        raise ValueError("private lifecycle did not finish at lock reservation")
    process_state = _string_field(row, "execution_process_state")
    eligibility_state = _string_field(row, "queue_eligibility_state")
    block_reason = _string_field(row, "queue_block_reason")
    lock_state = _string_field(row, "target_lock_state")
    if (
        process_state != "QUEUED"
        or eligibility_state != "BLOCKED"
        or block_reason != "PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED"
        or lock_state != "RESERVED"
    ):
        raise ValueError("private lifecycle response is not safely blocked")
    return PhaseAPrivateExecutionReceipt(
        execution_id=execution_id,
        authorization_id=authorization_id,
        grant_id=grant_id,
        lock_id=lock_id,
        job_id=_uuid_field(row, "job_id"),
        job_version_id=job_version_id,
        target_namespace_id=_uuid_field(row, "target_namespace_id"),
        checkpoint=checkpoint,
        execution_process_state=process_state,
        queue_eligibility_state=eligibility_state,
        queue_block_reason=block_reason,
        target_lock_state=lock_state,
        occurred_at=_aware_datetime_field(row, "occurred_at"),
    )


def _uuid_field(row: Mapping[str, object], name: str) -> UUID:
    value = row[name]
    if type(value) is not UUID:
        raise TypeError(f"{name} must be a UUID")
    return value


def _string_field(row: Mapping[str, object], name: str) -> str:
    value = row[name]
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    return value


def _aware_datetime_field(row: Mapping[str, object], name: str) -> datetime:
    value = row[name]
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError(f"{name} must be an aware datetime")
    return value


def _sqlstate(error: DBAPIError) -> str | None:
    value = getattr(error.orig, "sqlstate", None)
    return value if type(value) is str else None


def _creation_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_ISSUER_UNAUTHORIZED",
            "22023": "PHASE_A_PRIVATE_EXECUTION_CREATION_REJECTED",
            "23505": "PHASE_A_PRIVATE_EXECUTION_CREATION_REJECTED",
            "P0001": "PHASE_A_PRIVATE_EXECUTION_CREATION_REJECTED",
            "55000": "PHASE_A_PRIVATE_EXECUTION_CREATION_REJECTED",
        }.get(_sqlstate(error), "PHASE_A_PRIVATE_EXECUTION_CREATION_UNCERTAIN")
    )
