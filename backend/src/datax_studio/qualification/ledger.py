"""Private PostgreSQL adapter for the ADR-0011 Phase-A grant ledger.

This module has no Settings integration and is intentionally not imported by
the standard API, Worker, Compose, or plugin-certification source.  A future
protected harness must inject an Engine authenticated as the dedicated issuer
or consumer role.  The ordinary product remains production deny-all.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from datax_studio.qualification.phase_a import (
    JobVersionBinding,
    PhaseADurableGrantFields,
    PhaseAExecutionBinding,
    PhaseAGrantIssuance,
    PhaseARuntimeIdentity,
    assert_execution_binding,
    durable_grant_fields,
    reconstruct_execution_binding_from_ledger,
)
from datax_studio.release_qualification import ExpectedHarness

_SCHEMA = "des_phase_a_qualification"
_ISSUE_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_issue_phase_a_qualification_grant(
        :grant_id,
        :nonce_id,
        :nonce_sha256,
        :payload_binding_sha256,
        :payload_root_sha256,
        :candidate_commit,
        :worker_image_digest,
        :runtime_sha256,
        :reader_plugin_name,
        :reader_plugin_sha256,
        :writer_plugin_name,
        :writer_plugin_sha256,
        :harness_identity,
        :harness_environment_id,
        :harness_environment_manifest_sha256,
        :harness_version,
        :qh_document_sha256,
        :qh_qualification_id,
        :qh_issuer_key_id,
        :qh_issued_at,
        :qh_not_before,
        :qh_valid_until
    ) AS grant_id
    """
)
_REVOKE_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_revoke_phase_a_qualification_grant(
        :grant_id,
        :reason
    ) AS revoked
    """
)
_READ_SQL = text(
    f"""
    SELECT *
    FROM {_SCHEMA}.des_read_active_phase_a_qualification_grant(:grant_id)
    """
)


class PhaseALedgerError(ValueError):
    """Stable non-secret result from the protected database boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class PhaseAGrantRef:
    """Opaque durable grant identity; it is not an execution authorization."""

    grant_id: UUID


@dataclass(frozen=True)
class PhaseAActiveGrant:
    """Current private grant row reconstructed as a checked local binding."""

    ref: PhaseAGrantRef
    binding: PhaseAExecutionBinding


class PhaseALedgerIssuer:
    """Issuer-only adapter for atomic nonce consumption and PAG persistence."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def issue(self, issuance: PhaseAGrantIssuance) -> PhaseAGrantRef:
        fields = durable_grant_fields(issuance)
        grant_id = uuid4()
        nonce_id = uuid4()
        try:
            with self._engine.begin() as connection:
                returned = connection.execute(
                    _ISSUE_SQL,
                    _issuance_parameters(
                        fields=fields,
                        grant_id=grant_id,
                        nonce_id=nonce_id,
                    ),
                ).scalar_one()
        except DBAPIError as error:
            raise _issue_error(error) from None
        except SQLAlchemyError:
            # A failure during commit can be ambiguous: do not automatically
            # retry a one-time nonce issuance and accidentally classify it as a
            # harmless replay.
            raise PhaseALedgerError("PHASE_A_ISSUANCE_UNCERTAIN") from None
        if type(returned) is not UUID or returned != grant_id:
            raise PhaseALedgerError("PHASE_A_ISSUANCE_UNCERTAIN")
        return PhaseAGrantRef(grant_id=grant_id)

    def revoke(self, ref: PhaseAGrantRef, *, reason: str) -> bool:
        grant_id = _grant_id(ref)
        if type(reason) is not str:
            raise PhaseALedgerError("PHASE_A_REVOCATION_REJECTED")
        try:
            with self._engine.begin() as connection:
                revoked = connection.execute(
                    _REVOKE_SQL,
                    {"grant_id": grant_id, "reason": reason},
                ).scalar_one()
        except DBAPIError as error:
            raise _revoke_error(error) from None
        except SQLAlchemyError:
            raise PhaseALedgerError("PHASE_A_REVOCATION_UNCERTAIN") from None
        if type(revoked) is not bool:
            raise PhaseALedgerError("PHASE_A_REVOCATION_UNCERTAIN")
        return revoked


class PhaseALedgerConsumer:
    """Consumer-only adapter that can read, not create or alter, a PAG."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def read_active(self, ref: PhaseAGrantRef) -> PhaseAActiveGrant:
        grant_id = _grant_id(ref)
        try:
            with self._engine.begin() as connection:
                row = connection.execute(_READ_SQL, {"grant_id": grant_id}).mappings().one_or_none()
        except DBAPIError as error:
            raise _read_error(error) from None
        except SQLAlchemyError:
            raise PhaseALedgerError("PHASE_A_GRANT_LOOKUP_UNAVAILABLE") from None
        if row is None:
            raise PhaseALedgerError("PHASE_A_GRANT_NOT_ACTIVE")
        try:
            fields = PhaseADurableGrantFields(
                payload_root_sha256=row["payload_root_sha256"],
                payload_binding_sha256=row["payload_binding_sha256"],
                payload_commit_sha=row["candidate_commit"],
                worker_image_digest=row["worker_image_digest"],
                datax_release=row["datax_release"],
                runtime_sha256=row["runtime_sha256"],
                reader_plugin_name=row["reader_plugin_name"],
                reader_plugin_sha256=row["reader_plugin_sha256"],
                writer_plugin_name=row["writer_plugin_name"],
                writer_plugin_sha256=row["writer_plugin_sha256"],
                harness=ExpectedHarness(
                    identity=row["harness_identity"],
                    environment_id=row["harness_environment_id"],
                    environment_manifest_sha256=row["harness_environment_manifest_sha256"],
                    harness_version=row["harness_version"],
                ),
                qualification_id=row["qh_qualification_id"],
                issuer_key_id=row["qh_issuer_key_id"],
                nonce_sha256=row["nonce_sha256"],
                qh_document_sha256=row["qh_document_sha256"],
                issued_at=row["qh_issued_at"],
                not_before=row["qh_not_before"],
                valid_until=row["qh_valid_until"],
            )
            binding = reconstruct_execution_binding_from_ledger(fields)
        except (KeyError, TypeError, ValueError) as error:
            raise PhaseALedgerError("PHASE_A_GRANT_RESPONSE_INVALID") from error
        return PhaseAActiveGrant(ref=ref, binding=binding)

    def require_for_private_preflight(
        self,
        *,
        ref: PhaseAGrantRef,
        version: JobVersionBinding,
        current_runtime: PhaseARuntimeIdentity,
        expected_harness: ExpectedHarness,
        now: datetime,
    ) -> PhaseAActiveGrant:
        """Recheck a durable PAG before a future private worker preflight.

        This is intentionally not a DataX-start API.  The grant has no
        execution ID and cannot protect a later process claim/start race; J0b
        must add an immutable execution authorization and all four gates.
        """

        active = self.read_active(ref)
        try:
            assert_execution_binding(
                binding=active.binding,
                version=version,
                current_runtime=current_runtime,
                expected_harness=expected_harness,
                now=now,
            )
        except ValueError as error:
            code = getattr(error, "code", "PHASE_A_GRANT_PRECHECK_REJECTED")
            raise PhaseALedgerError(code) from error
        return active


def _issuance_parameters(
    *,
    fields: PhaseADurableGrantFields,
    grant_id: UUID,
    nonce_id: UUID,
) -> dict[str, object]:
    return {
        "grant_id": grant_id,
        "nonce_id": nonce_id,
        "nonce_sha256": fields.nonce_sha256,
        "payload_binding_sha256": fields.payload_binding_sha256,
        "payload_root_sha256": fields.payload_root_sha256,
        "candidate_commit": fields.payload_commit_sha,
        "worker_image_digest": fields.worker_image_digest,
        "runtime_sha256": fields.runtime_sha256,
        "reader_plugin_name": fields.reader_plugin_name,
        "reader_plugin_sha256": fields.reader_plugin_sha256,
        "writer_plugin_name": fields.writer_plugin_name,
        "writer_plugin_sha256": fields.writer_plugin_sha256,
        "harness_identity": fields.harness.identity,
        "harness_environment_id": fields.harness.environment_id,
        "harness_environment_manifest_sha256": fields.harness.environment_manifest_sha256,
        "harness_version": fields.harness.harness_version,
        "qh_document_sha256": fields.qh_document_sha256,
        "qh_qualification_id": fields.qualification_id,
        "qh_issuer_key_id": fields.issuer_key_id,
        "qh_issued_at": fields.issued_at,
        "qh_not_before": fields.not_before,
        "qh_valid_until": fields.valid_until,
    }


def _grant_id(ref: PhaseAGrantRef) -> UUID:
    if type(ref) is not PhaseAGrantRef or type(ref.grant_id) is not UUID:
        raise PhaseALedgerError("PHASE_A_GRANT_REFERENCE_INVALID")
    return ref.grant_id


def _sqlstate(error: DBAPIError) -> str | None:
    value = getattr(error.orig, "sqlstate", None)
    return value if type(value) is str else None


def _issue_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_ISSUER_UNAUTHORIZED",
            "22023": "PHASE_A_ISSUANCE_REJECTED",
            "23505": "PHASE_A_NONCE_REPLAYED",
            "P0001": "PHASE_A_NONCE_REPLAYED",
        }.get(_sqlstate(error), "PHASE_A_ISSUANCE_UNCERTAIN")
    )


def _revoke_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_ISSUER_UNAUTHORIZED",
            "22023": "PHASE_A_REVOCATION_REJECTED",
        }.get(_sqlstate(error), "PHASE_A_REVOCATION_UNCERTAIN")
    )


def _read_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_CONSUMER_UNAUTHORIZED",
        }.get(_sqlstate(error), "PHASE_A_GRANT_LOOKUP_UNAVAILABLE")
    )
