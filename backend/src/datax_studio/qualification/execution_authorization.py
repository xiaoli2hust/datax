"""Private adapter for one immutable Phase-A execution authorization.

This module deliberately has no Settings integration and is not imported by
the standard API, Worker, Compose, or plugin-certification source.  A future
protected harness must inject narrowly authenticated issuer and consumer
Engines.  In particular, this adapter cannot create a private execution,
claim work, mutate queue state, or start DataX; the ordinary product remains
production deny-all until those later gates are implemented and qualified.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from datax_studio.qualification.ledger import PhaseAGrantRef, PhaseALedgerError
from datax_studio.qualification.phase_a import (
    JobVersionBinding,
    PhaseADurableGrantFields,
    PhaseAExecutionBinding,
    PhaseARuntimeIdentity,
    assert_execution_binding,
    reconstruct_execution_binding_from_ledger,
)
from datax_studio.release_qualification import ExpectedHarness

_SCHEMA = "des_phase_a_qualification"
_AUTHORIZE_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_authorize_phase_a_execution(
        :authorization_id,
        :grant_id,
        :execution_id
    ) AS authorization_id
    """
)
_READ_SQL = text(
    f"""
    SELECT *
    FROM {_SCHEMA}.des_read_active_phase_a_execution_authorization(:execution_id)
    """
)
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_TARGET_NORMALIZATION_VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,16}$")


@dataclass(frozen=True)
class PhaseAExecutionAuthorizationRef:
    """Opaque identifier for a grant bound to exactly one private execution."""

    authorization_id: UUID
    grant: PhaseAGrantRef
    execution_id: UUID


@dataclass(frozen=True)
class PhaseAExecutionAuthorizationSnapshot:
    """Non-secret immutable product facts returned by the private reader."""

    project_id: UUID
    job_id: UUID
    job_version_id: UUID
    job_version_artifact_hash: str
    job_spec_hash: str
    source_datasource_revision_id: UUID
    source_datasource_config_hash: str
    target_datasource_revision_id: UUID
    target_datasource_config_hash: str
    source_endpoint_policy_revision_id: UUID
    source_endpoint_policy_hash: str
    target_endpoint_policy_revision_id: UUID
    target_endpoint_policy_hash: str
    source_physical_endpoint_identity_id: UUID
    source_server_identity_hash: str
    target_physical_endpoint_identity_id: UUID
    target_server_identity_hash: str
    source_physical_table_identity_hash: str
    target_namespace_id: UUID
    target_physical_table_identity_hash: str
    target_normalization_version: str
    transfer_policy_id: UUID
    transfer_policy_scope_hash: str
    transfer_policy_row_version: int
    authorized_at: datetime


@dataclass(frozen=True)
class PhaseAActiveExecutionAuthorization:
    """Current checked authorization plus reconstructed Phase-A binding."""

    ref: PhaseAExecutionAuthorizationRef
    snapshot: PhaseAExecutionAuthorizationSnapshot
    binding: PhaseAExecutionBinding


class PhaseAExecutionAuthorizationIssuer:
    """Issuer-only adapter that atomically binds one PAG to one execution."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def authorize(
        self,
        *,
        grant: PhaseAGrantRef,
        execution_id: UUID,
    ) -> PhaseAExecutionAuthorizationRef:
        grant_id = _grant_id(grant)
        if type(execution_id) is not UUID:
            raise PhaseALedgerError("PHASE_A_EXECUTION_REFERENCE_INVALID")
        authorization_id = uuid4()
        try:
            with self._engine.begin() as connection:
                returned = connection.execute(
                    _AUTHORIZE_SQL,
                    {
                        "authorization_id": authorization_id,
                        "grant_id": grant_id,
                        "execution_id": execution_id,
                    },
                ).scalar_one()
        except DBAPIError as error:
            raise _authorize_error(error) from None
        except SQLAlchemyError:
            # A commit failure is ambiguous.  Do not retry automatically: the
            # grant may already have been irrevocably bound to this execution.
            raise PhaseALedgerError("PHASE_A_EXECUTION_AUTHORIZATION_UNCERTAIN") from None
        if type(returned) is not UUID or returned != authorization_id:
            raise PhaseALedgerError("PHASE_A_EXECUTION_AUTHORIZATION_UNCERTAIN")
        return PhaseAExecutionAuthorizationRef(
            authorization_id=authorization_id,
            grant=grant,
            execution_id=execution_id,
        )


class PhaseAExecutionAuthorizationConsumer:
    """Consumer-only adapter for checked reads of active private authorization."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def read_active(
        self,
        ref: PhaseAExecutionAuthorizationRef,
    ) -> PhaseAActiveExecutionAuthorization:
        authorization_id, grant_id, execution_id = _reference_fields(ref)
        try:
            with self._engine.begin() as connection:
                row = connection.execute(
                    _READ_SQL,
                    {"execution_id": execution_id},
                ).mappings().one_or_none()
        except DBAPIError as error:
            raise _read_error(error) from None
        except SQLAlchemyError:
            raise PhaseALedgerError("PHASE_A_EXECUTION_AUTHORIZATION_LOOKUP_UNAVAILABLE") from None
        if row is None:
            raise PhaseALedgerError("PHASE_A_EXECUTION_AUTHORIZATION_NOT_ACTIVE")
        try:
            active = _active_from_row(
                row=row,
                ref=ref,
                authorization_id=authorization_id,
                grant_id=grant_id,
                execution_id=execution_id,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PhaseALedgerError("PHASE_A_EXECUTION_AUTHORIZATION_RESPONSE_INVALID") from error
        return active

    def require_for_private_checkpoint(
        self,
        *,
        ref: PhaseAExecutionAuthorizationRef,
        version: JobVersionBinding,
        current_runtime: PhaseARuntimeIdentity,
        expected_harness: ExpectedHarness,
        now: datetime,
    ) -> PhaseAActiveExecutionAuthorization:
        """Revalidate authorization immediately before a future private gate.

        This method only reads and checks immutable facts.  It does not claim
        or mutate an Execution, queue work, decrypt credentials, or start
        DataX.  A future protected Worker must call it at its four separately
        designed checkpoints; this adapter alone is not an E3 integration.
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
            code = getattr(error, "code", "PHASE_A_EXECUTION_CHECKPOINT_REJECTED")
            raise PhaseALedgerError(code) from error
        return active


def _grant_id(grant: PhaseAGrantRef) -> UUID:
    if type(grant) is not PhaseAGrantRef or type(grant.grant_id) is not UUID:
        raise PhaseALedgerError("PHASE_A_GRANT_REFERENCE_INVALID")
    return grant.grant_id


def _reference_fields(ref: PhaseAExecutionAuthorizationRef) -> tuple[UUID, UUID, UUID]:
    if type(ref) is not PhaseAExecutionAuthorizationRef:
        raise PhaseALedgerError("PHASE_A_EXECUTION_AUTHORIZATION_REFERENCE_INVALID")
    grant_id = _grant_id(ref.grant)
    if type(ref.authorization_id) is not UUID or type(ref.execution_id) is not UUID:
        raise PhaseALedgerError("PHASE_A_EXECUTION_AUTHORIZATION_REFERENCE_INVALID")
    return ref.authorization_id, grant_id, ref.execution_id


def _active_from_row(
    *,
    row: Mapping[str, object],
    ref: PhaseAExecutionAuthorizationRef,
    authorization_id: UUID,
    grant_id: UUID,
    execution_id: UUID,
) -> PhaseAActiveExecutionAuthorization:
    if type(row) is not dict and not isinstance(row, Mapping):
        raise TypeError("Phase-A execution authorization row is not a mapping")
    if (
        _uuid_field(row, "authorization_id") != authorization_id
        or _uuid_field(row, "grant_id") != grant_id
        or _uuid_field(row, "execution_id") != execution_id
    ):
        raise ValueError("Phase-A execution authorization reference mismatch")

    snapshot = PhaseAExecutionAuthorizationSnapshot(
        project_id=_uuid_field(row, "project_id"),
        job_id=_uuid_field(row, "job_id"),
        job_version_id=_uuid_field(row, "job_version_id"),
        job_version_artifact_hash=_sha256_field(row, "job_version_artifact_hash"),
        job_spec_hash=_sha256_field(row, "job_spec_hash"),
        source_datasource_revision_id=_uuid_field(row, "source_datasource_revision_id"),
        source_datasource_config_hash=_sha256_field(row, "source_datasource_config_hash"),
        target_datasource_revision_id=_uuid_field(row, "target_datasource_revision_id"),
        target_datasource_config_hash=_sha256_field(row, "target_datasource_config_hash"),
        source_endpoint_policy_revision_id=_uuid_field(
            row,
            "source_endpoint_policy_revision_id",
        ),
        source_endpoint_policy_hash=_sha256_field(row, "source_endpoint_policy_hash"),
        target_endpoint_policy_revision_id=_uuid_field(
            row,
            "target_endpoint_policy_revision_id",
        ),
        target_endpoint_policy_hash=_sha256_field(row, "target_endpoint_policy_hash"),
        source_physical_endpoint_identity_id=_uuid_field(
            row,
            "source_physical_endpoint_identity_id",
        ),
        source_server_identity_hash=_sha256_field(row, "source_server_identity_hash"),
        target_physical_endpoint_identity_id=_uuid_field(
            row,
            "target_physical_endpoint_identity_id",
        ),
        target_server_identity_hash=_sha256_field(row, "target_server_identity_hash"),
        source_physical_table_identity_hash=_sha256_field(
            row,
            "source_physical_table_identity_hash",
        ),
        target_namespace_id=_uuid_field(row, "target_namespace_id"),
        target_physical_table_identity_hash=_sha256_field(
            row,
            "target_physical_table_identity_hash",
        ),
        target_normalization_version=_normalization_version_field(
            row,
            "target_normalization_version",
        ),
        transfer_policy_id=_uuid_field(row, "transfer_policy_id"),
        transfer_policy_scope_hash=_sha256_field(row, "transfer_policy_scope_hash"),
        transfer_policy_row_version=_positive_int_field(row, "transfer_policy_row_version"),
        authorized_at=_aware_datetime_field(row, "authorized_at"),
    )
    fields = PhaseADurableGrantFields(
        payload_root_sha256=_sha256_field(row, "payload_root_sha256"),
        payload_binding_sha256=_sha256_field(row, "payload_binding_sha256"),
        payload_commit_sha=_string_field(row, "candidate_commit"),
        worker_image_digest=_string_field(row, "worker_image_digest"),
        datax_release=_string_field(row, "datax_release"),
        runtime_sha256=_sha256_field(row, "runtime_sha256"),
        reader_plugin_name=_string_field(row, "reader_plugin_name"),
        reader_plugin_sha256=_sha256_field(row, "reader_plugin_sha256"),
        writer_plugin_name=_string_field(row, "writer_plugin_name"),
        writer_plugin_sha256=_sha256_field(row, "writer_plugin_sha256"),
        harness=ExpectedHarness(
            identity=_string_field(row, "harness_identity"),
            environment_id=_string_field(row, "harness_environment_id"),
            environment_manifest_sha256=_sha256_field(
                row,
                "harness_environment_manifest_sha256",
            ),
            harness_version=_string_field(row, "harness_version"),
        ),
        qualification_id=_string_field(row, "qh_qualification_id"),
        issuer_key_id=_string_field(row, "qh_issuer_key_id"),
        nonce_sha256=_sha256_field(row, "nonce_sha256"),
        qh_document_sha256=_sha256_field(row, "qh_document_sha256"),
        issued_at=_aware_datetime_field(row, "qh_issued_at"),
        not_before=_aware_datetime_field(row, "qh_not_before"),
        valid_until=_aware_datetime_field(row, "qh_valid_until"),
    )
    return PhaseAActiveExecutionAuthorization(
        ref=ref,
        snapshot=snapshot,
        binding=reconstruct_execution_binding_from_ledger(fields),
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


def _sha256_field(row: Mapping[str, object], name: str) -> str:
    value = _string_field(row, name)
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value


def _normalization_version_field(row: Mapping[str, object], name: str) -> str:
    value = _string_field(row, name)
    if _TARGET_NORMALIZATION_VERSION.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")
    return value


def _positive_int_field(row: Mapping[str, object], name: str) -> int:
    value = row[name]
    if type(value) is not int or value < 1:
        raise TypeError(f"{name} must be a positive integer")
    return value


def _aware_datetime_field(row: Mapping[str, object], name: str) -> datetime:
    value = row[name]
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError(f"{name} must be an aware datetime")
    return value


def _sqlstate(error: DBAPIError) -> str | None:
    value = getattr(error.orig, "sqlstate", None)
    return value if type(value) is str else None


def _authorize_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_ISSUER_UNAUTHORIZED",
            "22023": "PHASE_A_EXECUTION_AUTHORIZATION_REJECTED",
            "23505": "PHASE_A_EXECUTION_AUTHORIZATION_REJECTED",
            "P0001": "PHASE_A_EXECUTION_AUTHORIZATION_REJECTED",
            "55000": "PHASE_A_EXECUTION_AUTHORIZATION_REJECTED",
        }.get(_sqlstate(error), "PHASE_A_EXECUTION_AUTHORIZATION_UNCERTAIN")
    )


def _read_error(error: DBAPIError) -> PhaseALedgerError:
    return PhaseALedgerError(
        {
            "42501": "PHASE_A_CONSUMER_UNAUTHORIZED",
        }.get(_sqlstate(error), "PHASE_A_EXECUTION_AUTHORIZATION_LOOKUP_UNAVAILABLE")
    )
