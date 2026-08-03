from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from datax_studio.qualification.execution_authorization import (
    PhaseAExecutionAuthorizationConsumer,
    PhaseAExecutionAuthorizationIssuer,
    PhaseAExecutionAuthorizationRef,
)
from datax_studio.qualification.ledger import PhaseAGrantRef, PhaseALedgerError
from datax_studio.qualification.phase_a import PhaseARuntimeIdentity
from datax_studio.release_qualification import ExpectedHarness

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Version:
    datax_release: str
    runtime_sha256: str
    reader_plugin_name: str
    reader_plugin_sha256: str
    writer_plugin_name: str
    writer_plugin_sha256: str


def _expected_harness() -> ExpectedHarness:
    return ExpectedHarness(
        identity="phase-a-win-harness",
        environment_id="win11-qualification-01",
        environment_manifest_sha256=_hash("windows-environment"),
        harness_version="1.0.0+e2",
    )


def _version() -> _Version:
    return _Version(
        datax_release="datax_v202309",
        runtime_sha256=_hash("runtime"),
        reader_plugin_name="mysqlreader",
        reader_plugin_sha256=_hash("mysqlreader"),
        writer_plugin_name="postgresqlwriter",
        writer_plugin_sha256=_hash("postgresqlwriter"),
    )


def _runtime() -> PhaseARuntimeIdentity:
    return PhaseARuntimeIdentity(
        worker_image_digest=f"sha256:{_hash('worker')}",
        datax_release="datax_v202309",
        runtime_sha256=_hash("runtime"),
        plugin_sha256s={
            "mysqlreader": _hash("mysqlreader"),
            "mysqlwriter": _hash("mysqlwriter"),
            "postgresqlreader": _hash("postgresqlreader"),
            "postgresqlwriter": _hash("postgresqlwriter"),
        },
    )


def _ref() -> PhaseAExecutionAuthorizationRef:
    return PhaseAExecutionAuthorizationRef(
        authorization_id=uuid4(),
        grant=PhaseAGrantRef(grant_id=uuid4()),
        execution_id=uuid4(),
    )


def _row(ref: PhaseAExecutionAuthorizationRef) -> dict[str, object]:
    return {
        "authorization_id": ref.authorization_id,
        "grant_id": ref.grant.grant_id,
        "execution_id": ref.execution_id,
        "project_id": uuid4(),
        "job_id": uuid4(),
        "job_version_id": uuid4(),
        "job_version_artifact_hash": _hash("job-version-artifact"),
        "job_spec_hash": _hash("job-spec"),
        "source_datasource_revision_id": uuid4(),
        "source_datasource_config_hash": _hash("source-config"),
        "target_datasource_revision_id": uuid4(),
        "target_datasource_config_hash": _hash("target-config"),
        "source_endpoint_policy_revision_id": uuid4(),
        "source_endpoint_policy_hash": _hash("source-policy"),
        "target_endpoint_policy_revision_id": uuid4(),
        "target_endpoint_policy_hash": _hash("target-policy"),
        "source_physical_endpoint_identity_id": uuid4(),
        "source_server_identity_hash": _hash("source-server"),
        "target_physical_endpoint_identity_id": uuid4(),
        "target_server_identity_hash": _hash("target-server"),
        "source_physical_table_identity_hash": _hash("source-table"),
        "target_namespace_id": uuid4(),
        "target_physical_table_identity_hash": _hash("target-table"),
        "target_normalization_version": "1.0",
        "transfer_policy_id": uuid4(),
        "transfer_policy_scope_hash": _hash("transfer-policy"),
        "transfer_policy_row_version": 1,
        "payload_binding_sha256": _hash("payload-binding"),
        "payload_root_sha256": _hash("payload-root"),
        # The private read record contains a one-way digest, never the QH's
        # original nonce value.
        "nonce_sha256": _hash("one-time-nonce"),
        "candidate_commit": "a" * 40,
        "worker_image_digest": f"sha256:{_hash('worker')}",
        "datax_release": "datax_v202309",
        "runtime_sha256": _hash("runtime"),
        "reader_plugin_name": "mysqlreader",
        "reader_plugin_sha256": _hash("mysqlreader"),
        "writer_plugin_name": "postgresqlwriter",
        "writer_plugin_sha256": _hash("postgresqlwriter"),
        "harness_identity": "phase-a-win-harness",
        "harness_environment_id": "win11-qualification-01",
        "harness_environment_manifest_sha256": _hash("windows-environment"),
        "harness_version": "1.0.0+e2",
        "qh_document_sha256": _hash("qh-document"),
        "qh_qualification_id": "qualification-0001",
        "qh_issuer_key_id": "issuer-key-0001",
        "qh_issued_at": NOW - timedelta(minutes=5),
        "qh_not_before": NOW - timedelta(minutes=4),
        "qh_valid_until": NOW + timedelta(minutes=30),
        "authorized_at": NOW,
    }


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

    def one_or_none(self) -> dict[str, object] | None:
        return self._row


class _FakeConnection:
    def __init__(self, *, row: dict[str, object] | None) -> None:
        self._row = row
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(self, statement: object, parameters: dict[str, object]) -> object:
        rendered = str(statement)
        self.calls.append((rendered, dict(parameters)))
        if "des_authorize_phase_a_execution" in rendered:
            return _FakeScalarResult(parameters["authorization_id"])
        if "des_read_active_phase_a_execution_authorization" in rendered:
            return _FakeMappingsResult(self._row)
        raise AssertionError(f"unexpected private authorization query: {rendered}")


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


def _assert_code(callback: object, expected: str) -> None:
    with pytest.raises(PhaseALedgerError) as raised:
        assert callable(callback)
        callback()
    assert raised.value.code == expected


def test_private_execution_authorization_uses_only_private_functions_and_checked_fields() -> None:
    grant = PhaseAGrantRef(grant_id=uuid4())
    execution_id = uuid4()
    connection = _FakeConnection(row=None)
    issuer = PhaseAExecutionAuthorizationIssuer(_FakeEngine(connection))  # type: ignore[arg-type]

    ref = issuer.authorize(grant=grant, execution_id=execution_id)

    assert ref.grant == grant
    assert ref.execution_id == execution_id
    assert len(connection.calls) == 1
    authorize_query, authorize_parameters = connection.calls[0]
    assert "des_authorize_phase_a_execution" in authorize_query
    assert authorize_parameters == {
        "authorization_id": ref.authorization_id,
        "grant_id": grant.grant_id,
        "execution_id": execution_id,
    }


def test_consumer_reconstructs_only_matching_non_secret_execution_authorization() -> None:
    ref = _ref()
    row = _row(ref)
    connection = _FakeConnection(row=row)
    consumer = PhaseAExecutionAuthorizationConsumer(_FakeEngine(connection))  # type: ignore[arg-type]

    active = consumer.require_for_private_checkpoint(
        ref=ref,
        version=_version(),
        current_runtime=_runtime(),
        expected_harness=_expected_harness(),
        now=NOW,
    )

    assert active.ref == ref
    assert active.snapshot.job_version_id == row["job_version_id"]
    assert active.snapshot.transfer_policy_row_version == 1
    assert active.binding.nonce_sha256 == _hash("one-time-nonce")
    assert len(connection.calls) == 1
    read_query, read_parameters = connection.calls[0]
    assert "des_read_active_phase_a_execution_authorization" in read_query
    assert read_parameters == {"execution_id": ref.execution_id}
    assert "nonce" not in read_parameters


def test_consumer_rejects_inactive_mismatched_or_malformed_authorization_rows() -> None:
    ref = _ref()
    _assert_code(
        lambda: PhaseAExecutionAuthorizationConsumer(
            _FakeEngine(_FakeConnection(row=None))  # type: ignore[arg-type]
        ).read_active(ref),
        "PHASE_A_EXECUTION_AUTHORIZATION_NOT_ACTIVE",
    )

    mismatched = _row(ref)
    mismatched["grant_id"] = uuid4()
    _assert_code(
        lambda: PhaseAExecutionAuthorizationConsumer(
            _FakeEngine(_FakeConnection(row=mismatched))  # type: ignore[arg-type]
        ).read_active(ref),
        "PHASE_A_EXECUTION_AUTHORIZATION_RESPONSE_INVALID",
    )

    malformed = _row(ref)
    malformed["nonce_sha256"] = "not-a-digest"
    _assert_code(
        lambda: PhaseAExecutionAuthorizationConsumer(
            _FakeEngine(_FakeConnection(row=malformed))  # type: ignore[arg-type]
        ).read_active(ref),
        "PHASE_A_EXECUTION_AUTHORIZATION_RESPONSE_INVALID",
    )


def test_private_checkpoint_rechecks_runtime_and_rejects_forged_references() -> None:
    ref = _ref()
    row = _row(ref)
    consumer = PhaseAExecutionAuthorizationConsumer(
        _FakeEngine(_FakeConnection(row=row))  # type: ignore[arg-type]
    )
    _assert_code(
        lambda: consumer.require_for_private_checkpoint(
            ref=ref,
            version=_version(),
            current_runtime=replace(
                _runtime(),
                worker_image_digest=f"sha256:{'0' * 64}",
            ),
            expected_harness=_expected_harness(),
            now=NOW,
        ),
        "PHASE_A_RUNTIME_GRANT_MISMATCH",
    )
    _assert_code(
        lambda: consumer.read_active(replace(ref, execution_id="not-a-uuid")),  # type: ignore[arg-type]
        "PHASE_A_EXECUTION_AUTHORIZATION_REFERENCE_INVALID",
    )


def test_authorizer_rejects_non_uuid_execution_reference_before_database_access() -> None:
    connection = _FakeConnection(row=None)
    issuer = PhaseAExecutionAuthorizationIssuer(_FakeEngine(connection))  # type: ignore[arg-type]

    _assert_code(
        lambda: issuer.authorize(
            grant=PhaseAGrantRef(grant_id=uuid4()),
            execution_id="not-a-uuid",  # type: ignore[arg-type]
        ),
        "PHASE_A_EXECUTION_REFERENCE_INVALID",
    )
    assert connection.calls == []
