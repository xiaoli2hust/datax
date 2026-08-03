from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import CheckConstraint, Column, UniqueConstraint
from sqlalchemy.dialects import postgresql, sqlite

from datax_studio.auth.db import Base
from datax_studio.core.db import (
    PHASE_A_QUALIFICATION_SCHEMA,
    PhaseAQualificationBase,
    PhaseAQualificationGrant,
    PhaseAQualificationNonce,
)
from datax_studio.settings import Settings


@dataclass
class _RecordingOperations:
    dialect: object = field(default_factory=postgresql.dialect)
    created_tables: dict[str, tuple[object, ...]] = field(default_factory=dict)
    created_indexes: list[tuple[str, str, list[str], dict[str, object]]] = field(
        default_factory=list
    )
    executed: list[str] = field(default_factory=list)
    created_table_options: dict[str, dict[str, object]] = field(default_factory=dict)
    dropped_indexes: list[tuple[str, str, dict[str, object]]] = field(default_factory=list)
    dropped_tables: list[tuple[str, dict[str, object]]] = field(default_factory=list)

    def get_bind(self) -> _RecordingOperations:
        return self

    def create_table(
        self,
        table_name: str,
        *elements: object,
        **kwargs: object,
    ) -> None:
        self.created_tables[table_name] = elements
        self.created_table_options[table_name] = kwargs

    def create_index(
        self,
        name: str,
        table_name: str,
        columns: list[str],
        **kwargs: object,
    ) -> None:
        self.created_indexes.append((name, table_name, columns, kwargs))

    def execute(self, statement: str) -> None:
        self.executed.append(statement)

    def drop_index(self, name: str, *, table_name: str, **kwargs: object) -> None:
        self.dropped_indexes.append((name, table_name, kwargs))

    def drop_table(self, table_name: str, **kwargs: object) -> None:
        self.dropped_tables.append((table_name, kwargs))


def _migration_module() -> ModuleType:
    path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "20260802_0020_phase_a_qualification_persistence.py"
    )
    spec = importlib.util.spec_from_file_location(
        "phase_a_qualification_persistence_0020",
        path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _columns(elements: tuple[object, ...]) -> dict[str, Column[object]]:
    return {str(element.name): element for element in elements if isinstance(element, Column)}


def _constraint_names(elements: tuple[object, ...], kind: type[object]) -> set[str]:
    return {
        str(element.name)
        for element in elements
        if isinstance(element, kind) and element.name is not None
    }


def test_models_keep_raw_nonces_unrepresentable_and_grants_private() -> None:
    assert PhaseAQualificationNonce.__table__.metadata is PhaseAQualificationBase.metadata
    assert PhaseAQualificationGrant.__table__.metadata is PhaseAQualificationBase.metadata
    assert PhaseAQualificationNonce.__table__.metadata is not Base.metadata
    assert PhaseAQualificationNonce.__table__.schema == PHASE_A_QUALIFICATION_SCHEMA
    assert PhaseAQualificationGrant.__table__.schema == PHASE_A_QUALIFICATION_SCHEMA

    nonce_columns = set(PhaseAQualificationNonce.__table__.columns.keys())
    assert "nonce" not in nonce_columns
    assert "nonce_sha256" in nonce_columns
    assert {
        "issuer_key_id",
        "qualification_id",
        "payload_root_sha256",
        "valid_until",
        "consumed_at",
        "created_at",
    } <= nonce_columns

    nonce_unique = {
        tuple(constraint.columns.keys())
        for constraint in PhaseAQualificationNonce.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("issuer_key_id", "nonce_sha256") in nonce_unique
    assert ("issuer_key_id", "qualification_id") in nonce_unique

    grant_columns = set(PhaseAQualificationGrant.__table__.columns.keys())
    assert {
        "nonce_id",
        "payload_root_sha256",
        "payload_binding_sha256",
        "candidate_commit",
        "worker_image_digest",
        "runtime_sha256",
        "reader_plugin_name",
        "reader_plugin_sha256",
        "writer_plugin_name",
        "writer_plugin_sha256",
        "harness_identity",
        "harness_environment_id",
        "harness_environment_manifest_sha256",
        "harness_version",
        "qh_document_sha256",
        "qh_qualification_id",
        "qh_issuer_key_id",
        "qh_issued_at",
        "qh_not_before",
        "qh_valid_until",
        "state",
        "created_at",
        "revoked_at",
        "revocation_reason",
        "expired_at",
    } <= grant_columns
    assert "execution_id" not in grant_columns

    constraint_names = {
        constraint.name
        for constraint in PhaseAQualificationGrant.__table__.constraints
        if isinstance(constraint, CheckConstraint)
    }
    assert {
        "ck_phase_a_qualification_grants_lifecycle",
        "ck_phase_a_qualification_grants_qh_window",
        "ck_phase_a_qualification_grants_revoked_at",
        "ck_phase_a_qualification_grants_expired_at",
    } <= constraint_names


def test_0020_creates_durable_private_ledger_and_revokes_runtime_roles() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.upgrade()

    assert module.revision == "20260802_0020"
    assert module.down_revision == "20260802_0019"
    assert Settings().database_schema_revision == "20260802_0024"
    assert set(operations.created_tables) == {
        "phase_a_qualification_nonces",
        "phase_a_qualification_grants",
    }
    assert operations.created_table_options == {
        "phase_a_qualification_nonces": {"schema": PHASE_A_QUALIFICATION_SCHEMA},
        "phase_a_qualification_grants": {"schema": PHASE_A_QUALIFICATION_SCHEMA},
    }

    nonce_elements = operations.created_tables["phase_a_qualification_nonces"]
    nonce_columns = _columns(nonce_elements)
    assert "nonce" not in nonce_columns
    assert set(nonce_columns) == {
        "id",
        "issuer_key_id",
        "nonce_sha256",
        "qualification_id",
        "payload_root_sha256",
        "valid_until",
        "consumed_at",
        "created_at",
    }
    assert {
        "uq_phase_a_qualification_nonces_issuer_nonce",
        "uq_phase_a_qualification_nonces_issuer_qualification",
        "ck_phase_a_qualification_nonces_issuer",
        "ck_phase_a_qualification_nonces_qualification",
        "ck_phase_a_qualification_nonces_nonce_hash",
        "ck_phase_a_qualification_nonces_payload_root",
        "ck_phase_a_qualification_nonces_timestamps",
    } <= _constraint_names(nonce_elements, UniqueConstraint) | _constraint_names(
        nonce_elements,
        CheckConstraint,
    )

    grant_elements = operations.created_tables["phase_a_qualification_grants"]
    grant_columns = _columns(grant_elements)
    assert grant_columns["nonce_id"].nullable is False
    assert {
        "payload_binding_sha256",
        "qh_document_sha256",
        "reader_plugin_name",
        "writer_plugin_name",
        "expired_at",
    } <= set(grant_columns)
    checks = {
        str(element.name): str(element.sqltext)
        for element in grant_elements
        if isinstance(element, CheckConstraint)
    }
    assert {
        "ck_phase_a_qualification_grants_state",
        "ck_phase_a_qualification_grants_lifecycle",
        "ck_phase_a_qualification_grants_qh_window",
        "ck_phase_a_qualification_grants_revoked_at",
        "ck_phase_a_qualification_grants_expired_at",
        "ck_phase_a_qualification_grants_hashes",
        "ck_phase_a_qualification_grants_identity",
        "ck_phase_a_qualification_grants_runtime",
        "ck_phase_a_qualification_grants_plugins",
        "ck_phase_a_qualification_grants_harness",
        "ck_phase_a_qualification_grants_qh_identifiers",
    } <= set(checks)
    assert "INTERVAL '24 hours'" in checks["ck_phase_a_qualification_grants_qh_window"]
    assert "reader_plugin_name IN" in checks["ck_phase_a_qualification_grants_plugins"]

    indexes = {
        name: (table_name, columns, options)
        for name, table_name, columns, options in operations.created_indexes
    }
    assert "uq_phase_a_qualification_grants_execution" not in indexes

    rendered = "\n".join(operations.executed)
    for role in ("datax_api", "datax_worker"):
        assert (
            f"REVOKE ALL ON SCHEMA {PHASE_A_QUALIFICATION_SCHEMA} FROM {role}"
        ) in rendered
        assert (
            "REVOKE ALL PRIVILEGES ON TABLE "
            f"{PHASE_A_QUALIFICATION_SCHEMA}.phase_a_qualification_nonces FROM {role}"
        ) in rendered
        assert (
            "REVOKE ALL PRIVILEGES ON TABLE "
            f"{PHASE_A_QUALIFICATION_SCHEMA}.phase_a_qualification_grants FROM {role}"
        ) in rendered
    assert f"CREATE SCHEMA {PHASE_A_QUALIFICATION_SCHEMA}" in rendered
    assert "ALTER DEFAULT PRIVILEGES" in rendered
    assert "SET search_path = pg_catalog" in rendered
    assert (
        f"FROM {PHASE_A_QUALIFICATION_SCHEMA}.phase_a_qualification_nonces"
    ) in rendered
    assert (
        f"REVOKE ALL PRIVILEGES ON FUNCTION "
        f"{PHASE_A_QUALIFICATION_SCHEMA}.des_phase_a_qualification_grant_guard() FROM PUBLIC"
    ) in rendered
    assert "Phase-A QH nonce ledger is append-only" in rendered
    assert "Phase-A qualification bindings are immutable" in rendered
    assert "phase_a_qualification_grant_no_truncate" in rendered

    module.downgrade()

    assert operations.dropped_indexes == [
        (
            "ix_phase_a_qualification_grants_state_valid_until",
            "phase_a_qualification_grants",
            {"schema": PHASE_A_QUALIFICATION_SCHEMA},
        ),
        (
            "ix_phase_a_qualification_nonces_valid_until",
            "phase_a_qualification_nonces",
            {"schema": PHASE_A_QUALIFICATION_SCHEMA},
        ),
    ]
    assert operations.dropped_tables == [
        ("phase_a_qualification_grants", {"schema": PHASE_A_QUALIFICATION_SCHEMA}),
        ("phase_a_qualification_nonces", {"schema": PHASE_A_QUALIFICATION_SCHEMA}),
    ]
    assert f"DROP SCHEMA {PHASE_A_QUALIFICATION_SCHEMA}" in operations.executed


def test_0020_rejects_non_postgresql_migration_target() -> None:
    module = _migration_module()
    operations = _RecordingOperations(dialect=sqlite.dialect())
    module.op = operations

    with pytest.raises(RuntimeError, match="requires PostgreSQL"):
        module.upgrade()
