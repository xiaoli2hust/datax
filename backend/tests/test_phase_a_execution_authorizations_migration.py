from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import Column, UniqueConstraint
from sqlalchemy.dialects import postgresql, sqlite

from datax_studio.auth.db import Base
from datax_studio.core.db import (
    PHASE_A_QUALIFICATION_SCHEMA,
    PhaseAExecutionAuthorization,
    PhaseAQualificationBase,
    PhaseAQualificationGrant,
)
from datax_studio.settings import Settings


@dataclass
class _RecordingOperations:
    dialect: object = field(default_factory=postgresql.dialect)
    added_columns: dict[str, Column[object]] = field(default_factory=dict)
    checks: dict[str, str] = field(default_factory=dict)
    created_tables: dict[str, tuple[object, ...]] = field(default_factory=dict)
    created_table_options: dict[str, dict[str, object]] = field(default_factory=dict)
    created_indexes: list[tuple[str, str, list[str], dict[str, object]]] = field(
        default_factory=list
    )
    executed: list[str] = field(default_factory=list)
    dropped_indexes: list[tuple[str, str, dict[str, object]]] = field(default_factory=list)
    dropped_tables: list[tuple[str, dict[str, object]]] = field(default_factory=list)
    dropped_constraints: list[tuple[str, str, str]] = field(default_factory=list)
    dropped_columns: list[tuple[str, str]] = field(default_factory=list)

    def get_bind(self) -> _RecordingOperations:
        return self

    def add_column(self, table_name: str, column: Column[object]) -> None:
        assert table_name == "executions"
        self.added_columns[str(column.name)] = column

    def create_check_constraint(self, name: str, table_name: str, condition: str) -> None:
        assert table_name == "executions"
        self.checks[name] = condition

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

    def drop_constraint(self, name: str, table_name: str, *, type_: str) -> None:
        self.dropped_constraints.append((name, table_name, type_))

    def drop_column(self, table_name: str, column_name: str) -> None:
        self.dropped_columns.append((table_name, column_name))


def _migration_module() -> ModuleType:
    path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "20260802_0022_phase_a_execution_authorizations.py"
    )
    spec = importlib.util.spec_from_file_location(
        "phase_a_execution_authorizations_0022",
        path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _columns(elements: tuple[object, ...]) -> dict[str, Column[object]]:
    return {str(element.name): element for element in elements if isinstance(element, Column)}


def test_models_keep_phase_a_execution_authorizations_private_and_one_to_one() -> None:
    assert PhaseAExecutionAuthorization.__table__.metadata is PhaseAQualificationBase.metadata
    assert PhaseAExecutionAuthorization.__table__.metadata is not Base.metadata
    assert PhaseAExecutionAuthorization.__table__.schema == PHASE_A_QUALIFICATION_SCHEMA
    assert "execution_id" not in PhaseAQualificationGrant.__table__.columns

    columns = set(PhaseAExecutionAuthorization.__table__.columns.keys())
    assert {
        "grant_id",
        "execution_id",
        "job_version_artifact_hash",
        "job_spec_hash",
        "source_datasource_config_hash",
        "target_datasource_config_hash",
        "source_endpoint_policy_hash",
        "target_endpoint_policy_hash",
        "source_server_identity_hash",
        "target_server_identity_hash",
        "transfer_policy_scope_hash",
        "transfer_policy_row_version",
        "payload_binding_sha256",
        "nonce_sha256",
        "qh_document_sha256",
        "created_at",
    } <= columns
    unique = {
        tuple(constraint.columns.keys())
        for constraint in PhaseAExecutionAuthorization.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("grant_id",) in unique
    assert ("execution_id",) in unique


def test_0022_creates_private_one_grant_one_execution_authorization_boundary() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.upgrade()

    assert module.revision == "20260802_0022"
    assert module.down_revision == "20260802_0021"
    assert Settings().database_schema_revision == "20260802_0024"
    assert "Phase-A execution authorization migration requires a PostgreSQL superuser" in "\n".join(
        operations.executed
    )
    assert operations.added_columns["authorization_mode"].nullable is False
    assert str(operations.added_columns["authorization_mode"].server_default.arg) == "STANDARD"
    assert operations.checks["ck_executions_authorization_mode"] == (
        "authorization_mode IN ('STANDARD','PHASE_A_HARNESS')"
    )

    table_name = "phase_a_execution_authorizations"
    assert set(operations.created_tables) == {table_name}
    assert operations.created_table_options[table_name] == {
        "schema": PHASE_A_QUALIFICATION_SCHEMA
    }
    columns = _columns(operations.created_tables[table_name])
    assert {
        "id",
        "grant_id",
        "execution_id",
        "project_id",
        "job_id",
        "job_version_id",
        "source_datasource_revision_id",
        "target_datasource_revision_id",
        "source_endpoint_policy_revision_id",
        "target_endpoint_policy_revision_id",
        "target_namespace_id",
        "transfer_policy_id",
        "nonce_sha256",
        "candidate_commit",
        "worker_image_digest",
        "qh_valid_until",
    } <= set(columns)
    assert columns["grant_id"].nullable is False
    rendered = "\n".join(operations.executed)
    assert (
        "ALTER TABLE des_phase_a_qualification.phase_a_execution_authorizations "
        "OWNER TO datax_phase_a_ledger_owner"
    ) in rendered
    assert "Phase-A execution authorizations are append-only" in rendered
    assert "CREATE TRIGGER executions_phase_a_authorization_mode_guard" in rendered
    assert "execution authorization mode is immutable" in rendered
    assert "standard runtime roles cannot mutate a Phase-A execution" in rendered
    assert "PHASE_A_AUTHORIZATION_PENDING" in rendered
    assert "PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED" in rendered
    assert "JOIN des_phase_a_qualification.phase_a_qualification_nonces AS nonce_row" in rendered
    assert "nonce_row.nonce_sha256 = authorization_row.nonce_sha256" in rendered
    assert "grant_row.nonce_sha256" not in rendered
    assert "authorization_mode = 'PHASE_A_HARNESS'" in rendered
    assert "Execution.authorization_mode" not in rendered
    assert "GRANT SELECT ON TABLE public.executions TO datax_phase_a_ledger_owner" in rendered
    assert (
        "GRANT UPDATE (queue_eligibility_state, queue_block_reason, "
        "queue_state_changed_at, state_version) ON TABLE public.executions "
        "TO datax_phase_a_ledger_owner"
    ) in rendered
    assert "ALTER TABLE public.executions ENABLE ROW LEVEL SECURITY" in rendered
    assert "CREATE POLICY phase_a_ledger_execution_authorization" in rendered
    for table in (
        "executions",
        "execution_attempts",
        "target_copy_locks",
        "execution_events",
        "execution_cancel_requests",
        "execution_log_chunks",
        "execution_log_gaps",
        "recovery_gates",
        "recovery_probes",
        "recovery_probe_attempts",
        "endpoint_connection_evidences",
        "work_termination_requests",
    ):
        assert f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY" in rendered
        assert f"CREATE POLICY phase_a_standard_runtime_{table}" in rendered
    assert "CREATE FUNCTION des_phase_a_qualification.des_authorize_phase_a_execution" in rendered
    assert (
        "CREATE FUNCTION des_phase_a_qualification."
        "des_read_active_phase_a_execution_authorization"
    ) in rendered
    assert rendered.count("SECURITY DEFINER") == 3
    assert rendered.count("SET search_path = pg_catalog, pg_temp") == 2
    assert "IF session_user <> 'datax_phase_a_issuer'" in rendered
    assert "IF session_user <> 'datax_phase_a_consumer'" in rendered
    assert "FOR UPDATE OF authorization_row, grant_row, execution_row" in rendered
    assert (
        "GRANT EXECUTE ON FUNCTION des_phase_a_qualification."
        "des_authorize_phase_a_execution"
    ) in rendered
    assert (
        "GRANT EXECUTE ON FUNCTION des_phase_a_qualification."
        "des_read_active_phase_a_execution_authorization"
    ) in rendered
    for runtime_role in ("datax_api", "datax_worker", "datax_egress_guard"):
        assert (
            "GRANT EXECUTE ON FUNCTION des_phase_a_qualification."
            f"des_authorize_phase_a_execution(uuid, uuid, uuid) TO {runtime_role}"
        ) not in rendered
        assert (
            "GRANT EXECUTE ON FUNCTION des_phase_a_qualification."
            f"des_read_active_phase_a_execution_authorization(uuid) TO {runtime_role}"
        ) not in rendered

    indexes = {
        name: (table, columns, options)
        for name, table, columns, options in operations.created_indexes
    }
    assert indexes["ix_executions_authorization_queue"] == (
        "executions",
        ["authorization_mode", "process_state", "queue_eligibility_state", "queued_at", "id"],
        {},
    )
    assert indexes["ix_phase_a_execution_authorizations_execution_created"] == (
        table_name,
        ["execution_id", "created_at"],
        {"schema": PHASE_A_QUALIFICATION_SCHEMA},
    )

    module.downgrade()
    assert (
        "DROP TRIGGER IF EXISTS executions_phase_a_authorization_mode_guard "
        "ON public.executions"
    ) in "\n".join(operations.executed)
    assert (
        "DROP POLICY IF EXISTS phase_a_ledger_execution_authorization "
        "ON public.executions"
    ) in "\n".join(operations.executed)
    assert "ALTER TABLE public.executions DISABLE ROW LEVEL SECURITY" in "\n".join(
        operations.executed
    )
    assert (
        "phase_a_execution_authorizations",
        {"schema": PHASE_A_QUALIFICATION_SCHEMA},
    ) in operations.dropped_tables
    assert ("ix_executions_authorization_queue", "executions", {}) in operations.dropped_indexes
    assert (
        "ck_executions_authorization_mode",
        "executions",
        "check",
    ) in operations.dropped_constraints
    assert ("executions", "authorization_mode") in operations.dropped_columns


def test_0022_rejects_non_postgresql_migration_target() -> None:
    module = _migration_module()
    operations = _RecordingOperations(dialect=sqlite.dialect())
    module.op = operations

    with pytest.raises(RuntimeError, match="require PostgreSQL"):
        module.upgrade()
