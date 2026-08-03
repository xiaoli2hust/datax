from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

from sqlalchemy import Column
from sqlalchemy.dialects import postgresql

from datax_studio.settings import Settings


@dataclass
class _RecordingOperations:
    dialect: object = field(default_factory=postgresql.dialect)
    created_tables: dict[str, tuple[object, ...]] = field(default_factory=dict)
    created_table_options: dict[str, dict[str, object]] = field(default_factory=dict)
    created_indexes: list[tuple[str, str, list[str], dict[str, object]]] = field(
        default_factory=list
    )
    executed: list[str] = field(default_factory=list)
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
        / "20260802_0024_phase_a_private_creation.py"
    )
    spec = importlib.util.spec_from_file_location("phase_a_private_creation_0024", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _columns(elements: tuple[object, ...]) -> dict[str, Column[object]]:
    return {str(element.name): element for element in elements if isinstance(element, Column)}


def test_0024_creates_only_an_atomic_private_lifecycle_boundary() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.upgrade()

    rendered = "\n".join(operations.executed)
    assert module.revision == "20260802_0024"
    assert module.down_revision == "20260802_0023"
    assert Settings().database_schema_revision == "20260802_0024"
    assert "Phase-A private creation migration requires superuser" in rendered

    table_name = "phase_a_execution_create_checkpoints"
    assert set(operations.created_tables) == {table_name}
    assert operations.created_table_options[table_name] == {"schema": "des_phase_a_qualification"}
    columns = _columns(operations.created_tables[table_name])
    assert {
        "execution_id",
        "authorization_id",
        "grant_id",
        "lock_id",
        "job_id",
        "job_version_id",
        "target_namespace_id",
        "checkpoint",
        "state",
        "lock_state",
        "occurred_at",
    } <= set(columns)
    assert columns["authorization_id"].nullable is True
    assert columns["grant_id"].nullable is True
    assert columns["lock_id"].nullable is True

    assert (
        "CREATE FUNCTION des_phase_a_qualification."
        "des_create_authorize_reserve_phase_a_execution" in rendered
    )
    assert "SECURITY DEFINER" in rendered
    assert "SET search_path = pg_catalog, pg_temp" in rendered
    assert "IF session_user <> 'datax_phase_a_issuer'" in rendered
    assert "SELECT draining" in rendered
    assert "FROM public.system_control" in rendered
    assert "FOR UPDATE" in rendered
    assert "GRANT UPDATE (singleton_id) ON TABLE public.system_control" in rendered
    assert "PHASE_A_AUTHORIZATION_PENDING" in rendered
    assert "PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED" in rendered
    assert "INSERT INTO public.target_copy_locks" in rendered
    assert "authorization_mode = 'PHASE_A_HARNESS'" in rendered
    assert "checkpoint_row.checkpoint = 'LOCK_RESERVED'" in rendered
    assert "target_lock.state::text" in rendered
    assert "CREATE ROLE" not in rendered

    # The only callable authority is the issuer's one fixed-function grant.
    # API/Worker/egress roles remain explicitly revoked and receive no direct
    # DML path to private executions or global target locks.
    for role in (
        "datax_api",
        "datax_worker",
        "datax_egress_guard",
        "datax_phase_a_consumer",
        "datax_phase_a_runner",
    ):
        assert f"REVOKE ALL PRIVILEGES ON TABLE {module._CHECKPOINT_TABLE} FROM {role}" in rendered
        assert (
            "GRANT EXECUTE ON FUNCTION "
            f"{module._CREATE_FUNCTION}({module._CREATE_SIGNATURE}) TO {role}"
        ) not in rendered
    assert (
        f"GRANT EXECUTE ON FUNCTION {module._CREATE_FUNCTION}({module._CREATE_SIGNATURE}) "
        "TO datax_phase_a_issuer"
    ) in rendered
    assert "GRANT INSERT (id, project_id, job_id, job_version_id" in rendered
    assert "GRANT INSERT ON TABLE public.executions TO datax_phase_a_issuer" not in rendered
    assert "GRANT INSERT ON TABLE public.target_copy_locks TO datax_phase_a_issuer" not in rendered

    # This slice is a database-only lifecycle foundation: it cannot become a
    # runner or ordinary desktop control path through a migration side effect.
    assert "Popen" not in rendered
    assert "DataX" not in rendered
    assert "CREATE EXTENSION" not in rendered


def test_0024_downgrade_removes_the_private_entrypoint_and_minimal_grants() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.downgrade()

    rendered = "\n".join(operations.executed)
    assert "LOCK TABLE" in rendered
    assert "public.executions" in rendered
    assert "public.execution_attempts" in rendered
    assert "public.target_copy_locks" in rendered
    assert "IN ACCESS EXCLUSIVE MODE" in rendered
    assert "Phase-A protected execution state blocks lifecycle downgrade" in rendered
    assert (
        f"DROP FUNCTION IF EXISTS {module._CREATE_FUNCTION}({module._CREATE_SIGNATURE})" in rendered
    )
    assert (
        "DROP FUNCTION IF EXISTS des_phase_a_qualification."
        "des_phase_a_execution_create_checkpoint_guard()"
    ) in rendered
    assert operations.dropped_tables == [
        ("phase_a_execution_create_checkpoints", {"schema": "des_phase_a_qualification"})
    ]
    assert "REVOKE INSERT (id, project_id, job_id, job_version_id" in rendered
    assert "REVOKE UPDATE (singleton_id) ON TABLE public.system_control" in rendered
