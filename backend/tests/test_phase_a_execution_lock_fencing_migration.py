from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

from sqlalchemy.dialects import postgresql

from datax_studio.settings import Settings


@dataclass
class _RecordingOperations:
    dialect: object = field(default_factory=postgresql.dialect)
    executed: list[str] = field(default_factory=list)

    def get_bind(self) -> _RecordingOperations:
        return self

    def execute(self, statement: str) -> None:
        self.executed.append(statement)


def _migration_module() -> ModuleType:
    path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "20260802_0023_phase_a_execution_lock_fencing.py"
    )
    spec = importlib.util.spec_from_file_location(
        "phase_a_execution_lock_fencing_0023",
        path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0023_reuses_global_target_lock_for_private_fencing() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.upgrade()

    rendered = "\n".join(operations.executed)
    assert module.revision == "20260802_0023"
    assert module.down_revision == "20260802_0022"
    assert Settings().database_schema_revision == "20260802_0023"
    assert "Phase-A execution lock migration requires a PostgreSQL superuser" in rendered
    assert "Phase-A private runner role must not pre-exist" in rendered
    assert "Phase-A private runner role membership is not allowed" in rendered
    assert "CREATE ROLE datax_phase_a_runner" in rendered
    for restriction in (
        "NOLOGIN",
        "NOSUPERUSER",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOINHERIT",
        "NOREPLICATION",
        "NOBYPASSRLS",
        "CONNECTION LIMIT 1",
    ):
        assert restriction in rendered

    # The existing public TargetCopyLock partial unique namespace invariant is
    # intentionally reused.  A parallel private table would split STANDARD
    # from PHASE_A_HARNESS and permit concurrent writes to one target.
    assert "CREATE TABLE phase_a_execution_locks" not in rendered
    assert "CREATE TABLE des_phase_a_qualification.phase_a_execution_locks" not in rendered
    assert "public.target_copy_locks" in rendered
    assert "public.execution_attempts" in rendered
    assert "phase_a_ledger_private_target_copy_locks" in rendered
    assert "phase_a_ledger_private_execution_attempts" in rendered
    assert "authorization_mode = 'PHASE_A_HARNESS'" in rendered
    assert "RECOVERY_REQUIRED" in rendered
    assert "fence_epoch = v_next_fence" in rendered
    assert "v_execution.fence_epoch + 1" in rendered

    for function in (
        "des_reserve_phase_a_execution_lock",
        "des_claim_phase_a_execution_lock",
        "des_heartbeat_phase_a_execution_lock",
        "des_require_phase_a_execution_recovery",
        "des_release_phase_a_execution_lock",
        "des_read_phase_a_execution_lock",
    ):
        assert f"CREATE FUNCTION des_phase_a_qualification.{function}" in rendered
    assert rendered.count("SECURITY DEFINER") == 6
    assert rendered.count("SET search_path = pg_catalog, pg_temp") == 6
    assert "IF session_user <> 'datax_phase_a_runner'" in rendered
    assert "PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED" in rendered
    assert "Phase-A execution authorization is not active" in rendered

    # No standard runtime role receives schema/table/function access.  Only a
    # NOLOGIN runner gets the exact private function entrypoints.
    for role in ("datax_api", "datax_worker", "datax_egress_guard"):
        assert (
            "REVOKE ALL ON SCHEMA des_phase_a_qualification "
            f"FROM {role}"
        ) in rendered
        assert (
            "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA "
            f"des_phase_a_qualification FROM {role}"
        ) in rendered
        assert (
            "GRANT EXECUTE ON FUNCTION des_phase_a_qualification."
            f"des_claim_phase_a_execution_lock({module._CLAIM_SIGNATURE}) TO {role}"
        ) not in rendered
    assert "GRANT USAGE ON SCHEMA des_phase_a_qualification TO datax_phase_a_runner" in rendered
    assert (
        "GRANT EXECUTE ON FUNCTION des_phase_a_qualification."
        "des_claim_phase_a_execution_lock(uuid, uuid, text, text, text, text, integer) "
        "TO datax_phase_a_runner"
    ) in rendered


def test_0023_downgrade_removes_runner_only_function_and_rls_grants() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.downgrade()

    rendered = "\n".join(operations.executed)
    assert (
        "DROP FUNCTION IF EXISTS des_phase_a_qualification."
        "des_read_phase_a_execution_lock(uuid)"
    ) in rendered
    assert (
        "DROP FUNCTION IF EXISTS des_phase_a_qualification."
        "des_reserve_phase_a_execution_lock(uuid, uuid)"
    ) in rendered
    assert "DROP POLICY IF EXISTS phase_a_ledger_private_target_copy_locks" in rendered
    assert "DROP POLICY IF EXISTS phase_a_ledger_private_execution_attempts" in rendered
    assert "DROP OWNED BY datax_phase_a_runner" in rendered
    assert "DROP ROLE datax_phase_a_runner" in rendered
