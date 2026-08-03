from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy.dialects import postgresql, sqlite


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
        / "20260802_0021_phase_a_ledger_roles.py"
    )
    spec = importlib.util.spec_from_file_location("phase_a_ledger_roles_0021", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0021_protects_phase_a_ledger_with_no_login_roles_and_exact_functions() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.upgrade()

    assert module.revision == "20260802_0021"
    assert module.down_revision == "20260802_0020"
    rendered = "\n".join(operations.executed)
    assert "Phase-A ledger migration requires a PostgreSQL superuser" in rendered
    assert "Phase-A private ledger roles must not pre-exist" in rendered
    assert "Phase-A private ledger role membership is not allowed" in rendered
    assert "GRANT datax_phase_a_ledger_owner" not in rendered
    assert "GRANT datax_phase_a_issuer TO datax_phase_a_ledger_owner" not in rendered
    assert "GRANT datax_phase_a_consumer TO datax_phase_a_ledger_owner" not in rendered
    assert "DES_PHASE_A_" not in rendered

    for role in (
        "datax_phase_a_ledger_owner",
        "datax_phase_a_issuer",
        "datax_phase_a_consumer",
    ):
        assert f"CREATE ROLE {role}" in rendered
        assert f"ALTER ROLE {role}" not in rendered
    for hardening in (
        "NOLOGIN",
        "NOSUPERUSER",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOINHERIT",
        "NOREPLICATION",
        "NOBYPASSRLS",
        "CONNECTION LIMIT 1",
    ):
        assert rendered.count(hardening) == 3

    private_schema = "des_phase_a_qualification"
    assert f"ALTER SCHEMA {private_schema} OWNER TO datax_phase_a_ledger_owner" in rendered
    assert (
        "ALTER DEFAULT PRIVILEGES FOR ROLE datax_phase_a_ledger_owner "
        "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
    ) in rendered
    for table in (
        "phase_a_qualification_nonces",
        "phase_a_qualification_grants",
    ):
        assert (
            f"ALTER TABLE {private_schema}.{table} OWNER TO datax_phase_a_ledger_owner"
            in rendered
        )

    denied_roles = (
        "PUBLIC",
        "datax_api",
        "datax_worker",
        "datax_egress_guard",
        "datax_phase_a_issuer",
        "datax_phase_a_consumer",
    )
    for role in denied_roles:
        assert f"REVOKE ALL ON SCHEMA {private_schema} FROM {role}" in rendered
        assert (
            f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA {private_schema} FROM {role}"
            in rendered
        )
        assert (
            f"REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA {private_schema} FROM {role}"
            in rendered
        )

    issue = f"{private_schema}.des_issue_phase_a_qualification_grant"
    revoke = f"{private_schema}.des_revoke_phase_a_qualification_grant"
    read = f"{private_schema}.des_read_active_phase_a_qualification_grant"
    assert rendered.count("SECURITY DEFINER") == 3
    assert rendered.count("SET search_path = pg_catalog, pg_temp") == 3
    assert "IF session_user <> 'datax_phase_a_issuer'" in rendered
    assert "IF session_user <> 'datax_phase_a_consumer'" in rendered
    assert "FOR UPDATE OF grant_row" in rendered
    for varchar_column in (
        "nonce_row.nonce_sha256",
        "grant_row.payload_binding_sha256",
        "grant_row.payload_root_sha256",
        "grant_row.candidate_commit",
        "grant_row.worker_image_digest",
        "grant_row.datax_release",
        "grant_row.runtime_sha256",
        "grant_row.reader_plugin_name",
        "grant_row.reader_plugin_sha256",
        "grant_row.writer_plugin_name",
        "grant_row.writer_plugin_sha256",
        "grant_row.harness_identity",
        "grant_row.harness_environment_id",
        "grant_row.harness_environment_manifest_sha256",
        "grant_row.harness_version",
        "grant_row.qh_document_sha256",
        "grant_row.qh_qualification_id",
        "grant_row.qh_issuer_key_id",
    ):
        assert f"{varchar_column}::text" in rendered
    assert "Phase-A QH nonce was already consumed" in rendered
    assert "ON CONFLICT DO NOTHING" in rendered
    assert "p_nonce_sha256" in rendered
    assert "p_nonce text" not in rendered
    for function in (issue, revoke, read):
        assert f"CREATE FUNCTION {function}" in rendered
        assert f"ALTER FUNCTION {function}" in rendered
    assert f"GRANT USAGE ON SCHEMA {private_schema} TO datax_phase_a_issuer" in rendered
    assert f"GRANT USAGE ON SCHEMA {private_schema} TO datax_phase_a_consumer" in rendered
    assert f"GRANT EXECUTE ON FUNCTION {issue}" in rendered
    assert f"GRANT EXECUTE ON FUNCTION {revoke}" in rendered
    assert f"GRANT EXECUTE ON FUNCTION {read}" in rendered

    module.downgrade()
    rendered_after_downgrade = "\n".join(operations.executed)
    for function in (issue, revoke, read):
        assert f"DROP FUNCTION IF EXISTS {function}" in rendered_after_downgrade
    for role in (
        "datax_phase_a_issuer",
        "datax_phase_a_consumer",
        "datax_phase_a_ledger_owner",
    ):
        assert f"DROP ROLE {role}" in rendered_after_downgrade
    assert "DROP OWNED BY datax_phase_a_ledger_owner" in rendered_after_downgrade


def test_0021_rejects_non_postgresql_migration_target() -> None:
    module = _migration_module()
    operations = _RecordingOperations(dialect=sqlite.dialect())
    module.op = operations

    with pytest.raises(RuntimeError, match="require PostgreSQL"):
        module.upgrade()
