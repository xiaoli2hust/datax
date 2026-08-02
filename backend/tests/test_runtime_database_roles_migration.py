from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy.dialects import postgresql

from datax_studio.settings import Settings


class _ScalarResult:
    def __init__(self, value: str) -> None:
        self._value = value

    def scalar_one(self) -> str:
        return self._value


class _RecordingBind:
    def __init__(self) -> None:
        self.dialect = postgresql.dialect()

    def execute(self, statement: object) -> _ScalarResult:
        rendered = str(statement)
        if "current_database" in rendered:
            return _ScalarResult("datax_studio")
        if "current_user" in rendered:
            return _ScalarResult("datax_studio")
        raise AssertionError(f"unexpected statement: {rendered}")


class _RecordingOperations:
    def __init__(self) -> None:
        self.bind = _RecordingBind()
        self.executed: list[str] = []

    def get_bind(self) -> _RecordingBind:
        return self.bind

    def execute(self, statement: str) -> None:
        self.executed.append(statement)


def _migration_module() -> ModuleType:
    path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "20260731_0013_runtime_database_roles.py"
    )
    spec = importlib.util.spec_from_file_location(
        "runtime_database_roles_0013",
        path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _secret(path: Path, character: str) -> Path:
    path.write_text(character * 64, encoding="ascii")
    return path


def _configure_secret_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = {
        "DES_DATABASE_PASSWORD_FILE": "1",
        "DES_EGRESS_GUARD_DATABASE_PASSWORD_FILE": "2",
        "DES_API_DATABASE_PASSWORD_FILE": "3",
        "DES_WORKER_DATABASE_PASSWORD_FILE": "4",
    }
    for environment_name, character in values.items():
        monkeypatch.setenv(
            environment_name,
            str(_secret(tmp_path / environment_name.lower(), character)),
        )


def test_0013_creates_separate_non_ddl_runtime_roles(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _migration_module()
    _configure_secret_environment(monkeypatch, tmp_path)
    operations = _RecordingOperations()
    module.op = operations

    module.upgrade()

    rendered = "\n".join(operations.executed)
    assert module.revision == "20260731_0013"
    assert module.down_revision == "20260731_0012"
    assert "REVOKE CREATE ON SCHEMA public FROM PUBLIC" in rendered
    assert (
        "REVOKE CONNECT, TEMPORARY ON DATABASE datax_studio FROM PUBLIC"
        in rendered
    )
    for role in ("datax_api", "datax_worker"):
        assert f"CREATE ROLE {role}" in rendered
        assert f"ALTER ROLE {role}" in rendered
        assert f"GRANT CONNECT ON DATABASE datax_studio TO {role}" in rendered
        assert f"GRANT USAGE ON SCHEMA public TO {role}" in rendered
        assert (
            "GRANT SELECT, INSERT, UPDATE, DELETE "
            f"ON ALL TABLES IN SCHEMA public TO {role}"
        ) in rendered
        assert f"GRANT CREATE ON SCHEMA public TO {role}" not in rendered
    for restriction in (
        "NOSUPERUSER",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOINHERIT",
        "NOREPLICATION",
    ):
        assert rendered.count(restriction) == 4
    assert Settings().database_schema_revision == "20260802_0021"


def test_0013_rejects_reused_database_passwords(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _migration_module()
    _configure_secret_environment(monkeypatch, tmp_path)
    reused = _secret(tmp_path / "reused", "3")
    monkeypatch.setenv("DES_WORKER_DATABASE_PASSWORD_FILE", str(reused))

    with pytest.raises(RuntimeError, match="must all be independent"):
        module._runtime_passwords()


def test_0013_rejects_noncanonical_secret_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _migration_module()
    _configure_secret_environment(monkeypatch, tmp_path)
    invalid = tmp_path / "invalid"
    invalid.write_text("A" * 64, encoding="ascii")
    monkeypatch.setenv("DES_API_DATABASE_PASSWORD_FILE", str(invalid))

    with pytest.raises(RuntimeError, match="lowercase hex"):
        module._runtime_passwords()
