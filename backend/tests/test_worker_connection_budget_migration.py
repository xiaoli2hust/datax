from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from sqlalchemy.dialects import postgresql


class _Bind:
    dialect = postgresql.dialect()


class _Operations:
    def __init__(self) -> None:
        self.executed: list[str] = []

    def get_bind(self) -> _Bind:
        return _Bind()

    def execute(self, statement: str) -> None:
        self.executed.append(statement)


def _migration_module() -> ModuleType:
    path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "20260802_0016_worker_connection_budget.py"
    )
    spec = importlib.util.spec_from_file_location("worker_connection_budget_0016", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0016_migrates_only_the_worker_connection_budget() -> None:
    module = _migration_module()
    operations = _Operations()
    module.op = operations

    module.upgrade()
    module.downgrade()

    assert module.revision == "20260802_0016"
    assert module.down_revision == "20260802_0015"
    assert operations.executed == [
        "ALTER ROLE datax_worker CONNECTION LIMIT 12",
        "ALTER ROLE datax_worker CONNECTION LIMIT 8",
    ]
