from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

from sqlalchemy import CheckConstraint, Column

from datax_studio.settings import Settings


@dataclass
class _RecordingOperations:
    created_tables: dict[str, tuple[object, ...]] = field(default_factory=dict)
    created_indexes: list[tuple[str, str, list[str], dict[str, object]]] = field(
        default_factory=list
    )
    dropped_indexes: list[str] = field(default_factory=list)
    dropped_tables: list[str] = field(default_factory=list)

    def create_table(self, table_name: str, *elements: object) -> None:
        assert table_name == "work_termination_requests"
        self.created_tables[table_name] = elements

    def create_index(
        self,
        name: str,
        table_name: str,
        columns: list[str],
        **kwargs: object,
    ) -> None:
        assert table_name == "work_termination_requests"
        self.created_indexes.append((name, table_name, columns, kwargs))

    def drop_index(self, name: str, *, table_name: str) -> None:
        assert table_name == "work_termination_requests"
        self.dropped_indexes.append(name)

    def drop_table(self, table_name: str) -> None:
        assert table_name == "work_termination_requests"
        self.dropped_tables.append(table_name)


def _migration_module() -> ModuleType:
    path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "20260802_0015_work_termination_requests.py"
    )
    spec = importlib.util.spec_from_file_location(
        "work_termination_requests_0015",
        path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0015_is_linear_and_settings_require_it() -> None:
    module = _migration_module()

    assert module.revision == "20260802_0015"
    assert module.down_revision == "20260731_0014"
    assert Settings().database_schema_revision == "20260802_0022"


def test_0015_creates_and_rolls_back_durable_termination_lifecycle() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.upgrade()

    elements = operations.created_tables["work_termination_requests"]
    columns = {
        str(element.name): element
        for element in elements
        if isinstance(element, Column)
    }
    assert set(columns) == {
        "id",
        "work_kind",
        "work_id",
        "credential_secret_id",
        "reason_code",
        "status",
        "requested_at",
        "acknowledged_at",
        "completed_at",
    }
    assert columns["credential_secret_id"].nullable is True
    checks = {
        str(element.name): str(element.sqltext)
        for element in elements
        if isinstance(element, CheckConstraint)
    }
    assert "SECRET_COMPROMISED" in checks["ck_work_termination_requests_reason"]
    assert "status = 'ACKNOWLEDGED'" in checks[
        "ck_work_termination_requests_lifecycle"
    ]
    assert "credential_secret_id IS NOT NULL" in checks[
        "ck_work_termination_requests_secret_reason"
    ]
    assert "work_kind = 'EXECUTION'" in checks[
        "ck_work_termination_requests_secret_reason"
    ]
    indexes = {
        name: (columns, options)
        for name, _table, columns, options in operations.created_indexes
    }
    assert indexes["uq_work_termination_requests_active_target"][0] == [
        "work_kind",
        "work_id",
        "reason_code",
    ]
    assert indexes["uq_work_termination_requests_active_target"][1]["unique"] is True
    assert indexes["uq_work_termination_requests_active_secret"][0] == [
        "work_kind",
        "work_id",
        "reason_code",
        "credential_secret_id",
    ]
    assert indexes["uq_work_termination_requests_active_secret"][1]["unique"] is True
    assert indexes["ix_work_termination_requests_pending"][0] == [
        "status",
        "requested_at",
        "id",
    ]

    module.downgrade()

    assert operations.dropped_indexes == [
        "ix_work_termination_requests_pending",
        "uq_work_termination_requests_active_secret",
        "uq_work_termination_requests_active_target",
    ]
    assert operations.dropped_tables == ["work_termination_requests"]
