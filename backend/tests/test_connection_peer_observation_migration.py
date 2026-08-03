from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

from sqlalchemy import Column

from datax_studio.settings import Settings


@dataclass
class _RecordingOperations:
    added_columns: dict[str, Column] = field(default_factory=dict)
    altered_columns: list[tuple[str, str, dict[str, object]]] = field(
        default_factory=list
    )
    checks: dict[str, str] = field(default_factory=dict)
    executed: list[str] = field(default_factory=list)
    dropped_constraints: list[str] = field(default_factory=list)
    dropped_columns: list[str] = field(default_factory=list)

    def add_column(self, table_name: str, column: Column) -> None:
        assert table_name == "endpoint_connection_evidences"
        self.added_columns[str(column.name)] = column

    def alter_column(
        self,
        table_name: str,
        column_name: str,
        **kwargs: object,
    ) -> None:
        assert table_name == "endpoint_connection_evidences"
        self.altered_columns.append((table_name, column_name, kwargs))

    def create_check_constraint(
        self,
        name: str,
        table_name: str,
        condition: str,
    ) -> None:
        assert table_name == "endpoint_connection_evidences"
        self.checks[name] = condition

    def execute(self, statement: str) -> None:
        self.executed.append(statement)

    def drop_constraint(
        self,
        name: str,
        table_name: str,
        *,
        type_: str,
    ) -> None:
        assert table_name == "endpoint_connection_evidences"
        assert type_ == "check"
        self.dropped_constraints.append(name)

    def drop_column(self, table_name: str, column_name: str) -> None:
        assert table_name == "endpoint_connection_evidences"
        self.dropped_columns.append(column_name)


def _migration_module() -> ModuleType:
    path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "20260731_0012_connection_peer_observation.py"
    )
    spec = importlib.util.spec_from_file_location(
        "connection_peer_observation_0012",
        path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0012_distinguishes_observed_peer_from_enforced_destination() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.upgrade()

    assert module.revision == "20260731_0012"
    assert module.down_revision == "20260730_0011"
    status = operations.added_columns["peer_observation_status"]
    assert status.nullable is False
    check = operations.checks[
        "ck_endpoint_connection_evidence_peer_observation"
    ]
    assert "peer_observation_status = 'OBSERVED' AND peer_ip IS NOT NULL" in check
    assert "operation_kind = 'DATAX'" in check
    assert "peer_observation_status = 'ENFORCED_NOT_OBSERVED'" in check
    assert "peer_ip IS NULL" in check
    assert any(
        column == "peer_ip" and options["nullable"] is True
        for _table, column, options in operations.altered_columns
    )
    assert Settings().database_schema_revision == "20260802_0024"


def test_0012_downgrade_refuses_to_fabricate_missing_peer() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.downgrade()

    assert any(
        "cannot downgrade while unobserved DataX peer evidence exists" in statement
        for statement in operations.executed
    )
    assert operations.dropped_columns == ["peer_observation_status"]
