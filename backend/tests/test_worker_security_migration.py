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
    checks: dict[str, str] = field(default_factory=dict)
    executed: list[str] = field(default_factory=list)
    dropped_constraints: list[str] = field(default_factory=list)
    altered_columns: list[str] = field(default_factory=list)

    def add_column(self, table_name: str, column: Column) -> None:
        assert table_name == "worker_heartbeats"
        self.added_columns[str(column.name)] = column

    def create_check_constraint(
        self,
        name: str,
        table_name: str,
        condition: str,
    ) -> None:
        assert table_name == "worker_heartbeats"
        self.checks[name] = condition

    def drop_constraint(
        self,
        name: str,
        table_name: str,
        *,
        type_: str,
    ) -> None:
        assert table_name == "worker_heartbeats"
        assert type_ == "check"
        self.dropped_constraints.append(name)

    def execute(self, statement: str) -> None:
        self.executed.append(statement)

    def alter_column(
        self,
        table_name: str,
        column_name: str,
        **kwargs: object,
    ) -> None:
        assert table_name == "worker_heartbeats"
        assert kwargs == {"server_default": None}
        self.altered_columns.append(column_name)


def _migration_module() -> ModuleType:
    path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "20260730_0011_worker_security_attestations.py"
    )
    spec = importlib.util.spec_from_file_location(
        "worker_security_attestations_0011",
        path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0011_requires_storage_and_egress_facts_for_ready_heartbeat() -> None:
    module = _migration_module()
    operations = _RecordingOperations()
    module.op = operations

    module.upgrade()

    assert module.revision == "20260730_0011"
    assert module.down_revision == "20260730_0010"
    assert set(operations.added_columns) == {
        "storage_code",
        "log_mount_identity_hash",
        "workspace_mount_identity_hash",
        "log_free_bytes",
        "workspace_free_bytes",
        "storage_checked_at",
        "egress_policy_set_hash",
        "egress_ruleset_hash",
        "egress_evidence_hash",
        "egress_checked_at",
    }
    assert operations.added_columns["storage_code"].nullable is False
    assert "BLOCKED_STORAGE" in operations.checks[
        "ck_worker_heartbeats_status"
    ]
    ready = operations.checks["ck_worker_heartbeats_ready_attested"]
    for required_fact in (
        "storage_code = 'STORAGE_OK'",
        "log_mount_identity_hash IS NOT NULL",
        "workspace_mount_identity_hash IS NOT NULL",
        "log_mount_identity_hash <> workspace_mount_identity_hash",
        "log_free_bytes IS NOT NULL",
        "workspace_free_bytes IS NOT NULL",
        "storage_checked_at >= checked_at - INTERVAL '30 seconds'",
        "egress_policy_set_hash IS NOT NULL",
        "egress_ruleset_hash IS NOT NULL",
        "egress_evidence_hash IS NOT NULL",
        "egress_checked_at >= checked_at - INTERVAL '30 seconds'",
    ):
        assert required_fact in ready
    assert any(
        "SET status = 'BLOCKED_STORAGE'" in statement
        for statement in operations.executed
    )
    assert operations.altered_columns == ["storage_code"]
    assert Settings().database_schema_revision == "20260802_0015"
