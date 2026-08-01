from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Any
from uuid import uuid4

import pytest

from datax_studio.core.schemas import JobSpecV1
from datax_studio.schema_snapshot import SchemaSnapshot, schema_snapshot_hash
from datax_studio.worker.schema_probe import (
    SchemaProbeError,
    TableIdentity,
    assert_snapshot_matches_job,
    logical_type_for_native,
    physical_table_identity_hash,
    probe_schema_snapshot,
)


class _ScriptedCursor:
    def __init__(self, responses: list[object], trace: list[str]) -> None:
        self._responses = responses
        self._trace = trace

    def execute(self, _query: str, _parameters: object = ()) -> None:
        self._trace.append("execute")

    def fetchone(self) -> tuple[Any, ...] | None:
        self._trace.append("fetchone")
        result = self._responses.pop(0)
        assert result is None or isinstance(result, tuple)
        return result

    def fetchall(self) -> list[tuple[Any, ...]]:
        self._trace.append("fetchall")
        result = self._responses.pop(0)
        assert isinstance(result, list)
        return result

    def __enter__(self) -> _ScriptedCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _ScriptedConnection:
    def __init__(self, responses: list[object], trace: list[str]) -> None:
        self.cursor_instance = _ScriptedCursor(responses, trace)

    def cursor(self, *_args: object, **_kwargs: object) -> _ScriptedCursor:
        return self.cursor_instance


def _identity(*, engine: str) -> TableIdentity:
    return TableIdentity(
        physical_endpoint_identity_id=uuid4(),
        physical_table_identity_hash="b" * 64,
        catalog_name="warehouse",
        schema_name="public" if engine == "POSTGRESQL_15" else "",
        table_name="orders",
    )


def _mysql_probe_responses() -> list[object]:
    return [
        (0,),
        ("BASE TABLE",),
        [
            (
                1,
                "id",
                "bigint",
                "NO",
                "",
                None,
                64,
                0,
                None,
                None,
                None,
                None,
                "",
            )
        ],
        [],
        [],
        (0,),
    ]


def _postgres_probe_responses() -> list[object]:
    return [
        (42, "r", False),
        [(1, "id", "bigint", False, "", "", None, 64, 0, None, None, None)],
        [(100, "f", [1], 99, True, "FOREIGN KEY (id) REFERENCES parents(id)")],
        [],
        [(99, "public", "parents")],
    ]


def _snapshot() -> SchemaSnapshot:
    return SchemaSnapshot.model_validate(
        {
            "schema_version": "1.0",
            "normalization_version": "1.0",
            "engine": "POSTGRESQL_15",
            "physical_endpoint_identity_id": str(uuid4()),
            "physical_table_identity_hash": "a" * 64,
            "identifier_case_mode": "POSTGRESQL_FOLDED_OR_QUOTED",
            "catalog_name": "warehouse",
            "schema_name": "public",
            "table_name": "orders",
            "table_kind": "BASE_TABLE",
            "columns": [
                {
                    "ordinal_position": 1,
                    "name": "id",
                    "native_type": "bigint",
                    "logical_type": "INTEGER",
                    "nullable": False,
                    "unsigned": False,
                    "generated": False,
                    "identity": False,
                    "character_maximum_length": None,
                    "numeric_precision": 64,
                    "numeric_scale": 0,
                    "datetime_precision": None,
                    "character_set_name": None,
                    "collation_name": None,
                    "default_present": False,
                    "default_expression_sha256": None,
                }
            ],
            "constraints": [],
            "triggers": [],
            "table_options": {
                "partitioned": False,
                "row_security_enabled": False,
            },
        }
    )


def _spec() -> JobSpecV1:
    return JobSpecV1.model_validate(
        {
            "schema_version": "1.0",
            "source": {
                "datasource_id": str(uuid4()),
                "datasource_revision_id": str(uuid4()),
                "plugin_name": "postgresqlreader",
                "table": {"schema_name": "public", "table_name": "source"},
            },
            "target": {
                "datasource_id": str(uuid4()),
                "datasource_revision_id": str(uuid4()),
                "plugin_name": "postgresqlwriter",
                "table": {"schema_name": "public", "table_name": "orders"},
            },
            "selection_mode": "ALL_COLUMNS",
            "mappings": [
                {
                    "source_column": "id",
                    "source_ordinal": 1,
                    "source_type": "bigint",
                    "source_nullable": False,
                    "target_column": "id",
                    "target_ordinal": 1,
                    "target_type": "bigint",
                    "target_nullable": False,
                    "oracle_logical_type": "INTEGER",
                    "compatibility": "EXACT",
                }
            ],
            "source_consistency_mode": "OPERATOR_QUIESCED",
            "target_precondition": "EMPTY_AND_VERIFIABLE",
            "write_semantics": "INSERT_ONLY_ONCE",
            "duplicate_policy": "REJECT_NONEMPTY_TARGET",
            "partial_write_policy": "MANUAL_REMEDIATE",
            "write_policy": {
                "mode": "INSERT",
                "target_table_must_exist": True,
                "target_table_must_be_empty": True,
                "platform_may_mutate_target_before_run": False,
            },
            "execution_policy": {
                "channel": 1,
                "timeout_seconds": 600,
                "dirty_data_limit": {"record_count": 0, "percentage": 0},
            },
        }
    )


@pytest.mark.parametrize(
    ("engine", "native_type", "logical_type"),
    [
        ("MYSQL_8", "tinyint(1)", "BOOLEAN"),
        ("MYSQL_8", "decimal(38, 10) unsigned", "DECIMAL"),
        ("POSTGRESQL_15", "timestamp(6) without time zone", "TIMESTAMP"),
        ("POSTGRESQL_15", "character varying(128)", "TEXT"),
        ("POSTGRESQL_15", "bytea", "BINARY"),
    ],
)
def test_native_type_mapping_is_closed_and_deterministic(
    engine: str,
    native_type: str,
    logical_type: str,
) -> None:
    assert logical_type_for_native(engine, native_type) == logical_type  # type: ignore[arg-type]


@pytest.mark.parametrize("native_type", ["float", "double precision", "jsonb", "uuid"])
def test_uncertified_types_fail_closed(native_type: str) -> None:
    with pytest.raises(SchemaProbeError):
        logical_type_for_native("POSTGRESQL_15", native_type)


@pytest.mark.parametrize(
    ("engine", "responses", "database_operations"),
    [
        (
            "MYSQL_8",
            _mysql_probe_responses,
            [
                "execute",
                "fetchone",
                "execute",
                "fetchone",
                "execute",
                "fetchall",
                "execute",
                "fetchall",
                "execute",
                "fetchall",
                "execute",
                "fetchone",
            ],
        ),
        (
            "POSTGRESQL_15",
            _postgres_probe_responses,
            [
                "execute",
                "fetchone",
                "execute",
                "fetchall",
                "execute",
                "fetchall",
                "execute",
                "fetchall",
                "execute",
                "fetchall",
            ],
        ),
    ],
)
def test_schema_probe_checks_control_around_every_database_boundary(
    engine: str,
    responses: Callable[[], list[object]],
    database_operations: list[str],
) -> None:
    trace: list[str] = []
    connection = _ScriptedConnection(responses(), trace)

    snapshot = probe_schema_snapshot(
        connection,
        engine=engine,  # type: ignore[arg-type]
        identity=_identity(engine=engine),
        control_callback=lambda: trace.append("control"),
    )

    assert snapshot.engine == engine
    assert trace == [
        item for operation in database_operations for item in ("control", operation, "control")
    ]


@pytest.mark.parametrize("engine", ["MYSQL_8", "POSTGRESQL_15"])
def test_schema_probe_stops_before_fetch_when_control_changes_during_execute(
    engine: str,
) -> None:
    trace: list[str] = []
    responses = _mysql_probe_responses() if engine == "MYSQL_8" else _postgres_probe_responses()
    connection = _ScriptedConnection(responses, trace)

    def stop_after_execute() -> None:
        trace.append("control")
        if trace == ["control", "execute", "control"]:
            raise RuntimeError("termination requested")

    with pytest.raises(RuntimeError, match="termination requested"):
        probe_schema_snapshot(
            connection,
            engine=engine,  # type: ignore[arg-type]
            identity=_identity(engine=engine),
            control_callback=stop_after_execute,
        )

    assert trace == ["control", "execute", "control"]


def test_physical_table_hash_is_domain_separated_and_identifier_sensitive() -> None:
    endpoint_id = uuid4()
    first = physical_table_identity_hash(
        physical_endpoint_identity_id=endpoint_id,
        engine="POSTGRESQL_15",
        catalog_name="warehouse",
        schema_name="public",
        table_name="orders",
    )
    second = physical_table_identity_hash(
        physical_endpoint_identity_id=endpoint_id,
        engine="POSTGRESQL_15",
        catalog_name="warehouse",
        schema_name="public",
        table_name="Orders",
    )

    assert len(first) == 64
    assert first != second


def test_preflight_recomputes_hash_and_mapping_contract() -> None:
    snapshot = _snapshot()

    assert_snapshot_matches_job(
        snapshot,
        expected_hash=schema_snapshot_hash(snapshot),
        spec=_spec(),
        side="target",
    )

    drifted = deepcopy(snapshot.model_dump(mode="json"))
    drifted["columns"][0]["logical_type"] = "TEXT"
    drifted_snapshot = SchemaSnapshot.model_validate(drifted)
    with pytest.raises(SchemaProbeError, match="SCHEMA_DRIFT_DETECTED"):
        assert_snapshot_matches_job(
            drifted_snapshot,
            expected_hash=schema_snapshot_hash(snapshot),
            spec=_spec(),
            side="target",
        )
