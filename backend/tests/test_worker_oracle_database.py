from __future__ import annotations

from collections.abc import Sequence
from datetime import time, timedelta
from pathlib import Path
from typing import Any

import pytest

from datax_studio.worker.job_builder import OracleMapping
from datax_studio.worker.oracle_database import (
    _normalize_rows_for_oracle,
    capture_source_preflight,
    count_target_rows,
    load_oracle_module,
    verify_databases,
)

ORACLE_PATH = Path(__file__).parents[2] / "runtime" / "oracle" / "verification_oracle.py"


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.rows: list[Sequence[Any]] = []
        self.index = 0

    def execute(
        self,
        query: str,
        parameters: Sequence[object] = (),
    ) -> None:
        del parameters
        self.connection.queries.append(query)
        if "txid_current_snapshot" in query:
            self.rows = [["10:20:"]]
        elif query.startswith("SELECT COUNT(*)"):
            self.rows = [[len(self.connection.data_rows)]]
        elif query.startswith("SELECT "):
            self.rows = list(self.connection.data_rows)
        else:
            self.rows = []
        self.index = 0

    def fetchone(self) -> Sequence[Any] | None:
        batch = self.fetchmany(1)
        return batch[0] if batch else None

    def fetchmany(self, size: int = 0) -> list[Sequence[Any]]:
        size = size or 1
        result = self.rows[self.index : self.index + size]
        self.index += len(result)
        return result

    def close(self) -> None:
        return None


class FakeConnection:
    def __init__(self, rows: list[list[object]]) -> None:
        self.data_rows = rows
        self.queries: list[str] = []
        self.autocommit = True
        self.commits = 0
        self.rollbacks = 0

    def cursor(self, *args: object, **kwargs: object) -> FakeCursor:
        del args, kwargs
        return FakeCursor(self)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def _mappings() -> list[OracleMapping]:
    return [
        OracleMapping(
            ordinal=1,
            source_column='source"id',
            target_column='target"id',
            logical_type="INTEGER",
            source_native_type="integer",
            target_native_type="integer",
        ),
        OracleMapping(
            ordinal=2,
            source_column="name",
            target_column="name",
            logical_type="TEXT",
            source_native_type="text",
            target_native_type="text",
        ),
    ]


def _boolean_mappings(
    *,
    source_native_type: str = "tinyint(1)",
    target_native_type: str = "boolean",
) -> list[OracleMapping]:
    return [
        OracleMapping(
            ordinal=1,
            source_column="id",
            target_column="id",
            logical_type="INTEGER",
            source_native_type="integer",
            target_native_type="integer",
        ),
        OracleMapping(
            ordinal=2,
            source_column="is_active",
            target_column="is_active",
            logical_type="BOOLEAN",
            source_native_type=source_native_type,
            target_native_type=target_native_type,
        ),
    ]


def _time_mappings(*, source_native_type: str = "time") -> list[OracleMapping]:
    return [
        OracleMapping(
            ordinal=1,
            source_column="id",
            target_column="id",
            logical_type="INTEGER",
            source_native_type="integer",
            target_native_type="integer",
        ),
        OracleMapping(
            ordinal=2,
            source_column="at_time",
            target_column="at_time",
            logical_type="TIME",
            source_native_type=source_native_type,
            target_native_type="time without time zone",
        ),
    ]


def test_real_db_oracle_path_streams_both_sides_and_uses_one_target_snapshot(
    tmp_path: Path,
) -> None:
    oracle = load_oracle_module(ORACLE_PATH)
    source = FakeConnection([[1, "a"], [2, "b"], [1, "a"]])
    target = FakeConnection([[1, "a"], [1, "a"], [2, "b"]])

    preflight = capture_source_preflight(
        source,
        engine="POSTGRESQL_15",
        schema_name="public",
        table_name="source table",
        mappings=_mappings(),
        spool_directory=tmp_path,
        oracle=oracle,
        fetch_size=2,
    )
    reads = verify_databases(
        FakeConnection(source.data_rows),
        target,
        source_engine="POSTGRESQL_15",
        target_engine="POSTGRESQL_15",
        source_schema_name="public",
        source_table_name="source table",
        target_schema_name="public",
        target_table_name="target table",
        mappings=_mappings(),
        spool_directory=tmp_path,
        oracle=oracle,
        fetch_size=2,
    )

    assert preflight.summary == reads.source.summary
    assert reads.source.summary == reads.target.summary
    assert reads.difference.missing_row_count == 0
    assert reads.difference.unexpected_row_count == 0
    assert reads.target.snapshot_id.startswith("postgresql:")
    assert target.commits == 1
    assert any('"public"."target table"' in query for query in target.queries)
    assert any('"target""id"' in query for query in target.queries)


def test_target_count_is_read_in_a_consistent_read_transaction() -> None:
    connection = FakeConnection([[1], [2]])

    count, _checked_at = count_target_rows(
        connection,
        engine="POSTGRESQL_15",
        schema_name="public",
        table_name="orders",
    )

    assert count == 2
    assert connection.commits == 1
    assert connection.queries[0].startswith("BEGIN TRANSACTION")
    assert connection.queries[-1] == 'SELECT COUNT(*) FROM "public"."orders"'


def test_oracle_adapts_only_mysql_tinyint_boolean_driver_values(
    tmp_path: Path,
) -> None:
    oracle = load_oracle_module(ORACLE_PATH)

    reads = verify_databases(
        FakeConnection([[1, 0], [2, 1]]),
        FakeConnection([[1, False], [2, True]]),
        source_engine="MYSQL_8",
        target_engine="POSTGRESQL_15",
        source_schema_name="audit",
        source_table_name="source_table",
        target_schema_name="audit",
        target_table_name="target_table",
        mappings=_boolean_mappings(),
        spool_directory=tmp_path,
        oracle=oracle,
    )

    assert reads.source.summary == reads.target.summary
    assert reads.difference.missing_row_count == 0
    assert reads.difference.unexpected_row_count == 0


def test_oracle_adapts_mysql_tinyint_boolean_values_on_the_target_side(
    tmp_path: Path,
) -> None:
    oracle = load_oracle_module(ORACLE_PATH)

    reads = verify_databases(
        FakeConnection([[1, False], [2, True]]),
        FakeConnection([[1, 0], [2, 1]]),
        source_engine="POSTGRESQL_15",
        target_engine="MYSQL_8",
        source_schema_name="audit",
        source_table_name="source_table",
        target_schema_name="audit",
        target_table_name="target_table",
        mappings=_boolean_mappings(
            source_native_type="boolean",
            target_native_type="tinyint(1) unsigned",
        ),
        spool_directory=tmp_path,
        oracle=oracle,
    )

    assert reads.source.summary == reads.target.summary
    assert reads.difference.missing_row_count == 0
    assert reads.difference.unexpected_row_count == 0


def test_oracle_rejects_non_boolean_mysql_tinyint_values(
    tmp_path: Path,
) -> None:
    oracle = load_oracle_module(ORACLE_PATH)

    with pytest.raises(ValueError, match="BOOLEAN requires a bool value"):
        capture_source_preflight(
            FakeConnection([[1, 2]]),
            engine="MYSQL_8",
            schema_name="audit",
            table_name="source_table",
            mappings=_boolean_mappings(),
            spool_directory=tmp_path,
            oracle=oracle,
        )


@pytest.mark.parametrize("native_type", ["time", "TIME(6)"])
def test_oracle_adapts_lossless_mysql_time_timedelta_values(
    tmp_path: Path,
    native_type: str,
) -> None:
    oracle = load_oracle_module(ORACLE_PATH)

    reads = verify_databases(
        FakeConnection(
            [
                [1, timedelta()],
                [2, timedelta(hours=23, minutes=59, seconds=58, microseconds=123456)],
            ]
        ),
        FakeConnection([[1, time()], [2, time(23, 59, 58, 123456)]]),
        source_engine="MYSQL_8",
        target_engine="POSTGRESQL_15",
        source_schema_name="audit",
        source_table_name="source_table",
        target_schema_name="audit",
        target_table_name="target_table",
        mappings=_time_mappings(source_native_type=native_type),
        spool_directory=tmp_path,
        oracle=oracle,
    )

    assert reads.source.summary == reads.target.summary
    assert reads.difference.missing_row_count == 0
    assert reads.difference.unexpected_row_count == 0


@pytest.mark.parametrize(
    "value",
    [timedelta(microseconds=-1), timedelta(days=1), "not-a-time"],
)
def test_oracle_rejects_lossy_or_non_timedelta_mysql_time_values(
    tmp_path: Path,
    value: object,
) -> None:
    oracle = load_oracle_module(ORACLE_PATH)

    with pytest.raises(ValueError):
        capture_source_preflight(
            FakeConnection([[1, value]]),
            engine="MYSQL_8",
            schema_name="audit",
            table_name="source_table",
            mappings=_time_mappings(),
            spool_directory=tmp_path,
            oracle=oracle,
        )


def test_oracle_preserves_non_timedelta_mysql_time_values_for_the_fixed_oracle() -> None:
    rows = [[1, "23:59:58.123456"]]

    normalized = _normalize_rows_for_oracle(
        rows,
        engine="MYSQL_8",
        logical_types=["INTEGER", "TIME"],
        native_types=["integer", "time"],
    )

    assert normalized == [(1, "23:59:58.123456")]


@pytest.mark.parametrize(
    ("engine", "native_type", "value"),
    [
        ("MYSQL_8", "tinyint(2)", 1),
        ("POSTGRESQL_15", "smallint", 1),
        ("MYSQL_8", "tinyint(1)", "1"),
    ],
)
def test_oracle_never_coerces_other_tinyint_cross_engine_or_string_values(
    tmp_path: Path,
    engine: str,
    native_type: str,
    value: object,
) -> None:
    oracle = load_oracle_module(ORACLE_PATH)

    with pytest.raises(ValueError, match="BOOLEAN requires a bool value"):
        capture_source_preflight(
            FakeConnection([[1, value]]),
            engine=engine,  # type: ignore[arg-type]
            schema_name="audit",
            table_name="source_table",
            mappings=_boolean_mappings(source_native_type=native_type),
            spool_directory=tmp_path,
            oracle=oracle,
        )


def test_oracle_control_callback_interrupts_between_bounded_batches(
    tmp_path: Path,
) -> None:
    oracle = load_oracle_module(ORACLE_PATH)
    source = FakeConnection([[1, "a"], [2, "b"], [3, "c"]])
    target = FakeConnection(list(source.data_rows))
    control_checks = 0

    class OracleInterrupted(RuntimeError):
        pass

    def check_control() -> None:
        nonlocal control_checks
        control_checks += 1
        if control_checks == 3:
            raise OracleInterrupted

    with pytest.raises(OracleInterrupted):
        verify_databases(
            source,
            target,
            source_engine="POSTGRESQL_15",
            target_engine="POSTGRESQL_15",
            source_schema_name="public",
            source_table_name="source table",
            target_schema_name="public",
            target_table_name="target table",
            mappings=_mappings(),
            spool_directory=tmp_path,
            oracle=oracle,
            fetch_size=1,
            control_callback=check_control,
        )

    assert control_checks == 3
    assert source.commits == 0
    assert source.rollbacks == 1
    assert target.commits == 0


def test_oracle_database_propagates_control_callback_into_spool_summary(
    tmp_path: Path,
) -> None:
    oracle = load_oracle_module(ORACLE_PATH)
    source = FakeConnection([[1, "a"]])
    target = FakeConnection([[1, "a"]])
    control_checks = 0

    class OracleInterrupted(RuntimeError):
        pass

    def check_control() -> None:
        nonlocal control_checks
        control_checks += 1
        # _read_side checks before the query, after the non-empty fetch,
        # after spooling it and after the final empty fetch. Check five is the
        # DigestSpool.summary entry boundary.
        if control_checks == 5:
            raise OracleInterrupted

    with pytest.raises(OracleInterrupted):
        verify_databases(
            source,
            target,
            source_engine="POSTGRESQL_15",
            target_engine="POSTGRESQL_15",
            source_schema_name="public",
            source_table_name="source table",
            target_schema_name="public",
            target_table_name="target table",
            mappings=_mappings(),
            spool_directory=tmp_path,
            oracle=oracle,
            fetch_size=10,
            control_callback=check_control,
        )

    assert control_checks == 5
    assert source.commits == 0
    assert source.rollbacks == 1
    assert target.commits == 0


def test_oracle_loader_rejects_non_files(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="unavailable"):
        load_oracle_module(tmp_path / "missing.py")
