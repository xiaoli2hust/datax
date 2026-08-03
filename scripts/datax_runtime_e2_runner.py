#!/usr/bin/env python3
"""Run the direct, disposable DataX Runtime E2 checks inside a Worker image.

This program is deliberately launched only by ``test-datax-runtime-e2.sh`` on
an isolated temporary Docker network.  It is not an API/Worker/Compose test
and it must never be reported as product E3 or Windows E4 evidence.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import psycopg
import pymysql
from datax_studio.core.schemas import JobSpecV1
from datax_studio.datax_runner import build_datax_command, run_datax_job
from datax_studio.runtime_manifest import check_runtime_manifest
from datax_studio.worker.job_builder import (
    EngineName,
    OracleMapping,
    RuntimeConnection,
    build_datax_job,
    qualified_table,
    write_job_file,
)
from datax_studio.worker.oracle_database import load_oracle_module, verify_databases

FixtureMode = Literal["ALL_COLUMNS", "SELECTED_COLUMNS"]

_FIXTURE_ROW_COUNT = 10_000
_MYSQL_USER = "datax"
_DATABASE_NAME = "audit"
_SCHEMA_NAME = "audit"
_SOURCE_TABLE = "audit_source"
_FULL_TARGET_TABLE = "audit_target_full"
_SELECTED_TARGET_TABLE = "audit_target_selected"
_SELECTED_NAMES = frozenset({"id", "unicode_text", "nullable_text", "decimal_value"})
_PLUGIN_BY_ENGINE = {
    "MYSQL_8": ("mysqlreader", "mysqlwriter"),
    "POSTGRESQL_15": ("postgresqlreader", "postgresqlwriter"),
}
_RUNTIME_MANIFEST_PATH = Path("/opt/datax/runtime-manifest.json")
_JAVA_PATH = Path("/opt/java/openjdk/bin/java")


class RuntimeE2Failure(RuntimeError):
    """A sanitized direct-runtime assertion failure."""


@dataclass(frozen=True)
class ColumnSpec:
    name: str
    mysql_type: str
    postgres_type: str
    logical_type: str
    nullable: bool


_COLUMNS: tuple[ColumnSpec, ...] = (
    ColumnSpec("id", "int", "integer", "INTEGER", False),
    ColumnSpec("fixed_text", "char(10)", "character(10)", "TEXT", False),
    ColumnSpec("variable_text", "varchar(100)", "character varying(100)", "TEXT", False),
    ColumnSpec("unicode_text", "text", "text", "TEXT", False),
    ColumnSpec("empty_text", "varchar(10)", "character varying(10)", "TEXT", False),
    ColumnSpec("nullable_text", "varchar(50)", "character varying(50)", "TEXT", True),
    ColumnSpec("boolean_value", "tinyint(1)", "boolean", "BOOLEAN", False),
    ColumnSpec("date_value", "date", "date", "DATE", False),
    ColumnSpec("time_value", "time(6)", "time(6) without time zone", "TIME", False),
    ColumnSpec(
        "timestamp_value",
        "timestamp(6)",
        "timestamp(6) without time zone",
        "TIMESTAMP",
        False,
    ),
    ColumnSpec("decimal_value", "decimal(18,4)", "numeric(18,4)", "DECIMAL", False),
    ColumnSpec("binary_value", "binary(32)", "bytea", "BINARY", False),
)


def _require_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeE2Failure(f"required fixture environment is absent: {name}")
    return value


def _fixture_hosts() -> dict[str, str]:
    return {
        "mysql_source": _require_environment("DATAX_RUNTIME_E2_MYSQL_SOURCE_HOST"),
        "mysql_target": _require_environment("DATAX_RUNTIME_E2_MYSQL_TARGET_HOST"),
        "postgres_source": _require_environment("DATAX_RUNTIME_E2_POSTGRES_SOURCE_HOST"),
        "postgres_target": _require_environment("DATAX_RUNTIME_E2_POSTGRES_TARGET_HOST"),
    }


def _password() -> str:
    return _require_environment("DATAX_RUNTIME_E2_FIXTURE_PASSWORD")


def _datax_timeout_seconds() -> float:
    raw = os.environ.get("DATAX_RUNTIME_E2_TIMEOUT_SECONDS", "180")
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeE2Failure("fixture timeout must be numeric") from exc
    if not 1 <= value <= 900:
        raise RuntimeE2Failure("fixture timeout must be between 1 and 900 seconds")
    return value


def _mysql_connection(host: str, *, stream: bool = False) -> pymysql.Connection:
    return pymysql.connect(
        host=host,
        port=3306,
        user=_MYSQL_USER,
        password=_password(),
        database=_DATABASE_NAME,
        charset="utf8mb4",
        autocommit=True,
        cursorclass=pymysql.cursors.SSCursor if stream else pymysql.cursors.Cursor,
    )


def _postgres_connection(host: str, *, autocommit: bool) -> psycopg.Connection:
    return psycopg.connect(
        host=host,
        port=5432,
        user=_MYSQL_USER,
        password=_password(),
        dbname=_DATABASE_NAME,
        autocommit=autocommit,
    )


def _execute_many(connection: Any, statements: list[str]) -> None:
    with connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def _initialize_mysql(host: str) -> None:
    connection = _mysql_connection(host)
    try:
        _execute_many(
            connection,
            [
                "SET time_zone = '+00:00'",
                f"DROP TABLE IF EXISTS `{_FULL_TARGET_TABLE}`",
                f"DROP TABLE IF EXISTS `{_SELECTED_TARGET_TABLE}`",
                f"DROP TABLE IF EXISTS `{_SOURCE_TABLE}`",
                f"""
                CREATE TABLE `{_SOURCE_TABLE}` (
                  `id` INT NOT NULL,
                  `fixed_text` CHAR(10) NOT NULL,
                  `variable_text` VARCHAR(100) NOT NULL,
                  `unicode_text` TEXT NOT NULL,
                  `empty_text` VARCHAR(10) NOT NULL,
                  `nullable_text` VARCHAR(50) NULL,
                  `boolean_value` TINYINT(1) NOT NULL,
                  `date_value` DATE NOT NULL,
                  `time_value` TIME(6) NOT NULL,
                  `timestamp_value` TIMESTAMP(6) NOT NULL,
                  `decimal_value` DECIMAL(18,4) NOT NULL,
                  `binary_value` BINARY(32) NOT NULL,
                  PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """,
                f"""
                CREATE TABLE `{_FULL_TARGET_TABLE}` LIKE `{_SOURCE_TABLE}`
                """,
                f"""
                CREATE TABLE `{_SELECTED_TARGET_TABLE}` (
                  `id` INT NOT NULL,
                  `unicode_text` TEXT NOT NULL,
                  `nullable_text` VARCHAR(50) NULL,
                  `decimal_value` DECIMAL(18,4) NOT NULL,
                  PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """,
                f"""
                INSERT INTO `{_SOURCE_TABLE}`
                  (`id`, `fixed_text`, `variable_text`, `unicode_text`, `empty_text`,
                   `nullable_text`, `boolean_value`, `date_value`, `time_value`,
                   `timestamp_value`, `decimal_value`, `binary_value`)
                SELECT n,
                       CONCAT('F', LPAD(n, 9, '0')),
                       CONCAT('value-', n),
                       CONCAT('数据-', n, '🙂'),
                       '',
                       CASE WHEN MOD(n, 3) = 0 THEN NULL ELSE CONCAT('optional-', n) END,
                       MOD(n, 2),
                       DATE_ADD('2024-01-01', INTERVAL MOD(n, 365) DAY),
                       ADDTIME('12:00:00.000000', SEC_TO_TIME(MOD(n, 60))),
                       TIMESTAMPADD(SECOND, n, '2024-01-01 00:00:00.000000'),
                       CAST(n AS DECIMAL(18,4)) / 10,
                       UNHEX(CONCAT(MD5(CONCAT('row-', n)), MD5(CONCAT('row-', n))))
                FROM (
                  SELECT ones.digit + tens.digit * 10 + hundreds.digit * 100
                         + thousands.digit * 1000 + 1 AS n
                  FROM (SELECT 0 AS digit UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL
                        SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL
                        SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) AS ones
                  CROSS JOIN (SELECT 0 AS digit UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL
                              SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL
                              SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) AS tens
                  CROSS JOIN (SELECT 0 AS digit UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL
                              SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL
                              SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) AS hundreds
                  CROSS JOIN (SELECT 0 AS digit UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL
                              SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL
                              SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) AS thousands
                ) AS numbers
                WHERE n <= {_FIXTURE_ROW_COUNT}
                """,
            ],
        )
        _assert_fixture_count(connection, engine="MYSQL_8")
    finally:
        connection.close()


def _initialize_postgres(host: str) -> None:
    connection = _postgres_connection(host, autocommit=True)
    try:
        _execute_many(
            connection,
            [
                "SET TIME ZONE 'UTC'",
                f'CREATE SCHEMA IF NOT EXISTS "{_SCHEMA_NAME}"',
                f'DROP TABLE IF EXISTS "{_SCHEMA_NAME}"."{_FULL_TARGET_TABLE}"',
                f'DROP TABLE IF EXISTS "{_SCHEMA_NAME}"."{_SELECTED_TARGET_TABLE}"',
                f'DROP TABLE IF EXISTS "{_SCHEMA_NAME}"."{_SOURCE_TABLE}"',
                f'''
                CREATE TABLE "{_SCHEMA_NAME}"."{_SOURCE_TABLE}" (
                  "id" INTEGER PRIMARY KEY,
                  "fixed_text" CHARACTER(10) NOT NULL,
                  "variable_text" CHARACTER VARYING(100) NOT NULL,
                  "unicode_text" TEXT NOT NULL,
                  "empty_text" CHARACTER VARYING(10) NOT NULL,
                  "nullable_text" CHARACTER VARYING(50),
                  "boolean_value" BOOLEAN NOT NULL,
                  "date_value" DATE NOT NULL,
                  "time_value" TIME(6) WITHOUT TIME ZONE NOT NULL,
                  "timestamp_value" TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
                  "decimal_value" NUMERIC(18,4) NOT NULL,
                  "binary_value" BYTEA NOT NULL
                )
                ''',
                f'''
                CREATE TABLE "{_SCHEMA_NAME}"."{_FULL_TARGET_TABLE}" (
                  "id" INTEGER PRIMARY KEY,
                  "fixed_text" CHARACTER(10) NOT NULL,
                  "variable_text" CHARACTER VARYING(100) NOT NULL,
                  "unicode_text" TEXT NOT NULL,
                  "empty_text" CHARACTER VARYING(10) NOT NULL,
                  "nullable_text" CHARACTER VARYING(50),
                  "boolean_value" BOOLEAN NOT NULL,
                  "date_value" DATE NOT NULL,
                  "time_value" TIME(6) WITHOUT TIME ZONE NOT NULL,
                  "timestamp_value" TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
                  "decimal_value" NUMERIC(18,4) NOT NULL,
                  "binary_value" BYTEA NOT NULL
                )
                ''',
                f'''
                CREATE TABLE "{_SCHEMA_NAME}"."{_SELECTED_TARGET_TABLE}" (
                  "id" INTEGER PRIMARY KEY,
                  "unicode_text" TEXT NOT NULL,
                  "nullable_text" CHARACTER VARYING(50),
                  "decimal_value" NUMERIC(18,4) NOT NULL
                )
                ''',
                f'''
                INSERT INTO "{_SCHEMA_NAME}"."{_SOURCE_TABLE}"
                  ("id", "fixed_text", "variable_text", "unicode_text", "empty_text",
                   "nullable_text", "boolean_value", "date_value", "time_value",
                   "timestamp_value", "decimal_value", "binary_value")
                SELECT n,
                       'F' || lpad(n::text, 9, '0'),
                       'value-' || n::text,
                       '数据-' || n::text || '🙂',
                       '',
                       CASE WHEN mod(n, 3) = 0 THEN NULL ELSE 'optional-' || n::text END,
                       mod(n, 2) = 1,
                       DATE '2024-01-01' + mod(n, 365),
                       TIME '12:00:00.000000' + mod(n, 60) * INTERVAL '1 second',
                       TIMESTAMP '2024-01-01 00:00:00.000000' + n * INTERVAL '1 second',
                       (n::numeric / 10)::numeric(18,4),
                       decode(md5('row-' || n::text) || md5('row-' || n::text), 'hex')
                FROM generate_series(1, {_FIXTURE_ROW_COUNT}) AS n
                ''',
            ],
        )
        _assert_fixture_count(connection, engine="POSTGRESQL_15")
    finally:
        connection.close()


def _assert_fixture_count(connection: Any, *, engine: EngineName) -> None:
    query = (
        f"SELECT COUNT(*) FROM {qualified_table(engine, schema_name=_SCHEMA_NAME, table_name=_SOURCE_TABLE)}"
    )
    with connection.cursor() as cursor:
        cursor.execute(query)
        row = cursor.fetchone()
    if row is None or int(row[0]) != _FIXTURE_ROW_COUNT:
        raise RuntimeE2Failure("deterministic fixture row count is incorrect")


def _direction_host(engine: EngineName, *, side: Literal["source", "target"], hosts: dict[str, str]) -> str:
    key = ("mysql" if engine == "MYSQL_8" else "postgres") + f"_{side}"
    return hosts[key]


def _columns_for_mode(mode: FixtureMode) -> tuple[ColumnSpec, ...]:
    if mode == "ALL_COLUMNS":
        return _COLUMNS
    return tuple(column for column in _COLUMNS if column.name in _SELECTED_NAMES)


def _native_type(column: ColumnSpec, engine: EngineName) -> str:
    return column.mysql_type if engine == "MYSQL_8" else column.postgres_type


def _oracle_mappings(
    *,
    source_engine: EngineName,
    target_engine: EngineName,
    mode: FixtureMode,
) -> list[OracleMapping]:
    return [
        OracleMapping(
            ordinal=ordinal,
            source_column=column.name,
            target_column=column.name,
            logical_type=column.logical_type,
            source_native_type=_native_type(column, source_engine),
            target_native_type=_native_type(column, target_engine),
        )
        for ordinal, column in enumerate(_columns_for_mode(mode), start=1)
    ]


def _job_spec(
    *,
    source_engine: EngineName,
    target_engine: EngineName,
    mode: FixtureMode,
) -> JobSpecV1:
    source_reader, _ = _PLUGIN_BY_ENGINE[source_engine]
    _, target_writer = _PLUGIN_BY_ENGINE[target_engine]
    columns = _columns_for_mode(mode)
    target_table = _FULL_TARGET_TABLE if mode == "ALL_COLUMNS" else _SELECTED_TARGET_TABLE
    return JobSpecV1.model_validate(
        {
            "schema_version": "1.0",
            "source": {
                "datasource_id": str(uuid4()),
                "datasource_revision_id": str(uuid4()),
                "plugin_name": source_reader,
                "table": {"schema_name": _SCHEMA_NAME, "table_name": _SOURCE_TABLE},
            },
            "target": {
                "datasource_id": str(uuid4()),
                "datasource_revision_id": str(uuid4()),
                "plugin_name": target_writer,
                "table": {"schema_name": _SCHEMA_NAME, "table_name": target_table},
            },
            "selection_mode": mode,
            "mappings": [
                {
                    "source_column": column.name,
                    "source_ordinal": ordinal,
                    "source_type": _native_type(column, source_engine),
                    "source_nullable": column.nullable,
                    "target_column": column.name,
                    "target_ordinal": ordinal,
                    "target_type": _native_type(column, target_engine),
                    "target_nullable": column.nullable,
                    "compatibility": "EXACT",
                    "oracle_logical_type": column.logical_type,
                }
                for ordinal, column in enumerate(columns, start=1)
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
                "timeout_seconds": int(_datax_timeout_seconds()),
                "dirty_data_limit": {"record_count": 0, "percentage": 0},
            },
        }
    )


def _runtime_connection(engine: EngineName, host: str) -> RuntimeConnection:
    return RuntimeConnection(
        engine=engine,
        host=host,
        port=3306 if engine == "MYSQL_8" else 5432,
        database_name=_DATABASE_NAME,
        username=_MYSQL_USER,
        password=bytearray(_password().encode("utf-8")),
        ssl_mode="REQUIRE" if engine == "MYSQL_8" else "DISABLE",
    )


def _truncate_target(engine: EngineName, host: str, table_name: str) -> None:
    if engine == "MYSQL_8":
        connection = _mysql_connection(host)
    else:
        connection = _postgres_connection(host, autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"TRUNCATE TABLE {qualified_table(engine, schema_name=_SCHEMA_NAME, table_name=table_name)}"
            )
    finally:
        connection.close()


def _oracle_connections(
    source_engine: EngineName,
    target_engine: EngineName,
    hosts: dict[str, str],
) -> tuple[Any, Any]:
    source_host = _direction_host(source_engine, side="source", hosts=hosts)
    target_host = _direction_host(target_engine, side="target", hosts=hosts)
    source = (
        _mysql_connection(source_host, stream=True)
        if source_engine == "MYSQL_8"
        else _postgres_connection(source_host, autocommit=False)
    )
    target = (
        _mysql_connection(target_host, stream=True)
        if target_engine == "MYSQL_8"
        else _postgres_connection(target_host, autocommit=False)
    )
    return source, target


def _run_case(
    *,
    source_engine: EngineName,
    target_engine: EngineName,
    mode: FixtureMode,
    hosts: dict[str, str],
    workspace_root: Path,
) -> dict[str, Any]:
    target_table = _FULL_TARGET_TABLE if mode == "ALL_COLUMNS" else _SELECTED_TARGET_TABLE
    source_host = _direction_host(source_engine, side="source", hosts=hosts)
    target_host = _direction_host(target_engine, side="target", hosts=hosts)
    _truncate_target(target_engine, target_host, target_table)
    spec = _job_spec(source_engine=source_engine, target_engine=target_engine, mode=mode)
    job = build_datax_job(
        spec,
        source=_runtime_connection(source_engine, source_host),
        target=_runtime_connection(target_engine, target_host),
    )
    if job.get("common") != {"column": {"timeZone": "UTC"}}:
        raise RuntimeE2Failure("generated DataX job did not pin common.column.timeZone to UTC")

    identifier = f"{source_engine.lower()}-{target_engine.lower()}-{mode.lower()}"
    workspace = workspace_root / identifier
    job_root = workspace / "job"
    job_path = job_root / "job.json"
    write_job_file(job_path, job)
    process = run_datax_job(
        build_datax_command(
            java_path=Path("/opt/java/openjdk/bin/java"),
            datax_home=Path("/opt/datax/datax"),
            job_path=job_path,
            job_root=job_root,
            log_directory=workspace / "logs",
            workspace=workspace,
            job_id=str(10_000 + len(identifier)),
        ),
        workspace=workspace,
        timeout_seconds=_datax_timeout_seconds(),
    )
    report: dict[str, Any] = {
        "direction": f"{source_engine}->{target_engine}",
        "scope": mode,
        "process": {
            "returncode": process.returncode,
            "timed_out": process.timed_out,
            "stdout_original_bytes": process.stdout_original_bytes,
            "stderr_original_bytes": process.stderr_original_bytes,
        },
    }
    if process.returncode != 0 or process.timed_out:
        report["verification"] = {"status": "NOT_RUN"}
        return report

    source_connection, target_connection = _oracle_connections(
        source_engine,
        target_engine,
        hosts,
    )
    try:
        reads = verify_databases(
            source_connection,
            target_connection,
            source_engine=source_engine,
            target_engine=target_engine,
            source_schema_name=_SCHEMA_NAME,
            source_table_name=_SOURCE_TABLE,
            target_schema_name=_SCHEMA_NAME,
            target_table_name=target_table,
            mappings=_oracle_mappings(
                source_engine=source_engine,
                target_engine=target_engine,
                mode=mode,
            ),
            spool_directory=workspace / "oracle",
            # The direct diagnostic must exercise the oracle embedded in the
            # supplied Worker image, not a host-mounted repository copy.
            oracle=load_oracle_module(Path("/opt/datax/oracle/verification_oracle.py")),
            fetch_size=1000,
        )
    finally:
        source_connection.close()
        target_connection.close()

    digest_equal = reads.source.summary.multiset_sha256 == reads.target.summary.multiset_sha256
    report["verification"] = {
        "status": "PASSED"
        if digest_equal
        and reads.difference.missing_row_count == 0
        and reads.difference.unexpected_row_count == 0
        else "FAILED",
        "source_row_count": reads.source.summary.row_count,
        "target_row_count": reads.target.summary.row_count,
        "digest_equal": digest_equal,
        "missing_row_count": reads.difference.missing_row_count,
        "unexpected_row_count": reads.difference.unexpected_row_count,
    }
    return report


def _assert_fixed_runtime_integrity() -> dict[str, str]:
    check = check_runtime_manifest(
        _RUNTIME_MANIFEST_PATH,
        expected_java_path=_JAVA_PATH,
    )
    if not check.ready:
        raise RuntimeE2Failure("fixed Worker Runtime manifest validation failed")
    return {
        "manifest": "PASSED",
        "runtime_code": check.runtime_code,
        "oracle_code": check.oracle_code,
    }


def main() -> int:
    report: dict[str, Any] = {
        "suite": "DATAX_RUNTIME_E2_DIRECT",
        "status": "FAILED",
        "evidence_boundary": "NOT_PRODUCT_E3_OR_E4",
        "fixture": {
            "row_count": _FIXTURE_ROW_COUNT,
            "database_engines": ["MYSQL_8", "POSTGRESQL_15"],
            "network": "isolated_internal_docker_network",
            "product_components_started": [],
        },
        "runtime": {"manifest": "NOT_RUN"},
        "cases": [],
    }
    current_stage = "fixture_environment"
    try:
        hosts = _fixture_hosts()
        current_stage = "runtime_manifest"
        report["runtime"] = _assert_fixed_runtime_integrity()
        current_stage = "initialize_mysql_source"
        _initialize_mysql(hosts["mysql_source"])
        current_stage = "initialize_mysql_target"
        _initialize_mysql(hosts["mysql_target"])
        current_stage = "initialize_postgres_source"
        _initialize_postgres(hosts["postgres_source"])
        current_stage = "initialize_postgres_target"
        _initialize_postgres(hosts["postgres_target"])
        with tempfile.TemporaryDirectory(prefix="datax-runtime-e2-", dir="/tmp") as raw_workspace:
            workspace_root = Path(raw_workspace)
            for source_engine, target_engine in (
                ("MYSQL_8", "MYSQL_8"),
                ("MYSQL_8", "POSTGRESQL_15"),
                ("POSTGRESQL_15", "MYSQL_8"),
                ("POSTGRESQL_15", "POSTGRESQL_15"),
            ):
                for mode in ("ALL_COLUMNS", "SELECTED_COLUMNS"):
                    current_stage = f"run_{source_engine.lower()}_to_{target_engine.lower()}_{mode.lower()}"
                    case = _run_case(
                        source_engine=source_engine,
                        target_engine=target_engine,
                        mode=mode,
                        hosts=hosts,
                        workspace_root=workspace_root,
                    )
                    report["cases"].append(case)
                    verification = case["verification"]
                    if (
                        case["process"]["returncode"] != 0
                        or case["process"]["timed_out"]
                        or verification["status"] != "PASSED"
                    ):
                        raise RuntimeE2Failure("direct DataX Runtime E2 assertion failed")
        report["status"] = "PASSED"
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        report["failure_code"] = "RUNTIME_E2_INTERRUPTED"
        report["failure_stage"] = current_stage
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 130
    except RuntimeE2Failure as exc:
        report["failure_code"] = "RUNTIME_E2_ASSERTION_FAILED"
        report["failure_stage"] = current_stage
        report["exception_type"] = type(exc).__name__
    # This is an isolated command boundary. Do not allow an unexpected driver
    # or fixture exception to print connection details or a DataX command line.
    except Exception as exc:  # noqa: BLE001
        report["failure_code"] = "RUNTIME_E2_INFRASTRUCTURE_FAILED"
        report["failure_stage"] = current_stage
        report["exception_type"] = type(exc).__name__
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
