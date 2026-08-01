from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from datax_studio.core.schemas import JobSpecV1
from datax_studio.worker.job_builder import (
    RuntimeConnection,
    UnsafeJobSpec,
    _assert_safe_job_shape,
    build_datax_job,
    build_oracle_mappings,
    write_job_file,
)


def _spec(reader: str, writer: str) -> JobSpecV1:
    return JobSpecV1.model_validate(
        {
            "schema_version": "1.0",
            "source": {
                "datasource_id": str(uuid4()),
                "datasource_revision_id": str(uuid4()),
                "plugin_name": reader,
                "table": {"schema_name": "app", "table_name": 'source "table"'},
            },
            "target": {
                "datasource_id": str(uuid4()),
                "datasource_revision_id": str(uuid4()),
                "plugin_name": writer,
                "table": {"schema_name": "app", "table_name": "target`table"},
            },
            "selection_mode": "SELECTED_COLUMNS",
            "mappings": [
                {
                    "source_column": 'display"name',
                    "source_ordinal": 1,
                    "source_type": "varchar(100)",
                    "source_nullable": True,
                    "target_column": "display`name",
                    "target_ordinal": 1,
                    "target_type": "text",
                    "target_nullable": True,
                    "oracle_logical_type": "TEXT",
                    "compatibility": "WIDENING",
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
                "channel": 2,
                "timeout_seconds": 600,
                "dirty_data_limit": {"record_count": 0, "percentage": 0},
            },
        }
    )


def _connection(
    engine: str,
    *,
    host: str = "127.0.0.1",
) -> RuntimeConnection:
    return RuntimeConnection(
        engine=engine,  # type: ignore[arg-type]
        host=host,
        port=3306 if engine == "MYSQL_8" else 5432,
        database_name="warehouse",
        username="datax_user",
        password=bytearray("sëcret".encode()),
        ssl_mode="DISABLE",
    )


@pytest.mark.parametrize(
    ("source_engine", "target_engine", "reader", "writer"),
    [
        ("MYSQL_8", "MYSQL_8", "mysqlreader", "mysqlwriter"),
        ("MYSQL_8", "POSTGRESQL_15", "mysqlreader", "postgresqlwriter"),
        ("POSTGRESQL_15", "MYSQL_8", "postgresqlreader", "mysqlwriter"),
        (
            "POSTGRESQL_15",
            "POSTGRESQL_15",
            "postgresqlreader",
            "postgresqlwriter",
        ),
    ],
)
def test_generator_supports_only_the_certified_four_directions(
    source_engine: str,
    target_engine: str,
    reader: str,
    writer: str,
) -> None:
    spec = _spec(reader, writer)

    job = build_datax_job(
        spec,
        source=_connection(source_engine),
        target=_connection(target_engine),
    )

    content = job["job"]["content"]
    assert len(content) == 1
    assert content[0]["reader"]["name"] == reader
    assert content[0]["writer"]["name"] == writer
    assert job["job"]["setting"]["errorLimit"] == {"record": 0, "percentage": 0}
    assert not {
        "querySql",
        "where",
        "preSql",
        "postSql",
        "transformer",
        "egress_lease_creation_capability",
    }.intersection(str(job))


def test_control_capability_cannot_be_rendered_into_a_datax_job() -> None:
    with pytest.raises(UnsafeJobSpec, match="forbidden keys"):
        _assert_safe_job_shape(
            {
                "job": {
                    "egress_lease_creation_capability": "c" * 64,
                }
            }
        )


def test_mysql_writer_is_explicit_insert_but_postgres_omits_unsupported_mode() -> None:
    mysql_job = build_datax_job(
        _spec("postgresqlreader", "mysqlwriter"),
        source=_connection("POSTGRESQL_15"),
        target=_connection("MYSQL_8"),
    )
    postgres_job = build_datax_job(
        _spec("mysqlreader", "postgresqlwriter"),
        source=_connection("MYSQL_8"),
        target=_connection("POSTGRESQL_15"),
    )

    mysql_parameters = mysql_job["job"]["content"][0]["writer"]["parameter"]
    postgres_parameters = postgres_job["job"]["content"][0]["writer"]["parameter"]
    assert mysql_parameters["writeMode"] == "insert"
    assert "writeMode" not in postgres_parameters
    assert "preSql" not in mysql_parameters
    assert "postSql" not in mysql_parameters
    assert "preSql" not in postgres_parameters
    assert "postSql" not in postgres_parameters


@pytest.mark.parametrize(
    ("ssl_mode", "connector_mode"),
    [
        ("DISABLE", "DISABLED"),
        ("REQUIRE", "REQUIRED"),
        ("VERIFY_CA", "VERIFY_CA"),
        ("VERIFY_FULL", "VERIFY_IDENTITY"),
    ],
)
def test_mysql_jdbc_uses_connector_j_identity_aware_tls_modes(
    ssl_mode: str,
    connector_mode: str,
) -> None:
    connection = _connection("MYSQL_8", host="mysql.internal.example")
    connection = RuntimeConnection(
        engine=connection.engine,
        host=connection.host,
        port=connection.port,
        database_name=connection.database_name,
        username=connection.username,
        password=connection.password,
        ssl_mode=ssl_mode,  # type: ignore[arg-type]
    )

    job = build_datax_job(
        _spec("mysqlreader", "postgresqlwriter"),
        source=connection,
        target=_connection("POSTGRESQL_15"),
    )
    jdbc_url = job["job"]["content"][0]["reader"]["parameter"]["connection"][0][
        "jdbcUrl"
    ][0]

    assert f"sslMode={connector_mode}" in jdbc_url
    assert "fallbackToSystemTrustStore=true" in jdbc_url
    assert "allowPublicKeyRetrieval=false" in jdbc_url
    assert "allowLoadLocalInfile=false" in jdbc_url
    assert "allowUrlInLocalInfile=false" in jdbc_url
    assert "allowMultiQueries=false" in jdbc_url
    assert "useSSL=" not in jdbc_url
    assert "requireSSL=" not in jdbc_url
    assert "verifyServerCertificate=" not in jdbc_url


def test_mysql_verify_ca_and_verify_full_are_not_rendered_as_the_same_policy() -> None:
    def render(mode: str) -> str:
        base = _connection("MYSQL_8", host="mysql.internal.example")
        source = RuntimeConnection(
            engine=base.engine,
            host=base.host,
            port=base.port,
            database_name=base.database_name,
            username=base.username,
            password=base.password,
            ssl_mode=mode,  # type: ignore[arg-type]
        )
        job = build_datax_job(
            _spec("mysqlreader", "postgresqlwriter"),
            source=source,
            target=_connection("POSTGRESQL_15"),
        )
        return job["job"]["content"][0]["reader"]["parameter"]["connection"][0][
            "jdbcUrl"
        ][0]

    verify_ca = render("VERIFY_CA")
    verify_full = render("VERIFY_FULL")

    assert "sslMode=VERIFY_CA" in verify_ca
    assert "sslMode=VERIFY_IDENTITY" in verify_full
    assert verify_ca != verify_full


def test_mysql_writer_verify_full_uses_hostname_identity_validation() -> None:
    target = _connection("MYSQL_8", host="mysql-writer.internal.example")
    target = RuntimeConnection(
        engine=target.engine,
        host=target.host,
        port=target.port,
        database_name=target.database_name,
        username=target.username,
        password=target.password,
        ssl_mode="VERIFY_FULL",
    )

    job = build_datax_job(
        _spec("postgresqlreader", "mysqlwriter"),
        source=_connection("POSTGRESQL_15"),
        target=target,
    )
    jdbc_url = job["job"]["content"][0]["writer"]["parameter"]["connection"][0][
        "jdbcUrl"
    ]

    assert "sslMode=VERIFY_IDENTITY" in jdbc_url


def test_identifier_values_are_quoted_as_identifiers_not_sql() -> None:
    job = build_datax_job(
        _spec("postgresqlreader", "mysqlwriter"),
        source=_connection("POSTGRESQL_15"),
        target=_connection("MYSQL_8"),
    )
    content = job["job"]["content"][0]

    assert content["reader"]["parameter"]["column"] == ['"display""name"']
    assert content["reader"]["parameter"]["connection"][0]["table"] == ['"app"."source ""table"""']
    assert content["writer"]["parameter"]["column"] == ["`display``name`"]
    assert content["writer"]["parameter"]["connection"][0]["table"] == ["`app`.`target``table`"]


def test_binary_float_is_rejected_until_an_oracle_adr_exists() -> None:
    raw = _spec("mysqlreader", "postgresqlwriter").model_dump(mode="json")
    raw["mappings"][0]["source_type"] = "double"
    raw["mappings"][0]["target_type"] = "double precision"
    spec = JobSpecV1.model_validate(raw)

    with pytest.raises(UnsafeJobSpec, match="floating-point"):
        build_oracle_mappings(
            spec,
            source_engine="MYSQL_8",
            target_engine="POSTGRESQL_15",
        )


def test_job_file_is_create_only_and_owner_read_write(tmp_path: Path) -> None:
    path = tmp_path / "run" / "job.json"
    job = build_datax_job(
        _spec("mysqlreader", "postgresqlwriter"),
        source=_connection("MYSQL_8"),
        target=_connection("POSTGRESQL_15"),
    )

    write_job_file(path, job)

    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_job_file(path, job)


def test_runtime_connection_repr_never_contains_secret() -> None:
    connection = _connection("MYSQL_8", host="db.internal.example")

    assert "sëcret" not in repr(connection)
    assert "[REDACTED]" in repr(connection)
