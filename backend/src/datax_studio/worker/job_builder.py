from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

from datax_studio.core.schemas import JobSpecV1

EngineName = Literal["MYSQL_8", "POSTGRESQL_15"]

_MYSQL_READER = "mysqlreader"
_MYSQL_WRITER = "mysqlwriter"
_POSTGRES_READER = "postgresqlreader"
_POSTGRES_WRITER = "postgresqlwriter"
_FORBIDDEN_KEYS = frozenset(
    {
        "querySql",
        "where",
        "preSql",
        "postSql",
        "transformer",
        "jvm",
        "jvmParameters",
        "plugin",
        # This Launcher/guard control capability is never a DataX job option.
        "egress_lease_creation_capability",
    }
)
_TYPE_TOKEN = re.compile(r"^\s*([a-zA-Z]+(?:\s+[a-zA-Z]+)*)")


class UnsafeJobSpec(ValueError):
    """The immutable JobSpec cannot be rendered by the certified V1 runtime."""


@dataclass(frozen=True)
class RuntimeConnection:
    engine: EngineName
    host: str
    port: int
    database_name: str
    username: str
    password: bytearray
    ssl_mode: Literal["DISABLE", "REQUIRE", "VERIFY_CA", "VERIFY_FULL"]

    def __repr__(self) -> str:
        return (
            "RuntimeConnection("
            f"engine={self.engine!r}, host={self.host!r}, port={self.port!r}, "
            f"database_name={self.database_name!r}, username='[REDACTED]', "
            "password=bytearray(b'[REDACTED]'), "
            f"ssl_mode={self.ssl_mode!r})"
        )


@dataclass(frozen=True)
class OracleMapping:
    ordinal: int
    source_column: str
    target_column: str
    logical_type: str


def quote_identifier(engine: EngineName, value: str) -> str:
    if (
        not value
        or len(value) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise UnsafeJobSpec("identifier is empty, too long, or contains control characters")
    if engine == "MYSQL_8":
        return f"`{value.replace('`', '``')}`"
    return f'"{value.replace(chr(34), chr(34) * 2)}"'


def qualified_table(
    engine: EngineName,
    *,
    schema_name: str,
    table_name: str,
) -> str:
    return f"{quote_identifier(engine, schema_name)}.{quote_identifier(engine, table_name)}"


def _jdbc_host(host: str) -> str:
    value = host.rstrip(".")
    if not value or any(character in value for character in "/?#@"):
        raise UnsafeJobSpec("JDBC host is invalid")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if len(value) > 253 or any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in value.split(".")
        ):
            raise UnsafeJobSpec("JDBC host must be an exact FQDN or IP address") from None
        return value.lower()
    return f"[{address.compressed}]" if address.version == 6 else address.compressed


def _jdbc_url(connection: RuntimeConnection) -> str:
    if not 1 <= connection.port <= 65535:
        raise UnsafeJobSpec("JDBC port is outside 1..65535")
    host = _jdbc_host(connection.host)
    database = quote(connection.database_name, safe="")
    if not database:
        raise UnsafeJobSpec("database name is required")
    if connection.engine == "MYSQL_8":
        # Connector/J has no legacy useSSL/verifyServerCertificate combination
        # equivalent to hostname identity verification. The certified 9.7.0
        # runtime therefore uses sslMode directly and keeps VERIFY_CA distinct
        # from VERIFY_IDENTITY (the platform's VERIFY_FULL contract).
        mysql_ssl_mode = {
            "DISABLE": "DISABLED",
            "REQUIRE": "REQUIRED",
            "VERIFY_CA": "VERIFY_CA",
            "VERIFY_FULL": "VERIFY_IDENTITY",
        }[connection.ssl_mode]
        return (
            f"jdbc:mysql://{host}:{connection.port}/{database}"
            "?useUnicode=true&characterEncoding=UTF-8&serverTimezone=UTC"
            f"&sslMode={mysql_ssl_mode}"
            "&fallbackToSystemTrustStore=true"
            "&tlsVersions=TLSv1.2,TLSv1.3"
            "&allowPublicKeyRetrieval=false"
            "&allowLoadLocalInfile=false"
            "&allowUrlInLocalInfile=false"
            "&allowMultiQueries=false"
            "&paranoid=true"
        )
    ssl_mode = {
        "DISABLE": "disable",
        "REQUIRE": "require",
        "VERIFY_CA": "verify-ca",
        "VERIFY_FULL": "verify-full",
    }[connection.ssl_mode]
    return (
        f"jdbc:postgresql://{host}:{connection.port}/{database}"
        f"?sslmode={ssl_mode}&ApplicationName=DataXEnterpriseStudio"
    )


def _password_text(password: bytearray) -> str:
    try:
        return bytes(password).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsafeJobSpec("database password must be valid UTF-8") from exc


def _normalized_type(value: str) -> str:
    match = _TYPE_TOKEN.match(value)
    if match is None:
        raise UnsafeJobSpec("database type is empty or malformed")
    return " ".join(match.group(1).lower().split())


def infer_logical_type(
    source_engine: EngineName,
    source_type: str,
    target_engine: EngineName,
    target_type: str,
) -> str:
    """Map an already validated DB type pair to the exact oracle-v1 family.

    This is intentionally a closed list. In particular, binary floating point
    is rejected because oracle-v1 has no cross-database tolerance contract.
    """

    source = _normalized_type(source_type)
    target = _normalized_type(target_type)
    float_types = {"real", "float", "double", "double precision"}
    if source in float_types or target in float_types:
        raise UnsafeJobSpec("binary floating-point mappings are not certified in V1")

    integer_types = {
        "tinyint",
        "smallint",
        "mediumint",
        "int",
        "integer",
        "bigint",
        "int2",
        "int4",
        "int8",
        "smallserial",
        "serial",
        "bigserial",
    }
    decimal_types = {"decimal", "numeric"}
    text_types = {
        "char",
        "character",
        "character varying",
        "varchar",
        "tinytext",
        "text",
        "mediumtext",
        "longtext",
    }
    boolean_types = {"boolean", "bool"}
    date_types = {"date"}
    time_types = {"time", "time without time zone"}
    timestamp_types = {
        "datetime",
        "timestamp",
        "timestamp without time zone",
    }
    binary_types = {
        "binary",
        "varbinary",
        "tinyblob",
        "blob",
        "mediumblob",
        "longblob",
        "bytea",
    }

    if source in integer_types:
        if (
            source_engine == "MYSQL_8"
            and source == "tinyint"
            and "(1)" in source_type
            and (
                target in boolean_types
                or (target_engine == "MYSQL_8" and target == "tinyint" and "(1)" in target_type)
            )
        ):
            return "BOOLEAN"
        if target in integer_types or target in decimal_types:
            return "INTEGER"
    elif source in decimal_types and target in decimal_types:
        return "DECIMAL"
    elif source in text_types and target in text_types:
        return "TEXT"
    elif source in boolean_types:
        if target in boolean_types or (
            target_engine == "MYSQL_8" and target == "tinyint" and "(1)" in target_type
        ):
            return "BOOLEAN"
    elif source in date_types and target in date_types:
        return "DATE"
    elif source in time_types and target in time_types:
        return "TIME"
    elif source in timestamp_types and target in timestamp_types:
        return "TIMESTAMP"
    elif source in binary_types and target in binary_types:
        return "BINARY"
    raise UnsafeJobSpec(
        f"uncertified oracle type mapping: {source_engine}/{source} -> {target_engine}/{target}"
    )


def build_oracle_mappings(
    spec: JobSpecV1,
    *,
    source_engine: EngineName,
    target_engine: EngineName,
) -> list[OracleMapping]:
    result: list[OracleMapping] = []
    for index, mapping in enumerate(spec.mappings, start=1):
        # The logical type is a server-produced validation artifact fixed in
        # JobVersion. The worker never guesses it from display-oriented native
        # type strings. It still fail-closes the explicitly excluded float family.
        source_type = _normalized_type(mapping.source_type)
        target_type = _normalized_type(mapping.target_type)
        if source_type in {"real", "float", "double", "double precision"} or (
            target_type in {"real", "float", "double", "double precision"}
        ):
            raise UnsafeJobSpec("binary floating-point mappings are not certified in V1")
        result.append(
            OracleMapping(
                ordinal=index,
                source_column=mapping.source_column,
                target_column=mapping.target_column,
                logical_type=mapping.oracle_logical_type,
            )
        )
    return result


def build_datax_job(
    spec: JobSpecV1,
    *,
    source: RuntimeConnection,
    target: RuntimeConnection,
) -> dict[str, Any]:
    if spec.execution_policy.dirty_data_limit.record_count != 0:
        raise UnsafeJobSpec("dirty record count must be zero")
    if spec.execution_policy.dirty_data_limit.percentage != 0:
        raise UnsafeJobSpec("dirty record percentage must be zero")
    expected_reader = {
        "MYSQL_8": _MYSQL_READER,
        "POSTGRESQL_15": _POSTGRES_READER,
    }[source.engine]
    expected_writer = {
        "MYSQL_8": _MYSQL_WRITER,
        "POSTGRESQL_15": _POSTGRES_WRITER,
    }[target.engine]
    if spec.source.plugin_name != expected_reader:
        raise UnsafeJobSpec("reader plugin does not match the fixed source engine")
    if spec.target.plugin_name != expected_writer:
        raise UnsafeJobSpec("writer plugin does not match the fixed target engine")
    if spec.write_policy.mode != "INSERT":
        raise UnsafeJobSpec("V1 writer mode must be INSERT")

    source_columns = [
        quote_identifier(source.engine, mapping.source_column) for mapping in spec.mappings
    ]
    target_columns = [
        quote_identifier(target.engine, mapping.target_column) for mapping in spec.mappings
    ]
    reader_parameter: dict[str, Any] = {
        "username": source.username,
        "password": _password_text(source.password),
        "column": source_columns,
        "connection": [
            {
                "jdbcUrl": [_jdbc_url(source)],
                "table": [
                    qualified_table(
                        source.engine,
                        schema_name=spec.source.table.schema_name,
                        table_name=spec.source.table.table_name,
                    )
                ],
            }
        ],
    }
    writer_parameter: dict[str, Any] = {
        "username": target.username,
        "password": _password_text(target.password),
        "column": target_columns,
        "connection": [
            {
                "jdbcUrl": _jdbc_url(target),
                "table": [
                    qualified_table(
                        target.engine,
                        schema_name=spec.target.table.schema_name,
                        table_name=spec.target.table.table_name,
                    )
                ],
            }
        ],
    }
    # The pinned PostgreSQLWriter explicitly does not support writeMode.
    if target.engine == "MYSQL_8":
        writer_parameter["writeMode"] = "insert"

    job: dict[str, Any] = {
        "job": {
            "setting": {
                "speed": {"channel": spec.execution_policy.channel},
                "errorLimit": {"record": 0, "percentage": 0},
            },
            "content": [
                {
                    "reader": {
                        "name": spec.source.plugin_name,
                        "parameter": reader_parameter,
                    },
                    "writer": {
                        "name": spec.target.plugin_name,
                        "parameter": writer_parameter,
                    },
                }
            ],
        }
    }
    _assert_safe_job_shape(job)
    return job


def _assert_safe_job_shape(job: dict[str, Any]) -> None:
    stack: list[Any] = [job]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            forbidden = _FORBIDDEN_KEYS.intersection(value)
            if forbidden:
                raise UnsafeJobSpec(
                    f"generated DataX JSON contains forbidden keys: {sorted(forbidden)}"
                )
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)


def write_job_file(path: Path, job: dict[str, Any]) -> None:
    """Atomically create a new 0600 job file below a private directory."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = json.dumps(
        job,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    parent_descriptor = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    created = False
    try:
        parent_stat = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
        ):
            raise UnsafeJobSpec("job directory must be private to the Worker")
        descriptor = os.open(
            path.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        created = True
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short DataX job write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
    except BaseException:
        if created:
            with suppress(OSError):
                os.unlink(path.name, dir_fd=parent_descriptor)
        raise
    finally:
        os.close(parent_descriptor)
