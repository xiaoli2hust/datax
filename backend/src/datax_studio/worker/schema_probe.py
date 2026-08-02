from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol
from uuid import UUID

import rfc8785

from datax_studio.core.schemas import JobSpecV1
from datax_studio.schema_snapshot import (
    SchemaColumn,
    SchemaConstraint,
    SchemaSnapshot,
    SchemaTableOptions,
    SchemaTrigger,
    schema_snapshot_hash,
)

EngineName = Literal["MYSQL_8", "POSTGRESQL_15"]
_FLOAT_FAMILY = frozenset({"real", "float", "double", "double precision"})
_HASH_DOMAINS = {
    "default": b"DXSCHEMADEFAULTv1\n",
    "constraint": b"DXSCHEMACONSTRAINTv1\n",
    "trigger_name": b"DXSCHEMATRIGGERNAMEv1\n",
    "trigger": b"DXSCHEMATRIGGERv1\n",
}


class Cursor(Protocol):
    def execute(self, query: str, parameters: Sequence[object] = ()) -> object: ...

    def fetchone(self) -> Sequence[Any] | None: ...

    def fetchall(self) -> list[Sequence[Any]]: ...

    def __enter__(self) -> Cursor: ...

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None: ...


class Connection(Protocol):
    def cursor(self, *args: object, **kwargs: object) -> Cursor: ...


class SchemaProbeError(RuntimeError):
    code = "SCHEMA_ATTESTATION_UNAVAILABLE"


class _StatementBudgetCursor:
    """Run a caller-supplied budget hook immediately before every SQL call.

    ``control_callback`` deliberately runs both before and after execute/fetch
    so Worker cancellation is noticed promptly.  A timeout-setting SQL command
    cannot safely run in its *after execute* half, because a result set may not
    yet have been fetched.  This narrow proxy therefore supplies a separate,
    pre-statement hook for callers that must refresh a shared query deadline.
    """

    def __init__(
        self,
        cursor: Cursor,
        before_statement: Callable[[], None] | None,
    ) -> None:
        self._cursor = cursor
        self._before_statement = before_statement

    def execute(self, query: str, parameters: Sequence[object] = ()) -> object:
        if self._before_statement is not None:
            self._before_statement()
        return self._cursor.execute(query, parameters)

    def fetchone(self) -> Sequence[Any] | None:
        return self._cursor.fetchone()

    def fetchall(self) -> list[Sequence[Any]]:
        return self._cursor.fetchall()


@dataclass(frozen=True)
class TableIdentity:
    physical_endpoint_identity_id: UUID
    physical_table_identity_hash: str
    catalog_name: str
    schema_name: str
    table_name: str


def _hash(kind: str, value: object) -> str:
    return hashlib.sha256(_HASH_DOMAINS[kind] + rfc8785.dumps(value)).hexdigest()


def physical_table_identity_hash(
    *,
    physical_endpoint_identity_id: UUID,
    engine: EngineName,
    catalog_name: str,
    schema_name: str,
    table_name: str,
) -> str:
    preimage = (
        b"DXPHYSICALTABLEv1\n"
        + str(physical_endpoint_identity_id).lower().encode("ascii")
        + b"\n"
        + rfc8785.dumps(
            [engine, catalog_name, schema_name, table_name, "1.0"]
        )
    )
    return hashlib.sha256(preimage).hexdigest()


def _base_native_type(value: str) -> str:
    normalized = " ".join(value.strip().lower().split())
    match = re.match(r"^([a-z]+(?:\s+[a-z]+)*)", normalized)
    if match is None:
        raise SchemaProbeError("native database type is malformed")
    return match.group(1)


def logical_type_for_native(engine: EngineName, native_type: str) -> str:
    normalized = " ".join(native_type.strip().lower().split())
    base = _base_native_type(normalized)
    if base in _FLOAT_FAMILY:
        raise SchemaProbeError("binary floating-point types are not certified in V1")
    if engine == "MYSQL_8" and base == "tinyint" and re.search(
        r"\(\s*1\s*\)",
        normalized,
    ):
        return "BOOLEAN"
    families = {
        "INTEGER": {
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
        },
        "DECIMAL": {"decimal", "numeric"},
        "TEXT": {
            "char",
            "character",
            "character varying",
            "varchar",
            "tinytext",
            "text",
            "mediumtext",
            "longtext",
        },
        "BOOLEAN": {"boolean", "bool"},
        "DATE": {"date"},
        "TIME": {"time", "time without time zone"},
        "TIMESTAMP": {
            "datetime",
            "timestamp",
            "timestamp without time zone",
        },
        "BINARY": {
            "binary",
            "varbinary",
            "tinyblob",
            "blob",
            "mediumblob",
            "longblob",
            "bytea",
        },
    }
    for logical_type, native_types in families.items():
        if base in native_types or normalized in native_types:
            return logical_type
    raise SchemaProbeError(f"native database type is not certified in V1: {base}")


def probe_schema_snapshot(
    connection: Connection,
    *,
    engine: EngineName,
    identity: TableIdentity,
    control_callback: Callable[[], None] | None = None,
    statement_callback: Callable[[], None] | None = None,
) -> SchemaSnapshot:
    if engine == "MYSQL_8":
        return _probe_mysql(
            connection,
            identity,
            control_callback=control_callback,
            statement_callback=statement_callback,
        )
    if engine == "POSTGRESQL_15":
        return _probe_postgres(
            connection,
            identity,
            control_callback=control_callback,
            statement_callback=statement_callback,
        )
    raise SchemaProbeError("unsupported schema probe engine")


def _probe_mysql(
    connection: Connection,
    identity: TableIdentity,
    *,
    control_callback: Callable[[], None] | None,
    statement_callback: Callable[[], None] | None,
) -> SchemaSnapshot:
    with connection.cursor() as raw_cursor:
        cursor = _StatementBudgetCursor(raw_cursor, statement_callback)
        _controlled_execute(
            cursor,
            "SELECT @@lower_case_table_names",
            control_callback=control_callback,
        )
        case_row = _controlled_fetchone(
            cursor,
            control_callback=control_callback,
        )
        if case_row is None or int(case_row[0]) not in {0, 1, 2}:
            raise SchemaProbeError("MySQL identifier case mode is unavailable")
        case_mode = f"MYSQL_LOWER_CASE_TABLE_NAMES_{int(case_row[0])}"
        _controlled_execute(
            cursor,
            """
            SELECT TABLE_TYPE
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
            """,
            (identity.catalog_name, identity.table_name),
            control_callback=control_callback,
        )
        table_row = _controlled_fetchone(
            cursor,
            control_callback=control_callback,
        )
        if table_row is None or str(table_row[0]).upper() != "BASE TABLE":
            raise SchemaProbeError("MySQL source or target is not a base table")
        _controlled_execute(
            cursor,
            """
            SELECT
                ORDINAL_POSITION,
                COLUMN_NAME,
                COLUMN_TYPE,
                IS_NULLABLE,
                EXTRA,
                CHARACTER_MAXIMUM_LENGTH,
                NUMERIC_PRECISION,
                NUMERIC_SCALE,
                DATETIME_PRECISION,
                CHARACTER_SET_NAME,
                COLLATION_NAME,
                COLUMN_DEFAULT,
                GENERATION_EXPRESSION
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
            ORDER BY ORDINAL_POSITION
            """,
            (identity.catalog_name, identity.table_name),
            control_callback=control_callback,
        )
        raw_columns = _controlled_fetchall(
            cursor,
            control_callback=control_callback,
        )
        _controlled_execute(
            cursor,
            """
            SELECT
                tc.CONSTRAINT_NAME,
                tc.CONSTRAINT_TYPE,
                kcu.COLUMN_NAME,
                kcu.ORDINAL_POSITION,
                kcu.REFERENCED_TABLE_SCHEMA,
                kcu.REFERENCED_TABLE_NAME,
                cc.CHECK_CLAUSE,
                tc.ENFORCED
            FROM information_schema.TABLE_CONSTRAINTS AS tc
            LEFT JOIN information_schema.KEY_COLUMN_USAGE AS kcu
              ON kcu.CONSTRAINT_SCHEMA = tc.CONSTRAINT_SCHEMA
             AND kcu.TABLE_NAME = tc.TABLE_NAME
             AND kcu.CONSTRAINT_NAME = tc.CONSTRAINT_NAME
            LEFT JOIN information_schema.CHECK_CONSTRAINTS AS cc
              ON cc.CONSTRAINT_SCHEMA = tc.CONSTRAINT_SCHEMA
             AND cc.CONSTRAINT_NAME = tc.CONSTRAINT_NAME
            WHERE tc.TABLE_SCHEMA = %s AND tc.TABLE_NAME = %s
            ORDER BY tc.CONSTRAINT_NAME, kcu.ORDINAL_POSITION
            """,
            (identity.catalog_name, identity.table_name),
            control_callback=control_callback,
        )
        raw_constraints = _controlled_fetchall(
            cursor,
            control_callback=control_callback,
        )
        _controlled_execute(
            cursor,
            """
            SELECT
                TRIGGER_NAME,
                ACTION_TIMING,
                EVENT_MANIPULATION,
                ACTION_ORIENTATION,
                ACTION_STATEMENT
            FROM information_schema.TRIGGERS
            WHERE EVENT_OBJECT_SCHEMA = %s AND EVENT_OBJECT_TABLE = %s
            ORDER BY TRIGGER_NAME, EVENT_MANIPULATION
            """,
            (identity.catalog_name, identity.table_name),
            control_callback=control_callback,
        )
        raw_triggers = _controlled_fetchall(
            cursor,
            control_callback=control_callback,
        )
        _controlled_execute(
            cursor,
            """
            SELECT COUNT(*)
            FROM information_schema.PARTITIONS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = %s
              AND PARTITION_NAME IS NOT NULL
            """,
            (identity.catalog_name, identity.table_name),
            control_callback=control_callback,
        )
        partition_row = _controlled_fetchone(
            cursor,
            control_callback=control_callback,
        )

    columns = [
        _mysql_column(row)
        for row in raw_columns
    ]
    if not columns:
        raise SchemaProbeError("MySQL table has no visible columns")
    constraints = _mysql_constraints(
        raw_constraints,
        all_column_names=[column.name for column in columns],
        identity=identity,
    )
    triggers = [
        SchemaTrigger(
            name_sha256=_hash("trigger_name", str(row[0])),
            timing=str(row[1]).upper(),
            events=[str(row[2]).upper()],
            orientation=str(row[3]).upper(),
            enabled=True,
            definition_sha256=_hash(
                "trigger",
                {
                    "timing": str(row[1]).upper(),
                    "event": str(row[2]).upper(),
                    "orientation": str(row[3]).upper(),
                    "statement": str(row[4]),
                },
            ),
        )
        for row in raw_triggers
    ]
    return SchemaSnapshot(
        schema_version="1.0",
        normalization_version="1.0",
        engine="MYSQL_8",
        physical_endpoint_identity_id=identity.physical_endpoint_identity_id,
        physical_table_identity_hash=identity.physical_table_identity_hash,
        identifier_case_mode=case_mode,  # type: ignore[arg-type]
        catalog_name=identity.catalog_name,
        schema_name="",
        table_name=identity.table_name,
        table_kind="BASE_TABLE",
        columns=columns,
        constraints=sorted(
            constraints,
            key=lambda item: rfc8785.dumps(item.model_dump(mode="json")),
        ),
        triggers=sorted(
            triggers,
            key=lambda item: rfc8785.dumps(item.model_dump(mode="json")),
        ),
        table_options=SchemaTableOptions(
            partitioned=bool(partition_row and int(partition_row[0]) > 0),
            row_security_enabled=None,
        ),
    )


def _mysql_column(row: Sequence[Any]) -> SchemaColumn:
    native_type = " ".join(str(row[2]).strip().lower().split())
    extra = str(row[4] or "").upper()
    default = row[11]
    generated_expression = row[12]
    default_present = default is not None or "DEFAULT_GENERATED" in extra
    default_value = (
        {
            "default": str(default) if default is not None else None,
            "generated": str(generated_expression or ""),
        }
        if default_present
        else None
    )
    return SchemaColumn(
        ordinal_position=int(row[0]),
        name=str(row[1]),
        native_type=native_type,
        logical_type=logical_type_for_native("MYSQL_8", native_type),  # type: ignore[arg-type]
        nullable=str(row[3]).upper() == "YES",
        unsigned="unsigned" in native_type,
        generated="GENERATED" in extra or bool(generated_expression),
        identity="AUTO_INCREMENT" in extra,
        character_maximum_length=_optional_int(row[5]),
        numeric_precision=_optional_int(row[6]),
        numeric_scale=_optional_nonnegative_int(row[7]),
        datetime_precision=_optional_nonnegative_int(row[8]),
        character_set_name=str(row[9]) if row[9] is not None else None,
        collation_name=str(row[10]) if row[10] is not None else None,
        default_present=default_present,
        default_expression_sha256=(
            _hash("default", default_value) if default_present else None
        ),
    )


def _mysql_constraints(
    rows: Iterable[Sequence[Any]],
    *,
    all_column_names: list[str],
    identity: TableIdentity,
) -> list[SchemaConstraint]:
    groups: dict[tuple[str, str], list[Sequence[Any]]] = defaultdict(list)
    for row in rows:
        groups[(str(row[0]), str(row[1]).upper())].append(row)
    constraints: list[SchemaConstraint] = []
    kind_map = {
        "PRIMARY KEY": "PRIMARY_KEY",
        "UNIQUE": "UNIQUE",
        "FOREIGN KEY": "FOREIGN_KEY",
        "CHECK": "CHECK",
    }
    for (name, raw_kind), items in groups.items():
        if raw_kind not in kind_map:
            raise SchemaProbeError(f"unsupported MySQL constraint: {raw_kind}")
        kind = kind_map[raw_kind]
        columns = [
            str(item[2])
            for item in sorted(
                (item for item in items if item[2] is not None),
                key=lambda item: int(item[3]),
            )
        ]
        if not columns and kind == "CHECK":
            # MySQL does not expose CHECK column dependencies structurally.
            # Conservatively bind the definition to every table column.
            columns = list(all_column_names)
        referenced_hash = None
        referenced = next(
            (
                (str(item[4]), str(item[5]))
                for item in items
                if item[4] is not None and item[5] is not None
            ),
            None,
        )
        if kind == "FOREIGN_KEY":
            if referenced is None:
                raise SchemaProbeError("foreign-key target identity is unavailable")
            referenced_hash = physical_table_identity_hash(
                physical_endpoint_identity_id=identity.physical_endpoint_identity_id,
                engine="MYSQL_8",
                catalog_name=referenced[0],
                schema_name="",
                table_name=referenced[1],
            )
        definition = {
            "name": name,
            "kind": kind,
            "columns": columns,
            "referenced": referenced,
            "check": next(
                (str(item[6]) for item in items if item[6] is not None),
                None,
            ),
        }
        constraints.append(
            SchemaConstraint(
                kind=kind,  # type: ignore[arg-type]
                columns=columns,
                enforced=all(
                    item[7] is None or str(item[7]).upper() == "YES"
                    for item in items
                ),
                definition_sha256=_hash("constraint", definition),
                referenced_physical_table_identity_hash=referenced_hash,
            )
        )
    return constraints


def _probe_postgres(
    connection: Connection,
    identity: TableIdentity,
    *,
    control_callback: Callable[[], None] | None,
    statement_callback: Callable[[], None] | None,
) -> SchemaSnapshot:
    with connection.cursor() as raw_cursor:
        cursor = _StatementBudgetCursor(raw_cursor, statement_callback)
        _controlled_execute(
            cursor,
            """
            SELECT c.oid, c.relkind, c.relrowsecurity
            FROM pg_catalog.pg_class AS c
            JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = %s AND c.relname = %s
            """,
            (identity.schema_name, identity.table_name),
            control_callback=control_callback,
        )
        table_row = _controlled_fetchone(
            cursor,
            control_callback=control_callback,
        )
        if table_row is None or str(table_row[1]) not in {"r", "p"}:
            raise SchemaProbeError("PostgreSQL source or target is not a base table")
        table_oid = int(table_row[0])
        partitioned = str(table_row[1]) == "p"
        row_security = bool(table_row[2])
        _controlled_execute(
            cursor,
            """
            SELECT
                a.attnum,
                a.attname,
                pg_catalog.format_type(a.atttypid, a.atttypmod),
                NOT a.attnotnull,
                a.attgenerated,
                a.attidentity,
                information_schema._pg_char_max_length(
                    a.atttypid, a.atttypmod
                ),
                information_schema._pg_numeric_precision(
                    a.atttypid, a.atttypmod
                ),
                information_schema._pg_numeric_scale(
                    a.atttypid, a.atttypmod
                ),
                information_schema._pg_datetime_precision(
                    a.atttypid, a.atttypmod
                ),
                coll.collname,
                pg_catalog.pg_get_expr(ad.adbin, ad.adrelid)
            FROM pg_catalog.pg_attribute AS a
            LEFT JOIN pg_catalog.pg_attrdef AS ad
              ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
            LEFT JOIN pg_catalog.pg_collation AS coll
              ON coll.oid = a.attcollation AND a.attcollation != 0
            WHERE a.attrelid = %s
              AND a.attnum > 0
              AND NOT a.attisdropped
            ORDER BY a.attnum
            """,
            (table_oid,),
            control_callback=control_callback,
        )
        raw_columns = _controlled_fetchall(
            cursor,
            control_callback=control_callback,
        )
        _controlled_execute(
            cursor,
            """
            SELECT
                con.oid,
                con.contype,
                con.conkey,
                con.confrelid,
                con.convalidated,
                pg_catalog.pg_get_constraintdef(con.oid, true)
            FROM pg_catalog.pg_constraint AS con
            WHERE con.conrelid = %s
            ORDER BY con.oid
            """,
            (table_oid,),
            control_callback=control_callback,
        )
        raw_constraints = _controlled_fetchall(
            cursor,
            control_callback=control_callback,
        )
        _controlled_execute(
            cursor,
            """
            SELECT
                t.tgname,
                t.tgtype,
                t.tgenabled,
                pg_catalog.pg_get_triggerdef(t.oid, true)
            FROM pg_catalog.pg_trigger AS t
            WHERE t.tgrelid = %s AND NOT t.tgisinternal
            ORDER BY t.tgname
            """,
            (table_oid,),
            control_callback=control_callback,
        )
        raw_triggers = _controlled_fetchall(
            cursor,
            control_callback=control_callback,
        )
        referenced_oids = sorted(
            {int(row[3]) for row in raw_constraints if int(row[3] or 0) != 0}
        )
        references: dict[int, tuple[str, str]] = {}
        if referenced_oids:
            _controlled_execute(
                cursor,
                """
                SELECT c.oid, n.nspname, c.relname
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                WHERE c.oid = ANY(%s)
                """,
                (referenced_oids,),
                control_callback=control_callback,
            )
            references = {
                int(row[0]): (str(row[1]), str(row[2]))
                for row in _controlled_fetchall(
                    cursor,
                    control_callback=control_callback,
                )
            }

    columns = [_postgres_column(row) for row in raw_columns]
    if not columns:
        raise SchemaProbeError("PostgreSQL table has no visible columns")
    ordinal_names = {column.ordinal_position: column.name for column in columns}
    constraints = [
        _postgres_constraint(
            row,
            ordinal_names=ordinal_names,
            references=references,
            identity=identity,
        )
        for row in raw_constraints
    ]
    triggers = [_postgres_trigger(row) for row in raw_triggers]
    return SchemaSnapshot(
        schema_version="1.0",
        normalization_version="1.0",
        engine="POSTGRESQL_15",
        physical_endpoint_identity_id=identity.physical_endpoint_identity_id,
        physical_table_identity_hash=identity.physical_table_identity_hash,
        identifier_case_mode="POSTGRESQL_FOLDED_OR_QUOTED",
        catalog_name=identity.catalog_name,
        schema_name=identity.schema_name,
        table_name=identity.table_name,
        table_kind="BASE_TABLE",
        columns=columns,
        constraints=sorted(
            constraints,
            key=lambda item: rfc8785.dumps(item.model_dump(mode="json")),
        ),
        triggers=sorted(
            triggers,
            key=lambda item: rfc8785.dumps(item.model_dump(mode="json")),
        ),
        table_options=SchemaTableOptions(
            partitioned=partitioned,
            row_security_enabled=row_security,
        ),
    )


def _postgres_column(row: Sequence[Any]) -> SchemaColumn:
    native_type = " ".join(str(row[2]).strip().lower().split())
    default = row[11]
    return SchemaColumn(
        ordinal_position=int(row[0]),
        name=str(row[1]),
        native_type=native_type,
        logical_type=logical_type_for_native("POSTGRESQL_15", native_type),  # type: ignore[arg-type]
        nullable=bool(row[3]),
        unsigned=False,
        generated=bool(row[4]),
        identity=bool(row[5]),
        character_maximum_length=_optional_int(row[6]),
        numeric_precision=_optional_int(row[7]),
        numeric_scale=_optional_nonnegative_int(row[8]),
        datetime_precision=_optional_nonnegative_int(row[9]),
        character_set_name=None,
        collation_name=str(row[10]) if row[10] is not None else None,
        default_present=default is not None,
        default_expression_sha256=(
            _hash("default", str(default)) if default is not None else None
        ),
    )


def _postgres_constraint(
    row: Sequence[Any],
    *,
    ordinal_names: dict[int, str],
    references: dict[int, tuple[str, str]],
    identity: TableIdentity,
) -> SchemaConstraint:
    kind_map = {
        "p": "PRIMARY_KEY",
        "u": "UNIQUE",
        "f": "FOREIGN_KEY",
        "c": "CHECK",
    }
    raw_kind = str(row[1])
    if raw_kind not in kind_map:
        raise SchemaProbeError(f"unsupported PostgreSQL constraint: {raw_kind}")
    kind = kind_map[raw_kind]
    raw_ordinals = list(row[2] or [])
    columns = [ordinal_names[int(value)] for value in raw_ordinals]
    if not columns and kind == "CHECK":
        # pg_constraint.conkey can be null for expression checks. Binding the
        # definition to every column is conservative and deterministic.
        columns = [ordinal_names[key] for key in sorted(ordinal_names)]
    referenced_hash = None
    referenced_oid = int(row[3] or 0)
    if kind == "FOREIGN_KEY":
        referenced = references.get(referenced_oid)
        if referenced is None:
            raise SchemaProbeError("foreign-key target identity is unavailable")
        referenced_hash = physical_table_identity_hash(
            physical_endpoint_identity_id=identity.physical_endpoint_identity_id,
            engine="POSTGRESQL_15",
            catalog_name=identity.catalog_name,
            schema_name=referenced[0],
            table_name=referenced[1],
        )
    return SchemaConstraint(
        kind=kind,  # type: ignore[arg-type]
        columns=columns,
        enforced=bool(row[4]),
        definition_sha256=_hash("constraint", str(row[5])),
        referenced_physical_table_identity_hash=referenced_hash,
    )


def _postgres_trigger(row: Sequence[Any]) -> SchemaTrigger:
    trigger_type = int(row[1])
    events = [
        event
        for bit, event in ((4, "INSERT"), (16, "UPDATE"), (8, "DELETE"), (32, "TRUNCATE"))
        if trigger_type & bit
    ]
    if trigger_type & 64:
        timing = "INSTEAD_OF"
    elif trigger_type & 2:
        timing = "BEFORE"
    else:
        timing = "AFTER"
    return SchemaTrigger(
        name_sha256=_hash("trigger_name", str(row[0])),
        timing=timing,  # type: ignore[arg-type]
        events=events,  # type: ignore[arg-type]
        orientation="ROW" if trigger_type & 1 else "STATEMENT",
        enabled=str(row[2]) != "D",
        definition_sha256=_hash("trigger", str(row[3])),
    )


def assert_snapshot_matches_job(
    snapshot: SchemaSnapshot,
    *,
    expected_hash: str,
    spec: JobSpecV1,
    side: Literal["source", "target"],
) -> None:
    actual_hash = schema_snapshot_hash(snapshot)
    if actual_hash != expected_hash:
        raise SchemaProbeError("SCHEMA_DRIFT_DETECTED")
    columns_by_name = {column.name: column for column in snapshot.columns}
    for mapping in spec.mappings:
        name = (
            mapping.source_column
            if side == "source"
            else mapping.target_column
        )
        ordinal = (
            mapping.source_ordinal
            if side == "source"
            else mapping.target_ordinal
        )
        column = columns_by_name.get(name)
        if (
            column is None
            or column.ordinal_position != ordinal
            or column.logical_type != mapping.oracle_logical_type
        ):
            raise SchemaProbeError("SCHEMA_MAPPING_DRIFT_DETECTED")
        if side == "target" and column.generated:
            raise SchemaProbeError("TARGET_GENERATED_COLUMN_UNSAFE")
    if side == "target" and any(trigger.enabled for trigger in snapshot.triggers):
        raise SchemaProbeError("TARGET_TRIGGER_UNSAFE")


def _optional_int(value: Any) -> int | None:
    return int(value) if value is not None else None


def _optional_nonnegative_int(value: Any) -> int | None:
    if value is None:
        return None
    result = int(value)
    return result if result >= 0 else None


def _controlled_execute(
    cursor: Cursor,
    query: str,
    parameters: Sequence[object] | None = None,
    *,
    control_callback: Callable[[], None] | None,
) -> object:
    _check_control(control_callback)
    result = cursor.execute(query) if parameters is None else cursor.execute(query, parameters)
    _check_control(control_callback)
    return result


def _controlled_fetchone(
    cursor: Cursor,
    *,
    control_callback: Callable[[], None] | None,
) -> Sequence[Any] | None:
    _check_control(control_callback)
    result = cursor.fetchone()
    _check_control(control_callback)
    return result


def _controlled_fetchall(
    cursor: Cursor,
    *,
    control_callback: Callable[[], None] | None,
) -> list[Sequence[Any]]:
    _check_control(control_callback)
    result = cursor.fetchall()
    _check_control(control_callback)
    return result


def _check_control(control_callback: Callable[[], None] | None) -> None:
    if control_callback is not None:
        control_callback()
