from __future__ import annotations

import hashlib
import importlib.util
import sys
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Literal, Protocol
from uuid import uuid4

from datax_studio.worker.job_builder import (
    EngineName,
    OracleMapping,
    qualified_table,
    quote_identifier,
)


class Cursor(Protocol):
    def execute(self, query: str, parameters: Sequence[object] = ()) -> object: ...

    def fetchone(self) -> Sequence[Any] | None: ...

    def fetchmany(self, size: int = 0) -> list[Sequence[Any]]: ...

    def close(self) -> None: ...


class Connection(Protocol):
    autocommit: Any

    def cursor(self, *args: object, **kwargs: object) -> Cursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...


class OracleDatabaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class SideRead:
    summary: Any
    read_started_at: datetime
    read_finished_at: datetime
    snapshot_id: str | None
    snapshot_started_at: datetime | None
    snapshot_finished_at: datetime | None


@dataclass(frozen=True)
class VerificationReads:
    source: SideRead
    target: SideRead
    difference: Any


def load_oracle_module(path: Path) -> ModuleType:
    resolved = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise OracleDatabaseError("fixed oracle module is unavailable")
    name = "datax_studio_runtime_verification_oracle"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, resolved)
    if spec is None or spec.loader is None:
        raise OracleDatabaseError("fixed oracle module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    required = {
        "DigestSpool",
        "build_verification_report",
        "summary_fingerprint",
    }
    if not required <= set(vars(module)):
        raise OracleDatabaseError("fixed oracle module has an incompatible API")
    return module


def capture_source_preflight(
    connection: Connection,
    *,
    engine: EngineName,
    schema_name: str,
    table_name: str,
    mappings: Sequence[OracleMapping],
    spool_directory: Path,
    oracle: ModuleType,
    fetch_size: int = 1000,
) -> SideRead:
    with oracle.DigestSpool(spool_directory) as spool:
        result = _read_side(
            connection,
            engine=engine,
            schema_name=schema_name,
            table_name=table_name,
            column_names=[mapping.source_column for mapping in mappings],
            logical_types=[mapping.logical_type for mapping in mappings],
            spool=spool,
            side="source",
            target_snapshot=False,
            fetch_size=fetch_size,
        )
    return result


def verify_databases(
    source_connection: Connection,
    target_connection: Connection,
    *,
    source_engine: EngineName,
    target_engine: EngineName,
    source_schema_name: str,
    source_table_name: str,
    target_schema_name: str,
    target_table_name: str,
    mappings: Sequence[OracleMapping],
    spool_directory: Path,
    oracle: ModuleType,
    fetch_size: int = 1000,
    control_callback: Callable[[], None] | None = None,
) -> VerificationReads:
    """Read both databases independently and compare exact row multisets.

    The target count and hash are derived from the same row stream in one
    repeatable-read, read-only transaction. No DataX metric is an input.
    """

    logical_types = [mapping.logical_type for mapping in mappings]
    with oracle.DigestSpool(spool_directory) as spool:
        source = _read_side(
            source_connection,
            engine=source_engine,
            schema_name=source_schema_name,
            table_name=source_table_name,
            column_names=[mapping.source_column for mapping in mappings],
            logical_types=logical_types,
            spool=spool,
            side="source",
            target_snapshot=False,
            fetch_size=fetch_size,
            control_callback=control_callback,
        )
        target = _read_side(
            target_connection,
            engine=target_engine,
            schema_name=target_schema_name,
            table_name=target_table_name,
            column_names=[mapping.target_column for mapping in mappings],
            logical_types=logical_types,
            spool=spool,
            side="target",
            target_snapshot=True,
            fetch_size=fetch_size,
            control_callback=control_callback,
        )
        difference = spool.difference(control_callback=control_callback)
    return VerificationReads(source=source, target=target, difference=difference)


def count_target_rows(
    connection: Connection,
    *,
    engine: EngineName,
    schema_name: str,
    table_name: str,
) -> tuple[int, datetime]:
    _begin_consistent_read(connection, engine)
    cursor = connection.cursor()
    try:
        cursor.execute(
            f"SELECT COUNT(*) FROM "
            f"{qualified_table(engine, schema_name=schema_name, table_name=table_name)}"
        )
        row = cursor.fetchone()
        if row is None:
            raise OracleDatabaseError("target count query returned no row")
        count = int(row[0])
        checked_at = datetime.now(UTC)
        connection.commit()
        return count, checked_at
    except BaseException:
        _safe_rollback(connection)
        raise
    finally:
        cursor.close()


def _read_side(
    connection: Connection,
    *,
    engine: EngineName,
    schema_name: str,
    table_name: str,
    column_names: Sequence[str],
    logical_types: Sequence[str],
    spool: Any,
    side: Literal["source", "target"],
    target_snapshot: bool,
    fetch_size: int,
    control_callback: Callable[[], None] | None = None,
) -> SideRead:
    if not column_names or len(column_names) != len(logical_types):
        raise OracleDatabaseError("oracle mapping is empty or inconsistent")
    if not 1 <= fetch_size <= 100_000:
        raise ValueError("fetch_size must be between 1 and 100000")
    _invoke_control_callback(control_callback)
    snapshot_started_at = datetime.now(UTC)
    marker = _begin_consistent_read(connection, engine)
    query = (
        "SELECT "
        + ", ".join(quote_identifier(engine, name) for name in column_names)
        + " FROM "
        + qualified_table(
            engine,
            schema_name=schema_name,
            table_name=table_name,
        )
    )
    cursor = _streaming_cursor(connection, engine)
    read_started_at = datetime.now(UTC)
    try:
        cursor.execute(query)
        while True:
            batch = cursor.fetchmany(fetch_size)
            # Each database read is bounded by fetch_size. Check Worker
            # control facts after every bounded fetch, including the final
            # empty fetch, so cancellation/fence loss cannot be hidden by a
            # long-running oracle scan or an empty table.
            _invoke_control_callback(control_callback)
            if not batch:
                break
            spool.add_rows(
                side,
                batch,
                logical_types,
                batch_size=fetch_size,
            )
            _invoke_control_callback(control_callback)
        read_finished_at = datetime.now(UTC)
        summary = spool.summary(
            side,
            control_callback=control_callback,
        )
        snapshot_finished_at = datetime.now(UTC)
        connection.commit()
        return SideRead(
            summary=summary,
            read_started_at=read_started_at,
            read_finished_at=read_finished_at,
            snapshot_id=marker if target_snapshot else None,
            snapshot_started_at=snapshot_started_at if target_snapshot else None,
            snapshot_finished_at=snapshot_finished_at if target_snapshot else None,
        )
    except BaseException:
        _safe_rollback(connection)
        raise
    finally:
        cursor.close()


def _invoke_control_callback(callback: Callable[[], None] | None) -> None:
    if callback is not None:
        callback()


def _begin_consistent_read(connection: Connection, engine: EngineName) -> str:
    _set_autocommit(connection, False)
    cursor = connection.cursor()
    try:
        if engine == "POSTGRESQL_15":
            cursor.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            cursor.execute("SELECT pg_catalog.txid_current_snapshot()::text")
            row = cursor.fetchone()
            if row is None:
                raise OracleDatabaseError("PostgreSQL snapshot marker is unavailable")
            raw_marker = str(row[0])
            prefix = "postgresql"
        elif engine == "MYSQL_8":
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cursor.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
            cursor.execute("SELECT @@server_uuid, @@GLOBAL.gtid_executed, CONNECTION_ID()")
            row = cursor.fetchone()
            if row is None:
                raise OracleDatabaseError("MySQL snapshot marker is unavailable")
            raw_marker = "\n".join(str(value) for value in row)
            prefix = "mysql"
        else:
            raise OracleDatabaseError("unsupported oracle database engine")
        # Some engines expose long transaction-snapshot strings. Hash the exact
        # marker to keep the non-secret report field bounded and immutable.
        marker_hash = hashlib.sha256(
            b"DXORACLESNAPSHOTv1\0" + engine.encode("ascii") + b"\0" + raw_marker.encode("utf-8")
        ).hexdigest()
        return f"{prefix}:{marker_hash}"
    finally:
        cursor.close()


def _streaming_cursor(connection: Connection, engine: EngineName) -> Cursor:
    if engine == "POSTGRESQL_15":
        cursor = connection.cursor(name=f"oracle_{uuid4().hex}")
        if hasattr(cursor, "itersize"):
            cursor.itersize = 1000
        return cursor
    # The safe connector configures an unbuffered SSCursor for this path.
    return connection.cursor()


def _set_autocommit(connection: Connection, value: bool) -> None:
    current = getattr(connection, "autocommit", None)
    if callable(current):
        current(value)
    else:
        connection.autocommit = value


def _safe_rollback(connection: Connection) -> None:
    with suppress(Exception):
        connection.rollback()
