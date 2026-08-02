from __future__ import annotations

import ipaddress
import ssl
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

import psycopg
import pymysql

from datax_studio.credentials.network import (
    EgressLeaseSession,
    EndpointPolicyGuard,
    ResolvedEndpoint,
)
from datax_studio.credentials.operation_boundary import (
    OperationDeadline,
    OperationDeadlineExpired,
)
from datax_studio.schema_snapshot import SchemaSnapshot
from datax_studio.worker.schema_probe import (
    TableIdentity,
    physical_table_identity_hash,
    probe_schema_snapshot,
)


class DatasourceRevisionLike(Protocol):
    engine: str
    host: str
    port: int
    database_name: str
    default_schema: str
    username: str
    ssl_mode: str


@dataclass(frozen=True)
class ProbeResult:
    server_identity: str
    server_version: str
    peer_ip: str
    latency_ms: int
    tls_peer_spki_sha256: str | None = None


@dataclass(frozen=True)
class ColumnMetadata:
    schema_name: str
    table_name: str
    name: str
    ordinal: int
    native_type: str
    nullable: bool
    primary_key: bool


class DatabaseConnector:
    """Pinned MySQL/PostgreSQL connection probes with bounded queries."""

    def __init__(
        self,
        *,
        guard: EndpointPolicyGuard,
        connect_timeout_seconds: int,
        query_timeout_seconds: int,
    ) -> None:
        self.guard = guard
        self.connect_timeout_seconds = connect_timeout_seconds
        self.query_timeout_seconds = query_timeout_seconds

    def probe(
        self,
        revision: DatasourceRevisionLike,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
        control_callback: Callable[[], None] | None = None,
        deadline: OperationDeadline | None = None,
    ) -> ProbeResult:
        if deadline is not None:
            deadline.check_expired()
        if revision.engine == "POSTGRESQL_15":
            return self._probe_postgres(
                revision,
                password=password,
                resolved=resolved,
                control_callback=control_callback,
                deadline=deadline,
            )
        if revision.engine == "MYSQL_8":
            return self._probe_mysql(
                revision,
                password=password,
                resolved=resolved,
                control_callback=control_callback,
                deadline=deadline,
            )
        raise ValueError("UNSUPPORTED_ENGINE")

    @contextmanager
    def connection(
        self,
        revision: DatasourceRevisionLike,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
        stream: bool = False,
        read_only: bool = False,
        control_callback: Callable[[], None] | None = None,
        deadline: OperationDeadline | None = None,
    ) -> Iterator[psycopg.Connection | pymysql.Connection]:
        """Yield one pinned connection; callers never resolve the hostname again.

        PostgreSQL streaming callers can create a named cursor on the yielded
        non-autocommit connection. MySQL streaming callers receive a connection
        whose default cursor is SSCursor, so rows are not buffered in memory.
        """

        if revision.engine == "POSTGRESQL_15":
            with self._egress_lease(resolved, deadline=deadline) as lease:
                self._check_deadline(deadline)
                self._run_control_callback(control_callback)
                connection = self._connect_postgres(
                    revision,
                    password=password,
                    resolved=resolved,
                    lease=lease,
                    autocommit=not (stream or read_only),
                    deadline=deadline,
                )
                try:
                    self._check_deadline(deadline)
                    self._run_control_callback(control_callback)
                    if read_only:
                        self._run_control_callback(control_callback)
                        self._check_deadline(deadline)
                        self._apply_remaining_query_timeout(
                            connection,
                            engine=revision.engine,
                            deadline=deadline,
                        )
                        connection.execute(
                            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
                        )
                        self._run_control_callback(control_callback)
                        self._check_deadline(deadline)
                    yield connection
                    lease.assert_active()
                finally:
                    if not connection.autocommit:
                        connection.rollback()
                    connection.close()
            return
        if revision.engine == "MYSQL_8":
            cursor_class = pymysql.cursors.SSCursor if stream else pymysql.cursors.Cursor
            with self._egress_lease(resolved, deadline=deadline) as lease:
                self._check_deadline(deadline)
                self._run_control_callback(control_callback)
                connection = self._connect_mysql(
                    revision,
                    password=password,
                    resolved=resolved,
                    lease=lease,
                    cursor_class=cursor_class,
                    deadline=deadline,
                )
                try:
                    self._check_deadline(deadline)
                    self._run_control_callback(control_callback)
                    if read_only:
                        with connection.cursor() as cursor:
                            self._run_control_callback(control_callback)
                            self._check_deadline(deadline)
                            self._apply_remaining_query_timeout(
                                connection,
                                engine=revision.engine,
                                deadline=deadline,
                            )
                            cursor.execute("SET SESSION TRANSACTION READ ONLY")
                            self._run_control_callback(control_callback)
                            self._check_deadline(deadline)
                            self._run_control_callback(control_callback)
                            self._apply_remaining_query_timeout(
                                connection,
                                engine=revision.engine,
                                deadline=deadline,
                            )
                            cursor.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT")
                            self._run_control_callback(control_callback)
                    yield connection
                    lease.assert_active()
                finally:
                    self._close_mysql_connection(
                        connection,
                        deadline=deadline,
                        rollback=True,
                    )
            return
        raise ValueError("UNSUPPORTED_ENGINE")

    def schema_snapshots(
        self,
        revision: DatasourceRevisionLike,
        *,
        physical_endpoint_identity_id: UUID,
        password: bytearray,
        resolved: ResolvedEndpoint,
        schema_name: str | None,
        table_name: str | None,
        limit: int,
        after: tuple[str, str] | None = None,
        deadline: OperationDeadline | None = None,
    ) -> tuple[list[SchemaSnapshot], str, bool]:
        """Capture canonical, hashable table snapshots on one pinned connection."""

        with self.connection(
            revision,
            password=password,
            resolved=resolved,
            read_only=True,
            deadline=deadline,
        ) as connection:
            self._apply_remaining_query_timeout(
                connection,
                engine=revision.engine,
                deadline=deadline,
            )
            identities = self._list_table_identities(
                connection,
                revision=revision,
                physical_endpoint_identity_id=physical_endpoint_identity_id,
                schema_name=schema_name,
                table_name=table_name,
                limit=limit + 1,
                after=after,
            )
            # A listing query can itself consume the entire shared operation
            # budget, including when it returns an empty page.
            self._check_deadline(deadline)
            has_more = len(identities) > limit
            snapshots: list[SchemaSnapshot] = []
            for identity in identities[:limit]:
                self._apply_remaining_query_timeout(
                    connection,
                    engine=revision.engine,
                    deadline=deadline,
                )
                snapshots.append(
                    probe_schema_snapshot(
                        connection,
                        engine=revision.engine,  # type: ignore[arg-type]
                        identity=identity,
                        # The schema attestation contains several SQL
                        # statements.  Refresh the database-side timeout
                        # immediately before each one, while the control
                        # callback checks the shared deadline both before and
                        # after execute/fetch without issuing SQL mid-result.
                        control_callback=lambda: self._check_deadline(deadline),
                        statement_callback=lambda: self._apply_remaining_query_timeout(
                            connection,
                            engine=revision.engine,
                            deadline=deadline,
                        ),
                    )
                )
                self._check_deadline(deadline)
            peer_ip = self._connection_peer_ip(connection, revision.engine)
            self._check_deadline(deadline)
        if peer_ip != resolved.selected_ip:
            raise ValueError("ENDPOINT_PEER_MISMATCH")
        self._check_deadline(deadline)
        return snapshots, peer_ip, has_more

    def connection_peer_ip(
        self,
        connection: psycopg.Connection | pymysql.Connection,
        *,
        engine: str,
    ) -> str:
        """Return the normalized peer IP from an already pinned connection."""

        return self._connection_peer_ip(connection, engine)

    def columns(
        self,
        revision: DatasourceRevisionLike,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
        schema_name: str | None,
        table_name: str | None,
        limit: int,
    ) -> tuple[list[ColumnMetadata], str, int]:
        if revision.engine == "POSTGRESQL_15":
            return self._postgres_columns(
                revision,
                password=password,
                resolved=resolved,
                schema_name=schema_name,
                table_name=table_name,
                limit=limit,
            )
        if revision.engine == "MYSQL_8":
            return self._mysql_columns(
                revision,
                password=password,
                resolved=resolved,
                schema_name=schema_name,
                table_name=table_name,
                limit=limit,
            )
        raise ValueError("UNSUPPORTED_ENGINE")

    def _probe_postgres(
        self,
        revision: DatasourceRevisionLike,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
        control_callback: Callable[[], None] | None,
        deadline: OperationDeadline | None,
    ) -> ProbeResult:
        started = time.monotonic()
        with self._egress_lease(resolved, deadline=deadline) as lease:
            self._check_deadline(deadline)
            self._run_control_callback(control_callback)
            connection = self._connect_postgres(
                revision,
                password=password,
                resolved=resolved,
                lease=lease,
                deadline=deadline,
            )
            try:
                self._check_deadline(deadline)
                self._run_control_callback(control_callback)
                with connection.cursor() as cursor:
                    self._run_control_callback(control_callback)
                    self._apply_remaining_query_timeout(
                        connection,
                        engine=revision.engine,
                        deadline=deadline,
                    )
                    cursor.execute("SHOW server_version")
                    self._run_control_callback(control_callback)
                    server_version = str(cursor.fetchone()[0])
                    self._run_control_callback(control_callback)
                    # The first query result has been consumed, so it is now
                    # safe to issue the SET on a helper cursor.  Refresh the
                    # remaining total budget before the second probe query.
                    self._apply_remaining_query_timeout(
                        connection,
                        engine=revision.engine,
                        deadline=deadline,
                    )
                    cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
                    self._run_control_callback(control_callback)
                    server_identity = str(cursor.fetchone()[0])
                self._run_control_callback(control_callback)
                self._check_deadline(deadline)
                peer_ip = ipaddress.ip_address(connection.info.hostaddr).compressed
                if peer_ip != resolved.selected_ip:
                    raise ValueError("ENDPOINT_PEER_MISMATCH")
                lease.assert_active()
                return ProbeResult(
                    server_identity=server_identity,
                    server_version=server_version,
                    peer_ip=peer_ip,
                    latency_ms=max(0, int((time.monotonic() - started) * 1000)),
                )
            finally:
                connection.close()

    def _probe_mysql(
        self,
        revision: DatasourceRevisionLike,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
        control_callback: Callable[[], None] | None,
        deadline: OperationDeadline | None,
    ) -> ProbeResult:
        started = time.monotonic()
        with self._egress_lease(resolved, deadline=deadline) as lease:
            self._check_deadline(deadline)
            self._run_control_callback(control_callback)
            connection = self._connect_mysql(
                revision,
                password=password,
                resolved=resolved,
                lease=lease,
                deadline=deadline,
            )
            try:
                self._check_deadline(deadline)
                self._run_control_callback(control_callback)
                with connection.cursor() as cursor:
                    self._run_control_callback(control_callback)
                    self._apply_remaining_query_timeout(
                        connection,
                        engine=revision.engine,
                        deadline=deadline,
                    )
                    cursor.execute("SELECT VERSION(), @@server_uuid")
                    self._run_control_callback(control_callback)
                    server_version, server_identity = cursor.fetchone()
                self._run_control_callback(control_callback)
                self._check_deadline(deadline)
                peer_ip = ipaddress.ip_address(connection._sock.getpeername()[0]).compressed
                if peer_ip != resolved.selected_ip:
                    raise ValueError("ENDPOINT_PEER_MISMATCH")
                lease.assert_active()
                return ProbeResult(
                    server_identity=str(server_identity),
                    server_version=str(server_version),
                    peer_ip=peer_ip,
                    latency_ms=max(0, int((time.monotonic() - started) * 1000)),
                )
            finally:
                self._close_mysql_connection(
                    connection,
                    deadline=deadline,
                    rollback=False,
                )

    @staticmethod
    def _run_control_callback(callback: Callable[[], None] | None) -> None:
        """Consume a durable worker stop before the next probe operation."""

        if callback is not None:
            callback()

    @staticmethod
    def _check_deadline(deadline: OperationDeadline | None) -> None:
        if deadline is not None:
            deadline.check_expired()

    def _egress_lease(
        self,
        resolved: ResolvedEndpoint,
        *,
        deadline: OperationDeadline | None,
    ) -> EgressLeaseSession:
        """Pass a deadline when present without breaking narrow test guards."""

        if deadline is None:
            return self.guard.lease(resolved)
        return self.guard.lease(resolved, deadline=deadline)

    def _bounded_connect_timeout(
        self,
        deadline: OperationDeadline | None,
    ) -> float:
        if deadline is None:
            return float(self.connect_timeout_seconds)
        return deadline.bounded_timeout(self.connect_timeout_seconds)

    def _bounded_query_timeout(
        self,
        deadline: OperationDeadline | None,
    ) -> float:
        if deadline is None:
            return float(self.query_timeout_seconds)
        return deadline.bounded_timeout(self.query_timeout_seconds)

    def _postgres_connect_timeout_seconds(
        self,
        deadline: OperationDeadline | None,
    ) -> int:
        """Return a libpq integer timeout that never rounds beyond budget."""

        seconds = self._bounded_connect_timeout(deadline)
        if deadline is not None and seconds < 1.0:
            # libpq accepts whole seconds only.  Rounding a 0.2-second budget
            # up to one second violates the operation-wide limit, so fail
            # before opening a socket instead.
            raise OperationDeadlineExpired("DATASOURCE_OPERATION_DEADLINE_EXCEEDED")
        return max(1, int(seconds))

    def _bounded_query_timeout_milliseconds(
        self,
        deadline: OperationDeadline | None,
    ) -> int:
        milliseconds = self._bounded_query_timeout(deadline) * 1000
        if deadline is not None and milliseconds < 1.0:
            raise OperationDeadlineExpired("DATASOURCE_OPERATION_DEADLINE_EXCEEDED")
        return max(1, int(milliseconds))

    def _apply_remaining_query_timeout(
        self,
        connection: psycopg.Connection | pymysql.Connection,
        *,
        engine: str,
        deadline: OperationDeadline | None,
    ) -> None:
        """Clamp the next metadata/probe statement to the total deadline."""

        if deadline is None:
            return
        if engine == "MYSQL_8":
            # PyMySQL applies these private fields to every socket read/write,
            # including the MAX_EXECUTION_TIME SET itself, transaction setup,
            # rollback, and COM_QUIT.  The package version is pinned; refresh
            # them before every outgoing statement so prior TLS/auth time
            # cannot donate its old full timeout to later I/O.
            self._refresh_mysql_socket_timeout(connection, deadline=deadline)
        milliseconds = self._bounded_query_timeout_milliseconds(deadline)
        with connection.cursor() as cursor:
            if engine == "POSTGRESQL_15":
                cursor.execute(f"SET statement_timeout = {milliseconds}")
            elif engine == "MYSQL_8":
                cursor.execute(f"SET SESSION MAX_EXECUTION_TIME = {milliseconds}")
            else:
                raise ValueError("UNSUPPORTED_ENGINE")
        self._check_deadline(deadline)
        if engine == "MYSQL_8":
            # The budget-setting round trip can itself consume time.  Refresh
            # again so the caller's immediately following statement does not
            # inherit the timeout that applied only to this SET command.
            self._refresh_mysql_socket_timeout(connection, deadline=deadline)

    def _refresh_mysql_socket_timeout(
        self,
        connection: psycopg.Connection | pymysql.Connection,
        *,
        deadline: OperationDeadline | None,
    ) -> None:
        """Clamp PyMySQL's next socket read/write to the shared budget."""

        if deadline is None:
            return
        timeout = self._bounded_query_timeout(deadline)
        # PyMySQL 1.2.0 exposes these fields and uses them in _read_bytes() /
        # _write_bytes().  Do not silently continue without the client-side
        # clamp: server MAX_EXECUTION_TIME cannot bound a network black hole.
        if not isinstance(connection, pymysql.Connection):
            raise ValueError("MYSQL_CLIENT_TIMEOUT_UNAVAILABLE")
        connection._read_timeout = timeout
        connection._write_timeout = timeout

    @staticmethod
    def _force_close_mysql(connection: pymysql.Connection) -> None:
        """Close a MySQL socket without sending COM_QUIT."""

        connection._force_close()

    def _close_mysql_connection(
        self,
        connection: pymysql.Connection,
        *,
        deadline: OperationDeadline | None,
        rollback: bool,
    ) -> None:
        """Bound cleanup so it cannot reuse a stale PyMySQL I/O timeout."""

        try:
            if deadline is not None:
                if deadline.remaining_seconds() <= 0.0:
                    self._force_close_mysql(connection)
                    raise OperationDeadlineExpired("DATASOURCE_OPERATION_DEADLINE_EXCEEDED")
                self._refresh_mysql_socket_timeout(connection, deadline=deadline)
            if rollback:
                connection.rollback()
            if deadline is not None:
                if deadline.remaining_seconds() <= 0.0:
                    self._force_close_mysql(connection)
                    raise OperationDeadlineExpired("DATASOURCE_OPERATION_DEADLINE_EXCEEDED")
                self._refresh_mysql_socket_timeout(connection, deadline=deadline)
            connection.close()
        except BaseException:
            self._force_close_mysql(connection)
            raise

    def _postgres_columns(
        self,
        revision: DatasourceRevisionLike,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
        schema_name: str | None,
        table_name: str | None,
        limit: int,
    ) -> tuple[list[ColumnMetadata], str, int]:
        with self.guard.lease(resolved) as lease:
            connection = self._connect_postgres(
                revision,
                password=password,
                resolved=resolved,
                lease=lease,
            )
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                    SELECT
                        c.table_schema,
                        c.table_name,
                        c.column_name,
                        c.ordinal_position,
                        c.udt_name,
                        c.is_nullable = 'YES',
                        EXISTS (
                            SELECT 1
                            FROM information_schema.table_constraints tc
                            JOIN information_schema.key_column_usage kcu
                              ON tc.constraint_name = kcu.constraint_name
                             AND tc.constraint_schema = kcu.constraint_schema
                             AND tc.table_name = kcu.table_name
                            WHERE tc.constraint_type = 'PRIMARY KEY'
                              AND tc.table_schema = c.table_schema
                              AND tc.table_name = c.table_name
                              AND kcu.column_name = c.column_name
                        )
                    FROM information_schema.columns c
                    WHERE c.table_catalog = %s
                      AND (%s IS NULL OR c.table_schema = %s)
                      AND (%s IS NULL OR c.table_name = %s)
                    ORDER BY c.table_schema, c.table_name, c.ordinal_position
                    LIMIT %s
                    """,
                        (
                            revision.database_name,
                            schema_name,
                            schema_name,
                            table_name,
                            table_name,
                            limit,
                        ),
                    )
                    rows = cursor.fetchall()
                peer_ip = ipaddress.ip_address(connection.info.hostaddr).compressed
                if peer_ip != resolved.selected_ip:
                    raise ValueError("ENDPOINT_PEER_MISMATCH")
                lease.assert_active()
                return (
                    [
                        ColumnMetadata(
                            schema_name=str(row[0]),
                            table_name=str(row[1]),
                            name=str(row[2]),
                            ordinal=int(row[3]),
                            native_type=str(row[4]),
                            nullable=bool(row[5]),
                            primary_key=bool(row[6]),
                        )
                        for row in rows
                    ],
                    peer_ip,
                    limit,
                )
            finally:
                connection.close()

    def _mysql_columns(
        self,
        revision: DatasourceRevisionLike,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
        schema_name: str | None,
        table_name: str | None,
        limit: int,
    ) -> tuple[list[ColumnMetadata], str, int]:
        with self.guard.lease(resolved) as lease:
            connection = self._connect_mysql(
                revision,
                password=password,
                resolved=resolved,
                lease=lease,
            )
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                    SELECT
                        TABLE_SCHEMA,
                        TABLE_NAME,
                        COLUMN_NAME,
                        ORDINAL_POSITION,
                        COLUMN_TYPE,
                        IS_NULLABLE = 'YES',
                        COLUMN_KEY = 'PRI'
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = %s
                      AND (%s IS NULL OR TABLE_SCHEMA = %s)
                      AND (%s IS NULL OR TABLE_NAME = %s)
                    ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION
                    LIMIT %s
                    """,
                        (
                            revision.database_name,
                            schema_name,
                            schema_name,
                            table_name,
                            table_name,
                            limit,
                        ),
                    )
                    rows = cursor.fetchall()
                peer_ip = ipaddress.ip_address(connection._sock.getpeername()[0]).compressed
                if peer_ip != resolved.selected_ip:
                    raise ValueError("ENDPOINT_PEER_MISMATCH")
                lease.assert_active()
                return (
                    [
                        ColumnMetadata(
                            schema_name=str(row[0]),
                            table_name=str(row[1]),
                            name=str(row[2]),
                            ordinal=int(row[3]),
                            native_type=str(row[4]),
                            nullable=bool(row[5]),
                            primary_key=bool(row[6]),
                        )
                        for row in rows
                    ],
                    peer_ip,
                    limit,
                )
            finally:
                connection.close()

    def _list_table_identities(
        self,
        connection: psycopg.Connection | pymysql.Connection,
        *,
        revision: DatasourceRevisionLike,
        physical_endpoint_identity_id: UUID,
        schema_name: str | None,
        table_name: str | None,
        limit: int,
        after: tuple[str, str] | None,
    ) -> list[TableIdentity]:
        effective_schema = schema_name or revision.default_schema
        after_schema = after[0] if after is not None else None
        after_table = after[1] if after is not None else None
        with connection.cursor() as cursor:
            if revision.engine == "POSTGRESQL_15":
                cursor.execute(
                    """
                    SELECT table_catalog, table_schema, table_name
                    FROM information_schema.tables
                    WHERE table_type = 'BASE TABLE'
                      AND table_catalog = %s
                      AND table_schema = %s
                      AND (%s IS NULL OR table_name = %s)
                      AND (
                        %s IS NULL
                        OR table_schema > %s
                        OR (table_schema = %s AND table_name > %s)
                      )
                    ORDER BY table_schema, table_name
                    LIMIT %s
                    """,
                    (
                        revision.database_name,
                        effective_schema,
                        table_name,
                        table_name,
                        after_schema,
                        after_schema,
                        after_schema,
                        after_table,
                        limit,
                    ),
                )
            elif revision.engine == "MYSQL_8":
                cursor.execute(
                    """
                    SELECT table_schema, table_name
                    FROM information_schema.tables
                    WHERE table_type = 'BASE TABLE'
                      AND table_schema = %s
                      AND (%s IS NULL OR table_name = %s)
                      AND (
                        %s IS NULL
                        OR table_schema > %s
                        OR (table_schema = %s AND table_name > %s)
                      )
                    ORDER BY table_schema, table_name
                    LIMIT %s
                    """,
                    (
                        effective_schema,
                        table_name,
                        table_name,
                        after_schema,
                        after_schema,
                        after_schema,
                        after_table,
                        limit,
                    ),
                )
            else:
                raise ValueError("UNSUPPORTED_ENGINE")
            rows = cursor.fetchall()
        identities: list[TableIdentity] = []
        for row in rows:
            if revision.engine == "POSTGRESQL_15":
                catalog_name, identity_schema, actual_table = map(str, row)
            else:
                catalog_name, actual_table = map(str, row)
                identity_schema = ""
            identities.append(
                TableIdentity(
                    physical_endpoint_identity_id=physical_endpoint_identity_id,
                    physical_table_identity_hash=physical_table_identity_hash(
                        physical_endpoint_identity_id=physical_endpoint_identity_id,
                        engine=revision.engine,  # type: ignore[arg-type]
                        catalog_name=catalog_name,
                        schema_name=identity_schema,
                        table_name=actual_table,
                    ),
                    catalog_name=catalog_name,
                    schema_name=identity_schema,
                    table_name=actual_table,
                )
            )
        return identities

    @staticmethod
    def _connection_peer_ip(
        connection: psycopg.Connection | pymysql.Connection,
        engine: str,
    ) -> str:
        if engine == "POSTGRESQL_15":
            return ipaddress.ip_address(connection.info.hostaddr).compressed
        if engine == "MYSQL_8":
            raw_socket = connection._sock
            if raw_socket is None:
                raise ValueError("ENDPOINT_PEER_UNAVAILABLE")
            return ipaddress.ip_address(raw_socket.getpeername()[0]).compressed
        raise ValueError("UNSUPPORTED_ENGINE")

    def _connect_postgres(
        self,
        revision: DatasourceRevisionLike,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
        lease: EgressLeaseSession,
        autocommit: bool = True,
        deadline: OperationDeadline | None = None,
    ) -> psycopg.Connection:
        self._check_deadline(deadline)
        lease.assert_active()
        password_text = bytes(password).decode("utf-8")
        try:
            connect_timeout = self._postgres_connect_timeout_seconds(deadline)
            query_timeout_milliseconds = self._bounded_query_timeout_milliseconds(deadline)
            connection = psycopg.connect(
                host=revision.host,
                hostaddr=resolved.selected_ip,
                port=revision.port,
                dbname=revision.database_name,
                user=revision.username,
                password=password_text,
                sslmode=revision.ssl_mode.casefold().replace("_", "-"),
                connect_timeout=connect_timeout,
                options=f"-c statement_timeout={query_timeout_milliseconds}",
                autocommit=autocommit,
            )
        finally:
            del password_text
        lease.assert_active()
        self._check_deadline(deadline)
        return connection

    def _connect_mysql(
        self,
        revision: DatasourceRevisionLike,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
        lease: EgressLeaseSession,
        cursor_class: type[pymysql.cursors.Cursor] = pymysql.cursors.Cursor,
        deadline: OperationDeadline | None = None,
    ) -> pymysql.Connection:
        self._check_deadline(deadline)
        ssl_context: ssl.SSLContext | None
        if revision.ssl_mode == "DISABLE":
            ssl_context = None
        elif revision.ssl_mode == "REQUIRE":
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        elif revision.ssl_mode == "VERIFY_CA":
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
        elif revision.ssl_mode == "VERIFY_FULL":
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = True
        else:
            raise ValueError("SSL_MODE_INVALID")

        connect_timeout = self._bounded_connect_timeout(deadline)
        query_timeout = self._bounded_query_timeout(deadline)
        connection = pymysql.Connection(
            user=revision.username,
            password=password,
            host=revision.host,
            database=revision.database_name,
            port=revision.port,
            charset="utf8mb4",
            cursorclass=cursor_class,
            autocommit=True,
            local_infile=False,
            connect_timeout=connect_timeout,
            read_timeout=query_timeout,
            write_timeout=query_timeout,
            defer_connect=True,
            ssl=ssl_context,
            ssl_disabled=ssl_context is None,
            program_name="datax-enterprise-studio",
        )
        raw_socket = self.guard.connect_tcp(
            resolved,
            lease=lease,
            deadline=deadline,
        )
        try:
            # ``connect_tcp`` is itself deadline-bounded and can consume most
            # of the original budget.  PyMySQL performs its greeting/auth/TLS
            # exchange using private read/write timeouts, so recompute them
            # only after the pinned TCP connection is established.  Otherwise
            # a near-expired TCP stage would grant handshake I/O a fresh full
            # timeout.
            self._check_deadline(deadline)
            handshake_timeout = self._bounded_connect_timeout(deadline)
            connection._read_timeout = handshake_timeout
            connection._write_timeout = handshake_timeout
            connection.connect(sock=raw_socket)
        except BaseException:
            raw_socket.close()
            connection.close()
            raise
        self._apply_remaining_query_timeout(
            connection,
            engine=revision.engine,
            deadline=deadline,
        )
        lease.assert_active()
        self._check_deadline(deadline)
        return connection
