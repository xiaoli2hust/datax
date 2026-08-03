from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

import datax_studio.credentials.connectors as connectors_module
from datax_studio.credentials.connectors import DatabaseConnector
from datax_studio.credentials.network import DnsResolution, EndpointPolicyGuard
from datax_studio.credentials.operation_boundary import (
    OperationDeadline,
    OperationDeadlineExpired,
)
from datax_studio.egress_attestation import EgressVerification
from datax_studio.worker.schema_probe import TableIdentity


class _Clock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class _RecordingResolver:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def resolve(
        self,
        _hostname: str,
        *,
        timeout_seconds: float,
        ttl_ceiling_seconds: int,
        deadline: OperationDeadline | None = None,
    ) -> DnsResolution:
        del ttl_ceiling_seconds, deadline
        self.timeouts.append(timeout_seconds)
        return DnsResolution((), ("192.0.2.10",), 30)


class _Verifier:
    def verify_runtime(self) -> EgressVerification:
        return self._verification()

    def verify_policy(self, **_kwargs: object) -> EgressVerification:
        return self._verification()

    @staticmethod
    def _verification() -> EgressVerification:
        return EgressVerification(
            policy_engine_version="egress-v1",
            resolver_policy_version="resolver-v1",
            network_namespace_id="net:[1]",
            policy_set_hash="1" * 64,
            ruleset_hash="2" * 64,
            checked_at=datetime.now(UTC),
        )


class _PolicyRevision:
    id = UUID("11111111-1111-1111-1111-111111111111")
    host_kind = "EXACT_FQDN"
    host_value = "db.example.test"
    allowed_cidrs = ["192.0.2.0/24"]
    allowed_ports = [5432]
    dns_ttl_ceiling_seconds = 60
    resolver_policy_version = "resolver-v1"
    egress_policy_version = "egress-v1"
    policy_hash = "3" * 64


def _guard(resolver: _RecordingResolver) -> EndpointPolicyGuard:
    return EndpointPolicyGuard(
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        egress_verifier=_Verifier(),
        resolver=resolver,
        connect_timeout_seconds=5.0,
    )


def test_resolver_timeout_is_capped_by_remaining_operation_deadline() -> None:
    clock = _Clock()
    deadline = OperationDeadline(total_seconds=10.0, monotonic_clock=clock)
    resolver = _RecordingResolver()

    clock.value = 7.25
    _guard(resolver).resolve(
        _PolicyRevision(),
        host="db.example.test",
        port=5432,
        deadline=deadline,
    )

    assert resolver.timeouts == [2.75]


def test_exhausted_operation_deadline_rejects_before_dns_resolution() -> None:
    clock = _Clock()
    deadline = OperationDeadline(total_seconds=1.0, monotonic_clock=clock)
    resolver = _RecordingResolver()
    clock.value = 1.0

    with pytest.raises(OperationDeadlineExpired, match="DEADLINE_EXCEEDED"):
        _guard(resolver).resolve(
            _PolicyRevision(),
            host="db.example.test",
            port=5432,
            deadline=deadline,
        )

    assert resolver.timeouts == []


def test_schema_snapshots_does_not_reset_deadline_between_tables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An expired first table budget prevents probing the next table."""

    clock = _Clock()
    deadline = OperationDeadline(total_seconds=5.0, monotonic_clock=clock)
    connector = DatabaseConnector(
        guard=SimpleNamespace(),  # type: ignore[arg-type]
        connect_timeout_seconds=5,
        query_timeout_seconds=10,
    )
    deadline_objects: list[OperationDeadline | None] = []
    probed_tables: list[str] = []

    @contextmanager
    def fake_connection(*_args: object, **_kwargs: object):
        yield object()

    identities = [
        TableIdentity(
            physical_endpoint_identity_id=uuid4(),
            physical_table_identity_hash="a" * 64,
            catalog_name="warehouse",
            schema_name="public",
            table_name="orders",
        ),
        TableIdentity(
            physical_endpoint_identity_id=uuid4(),
            physical_table_identity_hash="b" * 64,
            catalog_name="warehouse",
            schema_name="public",
            table_name="customers",
        ),
    ]

    monkeypatch.setattr(connector, "connection", fake_connection)
    monkeypatch.setattr(
        connector,
        "_list_table_identities",
        lambda *_args, **_kwargs: identities,
    )

    def record_statement_timeout(
        _connection: object,
        *,
        engine: str,
        deadline: OperationDeadline | None,
    ) -> None:
        assert engine == "POSTGRESQL_15"
        deadline_objects.append(deadline)
        assert deadline is not None
        deadline.check_expired()

    monkeypatch.setattr(
        connector,
        "_apply_remaining_query_timeout",
        record_statement_timeout,
    )

    def expire_after_first_probe(
        _connection: object,
        *,
        engine: str,
        identity: TableIdentity,
        **_kwargs: object,
    ) -> object:
        assert engine == "POSTGRESQL_15"
        probed_tables.append(identity.table_name)
        clock.value = 5.0
        return object()

    monkeypatch.setattr(
        connectors_module,
        "probe_schema_snapshot",
        expire_after_first_probe,
    )

    with pytest.raises(OperationDeadlineExpired, match="DEADLINE_EXCEEDED"):
        connector.schema_snapshots(
            SimpleNamespace(engine="POSTGRESQL_15"),
            physical_endpoint_identity_id=uuid4(),
            password=bytearray(b"secret"),
            resolved=SimpleNamespace(selected_ip="192.0.2.10"),
            schema_name=None,
            table_name=None,
            limit=2,
            deadline=deadline,
        )

    assert probed_tables == ["orders"]
    assert deadline_objects == [deadline, deadline]


def test_mysql_handshake_timeout_is_reclamped_after_tcp_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TCP time must not leave PyMySQL auth/TLS with the old full timeout."""

    clock = _Clock()
    deadline = OperationDeadline(total_seconds=5.0, monotonic_clock=clock)
    raw_socket = SimpleNamespace(closed=False)

    def close() -> None:
        raw_socket.closed = True

    raw_socket.close = close

    class _Lease:
        def assert_active(self) -> None:
            return None

    class _Guard:
        def connect_tcp(self, *_args: object, **_kwargs: object) -> object:
            # The pinned TCP stage uses almost all of the shared budget.
            clock.value = 4.75
            return raw_socket

    created: list[object] = []

    class _Connection:
        def __init__(self, **kwargs: object) -> None:
            self._read_timeout = kwargs["read_timeout"]
            self._write_timeout = kwargs["write_timeout"]
            self.handshake_read_timeout: object | None = None
            self.handshake_write_timeout: object | None = None
            created.append(self)

        def connect(self, *, sock: object) -> None:
            assert sock is raw_socket
            self.handshake_read_timeout = self._read_timeout
            self.handshake_write_timeout = self._write_timeout

        def close(self) -> None:
            return None

    connector = DatabaseConnector(
        guard=_Guard(),  # type: ignore[arg-type]
        connect_timeout_seconds=5,
        query_timeout_seconds=5,
    )
    monkeypatch.setattr(connectors_module.pymysql, "Connection", _Connection)
    monkeypatch.setattr(
        connector,
        "_apply_remaining_query_timeout",
        lambda *_args, **_kwargs: None,
    )

    connection = connector._connect_mysql(
        SimpleNamespace(
            engine="MYSQL_8",
            ssl_mode="DISABLE",
            username="user",
            host="db.example.test",
            database_name="warehouse",
            port=3306,
        ),
        password=bytearray(b"secret"),
        resolved=SimpleNamespace(),
        lease=_Lease(),
        deadline=deadline,
    )

    assert connection is created[0]
    assert connection.handshake_read_timeout == pytest.approx(0.25)
    assert connection.handshake_write_timeout == pytest.approx(0.25)


def test_mysql_statement_budget_refreshes_client_socket_after_set_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SQL timeout SET must not leave the next client read at its old cap."""

    clock = _Clock()
    deadline = OperationDeadline(total_seconds=5.0, monotonic_clock=clock)
    events: list[tuple[str, float, float]] = []

    class _Cursor:
        def __enter__(self) -> _Cursor:
            return self

        def __exit__(
            self,
            _type: object,
            _value: object,
            _traceback: object,
        ) -> None:
            return None

        def execute(self, statement: str) -> None:
            events.append((statement, connection._read_timeout, connection._write_timeout))
            # The budget-setting network round trip consumes most of what
            # remained.  The target statement must use a re-clamped value.
            clock.value = 4.9

    class _Connection:
        def __init__(self) -> None:
            self._read_timeout = 5.0
            self._write_timeout = 5.0

        def cursor(self) -> _Cursor:
            return _Cursor()

    connection = _Connection()
    connector = DatabaseConnector(
        guard=SimpleNamespace(),  # type: ignore[arg-type]
        connect_timeout_seconds=5,
        query_timeout_seconds=5,
    )
    monkeypatch.setattr(connectors_module.pymysql, "Connection", _Connection)

    connector._apply_remaining_query_timeout(
        connection,
        engine="MYSQL_8",
        deadline=deadline,
    )

    assert events == [("SET SESSION MAX_EXECUTION_TIME = 5000", 5.0, 5.0)]
    assert connection._read_timeout == pytest.approx(0.1)
    assert connection._write_timeout == pytest.approx(0.1)


def test_mysql_cleanup_reclamps_quit_after_rollback_uses_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rollback time cannot donate its original socket timeout to COM_QUIT."""

    clock = _Clock()
    deadline = OperationDeadline(total_seconds=5.0, monotonic_clock=clock)
    events: list[tuple[str, float, float]] = []

    class _Connection:
        def __init__(self) -> None:
            self._read_timeout = 5.0
            self._write_timeout = 5.0

        def rollback(self) -> None:
            events.append(("rollback", self._read_timeout, self._write_timeout))
            clock.value = 4.9

        def close(self) -> None:
            events.append(("close", self._read_timeout, self._write_timeout))

        def _force_close(self) -> None:
            events.append(("force-close", self._read_timeout, self._write_timeout))

    connection = _Connection()
    connector = DatabaseConnector(
        guard=SimpleNamespace(),  # type: ignore[arg-type]
        connect_timeout_seconds=5,
        query_timeout_seconds=5,
    )
    monkeypatch.setattr(connectors_module.pymysql, "Connection", _Connection)

    connector._close_mysql_connection(
        connection,
        deadline=deadline,
        rollback=True,
    )

    assert events == [
        ("rollback", 5.0, 5.0),
        ("close", pytest.approx(0.1), pytest.approx(0.1)),
    ]
