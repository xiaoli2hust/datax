from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from datax_studio.api.problems import ProblemException
from datax_studio.recovery.service import ClaimedRecoveryProbe
from datax_studio.worker import recovery_probe as recovery_probe_module
from datax_studio.worker.recovery_probe import RecoveryProbeWorker


@pytest.mark.parametrize(
    ("stop_after", "forbidden_next_action", "callback_action"),
    [
        ("resolve", "probe", None),
        ("probe", "schema_connect", None),
        ("schema_connect", "schema_query", None),
        ("schema_query", "count_connect", "schema_control"),
        ("count_connect", "peer", None),
        ("peer", "count_query", None),
        ("count_query", "persist", "count_control"),
    ],
)
def test_probe_polls_safety_stop_after_each_bounded_database_action(
    monkeypatch: pytest.MonkeyPatch,
    stop_after: str,
    forbidden_next_action: str,
    callback_action: str | None,
) -> None:
    """An observed stop must prevent the next outbound connection or query."""

    actions: list[str] = []
    termination_completions: list[ClaimedRecoveryProbe] = []
    completed_results: list[str] = []
    state = SimpleNamespace(stop_requested=False, fence_lost=False)
    connection_count = 0

    def trigger(action: str) -> None:
        if action == stop_after:
            state.stop_requested = True

    class _Lease:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> _Lease:
            return self

        def __exit__(
            self,
            _type: object,
            _value: object,
            _traceback: object,
        ) -> None:
            return None

        def assert_owned(self) -> None:
            if state.fence_lost:
                raise ProblemException(
                    status=409,
                    code="RECOVERY_PROBE_FENCE_LOST",
                    title="fence lost",
                    detail="fixture",
                )

    class _Guard:
        def resolve(self, *_args: object, **_kwargs: object) -> object:
            actions.append("resolve")
            trigger("resolve")
            return object()

    class _Connector:
        def probe(
            self,
            *_args: object,
            control_callback: Callable[[], None] | None = None,
            **_kwargs: object,
        ) -> SimpleNamespace:
            actions.append("probe")
            trigger("probe")
            actions.append("probe_control")
            assert control_callback is not None
            control_callback()
            return SimpleNamespace(server_identity="target", server_version="15.1")

        @contextmanager
        def connection(self, *_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
            nonlocal connection_count
            action = "schema_connect" if connection_count == 0 else "count_connect"
            connection_count += 1
            actions.append(action)
            trigger(action)
            yield object()

        def connection_peer_ip(self, *_args: object, **_kwargs: object) -> str:
            actions.append("peer")
            trigger("peer")
            return "127.0.0.1"

    class _Recovery:
        def start_claimed_probe(self, _claim: ClaimedRecoveryProbe) -> None:
            return None

        def poll_claimed_probe_termination(self, _claim: ClaimedRecoveryProbe) -> bool:
            return bool(state.stop_requested)

        def complete_claimed_probe_termination(
            self,
            claim: ClaimedRecoveryProbe,
        ) -> bool:
            termination_completions.append(claim)
            return True

        def complete_probe(self, *, result: str, **_kwargs: object) -> None:
            completed_results.append(result)

    context = SimpleNamespace(
        datasource=SimpleNamespace(id=uuid4()),
        probe=SimpleNamespace(
            target_secret_id=uuid4(),
            target_secret_envelope_id=uuid4(),
        ),
        policy=SimpleNamespace(),
        revision=SimpleNamespace(
            id=uuid4(),
            host="target.example.test",
            port=5432,
            engine="POSTGRESQL_15",
        ),
        namespace=SimpleNamespace(
            id=uuid4(),
            physical_endpoint_identity_id=uuid4(),
            physical_table_identity_hash="a" * 64,
            normalized_catalog_name="target",
            normalized_schema_name="public",
            normalized_table_name="target_table",
        ),
        version=SimpleNamespace(target_schema_hash="b" * 64),
        spec=SimpleNamespace(
            target=SimpleNamespace(
                table=SimpleNamespace(schema_name="public", table_name="target_table")
            )
        ),
    )
    worker = object.__new__(RecoveryProbeWorker)
    worker.settings = SimpleNamespace(worker_lease_seconds=30)
    worker.control = SimpleNamespace()
    worker.recovery = _Recovery()
    worker.credentials = SimpleNamespace(
        guard=_Guard(),
        connector=_Connector(),
        sessions=lambda: nullcontext(object()),
        decrypted_worker_password=lambda **_kwargs: nullcontext(bytearray(b"secret")),
    )
    worker._load_context = lambda _claim: context  # type: ignore[method-assign]
    worker._assert_physical_endpoint = lambda **_kwargs: None  # type: ignore[method-assign]

    def persist_evidence(**_kwargs: object) -> UUID:
        actions.append("persist")
        return uuid4()

    worker._persist_evidence = persist_evidence  # type: ignore[method-assign]

    def schema_query(
        *_args: object,
        control_callback: Callable[[], None] | None = None,
        **_kwargs: object,
    ) -> object:
        actions.append("schema_query")
        trigger("schema_query")
        actions.append("schema_control")
        assert control_callback is not None
        control_callback()
        return object()

    def count_query(
        *_args: object,
        control_callback: Callable[[], None] | None = None,
        **_kwargs: object,
    ) -> tuple[int, datetime]:
        actions.append("count_query")
        trigger("count_query")
        actions.append("count_control")
        assert control_callback is not None
        control_callback()
        return 0, datetime.now(UTC)

    def assert_snapshot(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(recovery_probe_module, "ProbeLeaseKeeper", _Lease)
    monkeypatch.setattr(recovery_probe_module, "probe_schema_snapshot", schema_query)
    monkeypatch.setattr(
        recovery_probe_module,
        "assert_snapshot_matches_job",
        assert_snapshot,
    )
    monkeypatch.setattr(recovery_probe_module, "count_target_rows", count_query)
    claim = ClaimedRecoveryProbe(
        recovery_probe_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    worker.run_claimed(claim)

    assert stop_after in actions
    assert forbidden_next_action not in actions
    if callback_action is not None:
        assert callback_action in actions
    assert termination_completions == [claim]
    assert completed_results == []


def test_probe_fence_loss_after_resolution_prevents_database_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actions: list[str] = []
    termination_polls = 0
    state = SimpleNamespace(fence_lost=False)

    class _Lease:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> _Lease:
            return self

        def __exit__(
            self,
            _type: object,
            _value: object,
            _traceback: object,
        ) -> None:
            return None

        def assert_owned(self) -> None:
            if state.fence_lost:
                raise ProblemException(
                    status=409,
                    code="RECOVERY_PROBE_FENCE_LOST",
                    title="fence lost",
                    detail="fixture",
                )

    class _Guard:
        def resolve(self, *_args: object, **_kwargs: object) -> object:
            actions.append("resolve")
            state.fence_lost = True
            return object()

    class _Connector:
        def probe(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
            actions.append("probe")
            return SimpleNamespace(server_identity="target", server_version="15.1")

    class _Recovery:
        def start_claimed_probe(self, _claim: ClaimedRecoveryProbe) -> None:
            return None

        def poll_claimed_probe_termination(self, _claim: ClaimedRecoveryProbe) -> bool:
            nonlocal termination_polls
            termination_polls += 1
            return False

        def complete_claimed_probe_termination(self, _claim: ClaimedRecoveryProbe) -> bool:
            pytest.fail("a lost fence must not attempt a terminal write")

    context = SimpleNamespace(
        datasource=SimpleNamespace(id=uuid4()),
        probe=SimpleNamespace(
            target_secret_id=uuid4(),
            target_secret_envelope_id=uuid4(),
        ),
        policy=SimpleNamespace(),
        revision=SimpleNamespace(host="target.example.test", port=5432),
    )
    worker = object.__new__(RecoveryProbeWorker)
    worker.settings = SimpleNamespace(worker_lease_seconds=30)
    worker.control = SimpleNamespace()
    worker.recovery = _Recovery()
    worker.credentials = SimpleNamespace(
        guard=_Guard(),
        connector=_Connector(),
        sessions=lambda: nullcontext(object()),
        decrypted_worker_password=lambda **_kwargs: nullcontext(bytearray(b"secret")),
    )
    worker._load_context = lambda _claim: context  # type: ignore[method-assign]
    monkeypatch.setattr(recovery_probe_module, "ProbeLeaseKeeper", _Lease)
    claim = ClaimedRecoveryProbe(
        recovery_probe_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    worker.run_claimed(claim)

    assert actions == ["resolve"]
    assert termination_polls >= 1
