from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import Engine, create_engine, text

import datax_studio.lifecycle as lifecycle
from datax_studio.lifecycle import StopPreflight, inspect_resume_preflight
from datax_studio.worker.main import decide_worker_loop


@pytest.mark.parametrize(
    (
        "runtime_ready",
        "egress_verified",
        "dispatcher_available",
        "draining",
        "expected_status",
        "expected_code",
        "expected_dispatch",
    ),
    [
        (
            False,
            True,
            True,
            False,
            "BLOCKED_RUNTIME",
            "RUNTIME_HASH_MISMATCH",
            False,
        ),
        (
            True,
            False,
            True,
            False,
            "BLOCKED_EGRESS",
            "EGRESS_POLICY_UNVERIFIED",
            False,
        ),
        (
            True,
            True,
            False,
            False,
            "DRAINING",
            "WORKER_DISPATCHER_INITIALIZATION_FAILED",
            False,
        ),
        (
            True,
            True,
            True,
            True,
            "DRAINING",
            "LIFECYCLE_DRAINING",
            False,
        ),
        (
            True,
            True,
            True,
            False,
            "READY",
            "WORKER_READY",
            True,
        ),
    ],
)
def test_worker_loop_never_dispatches_before_every_gate(
    runtime_ready: bool,
    egress_verified: bool,
    dispatcher_available: bool,
    draining: bool,
    expected_status: str,
    expected_code: str,
    expected_dispatch: bool,
) -> None:
    decision = decide_worker_loop(
        runtime_ready=runtime_ready,
        runtime_code="RUNTIME_HASH_MISMATCH",
        egress_verified=egress_verified,
        dispatcher_available=dispatcher_available,
        draining=draining,
    )

    assert decision.status == expected_status
    assert decision.code == expected_code
    assert decision.dispatch is expected_dispatch
    assert decision.reconcile_expired_leases is expected_dispatch


def _lifecycle_engine(
    *,
    now: datetime,
    control_epoch: str = "epoch-1",
    worker_epoch: str = "epoch-1",
    worker_updated_at: datetime | None = None,
    worker_status: str = "READY",
) -> Engine:
    engine = create_engine("sqlite+pysqlite://")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE executions (
                    id TEXT PRIMARY KEY,
                    process_state TEXT NOT NULL,
                    active_attempt_id TEXT
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE recovery_probes (
                    id TEXT PRIMARY KEY,
                    process_state TEXT NOT NULL,
                    active_attempt_id TEXT
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE system_control (
                    singleton_id INTEGER PRIMARY KEY,
                    draining BOOLEAN NOT NULL,
                    host_boot_id TEXT,
                    reconcile_epoch TEXT,
                    reconciled_at TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE worker_heartbeats (
                    worker_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    host_boot_id TEXT,
                    reconcile_epoch TEXT,
                    reconciled_at TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL
                )
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO system_control
                    (
                        singleton_id,
                        draining,
                        host_boot_id,
                        reconcile_epoch,
                        reconciled_at,
                        updated_at
                    )
                VALUES
                    (1, true, :boot_id, :epoch, :reconciled_at, :updated_at)
                """
            ),
            {
                "boot_id": "boot-1",
                "epoch": control_epoch,
                "reconciled_at": now,
                "updated_at": now,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO worker_heartbeats
                    (
                        worker_id,
                        status,
                        host_boot_id,
                        reconcile_epoch,
                        reconciled_at,
                        updated_at
                    )
                VALUES
                    (
                        'worker-1',
                        :status,
                        :boot_id,
                        :epoch,
                        :reconciled_at,
                        :updated_at
                    )
                """
            ),
            {
                "status": worker_status,
                "boot_id": "boot-1",
                "epoch": worker_epoch,
                "reconciled_at": now,
                "updated_at": worker_updated_at or now,
            },
        )
    return engine


def test_resume_accepts_only_fresh_matching_reconciliation_without_mutating_drain() -> None:
    now = datetime.now(UTC)
    engine = _lifecycle_engine(now=now)

    result = inspect_resume_preflight(
        engine,
        worker_id="worker-1",
        worker_stale_seconds=20,
        current_boot_id="boot-1",
        now=now + timedelta(seconds=1),
    )

    assert result.safe_to_stop is True
    assert result.code == "SAFE_TO_STOP"
    assert result.active_execution_count == 0
    assert result.active_probe_count == 0
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT draining FROM system_control WHERE singleton_id = 1")
            ).scalar_one()
            == 1
        )


def test_resume_accepts_fresh_reconciled_worker_blocked_by_storage() -> None:
    now = datetime.now(UTC)
    engine = _lifecycle_engine(
        now=now,
        worker_status="BLOCKED_STORAGE",
    )

    result = inspect_resume_preflight(
        engine,
        worker_id="worker-1",
        worker_stale_seconds=20,
        current_boot_id="boot-1",
        now=now,
    )

    assert result.safe_to_stop is True
    assert result.code == "SAFE_TO_STOP"


@pytest.mark.parametrize(
    ("control_epoch", "worker_epoch", "updated_delta", "worker_status"),
    [
        ("epoch-1", "epoch-2", 0, "READY"),
        ("epoch-1", "epoch-1", -30, "READY"),
        ("epoch-1", "epoch-1", 0, "STOPPED"),
    ],
)
def test_resume_blocks_mismatch_stale_or_stopped_worker(
    control_epoch: str,
    worker_epoch: str,
    updated_delta: int,
    worker_status: str,
) -> None:
    now = datetime.now(UTC)
    engine = _lifecycle_engine(
        now=now,
        control_epoch=control_epoch,
        worker_epoch=worker_epoch,
        worker_updated_at=now + timedelta(seconds=updated_delta),
        worker_status=worker_status,
    )

    result = inspect_resume_preflight(
        engine,
        worker_id="worker-1",
        worker_stale_seconds=20,
        current_boot_id="boot-1",
        now=now,
    )

    assert result.safe_to_stop is False
    assert result.code == "RECONCILIATION_NOT_CONFIRMED"


def test_resume_keeps_active_attempts_blocked() -> None:
    now = datetime.now(UTC)
    engine = _lifecycle_engine(now=now)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO executions
                    (id, process_state, active_attempt_id)
                VALUES
                    ('execution-1', 'RUNNING', 'attempt-1')
                """
            )
        )

    result = inspect_resume_preflight(
        engine,
        worker_id="worker-1",
        worker_stale_seconds=20,
        current_boot_id="boot-1",
        now=now,
    )

    assert result.safe_to_stop is False
    assert result.code == "ACTIVE_ATTEMPTS_PRESENT"
    assert result.active_execution_count == 1


def test_resume_cli_emits_launcher_accepted_safe_result_without_undraining(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_engine = object()
    monkeypatch.setattr(
        lifecycle,
        "get_settings",
        lambda: SimpleNamespace(
            database_url="unused",
            worker_id="worker-1",
            worker_stale_seconds=20,
        ),
    )
    monkeypatch.setattr(
        lifecycle,
        "create_engine",
        lambda _url, **_kwargs: fake_engine,
    )
    monkeypatch.setattr(
        lifecycle,
        "inspect_resume_preflight",
        lambda *_args, **_kwargs: StopPreflight(
            safe_to_stop=True,
            code="SAFE_TO_STOP",
            active_execution_count=0,
            active_probe_count=0,
        ),
    )
    monkeypatch.setattr(
        lifecycle,
        "set_draining",
        lambda *_args, **_kwargs: pytest.fail("resume must not mutate draining"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["datax-studio-lifecycle", "resume", "--json"],
    )

    with pytest.raises(SystemExit) as exited:
        lifecycle.main()

    assert exited.value.code == 0
    assert json.loads(capsys.readouterr().out) == {
        "safe_to_stop": True,
        "code": "SAFE_TO_STOP",
        "active_execution_count": 0,
        "active_probe_count": 0,
    }
