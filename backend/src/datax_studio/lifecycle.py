from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, bindparam, create_engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError

from datax_studio.settings import get_settings

ACTIVE_EXECUTION_STATES = (
    "STARTING",
    "RUNNING",
    "VERIFYING",
    "CANCEL_REQUESTED",
)
ACTIVE_PROBE_STATES = ("STARTING", "RUNNING")
_ACTIVE_RELATIONS = frozenset({"executions", "recovery_probes"})


@dataclass(frozen=True)
class StopPreflight:
    safe_to_stop: bool
    code: str
    active_execution_count: int
    active_probe_count: int


def _relation_exists(engine: Engine, relation: str) -> bool:
    if relation not in _ACTIVE_RELATIONS:
        raise ValueError("unsupported lifecycle relation")
    return inspect(engine).has_table(relation)


def _active_count(engine: Engine, relation: str, states: tuple[str, ...]) -> int:
    if not _relation_exists(engine, relation):
        return 0
    statement = text(
        f"""
        SELECT count(*)
        FROM {relation}
        WHERE process_state IN :states
           OR active_attempt_id IS NOT NULL
        """
    ).bindparams(bindparam("states", expanding=True))
    with engine.connect() as connection:
        return int(connection.execute(statement, {"states": list(states)}).scalar_one())


def set_draining(engine: Engine, draining: bool, reason: str) -> None:
    with engine.begin() as connection:
        updated = connection.execute(
            text(
                """
                UPDATE system_control
                SET draining = :draining, reason = :reason, updated_at = CURRENT_TIMESTAMP
                WHERE singleton_id = 1
                """
            ),
            {"draining": draining, "reason": reason},
        )
        if updated.rowcount != 1:
            raise RuntimeError("system lifecycle control row is missing")


def is_draining(engine: Engine) -> bool:
    with engine.connect() as connection:
        return bool(
            connection.execute(
                text(
                    """
                    SELECT draining
                    FROM system_control
                    WHERE singleton_id = 1
                    """
                )
            ).scalar_one()
        )


def inspect_stop_preflight(engine: Engine) -> StopPreflight:
    active_executions = _active_count(engine, "executions", ACTIVE_EXECUTION_STATES)
    active_probes = _active_count(engine, "recovery_probes", ACTIVE_PROBE_STATES)
    safe = active_executions == 0 and active_probes == 0
    return StopPreflight(
        safe_to_stop=safe,
        code="SAFE_TO_STOP" if safe else "ACTIVE_ATTEMPTS_PRESENT",
        active_execution_count=active_executions,
        active_probe_count=active_probes,
    )


def inspect_resume_preflight(
    engine: Engine,
    *,
    worker_id: str,
    worker_stale_seconds: float,
    current_boot_id: str | None = None,
    now: datetime | None = None,
) -> StopPreflight:
    active = inspect_stop_preflight(engine)
    if not active.safe_to_stop:
        return active
    if not _relation_exists(engine, "executions") or not _relation_exists(
        engine,
        "recovery_probes",
    ):
        return _reconciliation_not_confirmed(active)
    boot_id = current_boot_id if current_boot_id is not None else _current_linux_boot_id()
    checked_at = (now or datetime.now(UTC)).astimezone(UTC)
    if not boot_id:
        return _reconciliation_not_confirmed(active)
    if not _relation_exists_by_name(engine, "system_control") or not (
        _relation_exists_by_name(engine, "worker_heartbeats")
    ):
        return _reconciliation_not_confirmed(active)
    with engine.connect() as connection:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        sc.host_boot_id AS control_host_boot_id,
                        sc.reconcile_epoch AS control_reconcile_epoch,
                        sc.reconciled_at AS control_reconciled_at,
                        wh.status AS worker_status,
                        wh.host_boot_id AS worker_host_boot_id,
                        wh.reconcile_epoch AS worker_reconcile_epoch,
                        wh.reconciled_at AS worker_reconciled_at,
                        wh.updated_at AS worker_updated_at
                    FROM system_control AS sc
                    LEFT JOIN worker_heartbeats AS wh
                      ON wh.worker_id = :worker_id
                    WHERE sc.singleton_id = 1
                    """
                ),
                {"worker_id": worker_id},
            )
            .mappings()
            .one_or_none()
        )
    if row is None:
        return _reconciliation_not_confirmed(active)
    try:
        control_reconciled_at = _as_utc_datetime(row["control_reconciled_at"])
        worker_reconciled_at = _as_utc_datetime(row["worker_reconciled_at"])
        worker_updated_at = _as_utc_datetime(row["worker_updated_at"])
    except (TypeError, ValueError):
        return _reconciliation_not_confirmed(active)
    control_epoch = row["control_reconcile_epoch"]
    worker_epoch = row["worker_reconcile_epoch"]
    age = (checked_at - worker_updated_at).total_seconds()
    if (
        row["worker_status"]
        not in {
            "READY",
            "DRAINING",
            "BLOCKED_RUNTIME",
            "BLOCKED_EGRESS",
            "BLOCKED_STORAGE",
        }
        or row["control_host_boot_id"] != boot_id
        or row["worker_host_boot_id"] != boot_id
        or control_epoch is None
        or worker_epoch is None
        or str(control_epoch) != str(worker_epoch)
        or control_reconciled_at != worker_reconciled_at
        or age < 0
        or age > worker_stale_seconds
    ):
        return _reconciliation_not_confirmed(active)
    return active


def wait_for_stop_preflight(engine: Engine, timeout_seconds: float) -> StopPreflight:
    set_draining(engine, True, "LOCAL_STOP_REQUESTED")
    deadline = time.monotonic() + timeout_seconds
    result = inspect_stop_preflight(engine)
    while not result.safe_to_stop and time.monotonic() < deadline:
        time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
        result = inspect_stop_preflight(engine)
    return result


def _emit(result: StopPreflight) -> None:
    print(json.dumps(asdict(result), separators=(",", ":"), sort_keys=True))


def _relation_exists_by_name(engine: Engine, relation: str) -> bool:
    return inspect(engine).has_table(relation)


def _current_linux_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError:
        return ""


def _as_utc_datetime(value: Any) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise TypeError("database timestamp is missing")
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _reconciliation_not_confirmed(
    active: StopPreflight,
) -> StopPreflight:
    return StopPreflight(
        safe_to_stop=False,
        code="RECONCILIATION_NOT_CONFIRMED",
        active_execution_count=active.active_execution_count,
        active_probe_count=active.active_probe_count,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="datax-studio-lifecycle")
    subcommands = parser.add_subparsers(dest="command", required=True)
    stop = subcommands.add_parser("preflight-stop")
    stop.add_argument("--json", action="store_true", dest="as_json")
    stop.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        choices=None,
    )
    resume = subcommands.add_parser("resume")
    resume.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main() -> None:
    args = _parser().parse_args()
    if getattr(args, "timeout_seconds", 0.0) < 0.0:
        raise SystemExit("--timeout-seconds must be non-negative")
    settings = get_settings()
    engine = create_engine(settings.database_url, pool_pre_ping=True)
    try:
        if args.command == "preflight-stop":
            result = wait_for_stop_preflight(engine, args.timeout_seconds)
            _emit(result)
            raise SystemExit(0 if result.safe_to_stop else 3)

        result = inspect_resume_preflight(
            engine,
            worker_id=settings.worker_id,
            worker_stale_seconds=settings.worker_stale_seconds,
        )
        _emit(result)
        if result.safe_to_stop:
            raise SystemExit(0)
        raise SystemExit(3 if result.code == "ACTIVE_ATTEMPTS_PRESENT" else 5)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "safe_to_stop": False,
                    "code": "LIFECYCLE_CHECK_FAILED",
                    "detail": type(exc).__name__,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stdout,
        )
        raise SystemExit(4) from None


if __name__ == "__main__":
    main()
