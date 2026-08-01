from __future__ import annotations

import stat
import sys
from pathlib import Path

from datax_studio.worker.process import (
    BoundedRedactedLog,
    ProcessAction,
    ProcessEndReason,
    StreamingRedactor,
    run_managed_process,
)


def test_streaming_redactor_catches_a_secret_split_across_reads() -> None:
    redactor = StreamingRedactor([b"split-secret"], carry_bytes=16)

    output = (
        redactor.feed(b"prefix split-")
        + redactor.feed(b"secret suffix " + b"x" * 32)
        + redactor.finish()
    )

    assert b"split-secret" not in output
    assert b"[REDACTED]" in output


def test_bounded_log_never_persists_raw_secret_and_accounts_truncation(
    tmp_path: Path,
) -> None:
    log = BoundedRedactedLog(
        tmp_path / "execution.log",
        secrets=[b"database-secret"],
        maximum_bytes=1024,
        maximum_line_bytes=128,
    )

    log.write_raw(
        b'{"password":"database-secret"}\n'
        + b"x" * 5000
        + b"\nend database-secret\n"
        + b"short safe line\n" * 1000
    )
    result = log.close()
    stored = result.path.read_bytes()

    assert b"database-secret" not in stored
    assert b"[REDACTED]" in stored
    assert result.stored_bytes <= 1024
    assert result.dropped_bytes == (result.redacted_received_bytes - result.stored_bytes)
    assert {gap.reason for gap in result.gaps} == {
        "LINE_LIMIT",
        "RING_EVICTION",
    }


def test_bounded_log_records_source_read_failure_without_error_text(
    tmp_path: Path,
) -> None:
    log = BoundedRedactedLog(
        tmp_path / "execution.log",
        secrets=[],
        maximum_bytes=1024,
        maximum_line_bytes=128,
    )
    log.write_raw(b"safe output\n")
    log.record_source_read_error()

    result = log.close()

    assert {gap.reason for gap in result.gaps} == {"SOURCE_READ_ERROR"}
    assert result.dropped_bytes == 0


def test_managed_process_cancellation_terminates_the_process_group_and_redacts(
    tmp_path: Path,
) -> None:
    ticks = 0

    def tick() -> ProcessAction:
        nonlocal ticks
        ticks += 1
        return ProcessAction.CANCEL if ticks >= 2 else ProcessAction.CONTINUE

    result = run_managed_process(
        [
            sys.executable,
            "-c",
            ("import sys,time;print('password=cancel-secret', flush=True);time.sleep(30)"),
        ],
        workspace=tmp_path / "workspace",
        log_path=tmp_path / "logs" / "execution.log",
        secrets=[b"cancel-secret"],
        timeout_seconds=10,
        tick=tick,
        process_started=lambda _identity: None,
        terminate_grace_seconds=0.2,
        poll_seconds=0.02,
        pid_start_time_reader=lambda _pid: 1,
    )

    assert result.end_reason == ProcessEndReason.CANCELED
    assert result.returncode != 0
    assert b"cancel-secret" not in result.log.path.read_bytes()


def test_managed_process_timeout_is_not_reported_as_normal_exit(
    tmp_path: Path,
) -> None:
    result = run_managed_process(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        workspace=tmp_path / "workspace",
        log_path=tmp_path / "logs" / "execution.log",
        secrets=[],
        timeout_seconds=0.05,
        tick=lambda: ProcessAction.CONTINUE,
        process_started=lambda _identity: None,
        terminate_grace_seconds=0.05,
        poll_seconds=0.01,
        pid_start_time_reader=lambda _pid: 1,
    )

    assert result.end_reason == ProcessEndReason.TIMED_OUT
    assert result.returncode != 0


def test_managed_process_stops_when_exact_ip_lease_is_lost(
    tmp_path: Path,
) -> None:
    result = run_managed_process(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        workspace=tmp_path / "workspace",
        log_path=tmp_path / "logs" / "execution.log",
        secrets=[],
        timeout_seconds=10,
        tick=lambda: ProcessAction.EGRESS_LOST,
        process_started=lambda _identity: None,
        terminate_grace_seconds=0.05,
        poll_seconds=0.01,
        pid_start_time_reader=lambda _pid: 1,
    )

    assert result.end_reason == ProcessEndReason.EGRESS_LOST
    assert result.returncode != 0


def test_managed_process_forces_private_mode_for_runtime_created_files(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    result = run_managed_process(
        [
            sys.executable,
            "-c",
            (
                "from pathlib import Path;"
                "Path('raw-runtime.log').write_text('sensitive', encoding='utf-8')"
            ),
        ],
        workspace=workspace,
        log_path=tmp_path / "logs" / "execution.log",
        secrets=[],
        timeout_seconds=5,
        tick=lambda: ProcessAction.CONTINUE,
        process_started=lambda _identity: None,
        poll_seconds=0.01,
        pid_start_time_reader=lambda _pid: 1,
    )

    assert result.returncode == 0
    assert stat.S_IMODE((workspace / "raw-runtime.log").stat().st_mode) == 0o600
