from __future__ import annotations

import os
import queue
import re
import signal
import subprocess
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO


class ProcessAction(StrEnum):
    CONTINUE = "CONTINUE"
    CANCEL = "CANCEL"
    FENCE_LOST = "FENCE_LOST"
    EGRESS_LOST = "EGRESS_LOST"


class ProcessEndReason(StrEnum):
    EXITED = "EXITED"
    TIMED_OUT = "TIMED_OUT"
    CANCELED = "CANCELED"
    FENCE_LOST = "FENCE_LOST"
    EGRESS_LOST = "EGRESS_LOST"


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    pid_start_time: int
    process_group_id: int


@dataclass(frozen=True)
class LogGap:
    reason: str
    raw_received_bytes: int
    redacted_received_bytes: int
    stored_bytes: int
    dropped_bytes: int


@dataclass(frozen=True)
class _PipeReadFailure:
    pass


@dataclass(frozen=True)
class ProcessLogResult:
    path: Path
    raw_received_bytes: int
    redacted_received_bytes: int
    stored_bytes: int
    dropped_bytes: int
    gaps: tuple[LogGap, ...]


@dataclass(frozen=True)
class ManagedProcessResult:
    returncode: int
    end_reason: ProcessEndReason
    identity: ProcessIdentity
    log: ProcessLogResult


class StreamingRedactor:
    """Redact exact credentials and bounded structured secret patterns.

    A carry window keeps secrets split across pipe reads from crossing the
    redaction boundary. V1 passwords are at most 512 bytes; the structured
    window is deliberately larger.
    """

    _PATTERNS = (
        re.compile(rb"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+"),
        re.compile(
            rb"""(?ix)
            (
              ["']?(?:password|passwd|token|access_token|refresh_token)["']?
              \s*[:=]\s*
            )
            (?:
              "(?:\\.|[^"\\])*"
              |
              '(?:\\.|[^'\\])*'
              |
              [^\s,;}]+
            )
            """
        ),
        re.compile(rb"(?i)(jdbc:[^\s]+[?&](?:user|password)=)[^&\s]+"),
    )

    def __init__(
        self,
        secrets: Sequence[bytes | bytearray],
        *,
        carry_bytes: int = 4096,
    ) -> None:
        exact = {bytes(secret) for secret in secrets if secret and len(secret) <= 4096}
        self._secrets = sorted(exact, key=len, reverse=True)
        self._carry_limit = max(
            carry_bytes,
            max((len(secret) for secret in self._secrets), default=1),
        )
        self._carry = b""

    def feed(self, chunk: bytes) -> bytes:
        combined = self._carry + chunk
        if len(combined) <= self._carry_limit:
            self._carry = combined
            return b""
        split = len(combined) - self._carry_limit
        # Never emit a suffix that could be the beginning of a known secret.
        # The remaining bytes stay in the carry until the next read proves
        # whether the complete secret is present.
        for secret in self._secrets:
            maximum = min(len(secret) - 1, split)
            for overlap in range(maximum, 0, -1):
                if combined[:split].endswith(secret[:overlap]):
                    split -= overlap
                    break
        emit = combined[:split]
        self._carry = combined[split:]
        return self._redact(emit)

    def finish(self) -> bytes:
        result = self._redact(self._carry)
        self._carry = b""
        return result

    def _redact(self, value: bytes) -> bytes:
        redacted = value
        for secret in self._secrets:
            redacted = redacted.replace(secret, b"[REDACTED]")
        for pattern in self._PATTERNS:
            redacted = pattern.sub(
                lambda match: match.group(1) + b"[REDACTED]",
                redacted,
            )
        return redacted


@dataclass
class _LineLimiter:
    limit: int
    _head: bytearray = field(default_factory=bytearray)
    _tail: deque[bytes] = field(default_factory=deque)
    _tail_bytes: int = 0
    _total: int = 0
    _truncated: bool = False

    def feed(self, value: bytes) -> tuple[list[bytes], int]:
        emitted: list[bytes] = []
        dropped = 0
        for part in value.splitlines(keepends=True):
            self._consume_part(part)
            if part.endswith((b"\n", b"\r")):
                line, line_dropped = self._finish_line()
                emitted.append(line)
                dropped += line_dropped
        return emitted, dropped

    def finish(self) -> tuple[bytes, int]:
        if self._total == 0:
            return b"", 0
        return self._finish_line()

    def _consume_part(self, part: bytes) -> None:
        self._total += len(part)
        if not self._truncated and len(self._head) + len(part) <= self.limit:
            self._head.extend(part)
            return
        self._truncated = True
        head_limit = self.limit // 2
        if len(self._head) > head_limit:
            overflow = bytes(self._head[head_limit:])
            del self._head[head_limit:]
            self._append_tail(overflow)
        available = max(0, head_limit - len(self._head))
        if available:
            self._head.extend(part[:available])
            part = part[available:]
        self._append_tail(part)

    def _append_tail(self, value: bytes) -> None:
        if not value:
            return
        tail_limit = self.limit - self.limit // 2
        self._tail.append(value)
        self._tail_bytes += len(value)
        while self._tail and self._tail_bytes > tail_limit:
            overflow = self._tail_bytes - tail_limit
            first = self._tail[0]
            if len(first) <= overflow:
                self._tail.popleft()
                self._tail_bytes -= len(first)
            else:
                self._tail[0] = first[overflow:]
                self._tail_bytes -= overflow

    def _finish_line(self) -> tuple[bytes, int]:
        stored = bytes(self._head) + b"".join(self._tail)
        dropped = self._total - len(stored)
        self._head.clear()
        self._tail.clear()
        self._tail_bytes = 0
        self._total = 0
        self._truncated = False
        return stored, dropped


class BoundedRedactedLog:
    def __init__(
        self,
        path: Path,
        *,
        secrets: Sequence[bytes | bytearray],
        maximum_bytes: int,
        maximum_line_bytes: int,
    ) -> None:
        if maximum_bytes < 1024:
            raise ValueError("maximum log bytes must be at least 1024")
        if not 128 <= maximum_line_bytes <= maximum_bytes:
            raise ValueError("maximum line bytes is invalid")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            raise FileExistsError("log path already exists")
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        self.path = path
        self._handle = os.fdopen(descriptor, "wb", buffering=0)
        self._redactor = StreamingRedactor(secrets)
        self._line_limiter = _LineLimiter(maximum_line_bytes)
        self._head_limit = maximum_bytes * 3 // 4
        self._tail_limit = maximum_bytes - self._head_limit
        self._tail = bytearray()
        self._raw = 0
        self._redacted = 0
        self._head_stored = 0
        self._line_dropped = 0
        self._ring_dropped = 0
        self._source_read_failed = False
        self._closed = False

    def write_raw(self, value: bytes) -> None:
        if self._closed:
            raise ValueError("log is closed")
        self._raw += len(value)
        self._consume_redacted(self._redactor.feed(value))

    def record_source_read_error(self) -> None:
        if self._closed:
            raise ValueError("log is closed")
        self._source_read_failed = True

    def _consume_redacted(self, value: bytes) -> None:
        if not value:
            return
        self._redacted += len(value)
        lines, line_dropped = self._line_limiter.feed(value)
        self._line_dropped += line_dropped
        for line in lines:
            self._store(line)

    def _store(self, value: bytes) -> None:
        if self._head_stored < self._head_limit:
            available = self._head_limit - self._head_stored
            prefix = value[:available]
            self._handle.write(prefix)
            self._head_stored += len(prefix)
            value = value[available:]
        if not value:
            return
        self._tail.extend(value)
        if len(self._tail) > self._tail_limit:
            overflow = len(self._tail) - self._tail_limit
            del self._tail[:overflow]
            self._ring_dropped += overflow

    def close(self) -> ProcessLogResult:
        if self._closed:
            raise ValueError("log is already closed")
        self._closed = True
        self._consume_redacted(self._redactor.finish())
        final_line, line_dropped = self._line_limiter.finish()
        self._line_dropped += line_dropped
        self._store(final_line)
        self._handle.write(self._tail)
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._handle.close()
        stored = self.path.stat().st_size
        dropped = self._redacted - stored
        if dropped != self._line_dropped + self._ring_dropped:
            raise RuntimeError("log byte accounting invariant failed")
        gaps: list[LogGap] = []
        if self._line_dropped:
            gaps.append(
                LogGap(
                    reason="LINE_LIMIT",
                    raw_received_bytes=self._raw,
                    redacted_received_bytes=self._redacted,
                    stored_bytes=stored,
                    dropped_bytes=self._line_dropped,
                )
            )
        if self._ring_dropped:
            gaps.append(
                LogGap(
                    reason="RING_EVICTION",
                    raw_received_bytes=self._raw,
                    redacted_received_bytes=self._redacted,
                    stored_bytes=stored,
                    dropped_bytes=self._ring_dropped,
                )
            )
        if self._source_read_failed:
            gaps.append(
                LogGap(
                    reason="SOURCE_READ_ERROR",
                    raw_received_bytes=0,
                    redacted_received_bytes=0,
                    stored_bytes=0,
                    dropped_bytes=0,
                )
            )
        return ProcessLogResult(
            path=self.path,
            raw_received_bytes=self._raw,
            redacted_received_bytes=self._redacted,
            stored_bytes=stored,
            dropped_bytes=dropped,
            gaps=tuple(gaps),
        )


def run_managed_process(
    command: Sequence[str],
    *,
    workspace: Path,
    log_path: Path,
    secrets: Sequence[bytes | bytearray],
    timeout_seconds: float,
    tick: Callable[[], ProcessAction],
    process_started: Callable[[ProcessIdentity], None],
    maximum_log_bytes: int = 4 * 1024 * 1024,
    maximum_line_bytes: int = 64 * 1024,
    terminate_grace_seconds: float = 10.0,
    poll_seconds: float = 0.2,
    pid_start_time_reader: Callable[[int], int] | None = None,
) -> ManagedProcessResult:
    if not command or any(not isinstance(item, str) or "\0" in item for item in command):
        raise ValueError("command must be a non-empty NUL-free argument vector")
    if timeout_seconds <= 0:
        raise ValueError("timeout must be positive")
    resolved_workspace = workspace.resolve()
    resolved_workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    if workspace.is_symlink() or not workspace.is_dir():
        raise ValueError("workspace must be a regular directory")
    log = BoundedRedactedLog(
        log_path,
        secrets=secrets,
        maximum_bytes=maximum_log_bytes,
        maximum_line_bytes=maximum_line_bytes,
    )
    process = subprocess.Popen(
        list(command),
        cwd=resolved_workspace,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/opt/java/openjdk/bin:/usr/local/bin:/usr/bin:/bin",
        },
        start_new_session=True,
        umask=0o077,
    )
    assert process.stdout is not None and process.stderr is not None
    try:
        identity = ProcessIdentity(
            pid=process.pid,
            pid_start_time=(pid_start_time_reader or _linux_pid_start_time)(process.pid),
            process_group_id=os.getpgid(process.pid),
        )
    except BaseException:
        _terminate_group(process, terminate_grace_seconds)
        with suppress(ValueError):
            log.close()
        raise
    messages: queue.Queue[bytes | _PipeReadFailure | None] = queue.Queue(maxsize=128)
    readers = [
        threading.Thread(
            target=_read_pipe,
            args=(handle, messages),
            daemon=True,
        )
        for handle in (process.stdout, process.stderr)
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout_seconds
    reason = ProcessEndReason.EXITED
    active_readers = len(readers)
    try:
        process_started(identity)
        while process.poll() is None:
            _drain_one(messages, log, timeout=poll_seconds)
            if time.monotonic() >= deadline:
                reason = ProcessEndReason.TIMED_OUT
                _terminate_group(process, terminate_grace_seconds)
                break
            action = tick()
            if action == ProcessAction.CANCEL:
                reason = ProcessEndReason.CANCELED
                _terminate_group(process, terminate_grace_seconds)
                break
            if action == ProcessAction.FENCE_LOST:
                reason = ProcessEndReason.FENCE_LOST
                _terminate_group(process, terminate_grace_seconds)
                break
            if action == ProcessAction.EGRESS_LOST:
                reason = ProcessEndReason.EGRESS_LOST
                _terminate_group(process, terminate_grace_seconds)
                break
        process.wait()
        while active_readers:
            item = messages.get(timeout=max(1.0, terminate_grace_seconds))
            if item is None:
                active_readers -= 1
            elif isinstance(item, _PipeReadFailure):
                log.record_source_read_error()
            else:
                log.write_raw(item)
        for reader in readers:
            reader.join(timeout=1)
        return ManagedProcessResult(
            returncode=process.returncode,
            end_reason=reason,
            identity=identity,
            log=log.close(),
        )
    except BaseException:
        if process.poll() is None:
            _terminate_group(process, terminate_grace_seconds)
        with suppress(ValueError):
            log.close()
        raise


def _read_pipe(
    handle: BinaryIO,
    output: queue.Queue[bytes | _PipeReadFailure | None],
) -> None:
    try:
        while True:
            chunk = handle.read(16 * 1024)
            if not chunk:
                return
            output.put(chunk)
    except Exception:
        output.put(_PipeReadFailure())
    finally:
        output.put(None)
        handle.close()


def _drain_one(
    messages: queue.Queue[bytes | _PipeReadFailure | None],
    log: BoundedRedactedLog,
    *,
    timeout: float,
) -> None:
    try:
        item = messages.get(timeout=timeout)
    except queue.Empty:
        return
    if item is not None:
        if isinstance(item, _PipeReadFailure):
            log.record_source_read_error()
        else:
            log.write_raw(item)
    else:
        # Reader-completion sentinels are consumed again in the final drain.
        messages.put(None)


def _terminate_group(
    process: subprocess.Popen[bytes],
    grace_seconds: float,
) -> None:
    if process.poll() is not None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def terminate_recorded_process_group(
    identity: ProcessIdentity,
    *,
    pid_start_time_reader: Callable[[int], int] | None = None,
) -> bool:
    """Terminate only when PID start time and process-group identity still match."""

    reader = pid_start_time_reader or _linux_pid_start_time
    try:
        if (
            reader(identity.pid) != identity.pid_start_time
            or os.getpgid(identity.pid) != identity.process_group_id
        ):
            return False
    except (ProcessLookupError, RuntimeError):
        return False
    with suppress(ProcessLookupError):
        os.killpg(identity.process_group_id, signal.SIGKILL)
        return True
    return False


def _linux_pid_start_time(pid: int) -> int:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
        return int(fields[21])
    except (OSError, ValueError, IndexError) as exc:
        raise RuntimeError("Linux PID start time is unavailable") from exc
