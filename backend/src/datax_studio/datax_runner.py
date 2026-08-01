from __future__ import annotations

import os
import signal
import subprocess
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass(frozen=True)
class DataXRunResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_original_bytes: int
    stdout_dropped_bytes: int
    stderr_original_bytes: int
    stderr_dropped_bytes: int


DEFAULT_CAPTURE_LIMIT_BYTES = 1024 * 1024


def _require_contained_file(path: Path, root: Path, label: str) -> Path:
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    if (
        not resolved_path.is_relative_to(resolved_root)
        or path.is_symlink()
        or not path.is_file()
    ):
        raise ValueError(f"{label} must be a regular file below its fixed root")
    return resolved_path


def build_datax_command(
    *,
    java_path: Path,
    datax_home: Path,
    job_path: Path,
    job_root: Path,
    log_directory: Path,
    workspace: Path,
    job_id: str,
) -> list[str]:
    java = java_path.resolve()
    if java_path.is_symlink() or not java_path.is_file():
        raise ValueError("java runtime is unavailable")
    home = datax_home.resolve()
    if datax_home.is_symlink() or not datax_home.is_dir():
        raise ValueError("DataX home is unavailable")
    job = _require_contained_file(job_path, job_root, "job")
    resolved_logs = log_directory.resolve()
    resolved_workspace = workspace.resolve()
    resolved_logs.mkdir(parents=True, exist_ok=True)
    resolved_workspace.mkdir(parents=True, exist_ok=True)
    if log_directory.is_symlink() or workspace.is_symlink():
        raise ValueError("runtime output roots must not be symbolic links")
    if (
        not job_id
        or not job_id.isascii()
        or not job_id.isdigit()
        or int(job_id) > 9_223_372_036_854_775_807
    ):
        raise ValueError("job id must be an unsigned DataX-compatible 64-bit decimal")

    return [
        str(java),
        "-server",
        "-Xms512m",
        "-Xmx1g",
        "-Dfile.encoding=UTF-8",
        "-Duser.timezone=UTC",
        "-Duser.language=en",
        "-Duser.country=US",
        (
            "-Dlogback.statusListenerClass="
            "ch.qos.logback.core.status.NopStatusListener"
        ),
        "-Djava.security.egd=file:///dev/urandom",
        f"-Ddatax.home={home}",
        f"-Dlogback.configurationFile={home / 'conf' / 'logback.xml'}",
        f"-Ddatax.log.dir={resolved_logs}",
        f"-Ddatax.perf.dir={resolved_logs / 'perf'}",
        f"-Dlog.file.name={job_id}",
        "-Dloglevel=info",
        "-classpath",
        f"{home / 'lib'}/*:.",
        "com.alibaba.datax.core.Engine",
        "-mode",
        "standalone",
        "-jobid",
        job_id,
        "-job",
        str(job),
    ]


def run_datax_job(
    command: list[str],
    *,
    workspace: Path,
    timeout_seconds: float,
    capture_limit_bytes: int = DEFAULT_CAPTURE_LIMIT_BYTES,
) -> DataXRunResult:
    if timeout_seconds <= 0:
        raise ValueError("timeout must be positive")
    if capture_limit_bytes <= 0:
        raise ValueError("capture limit must be positive")
    resolved_workspace = workspace.resolve()
    resolved_workspace.mkdir(parents=True, exist_ok=True)
    if workspace.is_symlink() or not workspace.is_dir():
        raise ValueError("workspace must be a regular directory")

    with (
        tempfile.TemporaryFile(mode="w+b", dir=resolved_workspace) as stdout_file,
        tempfile.TemporaryFile(mode="w+b", dir=resolved_workspace) as stderr_file,
    ):
        process = subprocess.Popen(
            command,
            cwd=resolved_workspace,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            env={
                "HOME": "/tmp",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/opt/java/openjdk/bin:/usr/local/bin:/usr/bin:/bin",
            },
            start_new_session=True,
        )
        timed_out = False
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                with suppress(OSError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()

        stdout, stdout_original = _read_bounded_capture(
            stdout_file,
            capture_limit_bytes,
        )
        stderr, stderr_original = _read_bounded_capture(
            stderr_file,
            capture_limit_bytes,
        )
        return DataXRunResult(
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            stdout_original_bytes=stdout_original,
            stdout_dropped_bytes=stdout_original - len(stdout),
            stderr_original_bytes=stderr_original,
            stderr_dropped_bytes=stderr_original - len(stderr),
        )


def _read_bounded_capture(
    handle: BinaryIO,
    limit_bytes: int,
) -> tuple[bytes, int]:
    handle.flush()
    original_bytes = os.fstat(handle.fileno()).st_size
    handle.seek(0)
    return handle.read(limit_bytes), original_bytes
