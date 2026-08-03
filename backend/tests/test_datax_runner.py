from __future__ import annotations

import sys
from pathlib import Path

import pytest

from datax_studio.datax_runner import build_datax_command, run_datax_job


def _runtime_paths(tmp_path: Path) -> dict[str, Path]:
    java = tmp_path / "java"
    java.write_bytes(b"java")
    datax_home = tmp_path / "datax"
    (datax_home / "lib").mkdir(parents=True)
    (datax_home / "conf").mkdir()
    (datax_home / "conf" / "logback.xml").write_text("<configuration/>")
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    job = job_root / "job.json"
    job.write_text("{}")
    return {
        "java_path": java,
        "datax_home": datax_home,
        "job_path": job,
        "job_root": job_root,
        "log_directory": tmp_path / "logs",
        "workspace": tmp_path / "workspace",
    }


def test_command_is_a_fixed_argument_vector(tmp_path: Path) -> None:
    paths = _runtime_paths(tmp_path)

    command = build_datax_command(**paths, job_id="123")

    assert command[0] == str(paths["java_path"].resolve())
    assert "com.alibaba.datax.core.Engine" in command
    assert command[-2:] == ["-job", str(paths["job_path"].resolve())]
    assert all("\n" not in argument for argument in command)
    assert all("HeapDump" not in argument for argument in command)


def test_job_path_cannot_escape_fixed_root(tmp_path: Path) -> None:
    paths = _runtime_paths(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    paths["job_path"] = outside

    with pytest.raises(ValueError, match="fixed root"):
        build_datax_command(**paths, job_id="123")


def test_job_id_cannot_inject_jvm_arguments(tmp_path: Path) -> None:
    paths = _runtime_paths(tmp_path)

    with pytest.raises(ValueError, match="64-bit decimal"):
        build_datax_command(**paths, job_id="x -Dunsafe=true")


def test_job_id_cannot_overflow_java_long(tmp_path: Path) -> None:
    paths = _runtime_paths(tmp_path)

    with pytest.raises(ValueError, match="64-bit decimal"):
        build_datax_command(**paths, job_id="9223372036854775808")


def test_timeout_terminates_process_group(tmp_path: Path) -> None:
    result = run_datax_job(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        workspace=tmp_path,
        timeout_seconds=0.05,
    )

    assert result.timed_out is True
    assert result.returncode != 0


def test_stdout_and_stderr_are_spooled_and_truncation_is_explicit(
    tmp_path: Path,
) -> None:
    result = run_datax_job(
        [
            sys.executable,
            "-c",
            (
                "import sys;"
                "sys.stdout.write('o'*10000);"
                "sys.stderr.write('e'*8000)"
            ),
        ],
        workspace=tmp_path,
        timeout_seconds=5,
        capture_limit_bytes=64,
    )

    assert result.returncode == 0
    assert result.stdout == b"o" * 64
    assert result.stderr == b"e" * 64
    assert result.stdout_original_bytes == 10_000
    assert result.stdout_dropped_bytes == 9_936
    assert result.stderr_original_bytes == 8_000
    assert result.stderr_dropped_bytes == 7_936
