from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from datax_studio.worker.executor import ExecutionWorker
from datax_studio.worker.job_builder import write_job_file
from datax_studio.worker.sensitive_runtime import (
    SensitiveRuntimeError,
    SensitiveRuntimeStore,
)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)


def test_attempt_job_and_raw_runtime_logs_use_private_ephemeral_paths(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sensitive"
    store = SensitiveRuntimeStore(root)
    execution_id = uuid4()
    attempt_id = uuid4()

    attempt = store.create_attempt(
        execution_id=execution_id,
        attempt_id=attempt_id,
    )
    write_job_file(
        attempt.job_file,
        {"job": {"content": [{"password": "database-secret"}]}},
    )

    assert attempt.directory.parent == root
    assert attempt.job_file.read_text(encoding="utf-8").count("database-secret") == 1
    assert _mode(root) == 0o700
    assert _mode(attempt.directory) == 0o700
    assert _mode(attempt.runtime_log_directory) == 0o700
    assert _mode(attempt.process_working_directory) == 0o700
    assert _mode(attempt.job_file) == 0o600


def test_worker_restart_removes_marked_secret_residue_before_admission(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sensitive"
    execution_id = uuid4()
    attempt_id = uuid4()
    first_process = SensitiveRuntimeStore(root)
    attempt = first_process.create_attempt(
        execution_id=execution_id,
        attempt_id=attempt_id,
    )
    write_job_file(
        attempt.job_file,
        {"job": {"content": [{"password": "kill-restart-secret"}]}},
    )
    raw_runtime_log = attempt.runtime_log_directory / "datax.log"
    descriptor = os.open(
        raw_runtime_log,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        os.write(descriptor, b"password=kill-restart-secret\n")
    finally:
        os.close(descriptor)

    # Simulate SIGKILL/container process loss: no normal remove_attempt call.
    restarted_process = SensitiveRuntimeStore(root)
    assert restarted_process.prepare_and_cleanup() == 1

    assert list(root.iterdir()) == []
    assert b"kill-restart-secret" not in b"".join(
        path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    )


def test_unknown_or_unmarked_entry_blocks_claim_without_deleting_it(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sensitive"
    store = SensitiveRuntimeStore(root)
    store.prepare_and_cleanup()
    unknown = root / "operator-file"
    unknown.write_text("do not delete", encoding="utf-8")

    class _Control:
        claim_called = False

        def claim_next_execution(self, **_kwargs: object) -> None:
            self.claim_called = True
            return None

    control = _Control()
    worker = object.__new__(ExecutionWorker)
    worker.sensitive_runtime = store
    worker.control = control
    worker.settings = SimpleNamespace(
        worker_id="worker-1",
        worker_lease_seconds=30,
    )
    worker.credentials = SimpleNamespace(select_active_binding=object())

    with pytest.raises(SensitiveRuntimeError):
        worker.claim_and_run(host_boot_id="boot", cgroup_identity="cgroup")

    assert control.claim_called is False
    assert unknown.read_text(encoding="utf-8") == "do not delete"


def test_job_creation_rejects_symlink_without_touching_target(tmp_path: Path) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("safe", encoding="utf-8")
    job_file = directory / "job.json"
    job_file.symlink_to(victim)

    with pytest.raises(FileExistsError):
        write_job_file(job_file, {"password": "must-not-be-written"})

    assert victim.read_text(encoding="utf-8") == "safe"


def test_required_tmpfs_parent_cannot_be_overridden(tmp_path: Path) -> None:
    with pytest.raises(SensitiveRuntimeError):
        SensitiveRuntimeStore(
            tmp_path / "sensitive",
            required_parent=Path("/tmp"),
        )
