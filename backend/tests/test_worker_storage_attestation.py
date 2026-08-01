from __future__ import annotations

import os
from pathlib import Path

import pytest

from datax_studio.worker.storage_attestation import (
    StorageAttestationError,
    WorkerStorageVerifier,
)

_PROBE_GLOB = ".datax-studio-storage-probe-*"


def _mount_field(value: str) -> str:
    return (
        value.replace("\\", "\\134")
        .replace(" ", "\\040")
        .replace("\t", "\\011")
        .replace("\n", "\\012")
    )


def _mount_line(
    *,
    mount_id: int,
    parent_id: int,
    device: str,
    root: str,
    mount_point: Path | str,
    filesystem_type: str = "ext4",
    source: str = "/dev/test",
) -> str:
    return (
        f"{mount_id} {parent_id} {device} {_mount_field(root)} "
        f"{_mount_field(str(mount_point))} rw,nosuid,nodev - "
        f"{filesystem_type} {_mount_field(source)} rw"
    )


def _device(path: Path | str) -> str:
    device = os.stat(path).st_dev
    return f"{os.major(device)}:{os.minor(device)}"


def _write_mountinfo(
    path: Path,
    *,
    log_path: Path | str,
    workspace_path: Path | str,
    log_root: str = "/volumes/log",
    workspace_root: str = "/volumes/workspace",
    log_device: str | None = None,
    workspace_device: str | None = None,
    log_filesystem: str = "ext4",
    workspace_filesystem: str = "ext4",
    log_source: str = "/dev/test",
    workspace_source: str = "/dev/test",
) -> None:
    path.write_text(
        "\n".join(
            (
                _mount_line(
                    mount_id=101,
                    parent_id=1,
                    device=log_device or _device(log_path),
                    root=log_root,
                    mount_point=log_path,
                    filesystem_type=log_filesystem,
                    source=log_source,
                ),
                _mount_line(
                    mount_id=102,
                    parent_id=1,
                    device=workspace_device or _device(workspace_path),
                    root=workspace_root,
                    mount_point=workspace_path,
                    filesystem_type=workspace_filesystem,
                    source=workspace_source,
                ),
            )
        )
        + "\n",
        encoding="utf-8",
    )


def _verifier(
    *,
    log_path: Path,
    workspace_path: Path,
    mountinfo_path: Path,
    log_min_free_bytes: int = 0,
    workspace_min_free_bytes: int = 0,
) -> WorkerStorageVerifier:
    return WorkerStorageVerifier(
        log_volume_path=log_path,
        workspace_volume_path=workspace_path,
        log_min_free_bytes=log_min_free_bytes,
        workspace_min_free_bytes=workspace_min_free_bytes,
        mountinfo_path=mountinfo_path,
    )


def test_verifies_independent_exact_mounts_and_removes_probes(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "logs"
    workspace_path = tmp_path / "workspaces"
    log_path.mkdir()
    workspace_path.mkdir()
    mountinfo_path = tmp_path / "mountinfo"
    _write_mountinfo(
        mountinfo_path,
        log_path=log_path,
        workspace_path=workspace_path,
    )

    verification = _verifier(
        log_path=log_path,
        workspace_path=workspace_path,
        mountinfo_path=mountinfo_path,
    ).verify_runtime()

    assert len(verification.log_mount_identity_hash) == 64
    assert len(verification.workspace_mount_identity_hash) == 64
    assert (
        verification.log_mount_identity_hash
        != verification.workspace_mount_identity_hash
    )
    assert verification.log_free_bytes >= 0
    assert verification.workspace_free_bytes >= 0
    assert verification.checked_at.utcoffset() is not None
    assert list(log_path.glob(_PROBE_GLOB)) == []
    assert list(workspace_path.glob(_PROBE_GLOB)) == []


def test_rejects_symlink_in_volume_path(tmp_path: Path) -> None:
    real_log_path = tmp_path / "real-logs"
    real_log_path.mkdir()
    log_path = tmp_path / "logs"
    log_path.symlink_to(real_log_path, target_is_directory=True)
    workspace_path = tmp_path / "workspaces"
    workspace_path.mkdir()
    mountinfo_path = tmp_path / "mountinfo"
    _write_mountinfo(
        mountinfo_path,
        log_path=log_path,
        workspace_path=workspace_path,
    )

    with pytest.raises(StorageAttestationError) as raised:
        _verifier(
            log_path=log_path,
            workspace_path=workspace_path,
            mountinfo_path=mountinfo_path,
        ).verify_runtime()

    assert raised.value.code == "STORAGE_PATH_SYMLINK"
    assert str(raised.value) == "STORAGE_PATH_SYMLINK"
    assert list(real_log_path.glob(_PROBE_GLOB)) == []
    assert list(workspace_path.glob(_PROBE_GLOB)) == []


def test_rejects_container_overlay_root(tmp_path: Path) -> None:
    workspace_path = tmp_path / "workspaces"
    workspace_path.mkdir()
    mountinfo_path = tmp_path / "mountinfo"
    _write_mountinfo(
        mountinfo_path,
        log_path="/",
        workspace_path=workspace_path,
        log_root="/",
        log_device="0:99",
        log_filesystem="overlay",
        log_source="overlay",
    )

    with pytest.raises(StorageAttestationError) as raised:
        _verifier(
            log_path=Path("/"),
            workspace_path=workspace_path,
            mountinfo_path=mountinfo_path,
        ).verify_runtime()

    assert raised.value.code == "STORAGE_OVERLAY_ROOT_FORBIDDEN"
    assert list(workspace_path.glob(_PROBE_GLOB)) == []


def test_rejects_distinct_mountpoints_for_same_underlying_mount(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "logs"
    workspace_path = tmp_path / "workspaces"
    log_path.mkdir()
    workspace_path.mkdir()
    mountinfo_path = tmp_path / "mountinfo"
    _write_mountinfo(
        mountinfo_path,
        log_path=log_path,
        workspace_path=workspace_path,
        log_root="/same-volume",
        workspace_root="/same-volume",
    )

    with pytest.raises(StorageAttestationError) as raised:
        _verifier(
            log_path=log_path,
            workspace_path=workspace_path,
            mountinfo_path=mountinfo_path,
        ).verify_runtime()

    assert raised.value.code == "STORAGE_MOUNTS_NOT_INDEPENDENT"
    assert list(log_path.glob(_PROBE_GLOB)) == []
    assert list(workspace_path.glob(_PROBE_GLOB)) == []


def test_rejects_insufficient_space_without_leaving_probe(tmp_path: Path) -> None:
    log_path = tmp_path / "logs"
    workspace_path = tmp_path / "workspaces"
    log_path.mkdir()
    workspace_path.mkdir()
    mountinfo_path = tmp_path / "mountinfo"
    _write_mountinfo(
        mountinfo_path,
        log_path=log_path,
        workspace_path=workspace_path,
    )

    with pytest.raises(StorageAttestationError) as raised:
        _verifier(
            log_path=log_path,
            workspace_path=workspace_path,
            mountinfo_path=mountinfo_path,
            log_min_free_bytes=(2**63) - 1,
        ).verify_runtime()

    assert raised.value.code == "STORAGE_LOG_FREE_SPACE_INSUFFICIENT"
    assert list(log_path.glob(_PROBE_GLOB)) == []
    assert list(workspace_path.glob(_PROBE_GLOB)) == []


def test_rejects_mountinfo_device_that_does_not_match_open_directory(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "logs"
    workspace_path = tmp_path / "workspaces"
    log_path.mkdir()
    workspace_path.mkdir()
    mountinfo_path = tmp_path / "mountinfo"
    _write_mountinfo(
        mountinfo_path,
        log_path=log_path,
        workspace_path=workspace_path,
        log_device="65535:65535",
    )

    with pytest.raises(StorageAttestationError) as raised:
        _verifier(
            log_path=log_path,
            workspace_path=workspace_path,
            mountinfo_path=mountinfo_path,
        ).verify_runtime()

    assert raised.value.code == "STORAGE_MOUNT_DEVICE_MISMATCH"
    assert list(log_path.glob(_PROBE_GLOB)) == []
    assert list(workspace_path.glob(_PROBE_GLOB)) == []


def test_rejects_non_exact_mount_without_creating_probe(tmp_path: Path) -> None:
    log_path = tmp_path / "logs"
    workspace_path = tmp_path / "workspaces"
    log_path.mkdir()
    workspace_path.mkdir()
    mountinfo_path = tmp_path / "mountinfo"
    _write_mountinfo(
        mountinfo_path,
        log_path=tmp_path,
        workspace_path=workspace_path,
    )

    with pytest.raises(StorageAttestationError) as raised:
        _verifier(
            log_path=log_path,
            workspace_path=workspace_path,
            mountinfo_path=mountinfo_path,
        ).verify_runtime()

    assert raised.value.code == "STORAGE_NOT_EXACT_MOUNT"
    assert list(log_path.glob(_PROBE_GLOB)) == []
    assert list(workspace_path.glob(_PROBE_GLOB)) == []


def test_mount_identity_never_exposes_raw_paths(tmp_path: Path) -> None:
    log_path = tmp_path / "sensitive-log-name"
    workspace_path = tmp_path / "sensitive-workspace-name"
    log_path.mkdir()
    workspace_path.mkdir()
    mountinfo_path = tmp_path / "mountinfo"
    _write_mountinfo(
        mountinfo_path,
        log_path=log_path,
        workspace_path=workspace_path,
    )

    verification = _verifier(
        log_path=log_path,
        workspace_path=workspace_path,
        mountinfo_path=mountinfo_path,
    ).verify_runtime()

    public_values = vars(verification)
    assert os.fspath(log_path) not in repr(public_values)
    assert os.fspath(workspace_path) not in repr(public_values)
