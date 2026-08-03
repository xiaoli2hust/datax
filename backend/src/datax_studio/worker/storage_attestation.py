from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_MOUNT_ESCAPE = re.compile(r"\\(011|012|040|134)")
_DEVICE_NUMBER = re.compile(r"^([0-9]+):([0-9]+)$")
_PROBE_BYTES = (
    b"DataX Enterprise Studio worker storage attestation\n" + (b"\0" * 4045)
)
_PROBE_PREFIX = ".datax-studio-storage-probe-"


class StorageAttestationError(ValueError):
    """Fail-closed storage attestation error with a stable public code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class StorageVerification:
    log_mount_identity_hash: str
    workspace_mount_identity_hash: str
    log_free_bytes: int
    workspace_free_bytes: int
    checked_at: datetime


@dataclass(frozen=True)
class _MountInfoEntry:
    mount_id: int
    parent_id: int
    device_major: int
    device_minor: int
    root: str
    mount_point: str
    filesystem_type: str
    mount_source: str

    @property
    def underlying_identity(self) -> tuple[int, int, str, str, str]:
        return (
            self.device_major,
            self.device_minor,
            self.root,
            self.filesystem_type,
            self.mount_source,
        )

    @property
    def identity_hash(self) -> str:
        material = json.dumps(
            {
                "device_major": self.device_major,
                "device_minor": self.device_minor,
                "filesystem_type": self.filesystem_type,
                "mount_id": self.mount_id,
                "mount_source": self.mount_source,
                "parent_id": self.parent_id,
                "root": self.root,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(b"DXWORKERSTORAGEMOUNTv1\n" + material).hexdigest()


def _decode_mount_field(value: str) -> str:
    decoded = _MOUNT_ESCAPE.sub(
        lambda match: chr(int(match.group(1), 8)),
        value,
    )
    if "\\" in decoded or "\0" in decoded:
        raise StorageAttestationError("STORAGE_MOUNTINFO_INVALID")
    return decoded


def _parse_mountinfo(value: str) -> tuple[_MountInfoEntry, ...]:
    entries: list[_MountInfoEntry] = []
    try:
        for line in value.splitlines():
            if not line:
                continue
            left, separator, right = line.partition(" - ")
            if not separator:
                raise ValueError
            left_fields = left.split()
            right_fields = right.split()
            if len(left_fields) < 6 or len(right_fields) < 3:
                raise ValueError
            device = _DEVICE_NUMBER.fullmatch(left_fields[2])
            if device is None:
                raise ValueError
            root = _decode_mount_field(left_fields[3])
            mount_point = _decode_mount_field(left_fields[4])
            mount_source = _decode_mount_field(right_fields[1])
            if not root.startswith("/") or not mount_point.startswith("/"):
                raise ValueError
            entries.append(
                _MountInfoEntry(
                    mount_id=int(left_fields[0]),
                    parent_id=int(left_fields[1]),
                    device_major=int(device.group(1)),
                    device_minor=int(device.group(2)),
                    root=root,
                    mount_point=mount_point,
                    filesystem_type=right_fields[0],
                    mount_source=mount_source,
                )
            )
    except (StorageAttestationError, UnicodeError):
        raise
    except (IndexError, TypeError, ValueError) as exc:
        raise StorageAttestationError("STORAGE_MOUNTINFO_INVALID") from exc
    if not entries:
        raise StorageAttestationError("STORAGE_MOUNTINFO_INVALID")
    return tuple(entries)


def _canonical_absolute_path(path: Path) -> str:
    raw = os.fspath(path)
    if not path.is_absolute():
        raise StorageAttestationError("STORAGE_PATH_NOT_ABSOLUTE")
    canonical = os.path.normpath(raw)
    if raw != canonical or canonical == "//":
        raise StorageAttestationError("STORAGE_PATH_INVALID")
    return canonical


def _open_directory_without_symlinks(path: str) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open("/", flags)
        for component in Path(path).parts[1:]:
            try:
                metadata = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise StorageAttestationError("STORAGE_PATH_UNAVAILABLE") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise StorageAttestationError("STORAGE_PATH_SYMLINK")
            if not stat.S_ISDIR(metadata.st_mode):
                raise StorageAttestationError("STORAGE_PATH_NOT_DIRECTORY")
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise StorageAttestationError("STORAGE_PATH_UNTRUSTED") from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except StorageAttestationError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise StorageAttestationError("STORAGE_PATH_UNAVAILABLE") from exc


def _exact_mount(
    entries: tuple[_MountInfoEntry, ...],
    path: str,
) -> _MountInfoEntry:
    matches = [entry for entry in entries if entry.mount_point == path]
    if len(matches) != 1:
        raise StorageAttestationError("STORAGE_NOT_EXACT_MOUNT")
    entry = matches[0]
    if entry.mount_point == "/" and entry.filesystem_type == "overlay":
        raise StorageAttestationError("STORAGE_OVERLAY_ROOT_FORBIDDEN")
    return entry


def _write_probe(directory_descriptor: int) -> None:
    name = f"{_PROBE_PREFIX}{os.getpid()}-{secrets.token_hex(8)}"
    file_descriptor: int | None = None
    created = False
    probe_error: StorageAttestationError | None = None
    try:
        file_descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        created = True
        offset = 0
        while offset < len(_PROBE_BYTES):
            written = os.write(file_descriptor, _PROBE_BYTES[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(file_descriptor)
    except OSError:
        probe_error = StorageAttestationError("STORAGE_PROBE_FAILED")
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                probe_error = StorageAttestationError("STORAGE_PROBE_FAILED")
        if created:
            try:
                os.unlink(name, dir_fd=directory_descriptor)
            except OSError:
                probe_error = StorageAttestationError("STORAGE_PROBE_CLEANUP_FAILED")
            else:
                # Some filesystems do not support fsync on a directory.
                with suppress(OSError):
                    os.fsync(directory_descriptor)
    if probe_error is not None:
        raise probe_error


def _free_bytes(directory_descriptor: int) -> int:
    try:
        filesystem = os.fstatvfs(directory_descriptor)
    except OSError as exc:
        raise StorageAttestationError("STORAGE_SPACE_UNAVAILABLE") from exc
    free_bytes = filesystem.f_bavail * filesystem.f_frsize
    if free_bytes < 0:
        raise StorageAttestationError("STORAGE_SPACE_UNAVAILABLE")
    return free_bytes


def _assert_mount_device(
    directory_descriptor: int,
    mount: _MountInfoEntry,
) -> None:
    try:
        device = os.fstat(directory_descriptor).st_dev
    except OSError as exc:
        raise StorageAttestationError("STORAGE_MOUNT_DEVICE_UNAVAILABLE") from exc
    if (
        os.major(device) != mount.device_major
        or os.minor(device) != mount.device_minor
    ):
        raise StorageAttestationError("STORAGE_MOUNT_DEVICE_MISMATCH")


class WorkerStorageVerifier:
    def __init__(
        self,
        *,
        log_volume_path: Path,
        workspace_volume_path: Path,
        log_min_free_bytes: int,
        workspace_min_free_bytes: int,
        mountinfo_path: Path = Path("/proc/self/mountinfo"),
    ) -> None:
        self.log_volume_path = log_volume_path
        self.workspace_volume_path = workspace_volume_path
        self.log_min_free_bytes = log_min_free_bytes
        self.workspace_min_free_bytes = workspace_min_free_bytes
        self.mountinfo_path = mountinfo_path

    def verify_runtime(self) -> StorageVerification:
        if self.log_min_free_bytes < 0 or self.workspace_min_free_bytes < 0:
            raise StorageAttestationError("STORAGE_CONFIGURATION_INVALID")

        log_path = _canonical_absolute_path(self.log_volume_path)
        workspace_path = _canonical_absolute_path(self.workspace_volume_path)
        if log_path == workspace_path:
            raise StorageAttestationError("STORAGE_MOUNTS_NOT_INDEPENDENT")

        try:
            mountinfo = self.mountinfo_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise StorageAttestationError("STORAGE_MOUNTINFO_UNAVAILABLE") from exc
        entries = _parse_mountinfo(mountinfo)
        log_mount = _exact_mount(entries, log_path)
        workspace_mount = _exact_mount(entries, workspace_path)
        if log_mount.underlying_identity == workspace_mount.underlying_identity:
            raise StorageAttestationError("STORAGE_MOUNTS_NOT_INDEPENDENT")

        log_descriptor: int | None = None
        workspace_descriptor: int | None = None
        try:
            log_descriptor = _open_directory_without_symlinks(log_path)
            workspace_descriptor = _open_directory_without_symlinks(workspace_path)
            _assert_mount_device(log_descriptor, log_mount)
            _assert_mount_device(workspace_descriptor, workspace_mount)

            _write_probe(log_descriptor)
            log_free_bytes = _free_bytes(log_descriptor)
            if log_free_bytes < self.log_min_free_bytes:
                raise StorageAttestationError(
                    "STORAGE_LOG_FREE_SPACE_INSUFFICIENT"
                )

            _write_probe(workspace_descriptor)
            workspace_free_bytes = _free_bytes(workspace_descriptor)
            if workspace_free_bytes < self.workspace_min_free_bytes:
                raise StorageAttestationError(
                    "STORAGE_WORKSPACE_FREE_SPACE_INSUFFICIENT"
                )
        finally:
            if workspace_descriptor is not None:
                os.close(workspace_descriptor)
            if log_descriptor is not None:
                os.close(log_descriptor)

        return StorageVerification(
            log_mount_identity_hash=log_mount.identity_hash,
            workspace_mount_identity_hash=workspace_mount.identity_hash,
            log_free_bytes=log_free_bytes,
            workspace_free_bytes=workspace_free_bytes,
            checked_at=datetime.now(UTC),
        )
