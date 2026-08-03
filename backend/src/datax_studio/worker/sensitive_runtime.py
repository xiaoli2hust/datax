from __future__ import annotations

import os
import stat
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

_MARKER_NAME = ".datax-studio-sensitive-v1"
_NAME_SEPARATOR = "--"


class SensitiveRuntimeError(RuntimeError):
    """The private tmpfs runtime area cannot be proven safe."""


@dataclass(frozen=True)
class SensitiveAttempt:
    directory: Path
    job_file: Path
    runtime_log_directory: Path
    process_working_directory: Path


class SensitiveRuntimeStore:
    """Own secret-bearing, per-attempt files below a private tmpfs directory."""

    def __init__(
        self,
        root: Path,
        *,
        required_parent: Path | None = None,
    ) -> None:
        if not root.is_absolute() or root.name in {"", ".", ".."}:
            raise SensitiveRuntimeError("sensitive runtime root must be absolute")
        if required_parent is not None and root.parent != required_parent:
            raise SensitiveRuntimeError(
                "sensitive runtime root is outside the required tmpfs mount"
            )
        self.root = root
        self._lock = threading.RLock()

    def prepare_and_cleanup(self) -> int:
        """Remove only marked product attempts; unknown entries block admission."""

        with self._lock:
            root_fd = self._open_root()
            try:
                names = sorted(os.listdir(root_fd))
                for name in names:
                    self._validate_owned_attempt(root_fd, name)
                for name in names:
                    self._remove_owned_attempt(root_fd, name)
                os.fsync(root_fd)
                return len(names)
            except SensitiveRuntimeError:
                raise
            except OSError as exc:
                raise SensitiveRuntimeError("sensitive runtime cleanup failed") from exc
            finally:
                os.close(root_fd)

    def create_attempt(
        self,
        *,
        execution_id: UUID,
        attempt_id: UUID,
    ) -> SensitiveAttempt:
        name = self._attempt_name(execution_id, attempt_id)
        marker = self._marker_bytes(execution_id, attempt_id)
        with self._lock:
            root_fd = self._open_root()
            created = False
            attempt_fd: int | None = None
            try:
                os.mkdir(name, mode=0o700, dir_fd=root_fd)
                created = True
                attempt_fd = os.open(name, self._directory_flags(), dir_fd=root_fd)
                self._assert_private_directory(attempt_fd, os.fstat(root_fd).st_dev)
                self._write_exclusive(attempt_fd, _MARKER_NAME, marker)
                os.mkdir("runtime-logs", mode=0o700, dir_fd=attempt_fd)
                os.mkdir("process-workspace", mode=0o700, dir_fd=attempt_fd)
                for child_name in ("runtime-logs", "process-workspace"):
                    child_fd = os.open(
                        child_name,
                        self._directory_flags(),
                        dir_fd=attempt_fd,
                    )
                    try:
                        self._assert_private_directory(
                            child_fd,
                            os.fstat(root_fd).st_dev,
                        )
                    finally:
                        os.close(child_fd)
                os.fsync(attempt_fd)
                os.fsync(root_fd)
            except (OSError, SensitiveRuntimeError) as exc:
                if attempt_fd is not None:
                    os.close(attempt_fd)
                    attempt_fd = None
                if created:
                    self._cleanup_failed_creation(root_fd, name, marker)
                if isinstance(exc, SensitiveRuntimeError):
                    raise
                raise SensitiveRuntimeError("sensitive attempt directory creation failed") from exc
            finally:
                if attempt_fd is not None:
                    os.close(attempt_fd)
                os.close(root_fd)

        directory = self.root / name
        return SensitiveAttempt(
            directory=directory,
            job_file=directory / "job.json",
            runtime_log_directory=directory / "runtime-logs",
            process_working_directory=directory / "process-workspace",
        )

    def remove_attempt(
        self,
        *,
        execution_id: UUID,
        attempt_id: UUID,
    ) -> None:
        name = self._attempt_name(execution_id, attempt_id)
        with self._lock:
            root_fd = self._open_root()
            try:
                try:
                    os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return
                self._validate_owned_attempt(root_fd, name)
                self._remove_owned_attempt(root_fd, name)
                os.fsync(root_fd)
            except SensitiveRuntimeError:
                raise
            except OSError as exc:
                raise SensitiveRuntimeError("sensitive attempt cleanup failed") from exc
            finally:
                os.close(root_fd)

    def _open_root(self) -> int:
        parent_fd: int | None = None
        try:
            parent_fd = os.open(self.root.parent, self._directory_flags())
            with suppress(FileExistsError):
                os.mkdir(self.root.name, mode=0o700, dir_fd=parent_fd)
            root_fd = os.open(
                self.root.name,
                self._directory_flags(),
                dir_fd=parent_fd,
            )
            self._assert_private_directory(root_fd, os.fstat(parent_fd).st_dev)
            return root_fd
        except (OSError, SensitiveRuntimeError) as exc:
            if isinstance(exc, SensitiveRuntimeError):
                raise
            raise SensitiveRuntimeError("sensitive runtime root is unsafe") from exc
        finally:
            if parent_fd is not None:
                os.close(parent_fd)

    @staticmethod
    def _directory_flags() -> int:
        return (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

    @staticmethod
    def _attempt_name(execution_id: UUID, attempt_id: UUID) -> str:
        return f"{execution_id}{_NAME_SEPARATOR}{attempt_id}"

    @staticmethod
    def _marker_bytes(execution_id: UUID, attempt_id: UUID) -> bytes:
        return (
            f"DXES-SENSITIVE-RUNTIME-v1\nexecution_id={execution_id}\nattempt_id={attempt_id}\n"
        ).encode("ascii")

    @staticmethod
    def _parse_attempt_name(name: str) -> tuple[UUID, UUID]:
        parts = name.split(_NAME_SEPARATOR)
        if len(parts) != 2:
            raise SensitiveRuntimeError("unknown entry in sensitive runtime root")
        try:
            execution_id, attempt_id = (UUID(part) for part in parts)
        except ValueError as exc:
            raise SensitiveRuntimeError("unknown entry in sensitive runtime root") from exc
        if str(execution_id) != parts[0] or str(attempt_id) != parts[1]:
            raise SensitiveRuntimeError("non-canonical sensitive attempt name")
        return execution_id, attempt_id

    def _validate_owned_attempt(self, root_fd: int, name: str) -> None:
        execution_id, attempt_id = self._parse_attempt_name(name)
        attempt_fd = os.open(name, self._directory_flags(), dir_fd=root_fd)
        try:
            self._assert_private_directory(attempt_fd, os.fstat(root_fd).st_dev)
            expected = self._marker_bytes(execution_id, attempt_id)
            marker_fd = os.open(
                _MARKER_NAME,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=attempt_fd,
            )
            try:
                marker_stat = os.fstat(marker_fd)
                if (
                    not stat.S_ISREG(marker_stat.st_mode)
                    or marker_stat.st_uid != os.geteuid()
                    or stat.S_IMODE(marker_stat.st_mode) != 0o600
                    or marker_stat.st_dev != os.fstat(root_fd).st_dev
                ):
                    raise SensitiveRuntimeError("sensitive attempt ownership marker is unsafe")
                actual = os.read(marker_fd, len(expected) + 1)
                if actual != expected:
                    raise SensitiveRuntimeError("sensitive attempt ownership marker is invalid")
            finally:
                os.close(marker_fd)
        except OSError as exc:
            raise SensitiveRuntimeError("sensitive attempt cannot be proven product-owned") from exc
        finally:
            os.close(attempt_fd)

    def _remove_owned_attempt(self, root_fd: int, name: str) -> None:
        attempt_fd = os.open(name, self._directory_flags(), dir_fd=root_fd)
        try:
            self._remove_tree_contents(
                attempt_fd,
                expected_device=os.fstat(root_fd).st_dev,
            )
        finally:
            os.close(attempt_fd)
        os.rmdir(name, dir_fd=root_fd)

    def _remove_tree_contents(self, directory_fd: int, *, expected_device: int) -> None:
        for name in os.listdir(directory_fd):
            entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if entry.st_dev != expected_device:
                raise SensitiveRuntimeError("sensitive runtime cleanup crossed a mount boundary")
            if stat.S_ISDIR(entry.st_mode):
                child_fd = os.open(name, self._directory_flags(), dir_fd=directory_fd)
                try:
                    self._remove_tree_contents(
                        child_fd,
                        expected_device=expected_device,
                    )
                finally:
                    os.close(child_fd)
                os.rmdir(name, dir_fd=directory_fd)
            elif stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode):
                os.unlink(name, dir_fd=directory_fd)
            else:
                raise SensitiveRuntimeError(
                    "unexpected special file in sensitive runtime directory"
                )

    @staticmethod
    def _assert_private_directory(directory_fd: int, expected_device: int) -> None:
        value = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o700
            or value.st_dev != expected_device
        ):
            raise SensitiveRuntimeError("sensitive runtime directory is not private to the Worker")

    @staticmethod
    def _write_exclusive(directory_fd: int, name: str, content: bytes) -> None:
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short sensitive marker write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _cleanup_failed_creation(
        self,
        root_fd: int,
        name: str,
        marker: bytes,
    ) -> None:
        try:
            attempt_fd = os.open(name, self._directory_flags(), dir_fd=root_fd)
        except OSError:
            return
        try:
            try:
                marker_fd = os.open(
                    _MARKER_NAME,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=attempt_fd,
                )
            except FileNotFoundError:
                if not os.listdir(attempt_fd):
                    os.close(attempt_fd)
                    attempt_fd = -1
                    os.rmdir(name, dir_fd=root_fd)
                return
            try:
                if os.read(marker_fd, len(marker) + 1) != marker:
                    return
            finally:
                os.close(marker_fd)
            self._remove_tree_contents(
                attempt_fd,
                expected_device=os.fstat(root_fd).st_dev,
            )
        except OSError:
            return
        finally:
            if attempt_fd >= 0:
                os.close(attempt_fd)
        try:
            os.rmdir(name, dir_fd=root_fd)
        except OSError:
            return
