"""Private, fail-closed loading of ADR-0011 Phase-A P/QH evidence.

This module is intentionally not connected to Settings, environment variables,
the standard API, Worker, Compose, Launcher, or plugin-certification source.
It accepts only an explicitly injected private filesystem configuration and
returns non-secret evidence facts after verifying exact file hashes, canonical
P/QH parsing, QH validity, signature, and P/harness binding.

Loading evidence does not consume a QH nonce, write a grant, create an
Execution, or authorize DataX.  A future protected issuer must still re-read
the exact QH and atomically consume its nonce while writing a PAG.

The loader deliberately fails closed when the host lacks descriptor-relative
``O_NOFOLLOW`` opening.  It is therefore not a portable Windows harness source
provisioner; a future Windows implementation must provide an equivalent
reparse-safe primitive before it can consume private evidence.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Final

from datax_studio.release_qualification import (
    ExpectedHarness,
    QualificationVerificationError,
    ReleasePayload,
    VerifiedHarnessQualification,
    inspect_harness_qualification_evidence,
    parse_release_payload,
)

__all__ = [
    "LoadedPrivateHarnessEvidence",
    "PrivateHarnessEvidenceConfig",
    "PrivateHarnessEvidenceError",
    "PrivateHarnessEvidenceFile",
    "TrustedPrivateFilesystemRoot",
    "load_private_harness_evidence",
]

_MAX_EVIDENCE_DOCUMENT_BYTES: Final = 1024 * 1024
_MAX_RELATIVE_PATH_LENGTH: Final = 512
_SHA256: Final = re.compile(r"^[a-f0-9]{64}$")
_READ_CHUNK_BYTES: Final = 64 * 1024


class PrivateHarnessEvidenceError(ValueError):
    """Stable, non-secret failure from the private evidence loading boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TrustedPrivateFilesystemRoot:
    """An explicit private root injected by protected harness infrastructure.

    This value has no Settings/environment constructor on purpose.  The loader
    checks the root and every requested descendant with ``lstat`` plus
    descriptor-relative ``O_NOFOLLOW`` opens; this marker alone does not make
    an arbitrary path trusted.
    """

    path: Path = field(repr=False)


@dataclass(frozen=True)
class PrivateHarnessEvidenceFile:
    """One hash-pinned, relative evidence file under a private root."""

    root: TrustedPrivateFilesystemRoot = field(repr=False)
    relative_path: str = field(repr=False)
    sha256: str


@dataclass(frozen=True)
class PrivateHarnessEvidenceConfig:
    """All independently pinned inputs for one private P/QH inspection."""

    release_payload: PrivateHarnessEvidenceFile = field(repr=False)
    harness_qualification: PrivateHarnessEvidenceFile = field(repr=False)
    expected_payload_root_sha256: str
    expected_harness: ExpectedHarness


@dataclass(frozen=True)
class LoadedPrivateHarnessEvidence:
    """Non-secret facts from one checked private P/QH evidence pair.

    The original signed QH bytes and its raw nonce are intentionally not kept
    on this object.  It therefore cannot be used as the future issuer's input
    and rejects pickle serialization as an extra guard against later callers
    treating a loader result as a transferable capability.
    """

    release_payload: ReleasePayload
    qualification: VerifiedHarnessQualification
    payload_document_sha256: str
    qualification_document_sha256: str

    def __reduce__(self) -> object:
        raise TypeError("private harness evidence cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private harness evidence cannot be serialized")


def load_private_harness_evidence(
    *,
    config: PrivateHarnessEvidenceConfig,
    now: datetime,
) -> LoadedPrivateHarnessEvidence:
    """Load only exact P/QH evidence from injected private filesystem roots.

    The caller must independently inject the expected P root, document hashes,
    and harness identity.  In particular, the loader never accepts a root or a
    public-key source from the P/QH file itself as its trust anchor.
    """

    payload_file, qualification_file, expected_root, expected_harness = _config_fields(config)
    raw_payload = _read_hash_pinned_file(payload_file)
    try:
        release_payload = parse_release_payload(
            raw_payload,
            expected_payload_root_sha256=expected_root,
        )
    except QualificationVerificationError:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_PAYLOAD_REJECTED") from None

    raw_qualification = _read_hash_pinned_file(qualification_file)
    try:
        qualification = inspect_harness_qualification_evidence(
            raw_qualification,
            release_payload=release_payload,
            expected_harness=expected_harness,
            now=now,
        )
    except QualificationVerificationError:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_QUALIFICATION_REJECTED") from None
    finally:
        # The raw signed QH contains the one-time nonce.  Do not retain it in
        # a result object, exception, audit value, or log record.
        raw_qualification = b""

    return LoadedPrivateHarnessEvidence(
        release_payload=release_payload,
        qualification=qualification,
        payload_document_sha256=payload_file.sha256,
        qualification_document_sha256=qualification_file.sha256,
    )


def _config_fields(
    config: PrivateHarnessEvidenceConfig,
) -> tuple[
    PrivateHarnessEvidenceFile,
    PrivateHarnessEvidenceFile,
    str,
    ExpectedHarness,
]:
    if type(config) is not PrivateHarnessEvidenceConfig:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_CONFIG_INVALID")
    if (
        type(config.release_payload) is not PrivateHarnessEvidenceFile
        or type(config.harness_qualification) is not PrivateHarnessEvidenceFile
        or type(config.expected_payload_root_sha256) is not str
        or _SHA256.fullmatch(config.expected_payload_root_sha256) is None
        or type(config.expected_harness) is not ExpectedHarness
    ):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_CONFIG_INVALID")
    _validated_file_config(config.release_payload)
    _validated_file_config(config.harness_qualification)
    return (
        config.release_payload,
        config.harness_qualification,
        config.expected_payload_root_sha256,
        config.expected_harness,
    )


def _validated_file_config(value: PrivateHarnessEvidenceFile) -> tuple[str, ...]:
    if (
        type(value) is not PrivateHarnessEvidenceFile
        or type(value.root) is not TrustedPrivateFilesystemRoot
        or type(value.sha256) is not str
        or _SHA256.fullmatch(value.sha256) is None
    ):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_CONFIG_INVALID")
    return _relative_path_parts(value.relative_path)


def _relative_path_parts(value: str) -> tuple[str, ...]:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_RELATIVE_PATH_LENGTH
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
    ):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_PATH_INVALID")
    parts = tuple(value.split("/"))
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_PATH_INVALID")
    return parts


def _read_hash_pinned_file(value: PrivateHarnessEvidenceFile) -> bytes:
    parts = _validated_file_config(value)
    root_path = _validated_root_path(value.root)
    _assert_path_containment(root_path=root_path, parts=parts)
    raw = _read_regular_descendant(root_path=root_path, parts=parts)
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual_sha256, value.sha256):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_HASH_MISMATCH")
    return raw


def _validated_root_path(root: TrustedPrivateFilesystemRoot) -> Path:
    if type(root) is not TrustedPrivateFilesystemRoot or not isinstance(root.path, Path):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_CONFIG_INVALID")
    path = root.path
    if not path.is_absolute():
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_ROOT_INVALID")
    try:
        root_status = os.lstat(path)
    except OSError:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_ROOT_INVALID") from None
    if stat.S_ISLNK(root_status.st_mode):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_SYMLINK")
    if not stat.S_ISDIR(root_status.st_mode):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_ROOT_INVALID")
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_ROOT_INVALID") from None
    if resolved.parent == resolved:
        # A filesystem-wide root is not a bounded private evidence location.
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_ROOT_INVALID")
    return resolved


def _assert_path_containment(*, root_path: Path, parts: tuple[str, ...]) -> None:
    current = root_path
    for index, part in enumerate(parts):
        current = current / part
        try:
            current_status = os.lstat(current)
        except OSError:
            raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_READ_FAILED") from None
        if stat.S_ISLNK(current_status.st_mode):
            raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_SYMLINK")
        if index < len(parts) - 1 and not stat.S_ISDIR(current_status.st_mode):
            raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_PATH_INVALID")
    try:
        resolved_candidate = current.resolve(strict=True)
    except OSError:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_READ_FAILED") from None
    if not resolved_candidate.is_relative_to(root_path):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_PATH_INVALID")


def _read_regular_descendant(*, root_path: Path, parts: tuple[str, ...]) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if type(nofollow) is not int or type(directory) is not int:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_NOFOLLOW_UNAVAILABLE")
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    root_fd = _open_descriptor(
        root_path,
        os.O_RDONLY | directory | nofollow | close_on_exec,
    )
    try:
        _require_directory_descriptor(root_fd)
        directory_fd = root_fd
        for part in parts[:-1]:
            next_fd = _open_descriptor(
                part,
                os.O_RDONLY | directory | nofollow | close_on_exec,
                dir_fd=directory_fd,
            )
            try:
                _require_directory_descriptor(next_fd)
            except PrivateHarnessEvidenceError:
                os.close(next_fd)
                raise
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd
        file_fd = _open_descriptor(
            parts[-1],
            os.O_RDONLY | nofollow | close_on_exec,
            dir_fd=directory_fd,
        )
        try:
            return _read_regular_descriptor(file_fd)
        finally:
            os.close(file_fd)
    finally:
        if "directory_fd" in locals() and directory_fd != root_fd:
            os.close(directory_fd)
        os.close(root_fd)


def _open_descriptor(path: str | Path, flags: int, *, dir_fd: int | None = None) -> int:
    try:
        if dir_fd is None:
            return os.open(path, flags)
        return os.open(path, flags, dir_fd=dir_fd)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_SYMLINK") from None
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_READ_FAILED") from None


def _require_directory_descriptor(descriptor: int) -> None:
    try:
        mode = os.fstat(descriptor).st_mode
    except OSError:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_READ_FAILED") from None
    if not stat.S_ISDIR(mode):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_PATH_INVALID")


def _read_regular_descriptor(descriptor: int) -> bytes:
    try:
        file_status = os.fstat(descriptor)
    except OSError:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_READ_FAILED") from None
    if not stat.S_ISREG(file_status.st_mode):
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_NOT_REGULAR")
    if file_status.st_size > _MAX_EVIDENCE_DOCUMENT_BYTES:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_TOO_LARGE")
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_EVIDENCE_DOCUMENT_BYTES:
                raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_TOO_LARGE")
            chunks.append(chunk)
    except PrivateHarnessEvidenceError:
        raise
    except OSError:
        raise PrivateHarnessEvidenceError("PHASE_A_PRIVATE_FILE_READ_FAILED") from None
    return b"".join(chunks)
