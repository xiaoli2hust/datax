from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import stat
import struct
import sys
import tarfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Final

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from datax_studio.worker.process import StreamingRedactor

PACKAGE_MAGIC: Final = b"DXESBACKUP1\n"
PACKAGE_SCHEMA_VERSION: Final = "1.0"
MANIFEST_SCHEMA_VERSION: Final = "1.0"
BACKUP_HELPER_VERSION: Final = "1.0"
CHUNK_SIZE: Final = 1024 * 1024
MAX_HEADER_BYTES: Final = 16 * 1024
MAX_MANIFEST_BYTES: Final = 1024 * 1024
MAX_PASSWORD_BYTES: Final = 1024
ARGON2_MEMORY_KIB: Final = 64 * 1024
ARGON2_TIME_COST: Final = 3
ARGON2_PARALLELISM: Final = 1
AES_GCM_TAG_BYTES: Final = 16
MIN_PASSWORD_BYTES: Final = 20
BACKUP_SAFETY_BYTES: Final = 1024 * 1024 * 1024
MAX_METADATA_FILE_BYTES: Final = 4 * 1024 * 1024
MAX_RESTORE_JOURNAL_BYTES: Final = 64 * 1024
RESTORE_JOURNAL_SCHEMA_VERSION: Final = "1.0"
RESTORE_JOURNAL_KEY_DOMAIN: Final = b"DXES-RESTORE-JOURNAL-HMAC-v1\x00"
RESTORE_JOURNAL_STATES: Final = {
    "INITIALIZED",
    "DATA_STAGED",
    "SECRETS_STAGED",
    "STAGED_COMMIT_BLOCKED",
    "FAILED",
    "CLEANED",
}
FIXED_SECRET_SPECS: Final = {
    "postgres_password.txt": ("hex", 64, 64),
    "egress_guard_database_password.txt": ("hex", 64, 64),
    "api_database_password.txt": ("hex", 64, 64),
    "worker_database_password.txt": ("hex", 64, 64),
    "jwt_private_key.pem": ("pem", 1, 4096),
    "jwt_public_key.pem": ("pem", 1, 4096),
    "refresh_token_hmac_key": ("binary", 32, 32),
    "idempotency_hmac_key": ("binary", 32, 32),
}
KEK_NAME = re.compile(r"\Acredential-kek-[a-z0-9][a-z0-9_.-]{0,62}\.key\Z")
LOWER_HEX_64 = re.compile(r"\A[0-9a-f]{64}\Z")
BACKUP_ID = re.compile(r"\A[0-9a-f]{32}\Z")
PRODUCT_VERSION = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z.+-]{0,63}\Z")
MIGRATION_REVISION = re.compile(r"\A[0-9a-z][0-9a-z_]{0,63}\Z")
METADATA_FILES: Final = (
    "compose.yaml",
    "images.release.env",
    "release-manifest.json",
)
LOG_TREE_NAME: Final = "des-log-data"
POSTGRES_DUMP_FILENAME: Final = "postgres.dump"
POSTGRES_DUMP_FORMAT: Final = "POSTGRESQL_CUSTOM"
POSTGRES_DUMP_MAGIC: Final = b"PGDMP"
UUID_COMPONENT = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
PRIVATE_KEY_MARKERS_LOWER: Final = (
    b"-----begin " + b"private key-----",
    b"-----begin encrypted " + b"private key-----",
)


class BackupError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class TreeEvidence:
    root_name: str
    file_count: int
    directory_count: int
    uncompressed_bytes: int
    tree_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "root_name": self.root_name,
            "file_count": self.file_count,
            "directory_count": self.directory_count,
            "uncompressed_bytes": self.uncompressed_bytes,
            "tree_sha256": self.tree_sha256,
        }


@dataclass(frozen=True)
class PackageHeader:
    kind: str
    backup_id: str
    salt: bytes
    nonce_prefix: bytes

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PACKAGE_SCHEMA_VERSION,
            "kind": self.kind,
            "backup_id": self.backup_id,
            "kdf": {
                "algorithm": "ARGON2ID-1.3",
                "memory_kib": ARGON2_MEMORY_KIB,
                "time_cost": ARGON2_TIME_COST,
                "parallelism": ARGON2_PARALLELISM,
                "salt_hex": self.salt.hex(),
            },
            "cipher": {
                "algorithm": "AES-256-GCM-CHUNKED",
                "chunk_size": CHUNK_SIZE,
                "nonce_prefix_hex": self.nonce_prefix.hex(),
            },
        }


class HashingWriter:
    def __init__(self, raw: BinaryIO) -> None:
        self.raw = raw
        self.digest = hashlib.sha256()
        self.bytes_written = 0

    def write(self, value: bytes) -> int:
        written = self.raw.write(value)
        if written is None:
            written = len(value)
        if written != len(value):
            raise OSError("short backup package write")
        self.digest.update(value)
        self.bytes_written += written
        return written

    def flush(self) -> None:
        self.raw.flush()


class EncryptedWriter(io.RawIOBase):
    def __init__(self, raw: HashingWriter, password: bytearray, header: PackageHeader) -> None:
        super().__init__()
        self._raw = raw
        self._header_bytes = _encode_header(header)
        self._header_digest = hashlib.sha256(self._header_bytes).digest()
        self._nonce_prefix = header.nonce_prefix
        self._key = bytearray(_derive_key(password, header.salt))
        self._cipher = AESGCM(bytes(self._key))
        self._buffer = bytearray()
        self._counter = 0
        self._finalized = False
        self._raw.write(self._header_bytes)

    def writable(self) -> bool:
        return True

    def write(self, value: bytes | bytearray | memoryview) -> int:
        if self._finalized:
            raise ValueError("backup package is finalized")
        incoming = bytes(value)
        self._buffer.extend(incoming)
        while len(self._buffer) >= CHUNK_SIZE:
            chunk = bytes(self._buffer[:CHUNK_SIZE])
            del self._buffer[:CHUNK_SIZE]
            self._write_record(chunk)
        return len(incoming)

    def flush(self) -> None:
        self._raw.flush()

    def finalize(self) -> None:
        if self._finalized:
            return
        if self._buffer:
            chunk = bytes(self._buffer)
            self._buffer.clear()
            self._write_record(chunk)
        self._write_record(b"")
        self._raw.flush()
        self._finalized = True
        _zeroize(self._key)

    def _write_record(self, plaintext: bytes) -> None:
        if self._counter > 0xFFFFFFFF:
            raise BackupError("BACKUP_TOO_LARGE", "备份包超过受支持的加密分块上限。")
        length = len(plaintext)
        length_bytes = struct.pack(">I", length)
        counter_bytes = struct.pack(">I", self._counter)
        nonce = self._nonce_prefix + counter_bytes
        aad = self._header_digest + counter_bytes + length_bytes
        ciphertext = self._cipher.encrypt(nonce, plaintext, aad)
        self._raw.write(length_bytes)
        self._raw.write(ciphertext)
        self._counter += 1

    def close(self) -> None:
        try:
            self.finalize()
        finally:
            _zeroize(self._buffer)
            _zeroize(self._key)
            super().close()


class EncryptedReader(io.RawIOBase):
    def __init__(self, raw: BinaryIO, password: bytearray, expected_kind: str) -> None:
        super().__init__()
        self._raw = raw
        self.header, header_bytes = _read_header(raw, expected_kind)
        self._header_digest = hashlib.sha256(header_bytes).digest()
        self._nonce_prefix = self.header.nonce_prefix
        self._key = bytearray(_derive_key(password, self.header.salt))
        self._cipher = AESGCM(bytes(self._key))
        self._buffer = bytearray()
        self._counter = 0
        self._final_seen = False

    def readable(self) -> bool:
        return True

    def readinto(self, target: bytearray | memoryview) -> int:
        if not self._buffer and not self._final_seen:
            self._read_record()
        if not self._buffer:
            return 0
        size = min(len(target), len(self._buffer))
        target[:size] = self._buffer[:size]
        del self._buffer[:size]
        return size

    def _read_record(self) -> None:
        length_bytes = _read_exact(self._raw, 4, "BACKUP_TRUNCATED")
        length = struct.unpack(">I", length_bytes)[0]
        if length > CHUNK_SIZE:
            raise BackupError("BACKUP_RECORD_INVALID", "备份包包含超长加密分块。")
        if self._counter > 0xFFFFFFFF:
            raise BackupError("BACKUP_TOO_LARGE", "备份包超过受支持的加密分块上限。")
        ciphertext = _read_exact(
            self._raw,
            length + AES_GCM_TAG_BYTES,
            "BACKUP_TRUNCATED",
        )
        counter_bytes = struct.pack(">I", self._counter)
        nonce = self._nonce_prefix + counter_bytes
        aad = self._header_digest + counter_bytes + length_bytes
        try:
            plaintext = self._cipher.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise BackupError(
                "BACKUP_AUTHENTICATION_FAILED",
                "备份密码错误或备份内容已被篡改。",
            ) from exc
        self._counter += 1
        if length == 0:
            if plaintext:
                raise BackupError("BACKUP_RECORD_INVALID", "备份结束分块格式无效。")
            if self._raw.read(1):
                raise BackupError("BACKUP_TRAILING_DATA", "备份结束标记后存在额外数据。")
            self._final_seen = True
            _zeroize(self._key)
            return
        self._buffer.extend(plaintext)

    def finish(self) -> None:
        drain = bytearray(CHUNK_SIZE)
        while self.readinto(drain):
            pass
        _zeroize(drain)

    def close(self) -> None:
        _zeroize(self._buffer)
        _zeroize(self._key)
        super().close()


def _zeroize(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _derive_key(password: bytearray, salt: bytes) -> bytes:
    try:
        return hash_secret_raw(
            secret=bytes(password),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=32,
            type=Type.ID,
            version=19,
        )
    except Exception as exc:
        raise BackupError("BACKUP_KDF_FAILED", "无法派生备份加密密钥。") from exc


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _encode_header(header: PackageHeader) -> bytes:
    body = _canonical_json(header.as_dict())
    if len(body) > MAX_HEADER_BYTES:
        raise BackupError("BACKUP_HEADER_INVALID", "备份头超过允许大小。")
    return PACKAGE_MAGIC + struct.pack(">I", len(body)) + body


def _read_header(raw: BinaryIO, expected_kind: str) -> tuple[PackageHeader, bytes]:
    if expected_kind not in {"DATA", "SECRETS"}:
        raise BackupError("BACKUP_HEADER_INVALID", "备份类型不受支持。")
    magic = _read_exact(raw, len(PACKAGE_MAGIC), "BACKUP_HEADER_INVALID")
    if magic != PACKAGE_MAGIC:
        raise BackupError("BACKUP_HEADER_INVALID", "不是受支持的 DataX 备份包。")
    length_bytes = _read_exact(raw, 4, "BACKUP_HEADER_INVALID")
    length = struct.unpack(">I", length_bytes)[0]
    if not 1 <= length <= MAX_HEADER_BYTES:
        raise BackupError("BACKUP_HEADER_INVALID", "备份头长度无效。")
    body = _read_exact(raw, length, "BACKUP_HEADER_INVALID")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("BACKUP_HEADER_INVALID", "备份头不是有效 JSON。") from exc
    expected_top = {"schema_version", "kind", "backup_id", "kdf", "cipher"}
    if not isinstance(value, dict) or set(value) != expected_top:
        raise BackupError("BACKUP_HEADER_INVALID", "备份头字段不受支持。")
    if (
        value["schema_version"] != PACKAGE_SCHEMA_VERSION
        or value["kind"] != expected_kind
        or not isinstance(value["backup_id"], str)
        or not BACKUP_ID.fullmatch(value["backup_id"])
    ):
        raise BackupError("BACKUP_HEADER_INVALID", "备份版本、类型或标识无效。")
    kdf = value["kdf"]
    cipher = value["cipher"]
    if (
        not isinstance(kdf, dict)
        or set(kdf) != {"algorithm", "memory_kib", "time_cost", "parallelism", "salt_hex"}
        or kdf["algorithm"] != "ARGON2ID-1.3"
        or not _is_json_integer(kdf["memory_kib"])
        or kdf["memory_kib"] != ARGON2_MEMORY_KIB
        or not _is_json_integer(kdf["time_cost"])
        or kdf["time_cost"] != ARGON2_TIME_COST
        or not _is_json_integer(kdf["parallelism"])
        or kdf["parallelism"] != ARGON2_PARALLELISM
        or not isinstance(kdf["salt_hex"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", kdf["salt_hex"])
        or not isinstance(cipher, dict)
        or set(cipher) != {"algorithm", "chunk_size", "nonce_prefix_hex"}
        or cipher["algorithm"] != "AES-256-GCM-CHUNKED"
        or not _is_json_integer(cipher["chunk_size"])
        or cipher["chunk_size"] != CHUNK_SIZE
        or not isinstance(cipher["nonce_prefix_hex"], str)
        or not re.fullmatch(r"[0-9a-f]{16}", cipher["nonce_prefix_hex"])
    ):
        raise BackupError("BACKUP_HEADER_INVALID", "备份加密参数不受支持。")
    header = PackageHeader(
        kind=value["kind"],
        backup_id=value["backup_id"],
        salt=bytes.fromhex(kdf["salt_hex"]),
        nonce_prefix=bytes.fromhex(cipher["nonce_prefix_hex"]),
    )
    return header, magic + length_bytes + body


def _read_exact(raw: BinaryIO, size: int, code: str) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = raw.read(size - len(chunks))
        if not part:
            raise BackupError(code, "备份包意外截断。")
        chunks.extend(part)
    return bytes(chunks)


def _read_password() -> bytearray:
    value = bytearray(sys.stdin.buffer.readline(MAX_PASSWORD_BYTES + 2))
    trailing = sys.stdin.buffer.read(1)
    if trailing:
        _zeroize(value)
        raise BackupError("BACKUP_PASSWORD_INVALID", "备份密码输入超过允许长度。")
    if value.endswith(b"\n"):
        value.pop()
    if value.endswith(b"\r"):
        value.pop()
    if (
        not MIN_PASSWORD_BYTES <= len(value) <= MAX_PASSWORD_BYTES
        or b"\x00" in value
        or b"\r" in value
        or b"\n" in value
    ):
        _zeroize(value)
        raise BackupError(
            "BACKUP_PASSWORD_INVALID",
            "备份密码必须为 20 至 1024 bytes，且不能包含换行或 NUL。",
        )
    return value


def _read_restore_password_pair() -> tuple[bytearray, bytearray]:
    values: list[bytearray] = []
    try:
        for _ in range(2):
            value = bytearray(sys.stdin.buffer.readline(MAX_PASSWORD_BYTES + 2))
            values.append(value)
            if not value.endswith(b"\n"):
                raise BackupError(
                    "RESTORE_PASSWORD_INPUT_INVALID",
                    "配对恢复必须通过标准输入提供恰好两行恢复秘密。",
                )
            value.pop()
            if value.endswith(b"\r"):
                value.pop()
            if (
                not MIN_PASSWORD_BYTES <= len(value) <= MAX_PASSWORD_BYTES
                or b"\x00" in value
                or b"\r" in value
                or b"\n" in value
            ):
                raise BackupError(
                    "RESTORE_PASSWORD_INPUT_INVALID",
                    "每个恢复秘密必须为 20 至 1024 bytes，且不能包含换行或 NUL。",
                )
        if sys.stdin.buffer.read(1):
            raise BackupError(
                "RESTORE_PASSWORD_INPUT_INVALID",
                "标准输入包含两行恢复秘密之外的额外数据。",
            )
        return values[0], values[1]
    except Exception:
        for value in values:
            _zeroize(value)
        raise


def _validate_identifier(value: str, pattern: re.Pattern[str], label: str) -> str:
    if not pattern.fullmatch(value):
        raise BackupError("BACKUP_ARGUMENT_INVALID", f"{label}格式无效。")
    return value


def _is_json_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _ensure_plain_directory(path: Path, *, must_be_empty: bool = False) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("BACKUP_PATH_INVALID", "备份目录不可用。") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise BackupError("BACKUP_PATH_INVALID", "备份路径必须是非符号链接目录。")
    if must_be_empty:
        try:
            if any(path.iterdir()):
                raise BackupError("RESTORE_TARGET_NOT_EMPTY", "恢复目标目录必须为空。")
        except OSError as exc:
            raise BackupError("BACKUP_PATH_INVALID", "无法检查恢复目标目录。") from exc


def _safe_relative_bytes(root: Path, path: Path) -> bytes:
    relative = path.relative_to(root)
    pieces = relative.parts
    if not pieces or any(piece in {"", ".", ".."} for piece in pieces):
        raise BackupError("BACKUP_TREE_UNSAFE", "备份目录包含不安全路径。")
    encoded = os.fsencode(relative.as_posix())
    if b"\x00" in encoded or b"\\" in encoded or encoded.startswith(b"/"):
        raise BackupError("BACKUP_TREE_UNSAFE", "备份目录包含不安全路径。")
    return encoded


def _digest_record(
    digest: Any,
    entry_type: bytes,
    relative: bytes,
    mode: int,
    size: int,
    content_digest: bytes = b"",
) -> None:
    digest.update(entry_type)
    digest.update(struct.pack(">I", len(relative)))
    digest.update(relative)
    digest.update(struct.pack(">I", stat.S_IMODE(mode)))
    digest.update(struct.pack(">Q", size))
    digest.update(content_digest)


def inspect_tree(
    root_name: str,
    root: Path,
    *,
    path_validator: Callable[[tuple[str, ...], bool], None] | None = None,
    file_scanner: Callable[[Path], None] | None = None,
) -> TreeEvidence:
    _ensure_plain_directory(root)
    digest = hashlib.sha256()
    root_metadata = root.lstat()
    _digest_record(digest, b"D", b"", root_metadata.st_mode, 0)
    file_count = 0
    directory_count = 0
    total_bytes = 0
    paths: list[Path] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort(key=os.fsencode)
        files.sort(key=os.fsencode)
        current_path = Path(current)
        for name in directories:
            paths.append(current_path / name)
        for name in files:
            paths.append(current_path / name)
    paths.sort(key=lambda value: os.fsencode(value.relative_to(root).as_posix()))
    for path in paths:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise BackupError("BACKUP_TREE_READ_FAILED", "无法读取备份目录。") from exc
        relative = _safe_relative_bytes(root, path)
        if stat.S_ISDIR(metadata.st_mode):
            if path_validator is not None:
                path_validator(path.relative_to(root).parts, True)
            directory_count += 1
            _digest_record(digest, b"D", relative, metadata.st_mode, 0)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise BackupError(
                "BACKUP_TREE_UNSAFE",
                "备份目录只能包含普通文件和目录；符号链接或特殊文件已被拒绝。",
            )
        if path_validator is not None:
            path_validator(path.relative_to(root).parts, False)
        if file_scanner is not None:
            file_scanner(path)
        file_digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
                    file_digest.update(chunk)
        except OSError as exc:
            raise BackupError("BACKUP_TREE_READ_FAILED", "无法读取备份文件。") from exc
        file_count += 1
        total_bytes += metadata.st_size
        _digest_record(
            digest,
            b"F",
            relative,
            metadata.st_mode,
            metadata.st_size,
            file_digest.digest(),
        )
    return TreeEvidence(
        root_name=root_name,
        file_count=file_count,
        directory_count=directory_count,
        uncompressed_bytes=total_bytes,
        tree_sha256=digest.hexdigest(),
    )


def _validate_log_path(parts: tuple[str, ...], is_directory: bool) -> None:
    if any(
        part.casefold() == "job.json" or part.casefold().endswith(".job.json") for part in parts
    ):
        raise BackupError(
            "BACKUP_DATA_ALLOWLIST_REJECTED",
            "日志备份中发现运行时 job.json；数据包已阻断。",
        )
    if is_directory:
        valid = len(parts) == 1 and UUID_COMPONENT.fullmatch(parts[0])
    else:
        valid = (
            len(parts) == 2
            and UUID_COMPONENT.fullmatch(parts[0])
            and parts[1].endswith(".log")
            and UUID_COMPONENT.fullmatch(parts[1][:-4])
        )
    if not valid:
        raise BackupError(
            "BACKUP_DATA_ALLOWLIST_REJECTED",
            "日志卷只允许 <execution UUID>/<attempt UUID>.log 固定布局。",
        )


def _scan_redacted_file(path: Path, exact_secrets: Sequence[bytes | bytearray]) -> None:
    source_digest = hashlib.sha256()
    redacted_digest = hashlib.sha256()
    source_size = 0
    redacted_size = 0
    redactor = StreamingRedactor(exact_secrets)
    marker_tail = b""
    job_markers = {b'"job"': False, b'"reader"': False, b'"writer"': False}
    private_key_seen = False
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
                source_size += len(chunk)
                source_digest.update(chunk)
                redacted = redactor.feed(chunk)
                redacted_size += len(redacted)
                redacted_digest.update(redacted)
                window = (marker_tail + chunk).lower()
                private_key_seen = private_key_seen or any(
                    marker in window for marker in PRIVATE_KEY_MARKERS_LOWER
                )
                for marker in job_markers:
                    job_markers[marker] = job_markers[marker] or marker in window
                marker_tail = window[-128:]
        final = redactor.finish()
        redacted_size += len(final)
        redacted_digest.update(final)
    except OSError as exc:
        raise BackupError("BACKUP_TREE_READ_FAILED", "无法扫描脱敏日志。") from exc
    if private_key_seen or all(job_markers.values()):
        raise BackupError(
            "BACKUP_DATA_ALLOWLIST_REJECTED",
            "日志中发现私钥或 DataX 运行时任务配置特征；数据包已阻断。",
        )
    if source_size != redacted_size or source_digest.digest() != redacted_digest.digest():
        raise BackupError(
            "BACKUP_SECRET_LEAK_DETECTED",
            "日志未通过二次脱敏检查；数据包已阻断。",
        )


def _scan_exact_secret_values(
    path: Path,
    exact_secrets: Sequence[bytes | bytearray],
) -> tuple[int, str]:
    patterns = [bytes(value) for value in exact_secrets if value]
    patterns.extend(marker.upper() for marker in PRIVATE_KEY_MARKERS_LOWER)
    maximum = max((len(value) for value in patterns), default=1)
    digest = hashlib.sha256()
    consumed = 0
    tail = b""
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
                consumed += len(chunk)
                digest.update(chunk)
                window = tail + chunk
                if any(value in window for value in patterns):
                    raise BackupError(
                        "BACKUP_SECRET_LEAK_DETECTED",
                        "数据库逻辑备份包含部署密钥明文；数据包已阻断。",
                    )
                tail = window[-(maximum - 1) :] if maximum > 1 else b""
    except OSError as exc:
        raise BackupError("BACKUP_DUMP_READ_FAILED", "无法读取 PostgreSQL 逻辑备份。") from exc
    return consumed, digest.hexdigest()


def _inspect_postgres_dump(
    path: Path,
    exact_secrets: Sequence[bytes | bytearray],
) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("BACKUP_DUMP_INVALID", "PostgreSQL 逻辑备份不可用。") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_size <= len(POSTGRES_DUMP_MAGIC)
    ):
        raise BackupError(
            "BACKUP_DUMP_INVALID",
            "PostgreSQL 备份必须是非空、非符号链接的普通文件。",
        )
    try:
        with path.open("rb") as handle:
            if handle.read(len(POSTGRES_DUMP_MAGIC)) != POSTGRES_DUMP_MAGIC:
                raise BackupError(
                    "BACKUP_DUMP_INVALID",
                    "PostgreSQL 备份不是 pg_dump custom format。",
                )
    except OSError as exc:
        raise BackupError("BACKUP_DUMP_READ_FAILED", "无法读取 PostgreSQL 逻辑备份。") from exc
    consumed, digest = _scan_exact_secret_values(path, exact_secrets)
    if consumed != metadata.st_size:
        raise BackupError("BACKUP_DUMP_READ_FAILED", "PostgreSQL 逻辑备份读取长度不一致。")
    return {
        "filename": POSTGRES_DUMP_FILENAME,
        "format": POSTGRES_DUMP_FORMAT,
        "size": consumed,
        "sha256": digest,
    }


def _scan_metadata_value(
    name: str,
    value: bytes,
    exact_secrets: Sequence[bytes | bytearray],
) -> None:
    redactor = StreamingRedactor(exact_secrets)
    redacted = redactor.feed(value) + redactor.finish()
    lowered = value.lower()
    if (
        redacted != value
        or any(marker in lowered for marker in PRIVATE_KEY_MARKERS_LOWER)
        or (b'"job"' in lowered and b'"reader"' in lowered and b'"writer"' in lowered)
    ):
        raise BackupError(
            "BACKUP_SECRET_LEAK_DETECTED",
            f"发布元数据 {name} 包含秘密或运行时任务配置特征。",
        )


def _read_metadata(
    metadata_root: Path,
    exact_secrets: Sequence[bytes | bytearray],
) -> dict[str, dict[str, Any]]:
    _ensure_plain_directory(metadata_root)
    result: dict[str, dict[str, Any]] = {}
    for name in METADATA_FILES:
        path = metadata_root / name
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise BackupError("BACKUP_METADATA_MISSING", f"缺少发布元数据 {name}。") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or not 1 <= metadata.st_size <= MAX_METADATA_FILE_BYTES
        ):
            raise BackupError("BACKUP_METADATA_INVALID", f"发布元数据 {name} 无效。")
        value = path.read_bytes()
        _scan_metadata_value(name, value, exact_secrets)
        result[name] = {
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
    return result


def _load_validated_secret_values(root: Path) -> dict[str, bytearray]:
    _ensure_plain_directory(root)
    try:
        entries = sorted(root.iterdir(), key=lambda value: os.fsencode(value.name))
    except OSError as exc:
        raise BackupError("BACKUP_SECRET_READ_FAILED", "无法枚举密钥目录。") from exc
    names = {entry.name for entry in entries}
    missing = set(FIXED_SECRET_SPECS) - names
    kek_names = sorted(name for name in names if KEK_NAME.fullmatch(name))
    allowed = set(FIXED_SECRET_SPECS) | set(kek_names)
    if missing or not kek_names or names != allowed:
        raise BackupError(
            "BACKUP_SECRET_SET_INVALID",
            "密钥目录缺少固定文件、没有 KEK，或包含未识别对象；备份已阻断。",
        )
    values: dict[str, bytearray] = {}
    try:
        for entry in entries:
            metadata = entry.lstat()
            if not stat.S_ISREG(metadata.st_mode) or entry.is_symlink():
                raise BackupError("BACKUP_SECRET_SET_INVALID", "密钥目录包含非普通文件。")
            if entry.name in FIXED_SECRET_SPECS:
                kind, minimum, maximum = FIXED_SECRET_SPECS[entry.name]
            else:
                kind, minimum, maximum = ("binary", 32, 32)
            if not minimum <= metadata.st_size <= maximum:
                raise BackupError("BACKUP_SECRET_SET_INVALID", "密钥文件长度无效。")
            value = bytearray(entry.read_bytes())
            values[entry.name] = value
            if kind == "hex" and (
                len(value) != 64 or any(byte not in b"0123456789abcdef" for byte in value)
            ):
                raise BackupError("BACKUP_SECRET_SET_INVALID", "数据库密码文件格式无效。")
        symmetric_names = [
            "refresh_token_hmac_key",
            "idempotency_hmac_key",
            *kek_names,
        ]
        symmetric = [bytes(values[name]) for name in symmetric_names]
        if len(set(symmetric)) != len(symmetric):
            raise BackupError("BACKUP_SECRET_SET_INVALID", "HMAC/KEK 密钥未实现域分离。")
        database_passwords = [
            bytes(values[name])
            for name in (
                "postgres_password.txt",
                "egress_guard_database_password.txt",
                "api_database_password.txt",
                "worker_database_password.txt",
            )
        ]
        if len(set(database_passwords)) != len(database_passwords):
            raise BackupError("BACKUP_SECRET_SET_INVALID", "数据库角色密码未实现域分离。")
        private_key = serialization.load_pem_private_key(
            bytes(values["jwt_private_key.pem"]),
            password=None,
        )
        public_key = serialization.load_pem_public_key(bytes(values["jwt_public_key.pem"]))
        if not isinstance(private_key, Ed25519PrivateKey):
            raise BackupError("BACKUP_SECRET_SET_INVALID", "JWT 私钥不是 Ed25519。")
        expected_public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        actual_public = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if expected_public != actual_public:
            raise BackupError("BACKUP_SECRET_SET_INVALID", "JWT 公私钥不匹配。")
    except (TypeError, ValueError) as exc:
        for value in values.values():
            _zeroize(value)
        raise BackupError("BACKUP_SECRET_SET_INVALID", "JWT 密钥格式无效。") from exc
    except Exception:
        for value in values.values():
            _zeroize(value)
        raise
    return values


def _validate_secret_root(root: Path) -> TreeEvidence:
    values = _load_validated_secret_values(root)
    try:
        return inspect_tree("secrets", root)
    finally:
        for value in values.values():
            _zeroize(value)


def _tar_info_for_bytes(name: str, value: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = len(value)
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.mtime = 0
    return info


def _tar_filter(info: tarfile.TarInfo) -> tarfile.TarInfo:
    if not (info.isfile() or info.isdir()):
        raise BackupError("BACKUP_TREE_UNSAFE", "备份树包含链接或特殊文件。")
    info.name = PurePosixPath(info.name).as_posix()
    info.pax_headers = {}
    return info


def _new_backup_id() -> str:
    return os.urandom(16).hex()


def _manifest_common(
    *,
    kind: str,
    backup_id: str,
    installation_id: str,
    product_version: str,
    migration_revision: str,
    evidence: Iterable[TreeEvidence],
) -> dict[str, Any]:
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": kind,
        "backup_id": backup_id,
        "created_at": datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "product_version": product_version,
        "installation_id": installation_id,
        "migration_revision": migration_revision,
        "backup_helper_version": BACKUP_HELPER_VERSION,
        "trees": [item.as_dict() for item in evidence],
    }


def _validate_common_arguments(
    installation_id: str,
    product_version: str,
    migration_revision: str,
) -> None:
    _validate_identifier(installation_id, LOWER_HEX_64, "installation-id")
    _validate_identifier(product_version, PRODUCT_VERSION, "产品版本")
    _validate_identifier(migration_revision, MIGRATION_REVISION, "迁移版本")


def _required_free_bytes(
    evidence: Iterable[TreeEvidence],
    *,
    additional_bytes: int = 0,
) -> int:
    total = sum(item.uncompressed_bytes for item in evidence) + additional_bytes
    return total + max(BACKUP_SAFETY_BYTES, total // 10)


def _ensure_free_space(path: Path, required: int) -> None:
    try:
        free = shutil.disk_usage(path).free
    except OSError as exc:
        raise BackupError("BACKUP_DISK_CHECK_FAILED", "无法核验备份磁盘空间。") from exc
    if free < required:
        raise BackupError(
            "BACKUP_DISK_INSUFFICIENT",
            "备份或恢复磁盘空间不足，尚未写入目标。",
        )


def export_data(
    *,
    output_dir: Path,
    password: bytearray,
    installation_id: str,
    product_version: str,
    migration_revision: str,
    metadata_root: Path,
    postgres_dump: Path,
    log_root: Path,
    secret_root_for_scan: Path,
) -> dict[str, Any]:
    _validate_common_arguments(installation_id, product_version, migration_revision)
    _ensure_plain_directory(output_dir)
    secret_values = _load_validated_secret_values(secret_root_for_scan)
    exact_secrets = [value for name, value in secret_values.items() if name != "jwt_public_key.pem"]
    try:
        database_dump = _inspect_postgres_dump(postgres_dump, exact_secrets)
        evidence = [
            inspect_tree(
                LOG_TREE_NAME,
                log_root,
                path_validator=_validate_log_path,
                file_scanner=lambda path: _scan_redacted_file(path, exact_secrets),
            )
        ]
        metadata = _read_metadata(metadata_root, exact_secrets)
    finally:
        for value in secret_values.values():
            _zeroize(value)
    _ensure_free_space(
        output_dir,
        _required_free_bytes(
            evidence,
            additional_bytes=database_dump["size"],
        ),
    )
    backup_id = _new_backup_id()
    manifest = _manifest_common(
        kind="DATA",
        backup_id=backup_id,
        installation_id=installation_id,
        product_version=product_version,
        migration_revision=migration_revision,
        evidence=evidence,
    )
    manifest["database_dump"] = database_dump
    manifest["release_metadata"] = metadata
    return _write_verified_package(
        kind="DATA",
        backup_id=backup_id,
        output_dir=output_dir,
        suffix=".dxdata",
        password=password,
        manifest=manifest,
        trees=[("logs", log_root)],
        files=[("database/postgres.dump", postgres_dump)],
        metadata_root=metadata_root,
    )


def export_secrets(
    *,
    output_dir: Path,
    password: bytearray,
    installation_id: str,
    product_version: str,
    migration_revision: str,
    related_data_backup_id: str,
    secret_root: Path,
) -> dict[str, Any]:
    _validate_common_arguments(installation_id, product_version, migration_revision)
    _validate_identifier(related_data_backup_id, BACKUP_ID, "数据备份标识")
    _ensure_plain_directory(output_dir)
    evidence = [_validate_secret_root(secret_root)]
    _ensure_free_space(output_dir, _required_free_bytes(evidence))
    backup_id = _new_backup_id()
    manifest = _manifest_common(
        kind="SECRETS",
        backup_id=backup_id,
        installation_id=installation_id,
        product_version=product_version,
        migration_revision=migration_revision,
        evidence=evidence,
    )
    manifest["related_data_backup_id"] = related_data_backup_id
    return _write_verified_package(
        kind="SECRETS",
        backup_id=backup_id,
        output_dir=output_dir,
        suffix=".dxkeys",
        password=password,
        manifest=manifest,
        trees=[("secrets", secret_root)],
        files=[],
        metadata_root=None,
    )


def _write_package(
    *,
    kind: str,
    backup_id: str,
    output_dir: Path,
    suffix: str,
    password: bytearray,
    manifest: dict[str, Any],
    trees: list[tuple[str, Path]],
    files: list[tuple[str, Path]],
    metadata_root: Path | None,
) -> dict[str, Any]:
    final_path = output_dir / f"{backup_id}{suffix}"
    partial_path = output_dir / f".{backup_id}{suffix}.partial"
    header = PackageHeader(
        kind=kind,
        backup_id=backup_id,
        salt=os.urandom(16),
        nonce_prefix=os.urandom(8),
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(partial_path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as raw:
            descriptor = -1
            hashing = HashingWriter(raw)
            encrypted = EncryptedWriter(hashing, password, header)
            with tarfile.open(fileobj=encrypted, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                manifest_bytes = _canonical_json(manifest)
                if len(manifest_bytes) > MAX_MANIFEST_BYTES:
                    raise BackupError("BACKUP_MANIFEST_INVALID", "备份清单超过允许大小。")
                archive.addfile(
                    _tar_info_for_bytes("manifest.json", manifest_bytes),
                    io.BytesIO(manifest_bytes),
                )
                if metadata_root is not None:
                    for name in METADATA_FILES:
                        value = (metadata_root / name).read_bytes()
                        archive.addfile(
                            _tar_info_for_bytes(f"metadata/{name}", value),
                            io.BytesIO(value),
                        )
                for archive_name, source in trees:
                    archive.add(source, arcname=archive_name, recursive=True, filter=_tar_filter)
                for archive_name, source in files:
                    archive.add(
                        source,
                        arcname=archive_name,
                        recursive=False,
                        filter=_tar_filter,
                    )
            encrypted.finalize()
            raw.flush()
            os.fsync(raw.fileno())
            package_sha256 = hashing.digest.hexdigest()
            package_bytes = hashing.bytes_written
        _publish_without_replace(partial_path, final_path)
        _fsync_directory(output_dir)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            partial_path.unlink(missing_ok=True)
        raise
    finally:
        _zeroize(password)
    return {
        "schema_version": "1.0",
        "code": "BACKUP_CREATED",
        "kind": kind,
        "backup_id": backup_id,
        "filename": final_path.name,
        "package_bytes": package_bytes,
        "package_sha256": package_sha256,
    }


def _write_verified_package(
    *,
    kind: str,
    backup_id: str,
    output_dir: Path,
    suffix: str,
    password: bytearray,
    manifest: dict[str, Any],
    trees: list[tuple[str, Path]],
    files: list[tuple[str, Path]],
    metadata_root: Path | None,
) -> dict[str, Any]:
    inspection_password = bytearray(password)
    result: dict[str, Any] | None = None
    try:
        result = _write_package(
            kind=kind,
            backup_id=backup_id,
            output_dir=output_dir,
            suffix=suffix,
            password=password,
            manifest=manifest,
            trees=trees,
            files=files,
            metadata_root=metadata_root,
        )
        package = output_dir / str(result["filename"])
        inspected = inspect_package(package, inspection_password, kind)
        if inspected != manifest:
            raise BackupError(
                "BACKUP_SELF_CHECK_FAILED",
                "刚发布的备份包与导出清单不一致。",
            )
        return result
    except Exception:
        if result is not None:
            with contextlib.suppress(OSError):
                (output_dir / str(result["filename"])).unlink(missing_ok=True)
        raise
    finally:
        _zeroize(inspection_password)


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _publish_without_replace(partial_path: Path, final_path: Path) -> None:
    try:
        os.link(partial_path, final_path, follow_symlinks=False)
    except OSError as exc:
        raise BackupError(
            "BACKUP_PUBLISH_FAILED",
            "无法以不覆盖已有文件的方式发布备份包。",
        ) from exc
    try:
        partial_path.unlink()
    except OSError as exc:
        with contextlib.suppress(OSError):
            final_path.unlink(missing_ok=True)
        raise BackupError("BACKUP_PUBLISH_FAILED", "无法完成备份包原子发布。") from exc


def inspect_package(path: Path, password: bytearray, expected_kind: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        _zeroize(password)
        raise BackupError("BACKUP_FILE_INVALID", "备份文件不可用。") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        _zeroize(password)
        raise BackupError("BACKUP_FILE_INVALID", "备份路径必须是普通文件。")
    try:
        with path.open("rb") as raw:
            encrypted = EncryptedReader(raw, password, expected_kind)
            try:
                manifest = _validate_tar(encrypted, expected_kind)
                encrypted.finish()
                if encrypted.header.backup_id != manifest["backup_id"]:
                    raise BackupError("BACKUP_MANIFEST_INVALID", "备份头与清单标识不一致。")
                return manifest
            finally:
                encrypted.close()
    finally:
        _zeroize(password)


def _validate_tar(
    raw: BinaryIO,
    expected_kind: str,
    *,
    restore_destination: Path | None = None,
) -> dict[str, Any]:
    manifest: dict[str, Any] | None = None
    evidence_by_root: dict[str, _TreeAccumulator] = {}
    metadata_seen: dict[str, tuple[int, str]] = {}
    database_dump_seen = False
    seen_paths: set[str] = set()
    if restore_destination is not None:
        _ensure_plain_directory(restore_destination, must_be_empty=True)
    with tarfile.open(fileobj=raw, mode="r|*") as archive:
        for index, member in enumerate(archive):
            name = _safe_tar_name(member.name)
            if name in seen_paths:
                raise BackupError("BACKUP_ARCHIVE_INVALID", "备份归档包含重复路径。")
            seen_paths.add(name)
            if index == 0:
                if name != "manifest.json" or not member.isfile():
                    raise BackupError("BACKUP_MANIFEST_INVALID", "备份清单不是归档首项。")
                manifest = _read_manifest_member(archive, member, expected_kind)
                evidence_by_root = {
                    item["root_name"]: _TreeAccumulator(item["root_name"])
                    for item in manifest["trees"]
                }
                continue
            if manifest is None:
                raise BackupError("BACKUP_MANIFEST_INVALID", "备份清单缺失。")
            if name.startswith("metadata/"):
                metadata_name = name.removeprefix("metadata/")
                _validate_metadata_member(
                    archive,
                    member,
                    name,
                    manifest,
                    metadata_seen,
                    (
                        restore_destination / "metadata" / metadata_name
                        if restore_destination is not None
                        else None
                    ),
                )
                continue
            if expected_kind == "DATA" and name == "database/postgres.dump":
                if database_dump_seen:
                    raise BackupError("BACKUP_ARCHIVE_INVALID", "数据库逻辑备份重复。")
                _validate_database_dump_member(
                    archive,
                    member,
                    manifest,
                    (
                        restore_destination / "database" / POSTGRES_DUMP_FILENAME
                        if restore_destination is not None
                        else None
                    ),
                )
                database_dump_seen = True
                continue
            root_name, relative = _route_tree_member(name, expected_kind)
            accumulator = evidence_by_root.get(root_name)
            if accumulator is None:
                raise BackupError("BACKUP_ARCHIVE_INVALID", "备份归档包含未声明数据树。")
            if expected_kind == "DATA" and relative:
                _validate_log_path(PurePosixPath(relative).parts, member.isdir())
            output_root = None
            if restore_destination is not None:
                tree_name = "logs" if expected_kind == "DATA" else "secrets"
                output_root = restore_destination / tree_name
            accumulator.add(archive, member, relative, output_root=output_root)
    if manifest is None:
        raise BackupError("BACKUP_MANIFEST_INVALID", "备份清单缺失。")
    _compare_tree_evidence(manifest, evidence_by_root)
    if expected_kind == "DATA":
        if not database_dump_seen:
            raise BackupError("BACKUP_DUMP_INVALID", "数据包缺少 PostgreSQL 逻辑备份。")
        expected_metadata = manifest["release_metadata"]
        if set(metadata_seen) != set(expected_metadata):
            raise BackupError("BACKUP_METADATA_INVALID", "发布元数据不完整。")
    elif metadata_seen:
        raise BackupError("BACKUP_ARCHIVE_INVALID", "密钥包不得包含发布元数据。")
    return manifest


def _validate_database_dump_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    manifest: dict[str, Any],
    output_path: Path | None = None,
) -> None:
    expected = manifest["database_dump"]
    if not member.isfile() or member.size != expected["size"]:
        raise BackupError("BACKUP_DUMP_INVALID", "数据库逻辑备份归档项无效。")
    source = archive.extractfile(member)
    if source is None:
        raise BackupError("BACKUP_DUMP_INVALID", "无法读取数据库逻辑备份。")
    digest = hashlib.sha256()
    consumed = 0
    prefix = bytearray()
    output = _open_restore_file(output_path) if output_path is not None else None
    try:
        for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
            consumed += len(chunk)
            digest.update(chunk)
            if len(prefix) < len(POSTGRES_DUMP_MAGIC):
                prefix.extend(chunk[: len(POSTGRES_DUMP_MAGIC) - len(prefix)])
            if output is not None:
                output.write(chunk)
        if output is not None:
            output.flush()
            os.fsync(output.fileno())
    finally:
        if output is not None:
            output.close()
    if (
        consumed != expected["size"]
        or bytes(prefix) != POSTGRES_DUMP_MAGIC
        or digest.hexdigest() != expected["sha256"]
    ):
        raise BackupError("BACKUP_DUMP_INVALID", "数据库逻辑备份摘要或格式不匹配。")


def _safe_tar_name(name: str) -> str:
    path = PurePosixPath(name)
    canonical = path.as_posix()
    if (
        not name
        or path.is_absolute()
        or "\\" in name
        or "\x00" in name
        or any(piece in {"", ".", ".."} for piece in path.parts)
        or canonical != name
    ):
        raise BackupError("BACKUP_ARCHIVE_UNSAFE", "备份归档包含不安全路径。")
    return canonical


def _create_restore_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(mode=0o700)
        except OSError as exc:
            raise BackupError(
                "RESTORE_STAGING_WRITE_FAILED",
                "无法创建受限恢复 staging 目录。",
            ) from exc
        return
    except OSError as exc:
        raise BackupError(
            "RESTORE_STAGING_WRITE_FAILED",
            "无法检查恢复 staging 目录。",
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise BackupError(
            "RESTORE_STAGING_UNSAFE",
            "恢复 staging 中出现链接或非目录对象。",
        )


def _open_restore_file(path: Path) -> BinaryIO:
    _create_restore_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise BackupError(
            "RESTORE_STAGING_WRITE_FAILED",
            "恢复 staging 文件无法以不覆盖方式创建。",
        ) from exc
    return os.fdopen(descriptor, "wb")


def _read_manifest_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    expected_kind: str,
) -> dict[str, Any]:
    if not 1 <= member.size <= MAX_MANIFEST_BYTES:
        raise BackupError("BACKUP_MANIFEST_INVALID", "备份清单大小无效。")
    source = archive.extractfile(member)
    if source is None:
        raise BackupError("BACKUP_MANIFEST_INVALID", "无法读取备份清单。")
    try:
        manifest = json.load(source)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("BACKUP_MANIFEST_INVALID", "备份清单不是有效 JSON。") from exc
    _validate_manifest(manifest, expected_kind)
    return manifest


def _validate_manifest(manifest: Any, expected_kind: str) -> None:
    common = {
        "schema_version",
        "kind",
        "backup_id",
        "created_at",
        "product_version",
        "installation_id",
        "migration_revision",
        "backup_helper_version",
        "trees",
    }
    expected = common | (
        {"database_dump", "release_metadata"}
        if expected_kind == "DATA"
        else {"related_data_backup_id"}
    )
    if not isinstance(manifest, dict) or set(manifest) != expected:
        raise BackupError("BACKUP_MANIFEST_INVALID", "备份清单字段不受支持。")
    if (
        manifest["schema_version"] != MANIFEST_SCHEMA_VERSION
        or manifest["kind"] != expected_kind
        or manifest["backup_helper_version"] != BACKUP_HELPER_VERSION
        or not isinstance(manifest["backup_id"], str)
        or not BACKUP_ID.fullmatch(manifest["backup_id"])
        or not isinstance(manifest["installation_id"], str)
        or not LOWER_HEX_64.fullmatch(manifest["installation_id"])
        or not isinstance(manifest["product_version"], str)
        or not PRODUCT_VERSION.fullmatch(manifest["product_version"])
        or not isinstance(manifest["migration_revision"], str)
        or not MIGRATION_REVISION.fullmatch(manifest["migration_revision"])
    ):
        raise BackupError("BACKUP_MANIFEST_INVALID", "备份清单身份或版本字段无效。")
    created_at_value = manifest["created_at"]
    if not isinstance(created_at_value, str) or not created_at_value.endswith("Z"):
        raise BackupError("BACKUP_MANIFEST_INVALID", "备份时间必须使用 UTC Z 后缀。")
    try:
        created_at = datetime.fromisoformat(created_at_value[:-1] + "+00:00")
    except (AttributeError, ValueError) as exc:
        raise BackupError("BACKUP_MANIFEST_INVALID", "备份时间无效。") from exc
    if created_at.tzinfo is None or created_at.utcoffset() != UTC.utcoffset(created_at):
        raise BackupError("BACKUP_MANIFEST_INVALID", "备份时间必须为 UTC。")
    trees = manifest["trees"]
    expected_roots = {LOG_TREE_NAME} if expected_kind == "DATA" else {"secrets"}
    if not isinstance(trees, list) or len(trees) != len(expected_roots):
        raise BackupError("BACKUP_MANIFEST_INVALID", "备份树清单无效。")
    roots: set[str] = set()
    for tree in trees:
        if not isinstance(tree, dict) or set(tree) != {
            "root_name",
            "file_count",
            "directory_count",
            "uncompressed_bytes",
            "tree_sha256",
        }:
            raise BackupError("BACKUP_MANIFEST_INVALID", "备份树字段无效。")
        if (
            tree["root_name"] not in expected_roots
            or tree["root_name"] in roots
            or not all(
                _is_json_integer(tree[field]) and tree[field] >= 0
                for field in ("file_count", "directory_count", "uncompressed_bytes")
            )
            or not isinstance(tree["tree_sha256"], str)
            or not LOWER_HEX_64.fullmatch(tree["tree_sha256"])
        ):
            raise BackupError("BACKUP_MANIFEST_INVALID", "备份树证据无效。")
        roots.add(tree["root_name"])
    if roots != expected_roots:
        raise BackupError("BACKUP_MANIFEST_INVALID", "备份树集合不完整。")
    if expected_kind == "DATA":
        database_dump = manifest["database_dump"]
        if (
            not isinstance(database_dump, dict)
            or set(database_dump) != {"filename", "format", "size", "sha256"}
            or database_dump["filename"] != POSTGRES_DUMP_FILENAME
            or database_dump["format"] != POSTGRES_DUMP_FORMAT
            or not _is_json_integer(database_dump["size"])
            or database_dump["size"] <= len(POSTGRES_DUMP_MAGIC)
            or not isinstance(database_dump["sha256"], str)
            or not LOWER_HEX_64.fullmatch(database_dump["sha256"])
        ):
            raise BackupError("BACKUP_DUMP_INVALID", "数据库逻辑备份清单无效。")
        metadata = manifest["release_metadata"]
        if not isinstance(metadata, dict) or set(metadata) != set(METADATA_FILES):
            raise BackupError("BACKUP_METADATA_INVALID", "发布元数据清单不完整。")
        for name, evidence in metadata.items():
            if (
                not isinstance(evidence, dict)
                or set(evidence) != {"size", "sha256"}
                or not _is_json_integer(evidence["size"])
                or not 1 <= evidence["size"] <= MAX_METADATA_FILE_BYTES
                or not isinstance(evidence["sha256"], str)
                or not LOWER_HEX_64.fullmatch(evidence["sha256"])
            ):
                raise BackupError("BACKUP_METADATA_INVALID", f"发布元数据 {name} 证据无效。")
    else:
        related = manifest["related_data_backup_id"]
        if not isinstance(related, str) or not BACKUP_ID.fullmatch(related):
            raise BackupError("BACKUP_MANIFEST_INVALID", "关联数据备份标识无效。")


def _validate_metadata_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    name: str,
    manifest: dict[str, Any],
    seen: dict[str, tuple[int, str]],
    output_path: Path | None = None,
) -> None:
    metadata_name = name.removeprefix("metadata/")
    expected = manifest.get("release_metadata", {}).get(metadata_name)
    if (
        expected is None
        or metadata_name in seen
        or not member.isfile()
        or member.size != expected["size"]
    ):
        raise BackupError("BACKUP_METADATA_INVALID", "发布元数据归档项无效。")
    source = archive.extractfile(member)
    if source is None:
        raise BackupError("BACKUP_METADATA_INVALID", "无法读取发布元数据。")
    digest = hashlib.sha256()
    output = _open_restore_file(output_path) if output_path is not None else None
    try:
        for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
            digest.update(chunk)
            if output is not None:
                output.write(chunk)
        if output is not None:
            output.flush()
            os.fsync(output.fileno())
    finally:
        if output is not None:
            output.close()
    if digest.hexdigest() != expected["sha256"]:
        raise BackupError("BACKUP_METADATA_INVALID", "发布元数据摘要不匹配。")
    seen[metadata_name] = (member.size, digest.hexdigest())


def _route_tree_member(name: str, kind: str) -> tuple[str, str]:
    parts = PurePosixPath(name).parts
    if kind == "DATA":
        if not parts or parts[0] != "logs":
            raise BackupError("BACKUP_ARCHIVE_INVALID", "数据包包含未识别归档项。")
        relative = PurePosixPath(*parts[1:]).as_posix() if len(parts) > 1 else ""
        return LOG_TREE_NAME, relative
    if not parts or parts[0] != "secrets":
        raise BackupError("BACKUP_ARCHIVE_INVALID", "密钥包包含未识别归档项。")
    relative = PurePosixPath(*parts[1:]).as_posix() if len(parts) > 1 else ""
    return "secrets", relative


class _TreeAccumulator:
    def __init__(self, root_name: str) -> None:
        self.root_name = root_name
        self.file_count = 0
        self.directory_count = 0
        self.uncompressed_bytes = 0
        self.paths: set[bytes] = set()
        self.records: dict[bytes, tuple[bytes, int, int, bytes]] = {}

    def add(
        self,
        archive: tarfile.TarFile,
        member: tarfile.TarInfo,
        relative: str,
        *,
        output_root: Path | None = None,
    ) -> None:
        if relative == "":
            if not member.isdir():
                raise BackupError("BACKUP_ARCHIVE_INVALID", "备份树根必须是目录。")
            if output_root is not None:
                _create_restore_directory(output_root)
            self.records[b""] = (b"D", member.mode, 0, b"")
            return
        encoded = relative.encode("utf-8", "surrogateescape")
        if encoded in self.paths:
            raise BackupError("BACKUP_ARCHIVE_INVALID", "备份树包含重复路径。")
        self.paths.add(encoded)
        if member.isdir():
            self.directory_count += 1
            self.records[encoded] = (b"D", member.mode, 0, b"")
            if output_root is not None:
                _create_restore_directory(output_root / relative)
            return
        if not member.isfile():
            raise BackupError("BACKUP_ARCHIVE_UNSAFE", "备份包含链接或特殊文件。")
        source = archive.extractfile(member)
        if source is None:
            raise BackupError("BACKUP_ARCHIVE_INVALID", "无法读取备份文件内容。")
        content_digest = hashlib.sha256()
        consumed = 0
        output = _open_restore_file(output_root / relative) if output_root is not None else None
        try:
            for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
                consumed += len(chunk)
                content_digest.update(chunk)
                if output is not None:
                    output.write(chunk)
            if output is not None:
                output.flush()
                os.fsync(output.fileno())
        finally:
            if output is not None:
                output.close()
        if consumed != member.size:
            raise BackupError("BACKUP_ARCHIVE_INVALID", "备份文件长度不匹配。")
        self.file_count += 1
        self.uncompressed_bytes += member.size
        self.records[encoded] = (
            b"F",
            member.mode,
            member.size,
            content_digest.digest(),
        )

    def evidence(self) -> TreeEvidence:
        digest = hashlib.sha256()
        for relative in sorted(self.records):
            entry_type, mode, size, content_digest = self.records[relative]
            _digest_record(
                digest,
                entry_type,
                relative,
                mode,
                size,
                content_digest,
            )
        return TreeEvidence(
            root_name=self.root_name,
            file_count=self.file_count,
            directory_count=self.directory_count,
            uncompressed_bytes=self.uncompressed_bytes,
            tree_sha256=digest.hexdigest(),
        )


def _compare_tree_evidence(
    manifest: dict[str, Any],
    actual: dict[str, _TreeAccumulator],
) -> None:
    expected = {item["root_name"]: item for item in manifest["trees"]}
    if set(actual) != set(expected):
        raise BackupError("BACKUP_TREE_MISMATCH", "备份树集合与清单不一致。")
    for root_name, accumulator in actual.items():
        if accumulator.evidence().as_dict() != expected[root_name]:
            raise BackupError("BACKUP_TREE_MISMATCH", f"{root_name} 数据树摘要不匹配。")


def restore_package(
    *,
    path: Path,
    password: bytearray,
    expected_kind: str,
    destinations: dict[str, Path],
    expected_product_version: str,
    expected_migration_revision: str,
    expected_related_data_backup_id: str | None = None,
) -> dict[str, Any]:
    del (
        path,
        expected_kind,
        destinations,
        expected_product_version,
        expected_migration_revision,
        expected_related_data_backup_id,
    )
    _zeroize(password)
    raise BackupError(
        "RESTORE_PAIR_REQUIRED",
        "禁止单包恢复；必须使用带认证 journal 的 DATA/SECRETS 配对 staging helper。",
    )


def _package_evidence(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("BACKUP_FILE_INVALID", "恢复包文件不可用。") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size <= 0:
        raise BackupError("BACKUP_FILE_INVALID", "恢复包必须是非空普通文件。")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise BackupError("BACKUP_FILE_INVALID", "无法完整读取恢复包。") from exc
    return {
        "size": metadata.st_size,
        "sha256": digest.hexdigest(),
    }


def _package_kdf_salt(path: Path, expected_kind: str) -> str:
    try:
        with path.open("rb") as raw:
            header, _ = _read_header(raw, expected_kind)
    except OSError as exc:
        raise BackupError("BACKUP_FILE_INVALID", "无法读取恢复包头。") from exc
    return header.salt.hex()


def _validate_restore_pair(
    data_manifest: dict[str, Any],
    secrets_manifest: dict[str, Any],
    *,
    expected_product_version: str,
    expected_migration_revision: str,
    expected_release_manifest_sha256: str,
    expected_installation_id: str | None,
) -> None:
    _validate_identifier(expected_product_version, PRODUCT_VERSION, "产品版本")
    _validate_identifier(expected_migration_revision, MIGRATION_REVISION, "迁移版本")
    _validate_identifier(
        expected_release_manifest_sha256,
        LOWER_HEX_64,
        "发布清单摘要",
    )
    if expected_installation_id is not None:
        _validate_identifier(expected_installation_id, LOWER_HEX_64, "installation-id")
    identity_fields = ("product_version", "installation_id", "migration_revision")
    if any(data_manifest[field] != secrets_manifest[field] for field in identity_fields):
        raise BackupError(
            "RESTORE_PACKAGE_PAIR_MISMATCH",
            "DATA 与 SECRETS 的安装身份、产品版本或迁移版本不一致。",
        )
    if secrets_manifest["related_data_backup_id"] != data_manifest["backup_id"]:
        raise BackupError(
            "RESTORE_PACKAGE_PAIR_MISMATCH",
            "SECRETS 未绑定当前 DATA 备份标识。",
        )
    if (
        data_manifest["product_version"] != expected_product_version
        or data_manifest["migration_revision"] != expected_migration_revision
    ):
        raise BackupError(
            "RESTORE_VERSION_INCOMPATIBLE",
            "恢复包与当前已签名程序的产品或数据库迁移版本不兼容。",
        )
    if (
        expected_installation_id is not None
        and data_manifest["installation_id"] != expected_installation_id
    ):
        raise BackupError(
            "RESTORE_INSTALLATION_ID_MISMATCH",
            "恢复包 installation-id 与指定安装身份不一致。",
        )
    actual_release_digest = data_manifest["release_metadata"]["release-manifest.json"]["sha256"]
    if not hmac.compare_digest(actual_release_digest, expected_release_manifest_sha256):
        raise BackupError(
            "RESTORE_RELEASE_BINDING_MISMATCH",
            "DATA 包内发布清单与当前已签名 Launcher 绑定摘要不一致。",
        )


def _restore_journal_key(
    data_password: bytes | bytearray,
    secrets_password: bytes | bytearray,
    data_salt_hex: str,
    secrets_salt_hex: str,
) -> bytearray:
    if not re.fullmatch(r"[0-9a-f]{32}", data_salt_hex) or not re.fullmatch(
        r"[0-9a-f]{32}",
        secrets_salt_hex,
    ):
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal KDF salt 无效。")
    data_input = bytearray(data_password)
    secrets_input = bytearray(secrets_password)
    data_key = bytearray()
    secrets_key = bytearray()
    try:
        data_key = bytearray(_derive_key(data_input, bytes.fromhex(data_salt_hex)))
        secrets_key = bytearray(_derive_key(secrets_input, bytes.fromhex(secrets_salt_hex)))
        digest = hashlib.sha256()
        digest.update(RESTORE_JOURNAL_KEY_DOMAIN)
        digest.update(data_key)
        digest.update(secrets_key)
        return bytearray(digest.digest())
    finally:
        _zeroize(data_input)
        _zeroize(secrets_input)
        _zeroize(data_key)
        _zeroize(secrets_key)


def _authenticated_journal(
    payload: dict[str, Any],
    journal_key: bytes | bytearray,
) -> dict[str, Any]:
    body = _canonical_json(payload)
    authenticated = dict(payload)
    authenticated["authentication"] = {
        "algorithm": "HMAC-SHA256",
        "key_domain": "DXES-RESTORE-JOURNAL-HMAC-v1",
        "mac_sha256": hmac.new(bytes(journal_key), body, hashlib.sha256).hexdigest(),
    }
    return authenticated


def _write_restore_journal(
    path: Path,
    payload: dict[str, Any],
    journal_key: bytes | bytearray,
    *,
    create: bool,
) -> None:
    parent = path.parent
    _ensure_plain_directory(parent)
    value = _canonical_json(_authenticated_journal(payload, journal_key))
    if len(value) > MAX_RESTORE_JOURNAL_BYTES:
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal 超过允许大小。")
    partial = parent / f".{path.name}.{os.urandom(8).hex()}.partial"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(partial, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        if create:
            try:
                os.link(partial, path, follow_symlinks=False)
            except OSError as exc:
                raise BackupError(
                    "RESTORE_JOURNAL_EXISTS",
                    "恢复 journal 已存在；不能覆盖未知恢复操作。",
                ) from exc
            partial.unlink()
        else:
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise BackupError(
                    "RESTORE_JOURNAL_MISSING",
                    "恢复 journal 在操作期间丢失。",
                ) from exc
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise BackupError("RESTORE_JOURNAL_UNSAFE", "恢复 journal 不是普通文件。")
            os.replace(partial, path)
        _fsync_directory(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            partial.unlink(missing_ok=True)


def _read_restore_journal(
    path: Path,
    journal_key: bytes | bytearray,
) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("RESTORE_JOURNAL_MISSING", "恢复 journal 不存在。") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or not 1 <= metadata.st_size <= MAX_RESTORE_JOURNAL_BYTES
    ):
        raise BackupError("RESTORE_JOURNAL_UNSAFE", "恢复 journal 类型或大小无效。")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal 不是有效 JSON。") from exc
    if not isinstance(value, dict):
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal 结构无效。")
    authentication = value.pop("authentication", None)
    if (
        not isinstance(authentication, dict)
        or set(authentication) != {"algorithm", "key_domain", "mac_sha256"}
        or authentication["algorithm"] != "HMAC-SHA256"
        or authentication["key_domain"] != "DXES-RESTORE-JOURNAL-HMAC-v1"
        or not isinstance(authentication["mac_sha256"], str)
        or not LOWER_HEX_64.fullmatch(authentication["mac_sha256"])
    ):
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal 认证字段无效。")
    expected = hmac.new(
        bytes(journal_key),
        _canonical_json(value),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(authentication["mac_sha256"], expected):
        raise BackupError(
            "RESTORE_JOURNAL_AUTHENTICATION_FAILED",
            "恢复 journal 与当前包对或恢复秘密不匹配。",
        )
    _validate_restore_journal_payload(value)
    return value


def _read_untrusted_restore_journal_salts(path: Path) -> tuple[str, str]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("RESTORE_JOURNAL_MISSING", "恢复 journal 不存在。") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or not 1 <= metadata.st_size <= MAX_RESTORE_JOURNAL_BYTES
    ):
        raise BackupError("RESTORE_JOURNAL_UNSAFE", "恢复 journal 类型或大小无效。")
    try:
        value = json.loads(path.read_bytes())
        data_salt = value["data_package"]["kdf_salt_hex"]
        secrets_salt = value["secrets_package"]["kdf_salt_hex"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal KDF salt 缺失。") from exc
    if (
        not isinstance(data_salt, str)
        or not re.fullmatch(r"[0-9a-f]{32}", data_salt)
        or not isinstance(secrets_salt, str)
        or not re.fullmatch(r"[0-9a-f]{32}", secrets_salt)
    ):
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal KDF salt 无效。")
    return data_salt, secrets_salt


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == UTC.utcoffset(parsed)


def _validate_restore_journal_payload(value: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "journal_id",
        "operation",
        "state",
        "created_at",
        "updated_at",
        "staging_root",
        "data_package",
        "secrets_package",
        "expected",
        "events",
    }
    if (
        set(value) != required
        or value["schema_version"] != RESTORE_JOURNAL_SCHEMA_VERSION
        or value["operation"] != "RESTORE_STAGE_PAIR"
        or not isinstance(value["journal_id"], str)
        or not BACKUP_ID.fullmatch(value["journal_id"])
        or value["state"] not in RESTORE_JOURNAL_STATES
        or not _is_utc_timestamp(value["created_at"])
        or not _is_utc_timestamp(value["updated_at"])
        or not isinstance(value["staging_root"], str)
        or not Path(value["staging_root"]).is_absolute()
        or not isinstance(value["events"], list)
        or not 1 <= len(value["events"]) <= 4096
    ):
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal 固定字段无效。")
    data_package = value["data_package"]
    if (
        not isinstance(data_package, dict)
        or set(data_package) != {"size", "sha256", "backup_id", "kdf_salt_hex"}
        or not _is_json_integer(data_package["size"])
        or data_package["size"] <= 0
        or not isinstance(data_package["sha256"], str)
        or not LOWER_HEX_64.fullmatch(data_package["sha256"])
        or not isinstance(data_package["backup_id"], str)
        or not BACKUP_ID.fullmatch(data_package["backup_id"])
        or not isinstance(data_package["kdf_salt_hex"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", data_package["kdf_salt_hex"])
    ):
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal DATA 包证据无效。")
    secrets_package = value["secrets_package"]
    if (
        not isinstance(secrets_package, dict)
        or set(secrets_package)
        != {
            "size",
            "sha256",
            "backup_id",
            "related_data_backup_id",
            "kdf_salt_hex",
        }
        or not _is_json_integer(secrets_package["size"])
        or secrets_package["size"] <= 0
        or not isinstance(secrets_package["sha256"], str)
        or not LOWER_HEX_64.fullmatch(secrets_package["sha256"])
        or not isinstance(secrets_package["backup_id"], str)
        or not BACKUP_ID.fullmatch(secrets_package["backup_id"])
        or not isinstance(secrets_package["related_data_backup_id"], str)
        or not BACKUP_ID.fullmatch(secrets_package["related_data_backup_id"])
        or not isinstance(secrets_package["kdf_salt_hex"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", secrets_package["kdf_salt_hex"])
        or secrets_package["related_data_backup_id"] != data_package["backup_id"]
    ):
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal SECRETS 包证据无效。")
    expected = value["expected"]
    if (
        not isinstance(expected, dict)
        or set(expected)
        != {
            "product_version",
            "migration_revision",
            "release_manifest_sha256",
            "installation_id",
        }
        or not isinstance(expected["product_version"], str)
        or not PRODUCT_VERSION.fullmatch(expected["product_version"])
        or not isinstance(expected["migration_revision"], str)
        or not MIGRATION_REVISION.fullmatch(expected["migration_revision"])
        or not isinstance(expected["release_manifest_sha256"], str)
        or not LOWER_HEX_64.fullmatch(expected["release_manifest_sha256"])
        or not isinstance(expected["installation_id"], str)
        or not LOWER_HEX_64.fullmatch(expected["installation_id"])
    ):
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal 预期身份无效。")
    events = value["events"]
    for index, event in enumerate(events, start=1):
        if (
            not isinstance(event, dict)
            or set(event) != {"sequence", "state", "code", "recorded_at"}
            or event["sequence"] != index
            or event["state"] not in RESTORE_JOURNAL_STATES
            or not isinstance(event["code"], str)
            or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", event["code"])
            or not _is_utc_timestamp(event["recorded_at"])
        ):
            raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal 事件序列无效。")
    if (
        events[0]["state"] != "INITIALIZED"
        or events[0]["recorded_at"] != value["created_at"]
        or events[-1]["state"] != value["state"]
        or events[-1]["recorded_at"] != value["updated_at"]
    ):
        raise BackupError("RESTORE_JOURNAL_INVALID", "恢复 journal 首尾状态不一致。")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _append_restore_event(
    journal: dict[str, Any],
    state: str,
    code: str,
) -> None:
    now = _utc_now()
    journal["state"] = state
    journal["updated_at"] = now
    journal["events"].append(
        {
            "sequence": len(journal["events"]) + 1,
            "state": state,
            "code": code,
            "recorded_at": now,
        }
    )


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _remove_restore_tree(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise BackupError("RESTORE_STAGING_CLEANUP_FAILED", "无法检查恢复 staging。") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise BackupError(
            "RESTORE_STAGING_CLEANUP_FAILED",
            "恢复 staging 根对象不是安全目录；未执行递归删除。",
        )
    for current, directories, files in os.walk(path, topdown=False, followlinks=False):
        current_path = Path(current)
        for name in files:
            candidate = current_path / name
            candidate_metadata = candidate.lstat()
            if not stat.S_ISREG(candidate_metadata.st_mode) or candidate.is_symlink():
                raise BackupError(
                    "RESTORE_STAGING_CLEANUP_FAILED",
                    "恢复 staging 包含链接或特殊文件；未继续删除。",
                )
            candidate.unlink()
        for name in directories:
            candidate = current_path / name
            candidate_metadata = candidate.lstat()
            if not stat.S_ISDIR(candidate_metadata.st_mode) or candidate.is_symlink():
                raise BackupError(
                    "RESTORE_STAGING_CLEANUP_FAILED",
                    "恢复 staging 包含链接或特殊目录；未继续删除。",
                )
            candidate.rmdir()
    path.rmdir()


def _cleanup_journal_staging(staging_root: Path) -> None:
    _ensure_plain_directory(staging_root)
    try:
        entries = list(staging_root.iterdir())
    except OSError as exc:
        raise BackupError(
            "RESTORE_STAGING_CLEANUP_FAILED",
            "无法枚举恢复 staging。",
        ) from exc
    if any(entry.name not in {"data", "secrets"} for entry in entries):
        raise BackupError(
            "RESTORE_STAGING_CLEANUP_FAILED",
            "恢复 staging 包含 journal 未声明对象；未执行清理。",
        )
    for name in ("data", "secrets"):
        _remove_restore_tree(staging_root / name)


def _extract_restore_package(
    *,
    path: Path,
    password: bytearray,
    expected_kind: str,
    destination: Path,
    expected_manifest: dict[str, Any],
    expected_package_evidence: dict[str, Any],
) -> None:
    before = _package_evidence(path)
    if before != expected_package_evidence:
        _zeroize(password)
        raise BackupError("RESTORE_PACKAGE_CHANGED", "恢复包在认证后发生变化。")
    _create_restore_directory(destination)
    try:
        with path.open("rb") as raw:
            encrypted = EncryptedReader(raw, password, expected_kind)
            try:
                actual_manifest = _validate_tar(
                    encrypted,
                    expected_kind,
                    restore_destination=destination,
                )
                encrypted.finish()
            finally:
                encrypted.close()
        if actual_manifest != expected_manifest or _package_evidence(path) != before:
            raise BackupError("RESTORE_PACKAGE_CHANGED", "恢复包在 staging 期间发生变化。")
    finally:
        _zeroize(password)


def _validate_restore_key_domain_separation(
    data_password: bytes | bytearray,
    secrets_password: bytes | bytearray,
    secret_root: Path,
) -> None:
    if hmac.compare_digest(bytes(data_password), bytes(secrets_password)):
        raise BackupError("RESTORE_KEY_REUSE_REJECTED", "DATA 与 SECRETS 恢复秘密必须不同。")
    values = _load_validated_secret_values(secret_root)
    try:
        protected: list[bytes] = []
        for value in values.values():
            raw = bytes(value)
            protected.extend((raw, raw.hex().encode("ascii")))
        for recovery_key in (bytes(data_password), bytes(secrets_password)):
            if any(hmac.compare_digest(recovery_key, value) for value in protected):
                raise BackupError(
                    "RESTORE_KEY_DOMAIN_REUSE_REJECTED",
                    "恢复秘密不得复用数据库密码、JWT、HMAC、KEK 或其十六进制编码。",
                )
    finally:
        for value in values.values():
            _zeroize(value)


def stage_restore_pair(
    *,
    data_path: Path,
    secrets_path: Path,
    data_password: bytearray,
    secrets_password: bytearray,
    staging_root: Path,
    journal_path: Path,
    expected_product_version: str,
    expected_migration_revision: str,
    expected_release_manifest_sha256: str,
    expected_installation_id: str | None = None,
) -> dict[str, Any]:
    if hmac.compare_digest(bytes(data_password), bytes(secrets_password)):
        _zeroize(data_password)
        _zeroize(secrets_password)
        raise BackupError("RESTORE_KEY_REUSE_REJECTED", "DATA 与 SECRETS 恢复秘密必须不同。")
    data_secret = bytearray(data_password)
    secrets_secret = bytearray(secrets_password)
    journal_key = bytearray()
    journal: dict[str, Any] | None = None
    try:
        _ensure_plain_directory(staging_root)
        canonical_staging = staging_root.resolve(strict=True)
        canonical_journal_parent = journal_path.parent.resolve(strict=True)
        canonical_journal = canonical_journal_parent / journal_path.name
        canonical_data = data_path.resolve(strict=True)
        canonical_secrets = secrets_path.resolve(strict=True)
        if (
            _path_is_within(canonical_journal, canonical_staging)
            or _path_is_within(canonical_data, canonical_staging)
            or _path_is_within(canonical_secrets, canonical_staging)
            or canonical_data == canonical_secrets
        ):
            raise BackupError(
                "RESTORE_PATH_OVERLAP_REJECTED",
                "恢复包、journal 与 staging 路径必须分离。",
            )
        data_evidence = _package_evidence(data_path)
        secrets_evidence = _package_evidence(secrets_path)
        data_salt = _package_kdf_salt(data_path, "DATA")
        secrets_salt = _package_kdf_salt(secrets_path, "SECRETS")
        journal_key = _restore_journal_key(
            data_password,
            secrets_password,
            data_salt,
            secrets_salt,
        )
        data_manifest = inspect_package(data_path, bytearray(data_password), "DATA")
        secrets_manifest = inspect_package(
            secrets_path,
            bytearray(secrets_password),
            "SECRETS",
        )
        _validate_restore_pair(
            data_manifest,
            secrets_manifest,
            expected_product_version=expected_product_version,
            expected_migration_revision=expected_migration_revision,
            expected_release_manifest_sha256=expected_release_manifest_sha256,
            expected_installation_id=expected_installation_id,
        )
        package_total = (
            data_manifest["database_dump"]["size"]
            + sum(item["uncompressed_bytes"] for item in data_manifest["trees"])
            + sum(item["size"] for item in data_manifest["release_metadata"].values())
            + sum(item["uncompressed_bytes"] for item in secrets_manifest["trees"])
        )
        _ensure_free_space(
            staging_root,
            package_total + max(BACKUP_SAFETY_BYTES, package_total // 10),
        )
        expected = {
            "product_version": expected_product_version,
            "migration_revision": expected_migration_revision,
            "release_manifest_sha256": expected_release_manifest_sha256,
            "installation_id": data_manifest["installation_id"],
        }
        package_records = {
            "data_package": {
                **data_evidence,
                "backup_id": data_manifest["backup_id"],
                "kdf_salt_hex": data_salt,
            },
            "secrets_package": {
                **secrets_evidence,
                "backup_id": secrets_manifest["backup_id"],
                "related_data_backup_id": secrets_manifest["related_data_backup_id"],
                "kdf_salt_hex": secrets_salt,
            },
        }
        if journal_path.exists():
            journal = _read_restore_journal(journal_path, journal_key)
            if (
                journal["staging_root"] != str(canonical_staging)
                or journal["expected"] != expected
                or journal["data_package"] != package_records["data_package"]
                or journal["secrets_package"] != package_records["secrets_package"]
            ):
                raise BackupError(
                    "RESTORE_JOURNAL_PAIR_MISMATCH",
                    "已有 restore journal 不属于当前包对、版本或 staging。",
                )
            _cleanup_journal_staging(staging_root)
            _append_restore_event(journal, "INITIALIZED", "RESTORE_RESUME_RESTARTED")
            _write_restore_journal(journal_path, journal, journal_key, create=False)
        else:
            _ensure_plain_directory(staging_root, must_be_empty=True)
            now = _utc_now()
            journal = {
                "schema_version": RESTORE_JOURNAL_SCHEMA_VERSION,
                "journal_id": _new_backup_id(),
                "operation": "RESTORE_STAGE_PAIR",
                "state": "INITIALIZED",
                "created_at": now,
                "updated_at": now,
                "staging_root": str(canonical_staging),
                **package_records,
                "expected": expected,
                "events": [
                    {
                        "sequence": 1,
                        "state": "INITIALIZED",
                        "code": "RESTORE_JOURNAL_CREATED",
                        "recorded_at": now,
                    }
                ],
            }
            _write_restore_journal(journal_path, journal, journal_key, create=True)

        _extract_restore_package(
            path=data_path,
            password=data_secret,
            expected_kind="DATA",
            destination=staging_root / "data",
            expected_manifest=data_manifest,
            expected_package_evidence=data_evidence,
        )
        _append_restore_event(journal, "DATA_STAGED", "RESTORE_DATA_STAGED")
        _write_restore_journal(journal_path, journal, journal_key, create=False)

        _extract_restore_package(
            path=secrets_path,
            password=secrets_secret,
            expected_kind="SECRETS",
            destination=staging_root / "secrets",
            expected_manifest=secrets_manifest,
            expected_package_evidence=secrets_evidence,
        )
        _validate_restore_key_domain_separation(
            data_password,
            secrets_password,
            staging_root / "secrets" / "secrets",
        )
        _append_restore_event(journal, "SECRETS_STAGED", "RESTORE_SECRETS_STAGED")
        _write_restore_journal(journal_path, journal, journal_key, create=False)

        _append_restore_event(
            journal,
            "STAGED_COMMIT_BLOCKED",
            "RESTORE_ATOMIC_VOLUME_COMMIT_UNAVAILABLE",
        )
        _write_restore_journal(journal_path, journal, journal_key, create=False)
        return {
            "schema_version": "1.0",
            "code": "RESTORE_STAGED_COMMIT_BLOCKED",
            "journal_id": journal["journal_id"],
            "state": journal["state"],
            "data_backup_id": data_manifest["backup_id"],
            "secrets_backup_id": secrets_manifest["backup_id"],
            "installation_id": data_manifest["installation_id"],
            "next_required_gate": "PG_RESTORE_NEW_EMPTY_VOLUME_AND_ATOMIC_COMMIT",
        }
    except BackupError as exc:
        if journal is not None:
            with contextlib.suppress(BackupError, OSError):
                _append_restore_event(journal, "FAILED", exc.code)
                _write_restore_journal(journal_path, journal, journal_key, create=False)
        raise
    finally:
        _zeroize(data_secret)
        _zeroize(secrets_secret)
        _zeroize(data_password)
        _zeroize(secrets_password)
        _zeroize(journal_key)


def cleanup_restore_staging(
    *,
    staging_root: Path,
    journal_path: Path,
    data_password: bytearray,
    secrets_password: bytearray,
) -> dict[str, Any]:
    journal_key = bytearray()
    try:
        data_salt, secrets_salt = _read_untrusted_restore_journal_salts(journal_path)
        journal_key = _restore_journal_key(
            data_password,
            secrets_password,
            data_salt,
            secrets_salt,
        )
        journal = _read_restore_journal(journal_path, journal_key)
        canonical_staging = staging_root.resolve(strict=True)
        if journal["staging_root"] != str(canonical_staging):
            raise BackupError(
                "RESTORE_JOURNAL_PAIR_MISMATCH",
                "restore journal 未授权清理当前 staging。",
            )
        _cleanup_journal_staging(staging_root)
        _append_restore_event(journal, "CLEANED", "RESTORE_STAGING_CLEANED")
        _write_restore_journal(journal_path, journal, journal_key, create=False)
        return {
            "schema_version": "1.0",
            "code": "RESTORE_STAGING_CLEANED",
            "journal_id": journal["journal_id"],
            "state": journal["state"],
        }
    finally:
        _zeroize(data_password)
        _zeroize(secrets_password)
        _zeroize(journal_key)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="datax-studio-system-backup")
    subcommands = parser.add_subparsers(dest="command", required=True)

    data = subcommands.add_parser("export-data")
    _common_export_arguments(data)
    data.add_argument("--metadata-root", type=Path, required=True)
    data.add_argument("--postgres-dump", type=Path, required=True)
    data.add_argument("--des-log-data", type=Path, required=True)
    data.add_argument("--secret-root-for-scan", type=Path, required=True)

    secrets = subcommands.add_parser("export-secrets")
    _common_export_arguments(secrets)
    secrets.add_argument("--related-data-backup-id", required=True)
    secrets.add_argument("--secret-root", type=Path, required=True)

    inspect_command = subcommands.add_parser("inspect")
    inspect_command.add_argument("--input", type=Path, required=True)
    inspect_command.add_argument("--kind", choices=("DATA", "SECRETS"), required=True)

    restore = subcommands.add_parser("stage-restore-pair")
    restore.add_argument("--data-input", type=Path, required=True)
    restore.add_argument("--secrets-input", type=Path, required=True)
    restore.add_argument("--staging-root", type=Path, required=True)
    restore.add_argument("--journal", type=Path, required=True)
    restore.add_argument("--expected-product-version", required=True)
    restore.add_argument("--expected-migration-revision", required=True)
    restore.add_argument("--expected-release-manifest-sha256", required=True)
    restore.add_argument("--expected-installation-id")

    cleanup = subcommands.add_parser("cleanup-restore-staging")
    cleanup.add_argument("--staging-root", type=Path, required=True)
    cleanup.add_argument("--journal", type=Path, required=True)
    return parser


def _common_export_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--migration-revision", required=True)


def _public_helper_payload(result: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the helper response from a closed, non-secret output contract."""
    if not isinstance(result, dict):
        raise BackupError("BACKUP_HELPER_RESPONSE_INVALID", "备份 helper 响应类型无效。")
    code = result.get("code")
    if code is None:
        kind = result.get("kind")
        if kind not in {"DATA", "SECRETS"}:
            raise BackupError("BACKUP_HELPER_RESPONSE_INVALID", "备份清单类型无效。")
        _validate_manifest(result, kind)
        return dict(result)
    if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code):
        raise BackupError("BACKUP_HELPER_RESPONSE_INVALID", "备份 helper 响应码无效。")
    if code == "BACKUP_CREATED":
        expected = {
            "schema_version",
            "code",
            "kind",
            "backup_id",
            "filename",
            "package_bytes",
            "package_sha256",
        }
        kind = result.get("kind")
        suffix = ".dxdata" if kind == "DATA" else ".dxkeys"
        backup_id = result.get("backup_id")
        if (
            set(result) != expected
            or result.get("schema_version") != "1.0"
            or kind not in {"DATA", "SECRETS"}
            or not isinstance(backup_id, str)
            or not BACKUP_ID.fullmatch(backup_id)
            or result.get("filename") != f"{backup_id}{suffix}"
            or not _is_json_integer(result.get("package_bytes"))
            or result["package_bytes"] <= 0
            or not isinstance(result.get("package_sha256"), str)
            or not LOWER_HEX_64.fullmatch(result["package_sha256"])
        ):
            raise BackupError("BACKUP_HELPER_RESPONSE_INVALID", "备份创建响应无效。")
        return {key: result[key] for key in sorted(expected)}
    response_fields = {
        "RESTORE_STAGED_COMMIT_BLOCKED": {
            "schema_version",
            "code",
            "journal_id",
            "state",
            "data_backup_id",
            "secrets_backup_id",
            "installation_id",
            "next_required_gate",
        },
        "RESTORE_STAGING_CLEANED": {
            "schema_version",
            "code",
            "journal_id",
            "state",
        },
    }
    if code in response_fields:
        expected = response_fields[code]
        if (
            set(result) != expected
            or result.get("schema_version") != "1.0"
            or not isinstance(result.get("journal_id"), str)
            or not BACKUP_ID.fullmatch(result["journal_id"])
        ):
            raise BackupError("BACKUP_HELPER_RESPONSE_INVALID", "恢复 helper 响应无效。")
        if code == "RESTORE_STAGED_COMMIT_BLOCKED" and (
            result.get("state") != "STAGED_COMMIT_BLOCKED"
            or result.get("next_required_gate")
            != "PG_RESTORE_NEW_EMPTY_VOLUME_AND_ATOMIC_COMMIT"
            or any(
                not isinstance(result.get(field), str)
                or not pattern.fullmatch(result[field])
                for field, pattern in (
                    ("data_backup_id", BACKUP_ID),
                    ("secrets_backup_id", BACKUP_ID),
                    ("installation_id", LOWER_HEX_64),
                )
            )
        ):
            raise BackupError("BACKUP_HELPER_RESPONSE_INVALID", "恢复 staging 响应无效。")
        if code == "RESTORE_STAGING_CLEANED" and result.get("state") != "CLEANED":
            raise BackupError("BACKUP_HELPER_RESPONSE_INVALID", "恢复清理响应无效。")
        return {key: result[key] for key in sorted(expected)}
    if set(result) != {"schema_version", "code", "message"}:
        raise BackupError("BACKUP_HELPER_RESPONSE_INVALID", "备份 helper 错误响应无效。")
    message = result.get("message")
    if (
        result.get("schema_version") != "1.0"
        or not isinstance(message, str)
        or not 1 <= len(message) <= 512
        or any(character in message for character in ("\x00", "\r", "\n"))
    ):
        raise BackupError("BACKUP_HELPER_RESPONSE_INVALID", "备份 helper 错误响应无效。")
    return {"schema_version": "1.0", "code": code, "message": message}


def _emit(result: dict[str, Any]) -> None:
    public_payload = _public_helper_payload(result)
    encoded = json.dumps(
        public_payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    password = bytearray()
    second_password = bytearray()
    try:
        if args.command in {"stage-restore-pair", "cleanup-restore-staging"}:
            password, second_password = _read_restore_password_pair()
        else:
            password = _read_password()
        if args.command == "export-data":
            result = export_data(
                output_dir=args.output_dir,
                password=password,
                installation_id=args.installation_id,
                product_version=args.product_version,
                migration_revision=args.migration_revision,
                metadata_root=args.metadata_root,
                postgres_dump=args.postgres_dump,
                log_root=args.des_log_data,
                secret_root_for_scan=args.secret_root_for_scan,
            )
        elif args.command == "export-secrets":
            result = export_secrets(
                output_dir=args.output_dir,
                password=password,
                installation_id=args.installation_id,
                product_version=args.product_version,
                migration_revision=args.migration_revision,
                related_data_backup_id=args.related_data_backup_id,
                secret_root=args.secret_root,
            )
        elif args.command == "stage-restore-pair":
            result = stage_restore_pair(
                data_path=args.data_input,
                secrets_path=args.secrets_input,
                data_password=password,
                secrets_password=second_password,
                staging_root=args.staging_root,
                journal_path=args.journal,
                expected_product_version=args.expected_product_version,
                expected_migration_revision=args.expected_migration_revision,
                expected_release_manifest_sha256=args.expected_release_manifest_sha256,
                expected_installation_id=args.expected_installation_id,
            )
        elif args.command == "cleanup-restore-staging":
            result = cleanup_restore_staging(
                staging_root=args.staging_root,
                journal_path=args.journal,
                data_password=password,
                secrets_password=second_password,
            )
        else:
            result = inspect_package(args.input, password, args.kind)
        _emit(result)
        return 3 if result.get("code") == "RESTORE_STAGED_COMMIT_BLOCKED" else 0
    except BackupError as exc:
        _emit(
            {
                "schema_version": "1.0",
                "code": exc.code,
                "message": exc.message,
            }
        )
        return 4
    except (OSError, tarfile.TarError):
        _emit(
            {
                "schema_version": "1.0",
                "code": "BACKUP_HELPER_FAILED",
                "message": "备份 helper 遇到受控 I/O 或归档错误；未报告成功。",
            }
        )
        return 5
    finally:
        _zeroize(password)
        _zeroize(second_password)


if __name__ == "__main__":
    raise SystemExit(main())
