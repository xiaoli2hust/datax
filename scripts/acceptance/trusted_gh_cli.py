#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

TRUSTED_GH_VERSION = "2.97.0"
TRUSTED_GH_PLATFORM = "linux-amd64"
TRUSTED_GH_ARCHIVE_URL = (
    "https://github.com/cli/cli/releases/download/v2.97.0/gh_2.97.0_linux_amd64.tar.gz"
)
TRUSTED_GH_RELEASE_URL = "https://github.com/cli/cli/releases/tag/v2.97.0"
TRUSTED_GH_ARCHIVE_SHA256 = (
    "a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112"
)
TRUSTED_GH_ARCHIVE_MEMBER = "gh_2.97.0_linux_amd64/bin/gh"
TRUSTED_GH_EXECUTABLE_SHA256 = (
    "141507c337e8b202ad398550c3b73d72f5af92e86f71665214538a81efd4c409"
)
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024

Runner = Callable[..., subprocess.CompletedProcess[str]]


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Install or verify the exact GitHub CLI used by the hosted "
            "candidate-root attestor."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("archive-url")
    metadata = subparsers.add_parser("metadata")
    metadata.add_argument("--output", type=Path, required=True)
    install = subparsers.add_parser("install")
    install.add_argument("--archive", type=Path, required=True)
    install.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--executable", type=Path, required=True)
    return parser.parse_args()


def _is_reparse_point(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _regular_file(path: Path, label: str, *, max_bytes: int) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} path must be absolute")
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise ValueError(f"{label} must not be a symlink or reparse point")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > max_bytes
    ):
        raise ValueError(f"{label} must be a bounded non-empty regular file")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise ValueError(f"{label} path must not traverse a symlink or alias")
    return resolved


def _output_path(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("trusted GitHub CLI output path must be absolute")
    absolute = Path(os.path.abspath(path))
    if absolute != path:
        raise ValueError("trusted GitHub CLI output path must be normalized")
    if path.exists() or path.is_symlink():
        raise FileExistsError("trusted GitHub CLI output path already exists")
    parent = path.parent
    metadata = os.lstat(parent)
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise ValueError("trusted GitHub CLI output directory must not be a link")
    if not stat.S_ISDIR(metadata.st_mode) or parent.resolve(strict=True) != parent:
        raise ValueError("trusted GitHub CLI output directory is invalid")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def trusted_metadata() -> dict[str, str]:
    return {
        "archive_member": TRUSTED_GH_ARCHIVE_MEMBER,
        "archive_sha256": TRUSTED_GH_ARCHIVE_SHA256,
        "archive_url": TRUSTED_GH_ARCHIVE_URL,
        "executable_sha256": TRUSTED_GH_EXECUTABLE_SHA256,
        "platform": TRUSTED_GH_PLATFORM,
        "release_url": TRUSTED_GH_RELEASE_URL,
        "version": TRUSTED_GH_VERSION,
    }


def write_trusted_metadata(*, output_path: Path) -> None:
    output = _output_path(output_path)
    payload = (
        json.dumps(trusted_metadata(), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(descriptor, "wb") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def install_trusted_gh(*, archive_path: Path, output_path: Path) -> dict[str, Any]:
    archive = _regular_file(
        archive_path, "trusted GitHub CLI archive", max_bytes=MAX_ARCHIVE_BYTES
    )
    output = _output_path(output_path)
    if _sha256(archive) != TRUSTED_GH_ARCHIVE_SHA256:
        raise ValueError("trusted GitHub CLI archive SHA-256 does not match the lock")

    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            try:
                member = bundle.getmember(TRUSTED_GH_ARCHIVE_MEMBER)
            except KeyError as exc:
                raise ValueError("trusted GitHub CLI archive member is missing") from exc
            if (
                not member.isfile()
                or member.issym()
                or member.islnk()
                or member.size < 1
                or member.size > MAX_EXECUTABLE_BYTES
            ):
                raise ValueError("trusted GitHub CLI archive member is not a safe file")
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("trusted GitHub CLI archive member cannot be read")
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o555)
            try:
                with os.fdopen(descriptor, "wb") as target:
                    while chunk := source.read(1024 * 1024):
                        target.write(chunk)
                    target.flush()
                    os.fsync(target.fileno())
            finally:
                source.close()
        if _sha256(output) != TRUSTED_GH_EXECUTABLE_SHA256:
            raise ValueError(
                "trusted GitHub CLI executable SHA-256 does not match the lock"
            )
        os.chmod(output, 0o555)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return {
        "code": "TRUSTED_GH_CLI_INSTALLED",
        "executable": str(output),
        "executable_sha256": TRUSTED_GH_EXECUTABLE_SHA256,
        "version": TRUSTED_GH_VERSION,
    }


def verify_trusted_gh(
    *, executable_path: Path, runner: Runner = subprocess.run
) -> dict[str, Any]:
    executable = _regular_file(
        executable_path,
        "trusted GitHub CLI executable",
        max_bytes=MAX_EXECUTABLE_BYTES,
    )
    if sys.platform != "linux" or platform.machine().lower() not in {
        "amd64",
        "x86_64",
    }:
        raise ValueError("trusted GitHub CLI is locked to hosted Linux amd64")
    if not os.access(executable, os.X_OK):
        raise ValueError("trusted GitHub CLI executable is not executable")
    if _sha256(executable) != TRUSTED_GH_EXECUTABLE_SHA256:
        raise ValueError(
            "trusted GitHub CLI executable SHA-256 does not match the lock"
        )
    command = [str(executable), "version"]
    completed = runner(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    lines = completed.stdout.strip().splitlines()
    if (
        completed.returncode != 0
        or len(lines) != 2
        or not lines[0].startswith(f"gh version {TRUSTED_GH_VERSION} (")
        or lines[1] != TRUSTED_GH_RELEASE_URL
    ):
        raise ValueError("trusted GitHub CLI version output does not match the lock")
    return {
        "code": "TRUSTED_GH_CLI_VALID",
        "executable": str(executable),
        "executable_sha256": TRUSTED_GH_EXECUTABLE_SHA256,
        "version": TRUSTED_GH_VERSION,
    }


def main() -> int:
    arguments = _arguments()
    try:
        if arguments.command == "archive-url":
            print(TRUSTED_GH_ARCHIVE_URL)
        elif arguments.command == "metadata":
            write_trusted_metadata(output_path=arguments.output)
        elif arguments.command == "install":
            install_trusted_gh(
                archive_path=arguments.archive,
                output_path=arguments.output,
            )
        else:
            verify_trusted_gh(executable_path=arguments.executable)
        return 0
    except (
        OSError,
        tarfile.TarError,
        subprocess.SubprocessError,
        ValueError,
    ):
        print(
            json.dumps(
                {
                    "code": "TRUSTED_GH_CLI_INVALID",
                    "ready": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
