#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import re
import tempfile
from pathlib import Path

LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)$")
MANIFEST_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _files(root: Path, manifest: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlinks are forbidden in release evidence: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"non-regular release evidence entry: {path}")
        if path == manifest:
            continue
        relative = path.relative_to(root).as_posix()
        if LINE.fullmatch(f"{'0' * 64}  {relative}") is None:
            raise ValueError(f"non-canonical release evidence path: {relative}")
        result[relative] = path
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(root: Path, manifest: Path) -> None:
    files = _files(root, manifest)
    if not files:
        raise ValueError("release evidence must contain at least one file")
    lines = [
        f"{_sha256(files[relative])}  {relative}\n"
        for relative in sorted(files)
    ]
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".SHA256SUMS.",
        dir=manifest.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.writelines(lines)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, manifest)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def verify_manifest(root: Path, manifest: Path) -> None:
    raw_lines = manifest.read_text(encoding="utf-8").splitlines()
    declared: dict[str, str] = {}
    if raw_lines != sorted(raw_lines, key=lambda item: item.split("  ", 1)[-1]):
        raise ValueError("hash manifest paths are not sorted")
    for line in raw_lines:
        match = LINE.fullmatch(line)
        if match is None:
            raise ValueError("hash manifest contains a malformed entry")
        digest, relative = match.groups()
        if relative in declared or ".." in Path(relative).parts:
            raise ValueError("hash manifest contains a duplicate or unsafe path")
        declared[relative] = digest
    actual = _files(root, manifest)
    if set(declared) != set(actual):
        missing = sorted(set(declared) - set(actual))
        extra = sorted(set(actual) - set(declared))
        raise ValueError(f"hash manifest file set mismatch: missing={missing}, extra={extra}")
    for relative, path in actual.items():
        if _sha256(path) != declared[relative]:
            raise ValueError(f"hash mismatch: {relative}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("write", "verify"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", default="SHA256SUMS")
    args = parser.parse_args()
    if MANIFEST_NAME.fullmatch(args.manifest) is None:
        raise ValueError("hash manifest must be a canonical file name")
    input_root = args.root.absolute()
    root = input_root.resolve(strict=True)
    if input_root != root or not root.is_dir() or input_root.is_symlink():
        raise ValueError("evidence root must be a non-symlink directory")
    manifest = root / args.manifest
    if args.command == "verify":
        if manifest.is_symlink():
            raise ValueError("hash manifest must not be a symlink")
        manifest = manifest.resolve(strict=True)
    if args.command == "write":
        write_manifest(root, manifest)
    else:
        verify_manifest(root, manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
