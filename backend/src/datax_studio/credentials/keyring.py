from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_KEY_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def zeroize(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


class KekKeyring:
    """Read exact, versioned 256-bit KEKs without following symlinks."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def path_for(self, key_version: str) -> Path:
        if not _KEY_VERSION.fullmatch(key_version):
            raise ValueError("KEK version is invalid")
        return self.directory / f"credential-kek-{key_version}.key"

    @contextmanager
    def open_key(self, key_version: str) -> Iterator[bytearray]:
        path = self.path_for(key_version)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        key = bytearray()
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != 32:
                raise ValueError("KEK must be a regular file containing exactly 32 bytes")
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError("KEK must not be group- or world-writable")
            while len(key) < 33:
                chunk = os.read(descriptor, 33 - len(key))
                if not chunk:
                    break
                key.extend(chunk)
            if len(key) != 32:
                raise ValueError("KEK must contain exactly 32 bytes")
            yield key
        finally:
            os.close(descriptor)
            zeroize(key)

    def fingerprint(self, key_version: str) -> str:
        with self.open_key(key_version) as key:
            return hashlib.sha256(key).hexdigest()
