#!/usr/bin/env python3
"""Verify that every release image is anonymously pullable by immutable digest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections import OrderedDict
from pathlib import Path

IMAGE_RULES = OrderedDict(
    (
        ("DES_POSTGRES_IMAGE", "postgres"),
        ("DES_API_IMAGE", "ghcr.io/xiaoli2hust/datax-studio-api"),
        (
            "DES_EGRESS_GUARD_IMAGE",
            "ghcr.io/xiaoli2hust/datax-studio-egress-guard",
        ),
        ("DES_WORKER_IMAGE", "ghcr.io/xiaoli2hust/datax-studio-worker"),
        ("DES_WEB_IMAGE", "ghcr.io/xiaoli2hust/datax-studio-web"),
    )
)
EMPTY_DOCKER_CONFIG = b'{"auths":{}}\n'


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Pull the five release-locked images using an isolated empty "
            "Docker registry configuration."
        )
    )
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--docker", default="docker")
    return parser.parse_args()


def _regular_file(path: Path, description: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"{description} is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ValueError(f"{description} must be a non-symlink regular file")
    return path.resolve(strict=True)


def parse_image_lock(path: Path) -> OrderedDict[str, str]:
    path = _regular_file(path, "release image lock")
    if path.stat().st_size > 16 * 1024:
        raise ValueError("release image lock is too large")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("release image lock must be strict UTF-8") from exc
    if text.startswith("\ufeff"):
        raise ValueError("release image lock must not contain a BOM")

    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        if not raw_line or raw_line.startswith("#"):
            continue
        if raw_line != raw_line.strip():
            raise ValueError("release image lock contains non-canonical whitespace")
        key, separator, value = raw_line.partition("=")
        if (
            separator != "="
            or key not in IMAGE_RULES
            or key in values
        ):
            raise ValueError("release image lock contains an unknown or duplicate key")
        expected = rf"{re.escape(IMAGE_RULES[key])}@sha256:[0-9a-f]{{64}}"
        if re.fullmatch(expected, value) is None:
            raise ValueError(
                "release image lock contains a mutable or unexpected reference"
            )
        values[key] = value
    if set(values) != set(IMAGE_RULES):
        raise ValueError("release image lock is incomplete")
    return OrderedDict((key, values[key]) for key in IMAGE_RULES)


def _write_evidence(path: Path, document: object) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("anonymous pull evidence path already exists")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("anonymous pull evidence parent must be a directory")
    encoded = (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    descriptor = os.open(
        parent / path.name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            (parent / path.name).unlink()
        except FileNotFoundError:
            pass
        raise


def verify_anonymous_pulls(
    *,
    images: OrderedDict[str, str],
    evidence_path: Path,
    docker: str,
) -> None:
    evidence_path = evidence_path.absolute()
    if not docker or "\0" in docker:
        raise ValueError("docker command is invalid")

    config_hash = hashlib.sha256(EMPTY_DOCKER_CONFIG).hexdigest()
    results: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="des-anonymous-docker-config-") as directory:
        config_directory = Path(directory)
        os.chmod(config_directory, 0o700)
        config_path = config_directory / "config.json"
        config_path.write_bytes(EMPTY_DOCKER_CONFIG)
        os.chmod(config_path, 0o600)

        environment = os.environ.copy()
        environment["DOCKER_CONFIG"] = str(config_directory)
        environment.pop("DOCKER_AUTH_CONFIG", None)
        environment.pop("REGISTRY_AUTH_FILE", None)

        for key, reference in images.items():
            completed = subprocess.run(
                [
                    docker,
                    "image",
                    "pull",
                    "--platform",
                    "linux/amd64",
                    "--quiet",
                    reference,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                timeout=600,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(
                    f"anonymous pull failed for release image key {key}"
                )
            if (
                config_path.read_bytes() != EMPTY_DOCKER_CONFIG
                or {item.name for item in config_directory.iterdir()}
                != {"config.json"}
            ):
                raise RuntimeError(
                    "isolated Docker registry configuration changed during pull"
                )
            results.append(
                {
                    "key": key,
                    "reference": reference,
                    "result": "PULLED_ANONYMOUSLY",
                }
            )

    _write_evidence(
        evidence_path,
        {
            "schema_version": "1.0",
            "verification": "ANONYMOUS_PULL_BY_DIGEST",
            "result": "PASS",
            "platform": "linux/amd64",
            "docker_config_mode": "EPHEMERAL_EMPTY",
            "docker_config_sha256": config_hash,
            "registry_credentials_used": False,
            "images": results,
        },
    )


def main() -> int:
    args = _parse_args()
    images = parse_image_lock(args.images)
    verify_anonymous_pulls(
        images=images,
        evidence_path=args.evidence,
        docker=args.docker,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
