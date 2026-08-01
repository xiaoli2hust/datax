#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

if __package__:
    from .catalog import build_catalog_bytes, sha256_bytes
else:
    from catalog import build_catalog_bytes, sha256_bytes


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        expected = build_catalog_bytes(arguments.matrix)
        if arguments.check:
            if arguments.output.read_bytes() != expected:
                raise ValueError("checked-in requirements catalog is stale")
        else:
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                arguments.output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o644,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        print(
            json.dumps(
                {
                    "ready": True,
                    "code": "REQUIREMENTS_CATALOG_VALID",
                    "sha256": sha256_bytes(expected),
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "ready": False,
                    "code": "REQUIREMENTS_CATALOG_INVALID",
                    "detail": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
