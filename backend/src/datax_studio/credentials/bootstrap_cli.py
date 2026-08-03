"""Fail-closed, one-shot registration of the active credential KEK.

This command is only for the launcher-controlled ``keyring-bootstrap``
Compose service.  It runs after migrations with the API database role and the
smallest secret set that can establish the immutable active-key fingerprint.
The Worker remains read-only and will refuse to start if this prerequisite is
missing or inconsistent.
"""

from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy.exc import SQLAlchemyError

from datax_studio.credentials.service import build_credential_service
from datax_studio.settings import get_settings

EXIT_READY = 0
EXIT_FAILED = 4


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError("invalid command arguments")


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="datax-studio-keyring-bootstrap",
        description="Register and validate the local active credential KEK.",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def _emit(*, ready: bool, code: str, json_output: bool) -> None:
    payload = {"ready": ready, "code": code}
    if json_output:
        print(json.dumps(payload, ensure_ascii=True, separators=(",", ":")))
    else:
        print(code)


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    json_output = "--json" in raw_argv
    try:
        args = build_parser().parse_args(raw_argv)
        build_credential_service(get_settings())
    except (OSError, SQLAlchemyError, ValueError):
        _emit(ready=False, code="KEYRING_BOOTSTRAP_FAILED", json_output=json_output)
        return EXIT_FAILED
    except Exception:
        _emit(ready=False, code="KEYRING_BOOTSTRAP_FAILED", json_output=json_output)
        return EXIT_FAILED
    _emit(ready=True, code="KEYRING_BOOTSTRAP_READY", json_output=args.json_output)
    return EXIT_READY


if __name__ == "__main__":
    raise SystemExit(main())
