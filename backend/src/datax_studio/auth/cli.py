from __future__ import annotations

import argparse
import json
import sys
from uuid import uuid4

from datax_studio.api.problems import ProblemException
from datax_studio.auth.service import (
    AuditContext,
    bootstrap_required,
    build_auth_service,
)
from datax_studio.settings import get_settings

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
EXIT_CREATED_OR_REQUIRED = 0
EXIT_ALREADY_COMPLETED = 3
EXIT_FAILED = 4


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError("invalid command arguments")


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="datax-studio-bootstrap-admin",
        description="Create the one-time local organization administrator.",
    )
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--email")
    parser.add_argument("--display-name")
    parser.add_argument(
        "--organization-name",
        default="DataX Enterprise Studio",
    )
    return parser


def _emit(payload: dict[str, bool | str | None], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(payload, ensure_ascii=True, separators=(",", ":")))
    else:
        print(payload["code"])


def _status_payload(required: bool | None, code: str) -> dict[str, bool | str | None]:
    return {"required": required, "code": code}


def _create_payload(created: bool, code: str) -> dict[str, bool | str | None]:
    return {"created": created, "code": code}


def _read_password() -> str:
    if sys.stdin.isatty():
        raise ValueError("password must be piped on stdin")
    raw = sys.stdin.read(MAX_PASSWORD_LENGTH + 3)
    if len(raw) > MAX_PASSWORD_LENGTH + 2:
        raise ValueError("password input is too long")
    if raw.endswith("\r\n"):
        password = raw[:-2]
    elif raw.endswith(("\r", "\n")):
        password = raw[:-1]
    else:
        password = raw
    if (
        not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH
        or "\r" in password
        or "\n" in password
        or "\x00" in password
    ):
        raise ValueError("password input is invalid")
    return password


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    json_output = "--json" in raw_argv
    try:
        args = build_parser().parse_args(raw_argv)
        if args.status:
            if args.email is not None or args.display_name is not None:
                raise ValueError("create arguments are invalid with --status")
            required = bootstrap_required(get_settings())
            if required:
                _emit(
                    _status_payload(True, "BOOTSTRAP_REQUIRED"),
                    json_output=args.json_output,
                )
                return EXIT_CREATED_OR_REQUIRED
            _emit(
                _status_payload(False, "BOOTSTRAP_ALREADY_COMPLETED"),
                json_output=args.json_output,
            )
            return EXIT_ALREADY_COMPLETED

        if args.email is None or args.display_name is None:
            raise ValueError("email and display name are required")
        password = _read_password()
        service = build_auth_service(get_settings())
        service.bootstrap_admin(
            email=args.email,
            display_name=args.display_name,
            password=password,
            organization_name=args.organization_name,
            audit=AuditContext(
                request_id=uuid4(),
                source_ip=None,
                user_agent="datax-studio-bootstrap-admin",
            ),
        )
    except ProblemException as exc:
        if exc.code == "BOOTSTRAP_ALREADY_COMPLETED":
            _emit(
                _create_payload(False, "BOOTSTRAP_ALREADY_COMPLETED"),
                json_output=json_output,
            )
            return EXIT_ALREADY_COMPLETED
        _emit(
            _create_payload(False, "BOOTSTRAP_INTERNAL_ERROR"),
            json_output=json_output,
        )
        return EXIT_FAILED
    except ValueError:
        payload = (
            _status_payload(None, "BOOTSTRAP_INPUT_INVALID")
            if "--status" in raw_argv
            else _create_payload(False, "BOOTSTRAP_INPUT_INVALID")
        )
        _emit(payload, json_output=json_output)
        return EXIT_FAILED
    except Exception:
        payload = (
            _status_payload(None, "BOOTSTRAP_CHECK_FAILED")
            if "--status" in raw_argv
            else _create_payload(False, "BOOTSTRAP_INTERNAL_ERROR")
        )
        _emit(payload, json_output=json_output)
        return EXIT_FAILED
    finally:
        password = None
    _emit(
        _create_payload(True, "BOOTSTRAP_ADMIN_CREATED"),
        json_output=json_output,
    )
    return EXIT_CREATED_OR_REQUIRED


if __name__ == "__main__":
    raise SystemExit(main())
