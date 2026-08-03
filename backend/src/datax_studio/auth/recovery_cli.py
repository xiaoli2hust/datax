from __future__ import annotations

import argparse
import json
import sys
from uuid import uuid4

from datax_studio.api.problems import ProblemException
from datax_studio.auth.service import AuditContext, build_auth_service
from datax_studio.settings import get_settings

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
EXIT_RECOVERED = 0
EXIT_NOT_ALLOWED = 3
EXIT_FAILED = 4


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError("invalid command arguments")


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="datax-studio-recover-admin",
        description=(
            "Recover one locked local organization administrator only when "
            "no active administrator remains."
        ),
    )
    parser.add_argument("--email", required=True)
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


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


def _emit(*, recovered: bool, code: str, json_output: bool) -> None:
    if json_output:
        print(
            json.dumps(
                {"recovered": recovered, "code": code},
                ensure_ascii=True,
                separators=(",", ":"),
            )
        )
    else:
        print(code)


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    json_output = "--json" in raw_argv
    try:
        args = build_parser().parse_args(raw_argv)
        password = _read_password()
        service = build_auth_service(get_settings())
        service.recover_last_admin(
            email=args.email,
            password=password,
            audit=AuditContext(
                request_id=uuid4(),
                source_ip=None,
                user_agent="datax-studio-recover-admin",
            ),
        )
    except ProblemException as exc:
        code = (
            "ADMIN_RECOVERY_NOT_ALLOWED"
            if exc.code == "ADMIN_RECOVERY_NOT_ALLOWED"
            else "ADMIN_RECOVERY_FAILED"
        )
        _emit(recovered=False, code=code, json_output=json_output)
        return EXIT_NOT_ALLOWED if code == "ADMIN_RECOVERY_NOT_ALLOWED" else EXIT_FAILED
    except ValueError:
        _emit(
            recovered=False,
            code="ADMIN_RECOVERY_INPUT_INVALID",
            json_output=json_output,
        )
        return EXIT_FAILED
    except Exception:
        _emit(
            recovered=False,
            code="ADMIN_RECOVERY_FAILED",
            json_output=json_output,
        )
        return EXIT_FAILED
    finally:
        password = None
    _emit(recovered=True, code="ADMIN_RECOVERED", json_output=json_output)
    return EXIT_RECOVERED


if __name__ == "__main__":
    raise SystemExit(main())
