from __future__ import annotations

import io
import json

import pytest

from datax_studio.api.problems import ProblemException
from datax_studio.auth import recovery_cli


class FakeRecoveryService:
    def __init__(self) -> None:
        self.email: str | None = None
        self.password: str | None = None

    def recover_last_admin(self, **kwargs: object) -> None:
        self.email = str(kwargs["email"])
        self.password = str(kwargs["password"])


def _stdout(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert len(lines) == 1
    return json.loads(lines[0])


def test_recovery_password_is_stdin_only_and_output_is_safe(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = FakeRecoveryService()
    monkeypatch.setattr(recovery_cli, "build_auth_service", lambda settings: fake)
    monkeypatch.setattr(recovery_cli, "get_settings", lambda: object())
    monkeypatch.setattr(
        recovery_cli.sys,
        "stdin",
        io.StringIO("Recovery-password-123!\n"),
    )

    result = recovery_cli.main(
        ["--email", "admin@example.com", "--json"]
    )

    assert result == recovery_cli.EXIT_RECOVERED
    assert fake.email == "admin@example.com"
    assert fake.password == "Recovery-password-123!"
    assert _stdout(capsys) == {
        "recovered": True,
        "code": "ADMIN_RECOVERED",
    }


def test_recovery_cli_rejects_password_argument() -> None:
    with pytest.raises(ValueError):
        recovery_cli.build_parser().parse_args(
            [
                "--email",
                "admin@example.com",
                "--password",
                "must-not-be-accepted",
            ]
        )


def test_recovery_cli_reports_not_allowed_without_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = FakeRecoveryService()

    def reject(**kwargs: object) -> None:
        raise ProblemException(
            status=409,
            code="ADMIN_RECOVERY_NOT_ALLOWED",
            title="sensitive database state",
        )

    fake.recover_last_admin = reject  # type: ignore[method-assign]
    monkeypatch.setattr(recovery_cli, "build_auth_service", lambda settings: fake)
    monkeypatch.setattr(recovery_cli, "get_settings", lambda: object())
    monkeypatch.setattr(
        recovery_cli.sys,
        "stdin",
        io.StringIO("Recovery-password-123!\n"),
    )

    result = recovery_cli.main(
        ["--email", "admin@example.com", "--json"]
    )

    assert result == recovery_cli.EXIT_NOT_ALLOWED
    assert _stdout(capsys) == {
        "recovered": False,
        "code": "ADMIN_RECOVERY_NOT_ALLOWED",
    }
