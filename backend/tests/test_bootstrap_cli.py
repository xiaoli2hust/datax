from __future__ import annotations

import io
import json

import pytest

from datax_studio.api.problems import ProblemException
from datax_studio.auth import cli


class FakeBootstrapService:
    def __init__(self) -> None:
        self.password: str | None = None

    def bootstrap_admin(self, **kwargs: object) -> None:
        self.password = str(kwargs["password"])


def _json_stdout(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert len(lines) == 1
    return json.loads(lines[0])


def test_bootstrap_password_is_read_only_from_stdin(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = FakeBootstrapService()
    monkeypatch.setattr(cli, "build_auth_service", lambda settings: fake)
    monkeypatch.setattr(cli, "get_settings", lambda: object())
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("Secret-password-123!\n"))

    result = cli.main(
        [
            "--email",
            "admin@example.com",
            "--display-name",
            "Admin",
            "--json",
        ]
    )

    assert result == 0
    assert fake.password == "Secret-password-123!"
    assert _json_stdout(capsys) == {
        "created": True,
        "code": "BOOTSTRAP_ADMIN_CREATED",
    }


def test_bootstrap_cli_has_no_password_argument() -> None:
    with pytest.raises(ValueError):
        cli.build_parser().parse_args(
            [
                "--email",
                "admin@example.com",
                "--display-name",
                "Admin",
                "--password",
                "must-not-be-accepted",
            ]
        )


@pytest.mark.parametrize(
    "stdin_value",
    [
        "",
        "too-short\n",
        "Valid-password-123!\nsecond-line\n",
        f"{'x' * 257}\n",
        "Valid-password-123!\x00\n",
    ],
)
def test_bootstrap_rejects_invalid_stdin_without_leaking_it(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stdin_value: str,
) -> None:
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(stdin_value))

    result = cli.main(
        [
            "--email",
            "admin@example.com",
            "--display-name",
            "Admin",
            "--json",
        ]
    )

    assert result == 4
    assert _json_stdout(capsys) == {
        "created": False,
        "code": "BOOTSTRAP_INPUT_INVALID",
    }


def test_bootstrap_status_empty_is_read_only_and_does_not_read_stdin(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class ForbiddenStdin(io.StringIO):
        def read(self, *args: object, **kwargs: object) -> str:
            raise AssertionError("status must not read stdin")

    monkeypatch.setattr(cli.sys, "stdin", ForbiddenStdin("do-not-read"))
    monkeypatch.setattr(cli, "get_settings", lambda: object())
    monkeypatch.setattr(cli, "bootstrap_required", lambda settings: True)
    monkeypatch.setattr(
        cli,
        "build_auth_service",
        lambda settings: pytest.fail("status must not construct auth service"),
    )

    result = cli.main(["--status", "--json"])

    assert result == 0
    assert _json_stdout(capsys) == {
        "required": True,
        "code": "BOOTSTRAP_REQUIRED",
    }


def test_bootstrap_status_nonempty_has_distinct_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "get_settings", lambda: object())
    monkeypatch.setattr(cli, "bootstrap_required", lambda settings: False)

    result = cli.main(["--status", "--json"])

    assert result == 3
    assert _json_stdout(capsys) == {
        "required": False,
        "code": "BOOTSTRAP_ALREADY_COMPLETED",
    }


def test_bootstrap_status_failure_is_safe_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "get_settings", lambda: object())

    def fail_status(settings: object) -> bool:
        raise RuntimeError("database URL contains secret")

    monkeypatch.setattr(cli, "bootstrap_required", fail_status)

    result = cli.main(["--status", "--json"])

    assert result == 4
    assert _json_stdout(capsys) == {
        "required": None,
        "code": "BOOTSTRAP_CHECK_FAILED",
    }


def test_bootstrap_already_completed_is_exit_three(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = FakeBootstrapService()

    def reject_bootstrap(**kwargs: object) -> None:
        raise ProblemException(
            status=409,
            code="BOOTSTRAP_ALREADY_COMPLETED",
            title="already complete",
        )

    fake.bootstrap_admin = reject_bootstrap  # type: ignore[method-assign]
    monkeypatch.setattr(cli, "build_auth_service", lambda settings: fake)
    monkeypatch.setattr(cli, "get_settings", lambda: object())
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("Secret-password-123!\n"))

    result = cli.main(
        [
            "--email",
            "admin@example.com",
            "--display-name",
            "Admin",
            "--json",
        ]
    )

    assert result == 3
    assert _json_stdout(capsys) == {
        "created": False,
        "code": "BOOTSTRAP_ALREADY_COMPLETED",
    }
