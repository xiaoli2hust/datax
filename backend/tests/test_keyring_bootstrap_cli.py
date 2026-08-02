from __future__ import annotations

import json

import pytest

from datax_studio.credentials import bootstrap_cli


def _json_stdout(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert len(lines) == 1
    return json.loads(lines[0])


def test_keyring_bootstrap_registers_active_key_once(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = object()
    calls: list[object] = []
    monkeypatch.setattr(bootstrap_cli, "get_settings", lambda: settings)
    monkeypatch.setattr(
        bootstrap_cli,
        "build_credential_service",
        lambda actual_settings: calls.append(actual_settings),
    )

    result = bootstrap_cli.main(["--json"])

    assert result == 0
    assert calls == [settings]
    assert _json_stdout(capsys) == {
        "ready": True,
        "code": "KEYRING_BOOTSTRAP_READY",
    }


def test_keyring_bootstrap_fails_closed_without_leaking_exception(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(bootstrap_cli, "get_settings", lambda: object())

    def fail(_settings: object) -> object:
        raise RuntimeError("credential-kek-v1.key contains secret-material")

    monkeypatch.setattr(bootstrap_cli, "build_credential_service", fail)

    result = bootstrap_cli.main(["--json"])

    assert result == 4
    captured = _json_stdout(capsys)
    assert captured == {"ready": False, "code": "KEYRING_BOOTSTRAP_FAILED"}
    assert "secret-material" not in json.dumps(captured)


def test_keyring_bootstrap_rejects_unknown_arguments(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = bootstrap_cli.main(["--not-supported", "--json"])

    assert result == 4
    assert _json_stdout(capsys) == {
        "ready": False,
        "code": "KEYRING_BOOTSTRAP_FAILED",
    }
