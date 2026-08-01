from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from scripts.security.evaluate_grype_os_report import PolicyError, evaluate


def _write(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def _report(*matches: dict[str, object]) -> dict[str, object]:
    return {
        "descriptor": {"name": "grype", "version": "0.112.0"},
        "matches": list(matches),
    }


def _match(
    *,
    severity: str = "High",
    vulnerability_id: str = "CVE-2099-0001",
    fix_state: str = "fixed",
) -> dict[str, object]:
    return {
        "artifact": {
            "name": "example",
            "type": "deb",
            "version": "1.0-1",
        },
        "vulnerability": {
            "fix": {"state": fix_state, "versions": ["1.0-2"]},
            "id": vulnerability_id,
            "namespace": "debian:distro:debian:12",
            "severity": severity,
        },
    }


def _exception(*, expires: str = "2099-02-01") -> dict[str, str]:
    return {
        "component": "api",
        "expires": expires,
        "fix_state": "fixed",
        "namespace": "debian:distro:debian:12",
        "package_name": "example",
        "package_type": "deb",
        "package_version": "1.0-1",
        "reason": "Documented temporary risk acceptance.",
        "severity": "High",
        "vulnerability_id": "CVE-2099-0001",
    }


def test_blocks_unexcepted_high_distro_finding(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    exceptions = tmp_path / "exceptions.json"
    output = tmp_path / "policy.json"
    _write(report, _report(_match()))
    _write(exceptions, {"schema_version": "1.0", "exceptions": []})

    assert not evaluate(
        report_path=report,
        exceptions_path=exceptions,
        component="api",
        output_path=output,
        today=date(2099, 1, 1),
    )
    assert json.loads(output.read_text())["summary"]["blocking_finding_count"] == 1


def test_exact_unexpired_exception_is_consumed(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    exceptions = tmp_path / "exceptions.json"
    output = tmp_path / "policy.json"
    _write(report, _report(_match()))
    _write(exceptions, {"schema_version": "1.0", "exceptions": [_exception()]})

    assert evaluate(
        report_path=report,
        exceptions_path=exceptions,
        component="api",
        output_path=output,
        today=date(2099, 1, 1),
    )
    assert json.loads(output.read_text())["summary"]["accepted_exception_count"] == 1


def test_candidate_records_unfixed_high_for_review_but_does_not_block(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    exceptions = tmp_path / "exceptions.json"
    output = tmp_path / "policy.json"
    _write(report, _report(_match(fix_state="not-fixed")))
    _write(exceptions, {"schema_version": "1.0", "exceptions": []})

    assert evaluate(
        report_path=report,
        exceptions_path=exceptions,
        component="api",
        output_path=output,
        today=date(2099, 1, 1),
        mode="candidate",
    )
    policy = json.loads(output.read_text())
    assert policy["status"] == "candidate_passed_with_review"
    assert not policy["promotion_allowed"]
    assert policy["summary"]["review_required_finding_count"] == 1


def test_promotion_blocks_unfixed_high_without_exact_exception(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    exceptions = tmp_path / "exceptions.json"
    output = tmp_path / "policy.json"
    _write(report, _report(_match(fix_state="not-fixed")))
    _write(exceptions, {"schema_version": "1.0", "exceptions": []})

    assert not evaluate(
        report_path=report,
        exceptions_path=exceptions,
        component="api",
        output_path=output,
        today=date(2099, 1, 1),
    )


def test_low_distro_and_language_findings_do_not_block_os_policy(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    exceptions = tmp_path / "exceptions.json"
    output = tmp_path / "policy.json"
    language_match = _match()
    language_match["artifact"] = {
        "name": "library",
        "type": "python",
        "version": "1.0",
    }
    language_match["vulnerability"]["namespace"] = "github:language:python"
    _write(report, _report(_match(severity="Medium"), language_match))
    _write(exceptions, {"schema_version": "1.0", "exceptions": []})

    assert evaluate(
        report_path=report,
        exceptions_path=exceptions,
        component="api",
        output_path=output,
        today=date(2099, 1, 1),
    )


def test_blank_grype_fix_state_is_canonicalised_to_unknown(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    exceptions = tmp_path / "exceptions.json"
    output = tmp_path / "policy.json"
    _write(report, _report(_match(severity="Medium", fix_state="")))
    _write(exceptions, {"schema_version": "1.0", "exceptions": []})

    assert evaluate(
        report_path=report,
        exceptions_path=exceptions,
        component="api",
        output_path=output,
        today=date(2099, 1, 1),
    )
    assert json.loads(output.read_text())["summary"]["fix_states"] == {"unknown": 1}


def test_expired_or_unused_exception_is_rejected(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    exceptions = tmp_path / "exceptions.json"
    output = tmp_path / "policy.json"
    _write(report, _report())
    _write(
        exceptions,
        {
            "schema_version": "1.0",
            "exceptions": [_exception(expires="2099-01-01")],
        },
    )

    with pytest.raises(PolicyError, match="expired"):
        evaluate(
            report_path=report,
            exceptions_path=exceptions,
            component="api",
            output_path=output,
            today=date(2099, 1, 1),
        )


def test_exception_for_another_component_is_not_unused_here(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    exceptions = tmp_path / "exceptions.json"
    output = tmp_path / "policy.json"
    other_component = _exception()
    other_component["component"] = "worker"
    _write(report, _report())
    _write(
        exceptions,
        {"schema_version": "1.0", "exceptions": [other_component]},
    )

    assert evaluate(
        report_path=report,
        exceptions_path=exceptions,
        component="api",
        output_path=output,
        today=date(2099, 1, 1),
    )


def test_nvd_cpe_match_for_os_artifact_is_retained_but_not_used_by_os_gate(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    exceptions = tmp_path / "exceptions.json"
    output = tmp_path / "policy.json"
    finding = _match()
    finding["vulnerability"]["namespace"] = "nvd:cpe"
    _write(report, _report(finding))
    _write(exceptions, {"schema_version": "1.0", "exceptions": []})

    assert evaluate(
        report_path=report,
        exceptions_path=exceptions,
        component="api",
        output_path=output,
        today=date(2099, 1, 1),
    )
    assert json.loads(output.read_text())["summary"][
        "excluded_non_distro_os_match_count"
    ] == 1
