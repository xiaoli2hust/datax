#!/usr/bin/env python3
"""Enforce exact, expiring exceptions for high-risk distro package findings."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

SUPPORTED_PACKAGE_TYPES = frozenset({"apk", "deb", "rpm"})
BLOCKING_SEVERITIES = frozenset({"High", "Critical"})
KNOWN_COMPONENTS = frozenset({"api", "egress_guard", "postgres", "web", "worker"})
POLICY_MODES = frozenset({"candidate", "promotion"})
REQUIRED_EXCEPTION_KEYS = frozenset(
    {
        "component",
        "expires",
        "fix_state",
        "namespace",
        "package_name",
        "package_type",
        "package_version",
        "reason",
        "severity",
        "vulnerability_id",
    }
)


class PolicyError(ValueError):
    """Raised when an evidence or exception document is unsafe."""


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PolicyError(f"{label} must be a regular file")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise PolicyError(f"{label} must contain a JSON object")
    return document


def _parse_expiry(value: Any, *, today: date) -> str:
    if not isinstance(value, str):
        raise PolicyError("exception expiry must be an ISO date")
    try:
        expiry = date.fromisoformat(value)
    except ValueError as exc:
        raise PolicyError("exception expiry must be an ISO date") from exc
    if expiry <= today:
        raise PolicyError(f"exception expired on {value}")
    if (expiry - today).days > 90:
        raise PolicyError("exception expiry may not be more than 90 days away")
    return value


def _exception_key(document: dict[str, Any]) -> tuple[str, ...]:
    return (
        document["component"],
        document["vulnerability_id"],
        document["namespace"],
        document["package_type"],
        document["package_name"],
        document["package_version"],
        document["severity"],
        document["fix_state"],
    )


def _load_exceptions(
    path: Path, *, today: date, component: str
) -> dict[tuple[str, ...], dict[str, Any]]:
    document = _load_json(path, label="OS vulnerability exception manifest")
    if set(document) != {"schema_version", "exceptions"}:
        raise PolicyError("OS vulnerability exception manifest has unexpected fields")
    if document["schema_version"] != "1.0":
        raise PolicyError("unsupported OS vulnerability exception schema")
    raw_exceptions = document["exceptions"]
    if not isinstance(raw_exceptions, list):
        raise PolicyError("OS vulnerability exceptions must be an array")

    exceptions: dict[tuple[str, ...], dict[str, Any]] = {}
    for raw_exception in raw_exceptions:
        if not isinstance(raw_exception, dict) or set(raw_exception) != REQUIRED_EXCEPTION_KEYS:
            raise PolicyError("each OS vulnerability exception must have the exact required fields")
        for key in REQUIRED_EXCEPTION_KEYS - {"expires"}:
            value = raw_exception[key]
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise PolicyError(f"exception field {key} must be a non-empty canonical string")
        if raw_exception["package_type"] not in SUPPORTED_PACKAGE_TYPES:
            raise PolicyError("exception package_type is not supported")
        if raw_exception["component"] not in KNOWN_COMPONENTS:
            raise PolicyError("exception component is not a release image")
        if raw_exception["severity"] not in BLOCKING_SEVERITIES:
            raise PolicyError("exceptions are only valid for High or Critical findings")
        if len(raw_exception["reason"]) < 20:
            raise PolicyError("exception reason must contain at least 20 characters")
        _parse_expiry(raw_exception["expires"], today=today)
        key = _exception_key(raw_exception)
        if key in exceptions:
            raise PolicyError("duplicate OS vulnerability exception")
        if raw_exception["component"] == component:
            exceptions[key] = raw_exception
    return exceptions


def _normalise_match(
    component: str, match: Any
) -> tuple[dict[str, str] | None, bool]:
    if not isinstance(match, dict):
        raise PolicyError("Grype report contains a non-object match")
    artifact = match.get("artifact")
    vulnerability = match.get("vulnerability")
    if not isinstance(artifact, dict) or not isinstance(vulnerability, dict):
        raise PolicyError("Grype match is missing artifact or vulnerability data")

    package_type = artifact.get("type")
    if package_type not in SUPPORTED_PACKAGE_TYPES:
        return None, False
    namespace = vulnerability.get("namespace")
    expected_prefix = {
        "apk": "alpine:",
        "deb": "debian:",
        "rpm": ("amazon:", "oracle:", "rhel:", "rocky:", "sles:"),
    }[package_type]
    if not isinstance(namespace, str):
        raise PolicyError("Grype finding has an invalid vulnerability namespace")
    if not namespace.startswith(expected_prefix):
        # Grype can additionally CPE-match an OS package against NVD. The raw
        # report retains those heuristic matches, but the OS gate intentionally
        # evaluates only the distribution's own vulnerability namespace.
        return None, True

    fix = vulnerability.get("fix")
    if not isinstance(fix, dict) or not isinstance(fix.get("state"), str):
        raise PolicyError("distro vulnerability is missing its fix state")
    fix_state = fix["state"] or "unknown"
    fields = {
        "component": component,
        "fix_state": fix_state,
        "namespace": namespace,
        "package_name": artifact.get("name"),
        "package_type": package_type,
        "package_version": artifact.get("version"),
        "severity": vulnerability.get("severity"),
        "vulnerability_id": vulnerability.get("id"),
    }
    for name, value in fields.items():
        if not isinstance(value, str) or not value:
            raise PolicyError(f"Grype finding has an invalid {name}")
    return fields, False


def evaluate(
    *,
    report_path: Path,
    exceptions_path: Path,
    component: str,
    output_path: Path,
    today: date,
    mode: str = "promotion",
) -> bool:
    if component not in KNOWN_COMPONENTS:
        raise PolicyError("component is not a release image")
    if mode not in POLICY_MODES:
        raise PolicyError("policy mode is invalid")
    report = _load_json(report_path, label="Grype report")
    matches = report.get("matches")
    if not isinstance(matches, list):
        raise PolicyError("Grype report is missing its matches array")
    if report.get("descriptor", {}).get("name") != "grype":
        raise PolicyError("report was not generated by Grype")

    exceptions = _load_exceptions(
        exceptions_path,
        today=today,
        component=component,
    )
    used_exception_keys: set[tuple[str, ...]] = set()
    blocking: list[dict[str, str]] = []
    review_required: list[dict[str, str]] = []
    accepted: list[dict[str, str]] = []
    severities: Counter[str] = Counter()
    fix_states: Counter[str] = Counter()
    distro_matches = 0
    excluded_non_distro_os_matches = 0

    for raw_match in matches:
        finding, excluded_non_distro = _normalise_match(component, raw_match)
        if excluded_non_distro:
            excluded_non_distro_os_matches += 1
        if finding is None:
            continue
        distro_matches += 1
        severities[finding["severity"]] += 1
        fix_states[finding["fix_state"]] += 1
        if finding["severity"] not in BLOCKING_SEVERITIES:
            continue
        key = _exception_key(finding)
        if key in exceptions:
            used_exception_keys.add(key)
            accepted.append({**finding, "expires": exceptions[key]["expires"]})
        elif mode == "candidate" and finding["fix_state"] != "fixed":
            review_required.append(finding)
        else:
            blocking.append(finding)

    unused = [
        exception
        for key, exception in sorted(exceptions.items())
        if key not in used_exception_keys
    ]
    if unused:
        raise PolicyError("OS vulnerability exception manifest contains unused entries")

    output = {
        "accepted_exceptions": sorted(
            accepted,
            key=lambda item: (
                item["component"],
                item["vulnerability_id"],
                item["package_name"],
                item["package_version"],
            ),
        ),
        "blocking_findings": sorted(
            blocking,
            key=lambda item: (
                item["severity"],
                item["vulnerability_id"],
                item["package_name"],
                item["package_version"],
            ),
        ),
        "review_required_findings": sorted(
            review_required,
            key=lambda item: (
                item["severity"],
                item["vulnerability_id"],
                item["package_name"],
                item["package_version"],
            ),
        ),
        "component": component,
        "evaluated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "policy": {
            "blocking_severities": sorted(BLOCKING_SEVERITIES),
            "candidate_blocks_fix_state": "fixed",
            "distro_package_types": sorted(SUPPORTED_PACKAGE_TYPES),
            "exception_maximum_days": 90,
            "mode": mode,
            "requires_distro_namespace": True,
        },
        "promotion_allowed": not blocking and not review_required,
        "schema_version": "1.0",
        "status": (
            "passed"
            if not blocking and not review_required
            else "candidate_passed_with_review"
            if mode == "candidate" and not blocking
            else "blocked"
        ),
        "summary": {
            "accepted_exception_count": len(accepted),
            "blocking_finding_count": len(blocking),
            "distro_match_count": distro_matches,
            "excluded_non_distro_os_match_count": excluded_non_distro_os_matches,
            "fix_states": dict(sorted(fix_states.items())),
            "review_required_finding_count": len(review_required),
            "severities": dict(sorted(severities.items())),
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return not blocking


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", required=True)
    parser.add_argument("--exceptions", required=True, type=Path)
    parser.add_argument("--mode", choices=sorted(POLICY_MODES), default="promotion")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        passed = evaluate(
            report_path=args.report,
            exceptions_path=args.exceptions,
            component=args.component,
            output_path=args.output,
            today=datetime.now(timezone.utc).date(),
            mode=args.mode,
        )
    except PolicyError as exc:
        print(f"Grype OS policy error: {exc}", file=sys.stderr)
        return 2
    if not passed:
        print(
            f"Grype OS policy blocked {args.component}; inspect {args.output}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
