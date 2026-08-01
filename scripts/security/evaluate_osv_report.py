"""Fail-closed evaluator for application findings in an OSV Scanner JSON report."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
APPLICATION_ECOSYSTEMS = frozenset({"Maven", "PyPI", "Go", "npm", "crates.io"})
OS_ECOSYSTEM_PREFIXES = (
    "AlmaLinux",
    "Alpine",
    "Amazon Linux",
    "Chainguard",
    "Debian",
    "Mageia",
    "Oracle Linux",
    "Photon OS",
    "Red Hat",
    "Rocky Linux",
    "SUSE",
    "Ubuntu",
    "Wolfi",
    "openSUSE",
)
MAX_EXCEPTION_DAYS = 90
MANIFEST_FIELDS = frozenset({"schema_version", "scope", "exceptions"})
SCOPE_FIELDS = frozenset({"ecosystems"})
EXCEPTION_FIELDS = frozenset(
    {
        "vulnerability_id",
        "ecosystem",
        "name",
        "version",
        "reason",
        "expires",
    }
)


class EvaluationInputError(ValueError):
    """Raised when the report or exception manifest is malformed."""


@dataclass(frozen=True, order=True)
class ExceptionEntry:
    vulnerability_id: str
    ecosystem: str
    name: str
    version: str
    reason: str
    expires: date

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (
            self.vulnerability_id,
            self.ecosystem,
            self.name,
            self.version,
        )

    def as_json(self) -> dict[str, str]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "reason": self.reason,
            "expires": self.expires.isoformat(),
        }


@dataclass(frozen=True)
class Finding:
    ecosystem: str
    name: str
    version: str
    ids: tuple[str, ...]
    aliases: tuple[str, ...]
    max_severity: str | None
    source_index: int
    package_index: int
    group_index: int

    @property
    def all_ids(self) -> frozenset[str]:
        return frozenset((*self.ids, *self.aliases))

    @property
    def location(self) -> str:
        return (
            f"results[{self.source_index}].packages[{self.package_index}]"
            f".groups[{self.group_index}]"
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "ids": list(self.ids),
            "aliases": list(self.aliases),
            "max_severity": self.max_severity,
            "report_location": self.location,
        }


def _require_object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvaluationInputError(f"{location} must be a JSON object")
    return value


def _require_list(value: Any, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvaluationInputError(f"{location} must be a JSON array")
    return value


def _require_exact_fields(
    value: dict[str, Any], required: frozenset[str], location: str
) -> None:
    actual = frozenset(value)
    missing = sorted(required - actual)
    unknown = sorted(actual - required)
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing fields: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown fields: {', '.join(unknown)}")
        raise EvaluationInputError(f"{location} has {'; '.join(details)}")


def _require_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise EvaluationInputError(
            f"{location} must be a non-empty string without surrounding whitespace"
        )
    return value


def _require_string_list(value: Any, location: str, *, non_empty: bool) -> tuple[str, ...]:
    items = _require_list(value, location)
    if non_empty and not items:
        raise EvaluationInputError(f"{location} must not be empty")
    normalized = tuple(
        _require_string(item, f"{location}[{index}]")
        for index, item in enumerate(items)
    )
    if len(set(normalized)) != len(normalized):
        raise EvaluationInputError(f"{location} contains duplicate values")
    return normalized


def parse_exception_manifest(
    manifest: Any, *, as_of: date
) -> tuple[ExceptionEntry, ...]:
    root = _require_object(manifest, "exception manifest")
    _require_exact_fields(root, MANIFEST_FIELDS, "exception manifest")
    if root["schema_version"] != SCHEMA_VERSION:
        raise EvaluationInputError(
            f"exception manifest schema_version must be {SCHEMA_VERSION!r}"
        )

    scope = _require_object(root["scope"], "exception manifest.scope")
    _require_exact_fields(scope, SCOPE_FIELDS, "exception manifest.scope")
    ecosystems = _require_string_list(
        scope["ecosystems"],
        "exception manifest.scope.ecosystems",
        non_empty=True,
    )
    if frozenset(ecosystems) != APPLICATION_ECOSYSTEMS:
        expected = ", ".join(sorted(APPLICATION_ECOSYSTEMS))
        raise EvaluationInputError(
            "exception manifest.scope.ecosystems must contain exactly "
            f"the application ecosystems: {expected}"
        )

    raw_entries = _require_list(
        root["exceptions"], "exception manifest.exceptions"
    )
    entries: list[ExceptionEntry] = []
    seen_keys: set[tuple[str, str, str, str]] = set()
    for index, raw_entry in enumerate(raw_entries):
        location = f"exception manifest.exceptions[{index}]"
        entry_object = _require_object(raw_entry, location)
        _require_exact_fields(entry_object, EXCEPTION_FIELDS, location)
        vulnerability_id = _require_string(
            entry_object["vulnerability_id"], f"{location}.vulnerability_id"
        )
        ecosystem = _require_string(
            entry_object["ecosystem"], f"{location}.ecosystem"
        )
        if ecosystem not in APPLICATION_ECOSYSTEMS:
            raise EvaluationInputError(
                f"{location}.ecosystem is outside the application scope"
            )
        name = _require_string(entry_object["name"], f"{location}.name")
        version = _require_string(entry_object["version"], f"{location}.version")
        reason = _require_string(entry_object["reason"], f"{location}.reason")
        if len(reason) < 40:
            raise EvaluationInputError(
                f"{location}.reason must contain at least 40 characters"
            )
        raw_expiry = _require_string(entry_object["expires"], f"{location}.expires")
        try:
            expiry = date.fromisoformat(raw_expiry)
        except ValueError as exc:
            raise EvaluationInputError(
                f"{location}.expires must use YYYY-MM-DD"
            ) from exc
        if expiry <= as_of:
            raise EvaluationInputError(
                f"{location} expired on {expiry.isoformat()} (as of {as_of.isoformat()})"
            )
        if (expiry - as_of).days > MAX_EXCEPTION_DAYS:
            raise EvaluationInputError(
                f"{location}.expires is more than {MAX_EXCEPTION_DAYS} days "
                f"after {as_of.isoformat()}"
            )

        entry = ExceptionEntry(
            vulnerability_id=vulnerability_id,
            ecosystem=ecosystem,
            name=name,
            version=version,
            reason=reason,
            expires=expiry,
        )
        if entry.key in seen_keys:
            raise EvaluationInputError(
                f"{location} duplicates the exact binding {entry.key!r}"
            )
        seen_keys.add(entry.key)
        entries.append(entry)
    return tuple(entries)


def parse_application_findings(report: Any) -> tuple[Finding, ...]:
    root = _require_object(report, "OSV report")
    results = _require_list(root.get("results"), "OSV report.results")
    findings: list[Finding] = []
    for source_index, raw_result in enumerate(results):
        result_location = f"OSV report.results[{source_index}]"
        result = _require_object(raw_result, result_location)
        packages = _require_list(
            result.get("packages"), f"{result_location}.packages"
        )
        for package_index, raw_package_result in enumerate(packages):
            package_location = f"{result_location}.packages[{package_index}]"
            package_result = _require_object(raw_package_result, package_location)
            package = _require_object(
                package_result.get("package"), f"{package_location}.package"
            )
            ecosystem = _require_string(
                package.get("ecosystem"), f"{package_location}.package.ecosystem"
            )
            if ecosystem not in APPLICATION_ECOSYSTEMS:
                if _is_os_ecosystem(ecosystem):
                    continue
                raise EvaluationInputError(
                    f"{package_location}.package.ecosystem {ecosystem!r} is neither "
                    "an approved application ecosystem nor a recognized OS ecosystem"
                )
            name = _require_string(
                package.get("name"), f"{package_location}.package.name"
            )
            version = _require_string(
                package.get("version"), f"{package_location}.package.version"
            )
            groups = _require_list(
                package_result.get("groups"), f"{package_location}.groups"
            )
            for group_index, raw_group in enumerate(groups):
                group_location = f"{package_location}.groups[{group_index}]"
                group = _require_object(raw_group, group_location)
                ids = _require_string_list(
                    group.get("ids"), f"{group_location}.ids", non_empty=True
                )
                aliases = _require_string_list(
                    group.get("aliases", []),
                    f"{group_location}.aliases",
                    non_empty=False,
                )
                severity = group.get("max_severity")
                if severity is not None and not isinstance(severity, (str, int, float)):
                    raise EvaluationInputError(
                        f"{group_location}.max_severity must be a string, number, or null"
                    )
                findings.append(
                    Finding(
                        ecosystem=ecosystem,
                        name=name,
                        version=version,
                        ids=ids,
                        aliases=aliases,
                        max_severity=None if severity is None else str(severity),
                        source_index=source_index,
                        package_index=package_index,
                        group_index=group_index,
                    )
                )
    return tuple(findings)


def _is_os_ecosystem(ecosystem: str) -> bool:
    return any(
        ecosystem == prefix or ecosystem.startswith(f"{prefix}:")
        for prefix in OS_ECOSYSTEM_PREFIXES
    )


def _matching_exceptions(
    finding: Finding, entries: Iterable[ExceptionEntry]
) -> tuple[ExceptionEntry, ...]:
    return tuple(
        entry
        for entry in entries
        if entry.ecosystem == finding.ecosystem
        and entry.name == finding.name
        and entry.version == finding.version
        and entry.vulnerability_id in finding.all_ids
    )


def evaluate(
    report: Any, manifest: Any, *, as_of: date | None = None
) -> dict[str, Any]:
    evaluation_date = as_of or datetime.now(timezone.utc).date()
    entries = parse_exception_manifest(manifest, as_of=evaluation_date)
    findings = parse_application_findings(report)

    entry_match_counts = {entry.key: 0 for entry in entries}
    excepted_findings: list[dict[str, Any]] = []
    unexcepted_findings: list[dict[str, Any]] = []
    ambiguous_matches: list[dict[str, Any]] = []

    for finding in findings:
        matches = _matching_exceptions(finding, entries)
        for entry in matches:
            entry_match_counts[entry.key] += 1
        if not matches:
            unexcepted_findings.append(finding.as_json())
        elif len(matches) == 1:
            excepted_findings.append(
                {
                    "finding": finding.as_json(),
                    "exception": matches[0].as_json(),
                }
            )
        else:
            ambiguous_matches.append(
                {
                    "finding": finding.as_json(),
                    "matching_exceptions": [entry.as_json() for entry in matches],
                }
            )

    multiply_used_entries = [
        entry.as_json()
        for entry in entries
        if entry_match_counts[entry.key] > 1
    ]
    unused_entries = [
        entry.as_json()
        for entry in entries
        if entry_match_counts[entry.key] == 0
    ]
    if multiply_used_entries:
        ambiguous_matches.append(
            {
                "finding": None,
                "matching_exceptions": multiply_used_entries,
                "error": "an exception binding matched more than one report group",
            }
        )

    passed = not unexcepted_findings and not unused_entries and not ambiguous_matches
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if passed else "failed",
        "as_of": evaluation_date.isoformat(),
        "scope": {"ecosystems": sorted(APPLICATION_ECOSYSTEMS)},
        "summary": {
            "application_findings": len(findings),
            "excepted_findings": len(excepted_findings),
            "unexcepted_findings": len(unexcepted_findings),
            "unused_exceptions": len(unused_entries),
            "ambiguous_matches": len(ambiguous_matches),
        },
        "excepted_findings": excepted_findings,
        "unexcepted_findings": unexcepted_findings,
        "unused_exceptions": unused_entries,
        "ambiguous_matches": ambiguous_matches,
    }


def _read_json(path: Path, label: str) -> Any:
    try:
        path_status = path.lstat()
        if stat.S_ISLNK(path_status.st_mode):
            raise EvaluationInputError(f"{label} {path} must not be a symlink")
        if not stat.S_ISREG(path_status.st_mode):
            raise EvaluationInputError(
                f"{label} {path} must be a regular file"
            )
        return json.loads(path.read_text(encoding="utf-8"))
    except EvaluationInputError:
        raise
    except OSError as exc:
        raise EvaluationInputError(f"cannot read {label} {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise EvaluationInputError(
            f"{label} {path} is not valid JSON: {exc}"
        ) from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise EvaluationInputError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _write_result(result: dict[str, Any], output: Path | None) -> None:
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(
        f"OSV application gate: {result['status']} "
        f"({result['summary'].get('application_findings', 0)} findings); "
        f"evidence={output}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate runtime application OSV findings against exact, expiring exceptions."
        )
    )
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--exceptions", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        report = _read_json(args.report, "OSV report")
        manifest = _read_json(args.exceptions, "exception manifest")
        result = evaluate(report, manifest)
        result["inputs"] = {
            "report": {
                "path": str(args.report),
                "sha256": _sha256(args.report),
            },
            "exceptions": {
                "path": str(args.exceptions),
                "sha256": _sha256(args.exceptions),
            },
        }
        _write_result(result, args.output)
        return 0 if result["status"] == "passed" else 1
    except EvaluationInputError as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "invalid",
            "as_of": datetime.now(timezone.utc).date().isoformat(),
            "scope": {"ecosystems": sorted(APPLICATION_ECOSYSTEMS)},
            "summary": {
                "application_findings": 0,
                "excepted_findings": 0,
                "unexcepted_findings": 0,
                "unused_exceptions": 0,
                "ambiguous_matches": 0,
            },
            "errors": [str(exc)],
        }
        _write_result(result, args.output)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
