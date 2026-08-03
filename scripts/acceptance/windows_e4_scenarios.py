from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker

if __package__:
    from .catalog import load_catalog, sha256_bytes
    from .semantic_evidence import reject_duplicate_object_pairs
else:
    from catalog import load_catalog, sha256_bytes
    from semantic_evidence import reject_duplicate_object_pairs


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
AUTHORITATIVE_PROFILE_PATH = (
    REPOSITORY_ROOT / "docs" / "contracts" / "windows-e4-scenario-profile.v1.json"
)
PROFILE_SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "docs"
    / "contracts"
    / "windows-e4-scenario-profile.v1.schema.json"
)
RESULT_SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "docs"
    / "contracts"
    / "windows-e4-scenario-result.v1.schema.json"
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the fail-closed Windows E4 scenario profile/result catalogs."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    profile = subparsers.add_parser("profile")
    profile.add_argument("--profile", type=Path, required=True)
    profile.add_argument("--catalog", type=Path, required=True)
    profile.add_argument("--require-authoritative", action="store_true")

    results = subparsers.add_parser("results")
    results.add_argument("--profile", type=Path, required=True)
    results.add_argument("--results", type=Path, required=True)
    results.add_argument("--catalog", type=Path, required=True)
    results.add_argument("--release-candidate", required=True)
    results.add_argument("--commit", required=True)
    results.add_argument("--require-authoritative-profile", action="store_true")
    return parser.parse_args()


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _load_json_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise TypeError(f"{label} must be a JSON object")
    return document, raw


def _load_schema(path: Path, label: str) -> dict[str, Any]:
    document, _raw = _load_json_object(path, label)
    Draft202012Validator.check_schema(document)
    return document


def _validate_schema(
    document: dict[str, Any], schema: dict[str, Any], label: str
) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.path))
    if errors:
        location = "/".join(str(item) for item in errors[0].path) or "$"
        raise ValueError(f"{label} schema violation at {location}: {errors[0].message}")


def _is_sorted_unique(values: list[Any]) -> bool:
    return values == sorted(values) and len(values) == len(set(values))


def _expected_windows_pairs(catalog_path: Path) -> set[tuple[str, str]]:
    _catalog, entries, _raw = load_catalog(catalog_path)
    return {
        (entry.requirement_id, entry.test_id)
        for entry in entries
        if "WINDOWS_E4" in entry.evidence_requirements
    }


def validate_profile_catalog(
    *,
    profile_path: Path,
    catalog_path: Path,
    require_authoritative: bool = False,
) -> tuple[dict[str, Any], bytes]:
    document, raw = _load_json_object(profile_path, "Windows E4 scenario profile catalog")
    schema = _load_schema(PROFILE_SCHEMA_PATH, "Windows E4 scenario profile schema")
    _validate_schema(document, schema, "Windows E4 scenario profile catalog")

    _catalog, _entries, catalog_raw = load_catalog(catalog_path)
    if document["requirements_catalog_sha256"] != sha256_bytes(catalog_raw):
        raise ValueError("Windows E4 scenario profile catalog hash does not match")

    if require_authoritative:
        authoritative = AUTHORITATIVE_PROFILE_PATH.read_bytes()
        if raw != authoritative:
            raise ValueError(
                "Windows E4 scenario profile artifact does not match the authoritative profile"
            )

    profiles = document["profiles"]
    profile_ids = [profile["profile_id"] for profile in profiles]
    if not _is_sorted_unique(profile_ids):
        raise ValueError("Windows E4 scenario profile IDs are not canonical")

    bindings: list[tuple[str, str]] = []
    for profile in profiles:
        profile_id = profile["profile_id"]
        profile_bindings = profile["requirement_bindings"]
        pairs = [
            (binding["requirement_id"], binding["test_id"])
            for binding in profile_bindings
        ]
        if not _is_sorted_unique(pairs):
            raise ValueError(
                f"Windows E4 profile bindings are not canonical: {profile_id}"
            )
        if any(test_id != profile_id for _requirement_id, test_id in pairs):
            raise ValueError(
                f"Windows E4 profile binding test_id does not match profile: {profile_id}"
            )
        assertion_ids = profile["required_assertion_ids"]
        if not _is_sorted_unique(assertion_ids) or profile_id not in assertion_ids:
            raise ValueError(
                f"Windows E4 profile assertion IDs are not canonical: {profile_id}"
            )
        bindings.extend(pairs)

    if len(bindings) != len(set(bindings)):
        raise ValueError("Windows E4 scenario profile catalog has duplicate bindings")
    expected = _expected_windows_pairs(catalog_path)
    actual = set(bindings)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(
            "Windows E4 scenario profile catalog does not exactly cover the "
            f"requirements catalog: missing={missing}, extra={extra}"
        )
    return document, raw


def validate_result_catalog(
    *,
    results_path: Path,
    profile_document: dict[str, Any],
    profile_raw: bytes,
    release_candidate: str,
    commit_sha: str,
) -> tuple[dict[str, Any], bytes]:
    document, raw = _load_json_object(results_path, "Windows E4 scenario result catalog")
    schema = _load_schema(RESULT_SCHEMA_PATH, "Windows E4 scenario result schema")
    _validate_schema(document, schema, "Windows E4 scenario result catalog")

    if (
        document["profile_catalog_sha256"] != hashlib.sha256(profile_raw).hexdigest()
        or document["release_candidate"] != release_candidate
        or document["commit_sha"] != commit_sha
    ):
        raise ValueError("Windows E4 scenario result catalog identity does not match")

    profiles = {
        profile["profile_id"]: profile for profile in profile_document["profiles"]
    }
    results = document["results"]
    result_ids = [result["profile_id"] for result in results]
    if not _is_sorted_unique(result_ids) or set(result_ids) != set(profiles):
        missing = sorted(set(profiles) - set(result_ids))
        extra = sorted(set(result_ids) - set(profiles))
        raise ValueError(
            "Windows E4 scenario result catalog does not exactly cover profiles: "
            f"missing={missing}, extra={extra}"
        )

    for result in results:
        profile = profiles[result["profile_id"]]
        actual_assertions = result["assertion_ids"]
        expected_assertions = profile["required_assertion_ids"]
        status = result["result"]
        detail_fields = (
            "executed_at",
            "environment_id",
            "environment_manifest_sha256",
            "windows_baseline_id",
            "harness_version",
            "assertions_sha256",
        )
        if status == "NOT_RUN":
            if actual_assertions or any(result[field] is not None for field in detail_fields):
                raise ValueError(
                    "NOT_RUN Windows E4 scenario result must not contain execution evidence"
                )
            continue
        if actual_assertions != expected_assertions:
            raise ValueError(
                "Windows E4 scenario result assertion IDs do not match its profile"
            )
        if any(result[field] is None for field in detail_fields):
            raise ValueError(
                "executed Windows E4 scenario result is missing evidence identity"
            )
        _timestamp(result["executed_at"])
    return document, raw


def result_by_profile(result_document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {result["profile_id"]: result for result in result_document["results"]}


def validate_evidence_scenario(
    *,
    artifact: dict[str, Any],
    profile_document: dict[str, Any],
    profile_raw: bytes,
    result_document: dict[str, Any],
    result_raw: bytes,
) -> None:
    scenario = artifact["scenario"]
    profile_id = scenario["profile_id"]
    if (
        scenario["profile_catalog_sha256"] != hashlib.sha256(profile_raw).hexdigest()
        or scenario["result_catalog_sha256"] != hashlib.sha256(result_raw).hexdigest()
        or profile_id != artifact["binding"]["test_id"]
    ):
        raise ValueError("Windows E4 evidence scenario binding does not match")

    profiles = {
        profile["profile_id"]: profile for profile in profile_document["profiles"]
    }
    try:
        profile = profiles[profile_id]
        result = result_by_profile(result_document)[profile_id]
    except KeyError as exc:
        raise ValueError("Windows E4 evidence references an unknown scenario profile") from exc

    assertion_ids = [assertion["assertion_id"] for assertion in artifact["assertions"]]
    if assertion_ids != profile["required_assertion_ids"]:
        raise ValueError("Windows E4 evidence assertions do not exactly match profile")
    assertions_sha256 = hashlib.sha256(rfc8785.dumps(artifact["assertions"])).hexdigest()
    if (
        result["result"] != artifact["result"]
        or result["assertions_sha256"] != assertions_sha256
        or result["executed_at"] != artifact["executed_at"]
        or result["environment_id"] != artifact["binding"]["environment_id"]
        or result["environment_manifest_sha256"]
        != artifact["binding"]["environment_manifest_sha256"]
    ):
        raise ValueError("Windows E4 evidence does not match its scenario result")


def main() -> int:
    arguments = _arguments()
    try:
        profile, profile_raw = validate_profile_catalog(
            profile_path=arguments.profile,
            catalog_path=arguments.catalog,
            require_authoritative=getattr(arguments, "require_authoritative", False)
            or getattr(arguments, "require_authoritative_profile", False),
        )
        if arguments.command == "profile":
            result = {
                "ready": True,
                "code": "WINDOWS_E4_SCENARIO_PROFILE_VALID",
                "profile_catalog_sha256": hashlib.sha256(profile_raw).hexdigest(),
                "profile_count": len(profile["profiles"]),
            }
        else:
            results, results_raw = validate_result_catalog(
                results_path=arguments.results,
                profile_document=profile,
                profile_raw=profile_raw,
                release_candidate=arguments.release_candidate,
                commit_sha=arguments.commit,
            )
            result = {
                "ready": True,
                "code": "WINDOWS_E4_SCENARIO_RESULTS_VALID",
                "profile_catalog_sha256": hashlib.sha256(profile_raw).hexdigest(),
                "result_catalog_sha256": hashlib.sha256(results_raw).hexdigest(),
                "profile_count": len(profile["profiles"]),
                "result_count": len(results["results"]),
            }
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {
                    "ready": False,
                    "code": "WINDOWS_E4_SCENARIO_CATALOG_INVALID",
                    "detail": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
