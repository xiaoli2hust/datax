"""Validate a local Windows E4 harness preflight observation.

This validator deliberately does not promote an observation to E4 evidence.  The
v1 preflight contract has a fixed ``e4_result=NOT_RUN`` and
``release_approved=false`` so it can only catch malformed or internally
inconsistent local prerequisite records before a future protected harness exists.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

if __package__:
    from .semantic_evidence import reject_duplicate_object_pairs
else:
    from semantic_evidence import reject_duplicate_object_pairs


EXPECTED_CHECK_IDS = frozenset(
    {
        "WIN11_X64_CLIENT",
        "VIRTUALIZATION",
        "WSL2_STATUS",
        "DOCKER_AMBIENT_CONTEXT",
        "DOCKER_DESKTOP_LINUX_AMD64",
        "DOCKER_COMPOSE_V2",
        "CANDIDATE_HASHES",
        "CANDIDATE_SIGNATURES",
        "PRODUCT_STATE_ABSENT",
    }
)
_COMMIT_SHA = re.compile(r"^[a-f0-9]{40}$")
_RELEASE_CANDIDATE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-([a-f0-9]{12})$"
)


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            path.read_bytes(), object_pairs_hook=reject_duplicate_object_pairs
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise TypeError(f"{label} must be a JSON object")
    return document


def _validate_schema(document: dict[str, Any], schema: dict[str, Any]) -> None:
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.path))
    if errors:
        location = "/".join(str(item) for item in errors[0].path) or "$"
        raise ValueError(
            f"Windows E4 preflight schema violation at {location}: "
            f"{errors[0].message}"
        )


def _candidate_hash_matches(artifact: dict[str, Any]) -> bool:
    observed = artifact["sha256"]
    expected = artifact["expected_sha256"]
    matches = observed is not None and observed == expected
    if artifact["hash_matches"] is not matches:
        raise ValueError("candidate hash_matches does not match its observed SHA-256")
    return matches


def _candidate_signer_matches(
    artifact: dict[str, Any], expected_signer_certificate_der_sha256: str
) -> bool:
    observed = artifact["signer_certificate_der_sha256"]
    matches = (
        observed is not None
        and observed == expected_signer_certificate_der_sha256
    )
    if artifact["signer_matches"] is not matches:
        raise ValueError(
            "candidate signer_matches does not match its observed signer certificate"
        )
    return matches


def _observed_check_results(document: dict[str, Any]) -> dict[str, bool]:
    windows = document["windows"]
    docker = document["docker"]
    candidate = document["candidate"]
    setup = candidate["setup"]
    launcher = candidate["launcher"]

    setup_hash_matches = _candidate_hash_matches(setup)
    launcher_hash_matches = _candidate_hash_matches(launcher)
    expected_signer = candidate["expected_signer_certificate_der_sha256"]
    setup_signer_matches = _candidate_signer_matches(setup, expected_signer)
    launcher_signer_matches = _candidate_signer_matches(launcher, expected_signer)

    return {
        "WIN11_X64_CLIENT": (
            windows["edition"] == "Windows 11"
            and windows["product_type"] == "CLIENT"
            and windows["architecture"] == "X86_64"
        ),
        "VIRTUALIZATION": windows["virtualization_firmware_enabled"] is True,
        "DOCKER_AMBIENT_CONTEXT": docker["ambient_context_absent"] is True,
        "WSL2_STATUS": docker["wsl_status_available"] is True,
        "DOCKER_DESKTOP_LINUX_AMD64": (
            docker["desktop_install_detected"] is True
            and docker["engine_available"] is True
            and docker["server_os"] == "linux"
            and docker["server_architecture"] == "amd64"
        ),
        "DOCKER_COMPOSE_V2": bool(docker["compose_version"]),
        "CANDIDATE_HASHES": setup_hash_matches and launcher_hash_matches,
        "CANDIDATE_SIGNATURES": (
            setup["authenticode_status"] == "VALID"
            and launcher["authenticode_status"] == "VALID"
            and setup_signer_matches
            and launcher_signer_matches
            and setup["signer_certificate_der_sha256"] == expected_signer
            and launcher["signer_certificate_der_sha256"] == expected_signer
            and setup["timestamp_present"] is True
            and launcher["timestamp_present"] is True
        ),
        "PRODUCT_STATE_ABSENT": document["product_state_absent"] is True,
    }


def _validate_candidate_identity(document: dict[str, Any]) -> None:
    """Require the local E4 observation to name the exact candidate commit."""

    candidate = document["release_candidate"]
    commit_sha = document["commit_sha"]
    candidate_match = _RELEASE_CANDIDATE.fullmatch(candidate)
    if _COMMIT_SHA.fullmatch(commit_sha) is None or candidate_match is None:
        raise ValueError("Windows E4 preflight candidate identity is malformed")
    if candidate_match.group(4) != commit_sha[:12]:
        raise ValueError(
            "Windows E4 preflight release_candidate does not bind the commit prefix"
        )


def validate_windows_e4_preflight(
    *, document: dict[str, Any], schema: dict[str, Any]
) -> dict[str, Any]:
    """Validate the v1 contract and cross-field local-observation semantics."""

    _validate_schema(document, schema)

    checks = document["checks"]
    check_ids = [check["check_id"] for check in checks]
    if len(check_ids) != len(set(check_ids)):
        raise ValueError("Windows E4 preflight contains duplicate check IDs")
    if set(check_ids) != EXPECTED_CHECK_IDS:
        raise ValueError("Windows E4 preflight check IDs do not match the v1 roster")

    _validate_candidate_identity(document)
    observed = _observed_check_results(document)
    actual = {check["check_id"]: check["result"] for check in checks}
    for check_id, passed in observed.items():
        expected_result = "PASS" if passed else "BLOCKED"
        if actual[check_id] != expected_result:
            raise ValueError(
                f"Windows E4 preflight check {check_id} does not match observations"
            )

    all_checks_pass = all(observed.values())
    expected_preflight_result = "READY" if all_checks_pass else "BLOCKED"
    if document["local_preflight_result"] != expected_preflight_result:
        raise ValueError(
            "Windows E4 preflight local_preflight_result does not match checks"
        )

    # These are duplicated here as a defensive semantic guard.  They must never
    # become a hidden release-promotion path if the JSON Schema is accidentally
    # loosened in a future refactor.
    if document["e4_result"] != "NOT_RUN":
        raise ValueError("Windows E4 preflight must remain NOT_RUN")
    if document["release_approved"] is not False:
        raise ValueError("Windows E4 preflight must not approve a release")
    if document["baseline"]["independently_verified"] is not False:
        raise ValueError("local preflight must not claim an independent baseline")
    if document["runner"]["self_hosted_registration_verified"] is not False:
        raise ValueError("local preflight must not claim runner registration trust")
    return document


def validate_windows_e4_preflight_file(
    *, input_path: Path, schema_path: Path
) -> dict[str, Any]:
    document = _load_json_object(input_path, "Windows E4 preflight")
    schema = _load_json_object(schema_path, "Windows E4 preflight schema")
    return validate_windows_e4_preflight(document=document, schema=schema)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        document = validate_windows_e4_preflight_file(
            input_path=arguments.input, schema_path=arguments.schema
        )
    except (OSError, TypeError, ValueError) as exc:
        print(f"WINDOWS_E4_PREFLIGHT_INVALID: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "status": "WINDOWS_E4_PREFLIGHT_VALID",
                "local_preflight_result": document["local_preflight_result"],
                "e4_result": "NOT_RUN",
                "release_approved": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
