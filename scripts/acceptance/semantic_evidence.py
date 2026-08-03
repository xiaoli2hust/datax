from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker


def reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON object key: {key}")
        document[key] = value
    return document


def _load_json_object(
    path: Path, label: str, *, expected_sha256: str | None = None
) -> dict[str, Any]:
    raw = path.read_bytes()
    if (
        expected_sha256 is not None
        and hashlib.sha256(raw).hexdigest() != expected_sha256
    ):
        raise ValueError(f"{label} SHA-256 does not match")
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise TypeError(f"{label} must be a JSON object")
    return document


def _validate_schema(
    document: dict[str, Any], schema: dict[str, Any], label: str
) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.path))
    if errors:
        location = "/".join(str(item) for item in errors[0].path) or "$"
        raise ValueError(f"{label} schema violation at {location}: {errors[0].message}")


def _definition_schema(root: dict[str, Any], name: str) -> dict[str, Any]:
    return {
        "$schema": root["$schema"],
        "$defs": root["$defs"],
        "$ref": f"#/$defs/{name}",
    }


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_environment_manifest(
    *,
    path: Path,
    acceptance_schema: dict[str, Any],
    release_candidate: str,
    commit_sha: str,
    expected_sha256: str,
) -> dict[str, Any]:
    document = _load_json_object(
        path,
        "environment manifest",
        expected_sha256=expected_sha256,
    )
    _validate_schema(
        document,
        _definition_schema(acceptance_schema, "environmentManifest"),
        "environment manifest",
    )
    if (
        document["release_candidate"] != release_candidate
        or document["commit_sha"] != commit_sha
    ):
        raise ValueError("environment manifest candidate binding does not match")
    return document


def validate_oracle_artifact(
    *,
    path: Path,
    oracle_schema: dict[str, Any],
    expected_sha256: str,
) -> dict[str, Any]:
    document = _load_json_object(
        path,
        "verification oracle artifact",
        expected_sha256=expected_sha256,
    )
    _validate_schema(document, oracle_schema, "verification oracle artifact")

    payload = dict(document)
    claimed_hash = payload.pop("artifact_sha256")
    computed_hash = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    if claimed_hash != computed_hash:
        raise ValueError("verification oracle artifact_sha256 does not match content")

    mappings = document["mapping_order"]
    if [item["ordinal"] for item in mappings] != list(range(1, len(mappings) + 1)):
        raise ValueError("verification oracle mapping ordinals are not contiguous")

    started_at = _timestamp(document["started_at"])
    finished_at = _timestamp(document["finished_at"])
    if started_at > finished_at:
        raise ValueError("verification oracle started_at is after finished_at")

    source_quiescence = document["source_quiescence"]
    fingerprints_equal = (
        source_quiescence["preflight_fingerprint"]
        == source_quiescence["post_verification_fingerprint"]
    )
    if source_quiescence["unchanged"] is not fingerprints_equal:
        raise ValueError("source quiescence flag does not match its fingerprints")

    source = document["source_result"]
    target = document["target_result"]
    difference = document["difference"]
    if source is not None:
        source_read_started = _timestamp(source["read_started_at"])
        source_read_finished = _timestamp(source["read_finished_at"])
        if not started_at <= source_read_started <= source_read_finished <= finished_at:
            raise ValueError("source oracle read is outside the global oracle window")
        if source["distinct_row_digest_count"] > source["row_count"]:
            raise ValueError("source distinct_row_digest_count exceeds row_count")
    if target is not None:
        target_read_started = _timestamp(target["read_started_at"])
        target_read_finished = _timestamp(target["read_finished_at"])
        snapshot_started = _timestamp(target["snapshot_started_at"])
        snapshot_finished = _timestamp(target["snapshot_finished_at"])
        if not (
            started_at
            <= snapshot_started
            <= target_read_started
            <= target_read_finished
            <= snapshot_finished
            <= finished_at
        ):
            raise ValueError("target oracle read is outside its global snapshot window")
        if target["distinct_row_digest_count"] > target["row_count"]:
            raise ValueError("target distinct_row_digest_count exceeds row_count")
        if (
            document["target_exclusivity"]["target_snapshot_id"]
            != target["snapshot_id"]
        ):
            raise ValueError("target snapshot identity is not preserved")

    if source is not None and target is not None and difference is not None:
        row_count_equal = source["row_count"] == target["row_count"]
        multiset_equal = source["multiset_sha256"] == target["multiset_sha256"]
        if difference["row_count_equal"] is not row_count_equal:
            raise ValueError("oracle row_count_equal does not match side results")
        if difference["multiset_sha256_equal"] is not multiset_equal:
            raise ValueError("oracle multiset equality does not match side results")

    if document["result"] == "PASSED":
        if source is None or target is None or difference is None:
            raise ValueError("PASSED oracle is missing side results or difference")
        if (
            source["row_count"] != target["row_count"]
            or source["distinct_row_digest_count"]
            != target["distinct_row_digest_count"]
            or source["multiset_sha256"] != target["multiset_sha256"]
            or not fingerprints_equal
        ):
            raise ValueError("PASSED oracle side results are not equal")
        exclusivity = document["target_exclusivity"]
        confirmed_at = _timestamp(exclusivity["confirmed_at"])
        target_empty_checked_at = _timestamp(exclusivity["target_empty_checked_at"])
        if not (
            confirmed_at <= target_empty_checked_at
            and started_at
            <= target_empty_checked_at
            <= _timestamp(target["snapshot_started_at"])
            <= _timestamp(target["read_started_at"])
            <= _timestamp(target["read_finished_at"])
            <= _timestamp(target["snapshot_finished_at"])
            <= finished_at
            <= _timestamp(exclusivity["valid_until"])
        ):
            raise ValueError("PASSED oracle evidence window is invalid")
    return document


def validate_windows_evidence_artifact(
    *,
    path: Path,
    acceptance_schema: dict[str, Any],
    expected_sha256: str,
) -> dict[str, Any]:
    document = _load_json_object(
        path,
        "Windows E4 evidence artifact",
        expected_sha256=expected_sha256,
    )
    _validate_schema(
        document,
        _definition_schema(acceptance_schema, "windowsEvidenceArtifact"),
        "Windows E4 evidence artifact",
    )
    assertion_ids = [item["assertion_id"] for item in document["assertions"]]
    if len(assertion_ids) != len(set(assertion_ids)):
        raise ValueError("Windows E4 evidence contains duplicate assertion IDs")
    if document["binding"]["test_id"] not in assertion_ids:
        raise ValueError("Windows E4 assertions do not cover the bound test_id")
    if document["result"] == "PASSED" and any(
        item["result"] != "PASS" for item in document["assertions"]
    ):
        raise ValueError("PASSED Windows E4 evidence contains a failed assertion")
    return document
