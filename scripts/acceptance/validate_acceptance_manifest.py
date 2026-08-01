#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

if __package__:
    from .catalog import (
        build_catalog_bytes,
        load_catalog,
        sha256_bytes,
    )
else:
    from catalog import build_catalog_bytes, load_catalog, sha256_bytes

_EVIDENCE_ORDER = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--environment-manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_path(root: Path, relative: str) -> Path:
    if "\\" in relative:
        raise ValueError("evidence paths must use POSIX separators")
    candidate = root.joinpath(*relative.split("/"))
    current = root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            raise ValueError(f"evidence path contains a symbolic link: {relative}")
    resolved_root = root.resolve(strict=True)
    resolved_candidate = candidate.resolve(strict=True)
    if not resolved_candidate.is_relative_to(resolved_root):
        raise ValueError(f"evidence path escapes its root: {relative}")
    if not resolved_candidate.is_file():
        raise ValueError(f"evidence artifact is not a regular file: {relative}")
    return resolved_candidate


def _validate_artifacts(manifest: dict[str, object], root: Path) -> None:
    artifacts: list[dict[str, str]] = []
    for raw_entry in manifest["entries"]:  # type: ignore[index]
        entry = raw_entry  # validated by JSON Schema
        artifacts.extend(entry["evidence"])
        oracle = entry["oracle"]
        if oracle is not None:
            artifacts.append(oracle["artifact"])
    for artifact in artifacts:
        path = _artifact_path(root, artifact["path"])
        if _file_sha256(path) != artifact["sha256"]:
            raise ValueError(f"evidence SHA-256 mismatch: {artifact['path']}")


def validate(
    *,
    catalog_path: Path,
    matrix_path: Path,
    manifest_path: Path,
    schema_path: Path,
    environment_manifest_path: Path,
    evidence_root: Path,
    require_pass: bool,
) -> dict[str, object]:
    catalog, catalog_entries, catalog_raw = load_catalog(catalog_path)
    if build_catalog_bytes(matrix_path) != catalog_raw:
        raise ValueError("requirements catalog does not match the authoritative matrix")
    manifest_raw = manifest_path.read_bytes()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_raw)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(manifest), key=lambda item: list(item.path))
    if errors:
        location = "/".join(str(item) for item in errors[0].path) or "$"
        raise ValueError(f"acceptance schema violation at {location}: {errors[0].message}")
    if manifest["requirements_catalog_sha256"] != sha256_bytes(catalog_raw):
        raise ValueError("requirements catalog SHA-256 does not match")
    if (
        manifest["environment_manifest_sha256"]
        != _file_sha256(environment_manifest_path)
    ):
        raise ValueError("environment manifest SHA-256 does not match")

    expected = Counter(
        (
            entry.requirement_id,
            entry.requirement_priority,
            entry.test_id,
            entry.minimum_evidence_level,
        )
        for entry in catalog_entries
    )
    actual = Counter(
        (
            entry["requirement_id"],
            entry["requirement_priority"],
            entry["test_id"],
            entry["minimum_evidence_level"],
        )
        for entry in manifest["entries"]
    )
    if actual != expected:
        raise ValueError("manifest requirement tuples do not exactly match the catalog")
    duplicate_pairs = sorted(
        (
            requirement_id,
            test_id,
        )
        for (requirement_id, _priority, test_id, _minimum), count in actual.items()
        if count > 1
    )
    if duplicate_pairs:
        raise ValueError("manifest contains duplicate requirement/test pairs")

    v1_ids = {
        entry.requirement_id
        for entry in catalog_entries
        if entry.requirement_priority == "V1-MUST"
    }
    actual_v1_ids = {
        entry["requirement_id"]
        for entry in manifest["entries"]
        if entry["requirement_priority"] == "V1-MUST"
    }
    missing = sorted(v1_ids - actual_v1_ids)
    expected_coverage = {
        "expected_v1_must_count": len(v1_ids),
        "covered_v1_must_count": len(actual_v1_ids),
        "catalog_exact_match": actual == expected,
        "missing_requirement_ids": missing,
        "duplicate_requirement_test_pairs": [
            {"requirement_id": pair[0], "test_id": pair[1]}
            for pair in duplicate_pairs
        ],
    }
    if manifest["coverage"] != expected_coverage:
        raise ValueError("manifest coverage summary is not validator-derived")

    defects = {item["defect_id"]: item for item in manifest["defects"]}
    if len(defects) != len(manifest["defects"]):
        raise ValueError("manifest contains duplicate defect IDs")
    for entry in manifest["entries"]:
        for defect_id in entry.get("defect_ids", []):
            if defect_id not in defects:
                raise ValueError("manifest entry references an unknown defect")
        if (
            entry["result"] == "PASS"
            and _EVIDENCE_ORDER[entry["evidence_level"]]
            < _EVIDENCE_ORDER[entry["minimum_evidence_level"]]
        ):
            raise ValueError("PASS evidence level is below the catalog minimum")

    v1_results = {
        entry["result"]
        for entry in manifest["entries"]
        if entry["requirement_priority"] == "V1-MUST"
    }
    severe_defect = any(
        item["defect_severity"] in {"P0", "P1"} for item in manifest["defects"]
    )
    if "FAIL" in v1_results or severe_defect:
        expected_gate = "FAIL"
    elif v1_results == {"PASS"}:
        expected_gate = "PASS"
    else:
        expected_gate = "BLOCKED"
    if manifest["gate_result"] != expected_gate:
        raise ValueError("gate_result does not match requirement and defect results")
    if require_pass and expected_gate != "PASS":
        raise ValueError("public release requires gate_result=PASS")

    _validate_artifacts(manifest, evidence_root)
    return {
        "ready": True,
        "code": "ACCEPTANCE_MANIFEST_VALID",
        "gate_result": expected_gate,
        "catalog_sha256": sha256_bytes(catalog_raw),
        "manifest_sha256": sha256_bytes(manifest_raw),
        "requirement_count": catalog["requirement_count"],
        "entry_count": catalog["entry_count"],
    }


def main() -> int:
    arguments = _arguments()
    try:
        result = validate(
            catalog_path=arguments.catalog,
            matrix_path=arguments.matrix,
            manifest_path=arguments.manifest,
            schema_path=arguments.schema,
            environment_manifest_path=arguments.environment_manifest,
            evidence_root=arguments.evidence_root,
            require_pass=arguments.require_pass,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (
        OSError,
        UnicodeError,
        TypeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "ready": False,
                    "code": "ACCEPTANCE_MANIFEST_INVALID",
                    "detail": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
