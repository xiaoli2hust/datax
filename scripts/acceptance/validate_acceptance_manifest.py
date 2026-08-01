#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

if __package__:
    from .catalog import (
        build_catalog_bytes,
        load_catalog,
        sha256_bytes,
    )
    from .semantic_evidence import (
        reject_duplicate_object_pairs,
        validate_environment_manifest,
        validate_oracle_artifact,
        validate_windows_evidence_artifact,
    )
else:
    from catalog import build_catalog_bytes, load_catalog, sha256_bytes
    from semantic_evidence import (
        reject_duplicate_object_pairs,
        validate_environment_manifest,
        validate_oracle_artifact,
        validate_windows_evidence_artifact,
    )


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--oracle-schema", type=Path)
    parser.add_argument("--environment-manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-release-candidate")
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
        windows_evidence = entry["windows_evidence"]
        if windows_evidence is not None:
            artifacts.append(windows_evidence["artifact"])
    for artifact in artifacts:
        path = _artifact_path(root, artifact["path"])
        if _file_sha256(path) != artifact["sha256"]:
            raise ValueError(f"evidence SHA-256 mismatch: {artifact['path']}")


def _validate_nested_artifacts(
    *, artifacts: list[dict[str, str]], evidence_root: Path
) -> None:
    for artifact in artifacts:
        path = _artifact_path(evidence_root, artifact["path"])
        if _file_sha256(path) != artifact["sha256"]:
            raise ValueError(f"evidence SHA-256 mismatch: {artifact['path']}")


def _expected_binding(
    *, manifest: dict[str, object], entry: dict[str, object]
) -> dict[str, object]:
    return {
        "release_candidate": manifest["release_candidate"],
        "commit_sha": manifest["commit_sha"],
        "requirement_id": entry["requirement_id"],
        "test_id": entry["test_id"],
        "environment_id": entry["environment_id"],
        "environment_manifest_sha256": manifest["environment_manifest_sha256"],
    }


def _validate_semantic_evidence(
    *,
    manifest: dict[str, object],
    acceptance_schema: dict[str, object],
    oracle_schema: dict[str, object],
    environment_manifest_path: Path,
    evidence_root: Path,
) -> None:
    bound_entries = [
        entry
        for entry in manifest["entries"]  # type: ignore[index]
        if (entry["result"] == "PASS" and entry["evidence_level"] in {"E3", "E4"})
        or entry["oracle"] is not None
        or entry["windows_evidence"] is not None
    ]
    environment = None
    if bound_entries:
        environment = validate_environment_manifest(
            path=environment_manifest_path,
            acceptance_schema=acceptance_schema,
            release_candidate=manifest["release_candidate"],  # type: ignore[arg-type]
            commit_sha=manifest["commit_sha"],  # type: ignore[arg-type]
            expected_sha256=manifest["environment_manifest_sha256"],  # type: ignore[arg-type]
        )

    oracle_artifacts: dict[tuple[str, str], tuple[str, str]] = {}
    oracle_executions: dict[str, tuple[str, str]] = {}
    for entry in manifest["entries"]:  # type: ignore[index]
        oracle = entry["oracle"]
        if oracle is None:
            continue
        owner = (entry["requirement_id"], entry["test_id"])
        artifact_identity = (
            oracle["artifact"]["path"],
            oracle["artifact"]["sha256"],
        )
        execution_id = oracle["binding"]["execution_id"]
        if artifact_identity in oracle_artifacts:
            raise ValueError("verification oracle artifact is replayed across entries")
        if execution_id in oracle_executions:
            raise ValueError(
                "verification oracle execution_id is replayed across entries"
            )
        oracle_artifacts[artifact_identity] = owner
        oracle_executions[execution_id] = owner

    for entry in manifest["entries"]:  # type: ignore[index]
        required = set(entry["evidence_requirements"])
        oracle = entry["oracle"]
        windows_evidence = entry["windows_evidence"]
        if entry["result"] == "PASS":
            if "VERIFICATION_ORACLE_V1" in required and oracle is None:
                raise ValueError("PASS entry requires a verification oracle artifact")
            if "WINDOWS_E4" in required and windows_evidence is None:
                raise ValueError("PASS entry requires a Windows E4 evidence artifact")

        if (
            entry["result"] == "PASS"
            and entry["evidence_level"] in {"E3", "E4"}
            and (
                environment is None
                or _timestamp(environment["captured_at"])
                > _timestamp(entry["executed_at"])
            )
        ):
            raise ValueError("environment was captured after the test executed_at")

        if (oracle is not None or windows_evidence is not None) and (
            environment is None
            or environment["environment_id"] != entry["environment_id"]
        ):
            raise ValueError("structured evidence environment_id does not match")

        if oracle is not None:
            artifact_path = _artifact_path(evidence_root, oracle["artifact"]["path"])
            artifact = validate_oracle_artifact(
                path=artifact_path,
                oracle_schema=oracle_schema,
                expected_sha256=oracle["artifact"]["sha256"],
            )
            expected = _expected_binding(manifest=manifest, entry=entry)
            binding = dict(oracle["binding"])
            for key, value in expected.items():
                if binding[key] != value:
                    raise ValueError(
                        f"oracle binding does not match entry field: {key}"
                    )
            if (
                binding["execution_id"] != artifact["execution_id"]
                or binding["job_version_id"] != artifact["job_version_id"]
                or oracle["result"] != artifact["result"]
            ):
                raise ValueError("oracle binding does not match its artifact identity")
            if entry["executed_at"] is None or _timestamp(
                entry["executed_at"]
            ) < _timestamp(artifact["finished_at"]):
                raise ValueError("entry executed_at is earlier than oracle finished_at")

        if windows_evidence is not None:
            artifact_path = _artifact_path(
                evidence_root, windows_evidence["artifact"]["path"]
            )
            artifact = validate_windows_evidence_artifact(
                path=artifact_path,
                acceptance_schema=acceptance_schema,
                expected_sha256=windows_evidence["artifact"]["sha256"],
            )
            expected = _expected_binding(manifest=manifest, entry=entry)
            binding = dict(windows_evidence["binding"])
            for key, value in expected.items():
                if binding[key] != value:
                    raise ValueError(
                        f"Windows evidence binding does not match entry field: {key}"
                    )
            if (
                artifact["binding"] != binding
                or artifact["result"] != windows_evidence["result"]
                or artifact["executed_at"] != entry["executed_at"]
            ):
                raise ValueError("Windows evidence artifact binding does not match")
            if environment is None or (
                environment["environment_id"] != binding["environment_id"]
                or environment["system"]["os_family"] != "WINDOWS"
                or environment["system"]["architecture"] != "X86_64"
                or artifact["windows"]["build"] != environment["system"]["os_version"]
            ):
                raise ValueError("Windows evidence environment binding does not match")
            nested = [
                artifact["release_artifacts"]["setup"],
                artifact["release_artifacts"]["launcher"],
                *[
                    evidence
                    for assertion in artifact["assertions"]
                    for evidence in assertion["evidence"]
                ],
            ]
            _validate_nested_artifacts(
                artifacts=nested,
                evidence_root=evidence_root,
            )


def validate(
    *,
    catalog_path: Path,
    matrix_path: Path,
    manifest_path: Path,
    schema_path: Path,
    environment_manifest_path: Path,
    evidence_root: Path,
    require_pass: bool,
    oracle_schema_path: Path | None = None,
    expected_commit: str | None = None,
    expected_release_candidate: str | None = None,
) -> dict[str, object]:
    catalog, catalog_entries, catalog_raw = load_catalog(catalog_path)
    if build_catalog_bytes(matrix_path) != catalog_raw:
        raise ValueError("requirements catalog does not match the authoritative matrix")
    manifest_raw = manifest_path.read_bytes()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    oracle_schema_path = oracle_schema_path or schema_path.with_name(
        "verification-oracle.v1.schema.json"
    )
    oracle_schema = json.loads(oracle_schema_path.read_text(encoding="utf-8"))
    manifest = json.loads(
        manifest_raw,
        object_pairs_hook=reject_duplicate_object_pairs,
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(manifest), key=lambda item: list(item.path))
    if errors:
        location = "/".join(str(item) for item in errors[0].path) or "$"
        raise ValueError(
            f"acceptance schema violation at {location}: {errors[0].message}"
        )
    if require_pass and (expected_commit is None or expected_release_candidate is None):
        raise ValueError(
            "public release validation requires externally supplied candidate identity"
        )
    if expected_commit is not None and manifest["commit_sha"] != expected_commit:
        raise ValueError("manifest commit_sha does not match the external candidate")
    if (
        expected_release_candidate is not None
        and manifest["release_candidate"] != expected_release_candidate
    ):
        raise ValueError(
            "manifest release_candidate does not match the external candidate"
        )
    if require_pass:
        raise ValueError(
            "TRUSTED_RELEASE_ATTESTATION_NOT_IMPLEMENTED: public release approval "
            "requires a trusted Windows harness and candidate attestation validator"
        )
    if manifest["requirements_catalog_sha256"] != sha256_bytes(catalog_raw):
        raise ValueError("requirements catalog SHA-256 does not match")
    if manifest["environment_manifest_sha256"] != _file_sha256(
        environment_manifest_path
    ):
        raise ValueError("environment manifest SHA-256 does not match")

    expected = Counter(
        (
            entry.requirement_id,
            entry.requirement_priority,
            entry.test_id,
            entry.minimum_evidence_level,
            entry.evidence_requirements,
        )
        for entry in catalog_entries
    )
    actual = Counter(
        (
            entry["requirement_id"],
            entry["requirement_priority"],
            entry["test_id"],
            entry["minimum_evidence_level"],
            tuple(entry["evidence_requirements"]),
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
        for (
            requirement_id,
            _priority,
            test_id,
            _minimum,
            _evidence_requirements,
        ), count in actual.items()
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
            {"requirement_id": pair[0], "test_id": pair[1]} for pair in duplicate_pairs
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
        if entry["result"] == "PASS" and (
            entry["evidence_level"] != entry["minimum_evidence_level"]
        ):
            raise ValueError("PASS evidence level must exactly match the catalog")

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
    _validate_artifacts(manifest, evidence_root)
    _validate_semantic_evidence(
        manifest=manifest,
        acceptance_schema=schema,
        oracle_schema=oracle_schema,
        environment_manifest_path=environment_manifest_path,
        evidence_root=evidence_root,
    )
    return {
        "ready": True,
        "code": "ACCEPTANCE_MANIFEST_VALID",
        "gate_result": expected_gate,
        "catalog_sha256": sha256_bytes(catalog_raw),
        "manifest_sha256": sha256_bytes(manifest_raw),
        "requirement_count": catalog["requirement_count"],
        "entry_count": catalog["entry_count"],
        "release_approved": False,
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
            oracle_schema_path=arguments.oracle_schema,
            expected_commit=arguments.expected_commit,
            expected_release_candidate=arguments.expected_release_candidate,
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
