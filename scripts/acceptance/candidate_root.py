#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

if __package__:
    from .catalog import canonical_json_bytes, load_catalog
    from .semantic_evidence import reject_duplicate_object_pairs
    from .validate_acceptance_manifest import validate as validate_acceptance_manifest
else:
    from catalog import canonical_json_bytes, load_catalog
    from semantic_evidence import reject_duplicate_object_pairs
    from validate_acceptance_manifest import validate as validate_acceptance_manifest

EXPECTED_REPOSITORY = "xiaoli2hust/datax"
EXPECTED_WORKFLOW_PATH = ".github/workflows/release.yml"
EXPECTED_PROTECTED_ENVIRONMENT = "windows-candidate-signing"
CANDIDATE_ROOT_NAME = "candidate-root.v1.json"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
AUTHORITATIVE_SCHEMA_PATH = (
    REPOSITORY_ROOT / "docs" / "contracts" / "candidate-root.v1.schema.json"
)
AUTHORITATIVE_ACCEPTANCE_SCHEMA_PATH = (
    REPOSITORY_ROOT / "docs" / "contracts" / "acceptance-manifest.v1.schema.json"
)
AUTHORITATIVE_ORACLE_SCHEMA_PATH = (
    REPOSITORY_ROOT / "docs" / "contracts" / "verification-oracle.v1.schema.json"
)
AUTHORITATIVE_MATRIX_PATH = REPOSITORY_ROOT / "docs" / "12_需求追踪矩阵.md"

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_RUN_ID = re.compile(r"^[1-9][0-9]*$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SOURCE_REF = re.compile(
    r"^refs/(?:heads/main|tags/v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$"
)
_RELATIVE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")

_REQUIRED_IMAGE_REPOSITORIES = {
    "DES_POSTGRES_IMAGE": "postgres",
    "DES_API_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-api",
    "DES_EGRESS_GUARD_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-egress-guard",
    "DES_WORKER_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-worker",
    "DES_WEB_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-web",
}
_EXPECTED_SBOM_FILES = {
    "sbom/source.spdx.json",
    "sbom/postgres.image.spdx.json",
    "sbom/api.image.spdx.json",
    "sbom/egress_guard.image.spdx.json",
    "sbom/worker.image.spdx.json",
    "sbom/web.image.spdx.json",
}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate or validate the canonical, fail-closed Windows candidate root."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("generate", "validate"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--candidate-directory", type=Path, required=True)
        subparser.add_argument(
            "--trusted-linux-evidence-directory",
            type=Path,
            required=True,
            help=(
                "Independently downloaded Linux evidence artifact from the GitHub-hosted "
                "build job; it must remain outside the Windows handoff candidate."
            ),
        )
        subparser.add_argument(
            "--schema",
            type=Path,
            default=AUTHORITATIVE_SCHEMA_PATH,
        )
        subparser.add_argument("--workflow-run-id", required=True)
        subparser.add_argument("--workflow-run-attempt", type=int, required=True)
        subparser.add_argument("--source-ref", required=True)
        subparser.add_argument("--commit", required=True)
        subparser.add_argument("--product-version", required=True)
        subparser.add_argument("--release-candidate", required=True)
        if command == "generate":
            subparser.add_argument(
                "--scenario-blocked-reason",
                action="append",
                required=True,
                help=(
                    "Concrete reason the machine scenario/E3/E4 chain is still blocked; "
                    "may be repeated."
                ),
            )
    return parser.parse_args()


def _is_reparse_point(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _assert_non_reparse(metadata: os.stat_result, label: str) -> None:
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise ValueError(f"{label} must not be a symlink or reparse point")


def _resolve_candidate_directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    metadata = os.lstat(absolute)
    _assert_non_reparse(metadata, "candidate directory")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("candidate directory must be a directory")
    resolved = absolute.resolve(strict=True)
    if resolved != absolute:
        raise ValueError("candidate directory must not traverse a symlink or alias")
    return resolved


def _validate_relative_path(relative: str) -> None:
    if (
        "\\" in relative
        or not _RELATIVE_PATH.fullmatch(relative)
        or relative.startswith("/")
        or "//" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise ValueError(f"candidate contains an unsafe relative path: {relative}")


def _sha256_regular_file(path: Path, expected_metadata: os.stat_result) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = os.lstat(path)
    _assert_non_reparse(after, f"candidate file {path.name}")
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
    )
    if any(
        getattr(expected_metadata, field) != getattr(after, field)
        for field in stable_fields
    ):
        raise ValueError(f"candidate file changed while hashing: {path}")
    return digest.hexdigest()


def _scan_candidate_files(
    root: Path, *, excluded_relative_path: str | None = CANDIDATE_ROOT_NAME
) -> tuple[dict[str, Any], ...]:
    descriptors: list[dict[str, Any]] = []
    casefolded_paths: set[str] = set()

    def visit(directory: Path) -> None:
        entries = sorted(os.scandir(directory), key=lambda item: item.name)
        for entry in entries:
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            relative = path.relative_to(root).as_posix()
            _validate_relative_path(relative)
            _assert_non_reparse(metadata, f"candidate entry {relative}")
            folded = relative.casefold()
            if folded in casefolded_paths:
                raise ValueError(
                    f"candidate contains a case-insensitive duplicate path: {relative}"
                )
            casefolded_paths.add(folded)
            if stat.S_ISDIR(metadata.st_mode):
                visit(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"candidate entry is not a regular file: {relative}")
            if excluded_relative_path is not None and relative == excluded_relative_path:
                continue
            if metadata.st_size < 1:
                raise ValueError(f"candidate file must not be empty: {relative}")
            descriptors.append(
                {
                    "path": relative,
                    "size_bytes": metadata.st_size,
                    "sha256": _sha256_regular_file(path, metadata),
                }
            )

    visit(root)
    descriptors.sort(key=lambda item: item["path"])
    if not descriptors:
        raise ValueError("candidate directory contains no evidence files")
    return tuple(descriptors)


def _load_json_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise TypeError(f"{label} must be a JSON object")
    return document, raw


def _load_schema(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise ValueError("candidate-root schema path must be absolute")
    metadata = os.lstat(path)
    _assert_non_reparse(metadata, "candidate-root schema")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1:
        raise ValueError("candidate-root schema must be a non-empty regular file")
    resolved = path.resolve(strict=True)
    expected = AUTHORITATIVE_SCHEMA_PATH.resolve(strict=True)
    if resolved != path or resolved != expected:
        raise ValueError("candidate-root validation requires the authoritative schema")
    schema, _raw = _load_json_object(path, "candidate-root schema")
    Draft202012Validator.check_schema(schema)
    return schema


def _validate_schema(document: dict[str, Any], schema: dict[str, Any]) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.path))
    if errors:
        location = "/".join(str(part) for part in errors[0].path) or "$"
        raise ValueError(
            f"candidate-root schema violation at {location}: {errors[0].message}"
        )


def _validate_blocked_root_semantics(document: dict[str, Any]) -> None:
    if (
        document.get("schema_version") != "1.0"
        or document.get("artifact_kind") != "WINDOWS_RELEASE_CANDIDATE_ROOT"
        or document.get("root_status") != "BLOCKED"
        or document.get("release_approved") is not False
    ):
        raise ValueError(
            "candidate-root v1 is a BLOCKED foundation and cannot approve a release"
        )
    scenario = document.get("scenario_evidence")
    expected_scenario_keys = {
        "status",
        "scenario_profile_catalog",
        "scenario_result_catalog",
        "e3_e4_evidence_bundle",
        "windows_baseline_id",
        "harness_version",
        "started_at",
        "finished_at",
        "blocked_reasons",
    }
    nullable_fields = expected_scenario_keys - {"status", "blocked_reasons"}
    if (
        not isinstance(scenario, dict)
        or set(scenario) != expected_scenario_keys
        or scenario.get("status") != "BLOCKED"
        or any(scenario.get(field) is not None for field in nullable_fields)
    ):
        raise ValueError(
            "candidate-root v1 scenario evidence must remain explicitly BLOCKED/null"
        )
    reasons = scenario.get("blocked_reasons")
    if (
        not isinstance(reasons, list)
        or not reasons
        or any(not isinstance(reason, str) or not reason.strip() for reason in reasons)
        or reasons != sorted(set(reasons))
    ):
        raise ValueError("candidate-root blocked reasons are invalid or non-canonical")


def _expected_release_tag(source_ref: str) -> str | None:
    prefix = "refs/tags/"
    return source_ref.removeprefix(prefix) if source_ref.startswith(prefix) else None


def _validate_external_identity(
    *,
    workflow_run_id: str,
    workflow_run_attempt: int,
    source_ref: str,
    commit_sha: str,
    product_version: str,
    release_candidate: str,
) -> None:
    if _RUN_ID.fullmatch(workflow_run_id) is None:
        raise ValueError("workflow run ID must be a positive decimal string")
    if workflow_run_attempt < 1:
        raise ValueError("workflow run attempt must be positive")
    if _SOURCE_REF.fullmatch(source_ref) is None:
        raise ValueError("source ref must be refs/heads/main or an exact semver tag")
    if _COMMIT.fullmatch(commit_sha) is None:
        raise ValueError("commit must be a lowercase 40-character Git SHA-1")
    if _SEMVER.fullmatch(product_version) is None:
        raise ValueError("product version must be an exact three-part semver")
    if release_candidate != f"{product_version}-{commit_sha[:12]}":
        raise ValueError(
            "release candidate must bind product version and commit prefix"
        )
    release_tag = _expected_release_tag(source_ref)
    if release_tag is not None and release_tag != f"v{product_version}":
        raise ValueError("release tag must match the product version")


def _descriptor_by_path(files: tuple[dict[str, Any], ...]) -> dict[str, dict[str, Any]]:
    return {item["path"]: item for item in files}


def _require_descriptor(
    descriptors: dict[str, dict[str, Any]], relative_path: str
) -> dict[str, Any]:
    try:
        return dict(descriptors[relative_path])
    except KeyError as exc:
        raise ValueError(
            f"candidate is missing a required file: {relative_path}"
        ) from exc


def _required_artifacts(
    *, descriptors: dict[str, dict[str, Any]], product_version: str
) -> dict[str, Any]:
    return {
        "setup": _require_descriptor(
            descriptors,
            f"DataX-Enterprise-Studio-Setup-{product_version}-x64.exe",
        ),
        "launcher": _require_descriptor(descriptors, "launcher.exe"),
        "release_manifest": _require_descriptor(
            descriptors, "resources/release-manifest.json"
        ),
        "compose": _require_descriptor(descriptors, "resources/compose.yaml"),
        "images_lock": _require_descriptor(descriptors, "images.release.env"),
        "embedded_images_lock": _require_descriptor(
            descriptors, "resources/images.release.env"
        ),
        "acl_helper": _require_descriptor(descriptors, "resources/secure-acl.ps1"),
        "supply_chain_index": {
            "kind": "SPDX_SBOM_INDEX",
            "artifact": _require_descriptor(
                descriptors, "linux-evidence/sbom-index.json"
            ),
        },
        "acceptance_manifest": _require_descriptor(
            descriptors, "linux-evidence/acceptance-manifest.json"
        ),
        "acceptance_environment_manifest": _require_descriptor(
            descriptors, "linux-evidence/release-context.json"
        ),
        "requirements_catalog": _require_descriptor(
            descriptors, "linux-evidence/requirements-catalog.v1.json"
        ),
        "windows_environment_manifest": _require_descriptor(
            descriptors, "windows-build-environment.json"
        ),
    }


def _parse_image_lock(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("image lock is not valid UTF-8") from exc
    if text.startswith("\ufeff") or len(text.encode("utf-8")) > 16384:
        raise ValueError("image lock is too large or contains a BOM")
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line != line.strip():
            raise ValueError("image lock contains non-canonical whitespace")
        key, separator, value = line.partition("=")
        if separator != "=" or key in values or key not in _REQUIRED_IMAGE_REPOSITORIES:
            raise ValueError("image lock contains an unknown or duplicate entry")
        repository = re.escape(_REQUIRED_IMAGE_REPOSITORIES[key])
        if re.fullmatch(rf"{repository}@sha256:[0-9a-f]{{64}}", value) is None:
            raise ValueError(
                f"image lock contains an invalid immutable reference: {key}"
            )
        values[key] = value
    if set(values) != set(_REQUIRED_IMAGE_REPOSITORIES):
        raise ValueError("image lock is missing one or more required images")


def _validate_linux_evidence_handoff(
    *, root: Path, trusted_linux_evidence_directory: Path
) -> None:
    """Bind the Windows handoff copy to an independently downloaded Linux artifact."""

    trusted_root = _resolve_candidate_directory(trusted_linux_evidence_directory)
    if trusted_root.is_relative_to(root):
        raise ValueError(
            "trusted Linux evidence directory must remain outside the Windows handoff candidate"
        )
    candidate_linux_evidence = _resolve_candidate_directory(root / "linux-evidence")
    trusted_files = _scan_candidate_files(trusted_root, excluded_relative_path=None)
    candidate_files = _scan_candidate_files(
        candidate_linux_evidence,
        excluded_relative_path=None,
    )
    if trusted_files != candidate_files:
        trusted_by_path = {item["path"]: item for item in trusted_files}
        candidate_by_path = {item["path"]: item for item in candidate_files}
        missing = sorted(set(trusted_by_path) - set(candidate_by_path))
        extra = sorted(set(candidate_by_path) - set(trusted_by_path))
        changed = sorted(
            path
            for path in set(trusted_by_path) & set(candidate_by_path)
            if trusted_by_path[path] != candidate_by_path[path]
        )
        raise ValueError(
            "candidate Linux evidence differs from independently downloaded Linux "
            f"build evidence: missing={missing}, extra={extra}, changed={changed}"
        )


def _validate_cross_file_bindings(
    *,
    root: Path,
    document: dict[str, Any],
    files: tuple[dict[str, Any], ...],
    trusted_linux_evidence_directory: Path,
) -> None:
    identity = document["identity"]
    artifacts = document["artifacts"]
    inventory = _descriptor_by_path(files)

    required = [
        artifacts["setup"],
        artifacts["launcher"],
        artifacts["release_manifest"],
        artifacts["compose"],
        artifacts["images_lock"],
        artifacts["embedded_images_lock"],
        artifacts["acl_helper"],
        artifacts["supply_chain_index"]["artifact"],
        artifacts["acceptance_manifest"],
        artifacts["acceptance_environment_manifest"],
        artifacts["requirements_catalog"],
        artifacts["windows_environment_manifest"],
    ]
    for descriptor in required:
        if inventory.get(descriptor["path"]) != descriptor:
            raise ValueError(
                f"required artifact descriptor does not match inventory: {descriptor['path']}"
            )

    expected_artifacts = _required_artifacts(
        descriptors=inventory,
        product_version=identity["product_version"],
    )
    if artifacts != expected_artifacts:
        raise ValueError("candidate-root required artifact paths are not canonical")

    release_context_path = root / artifacts["acceptance_environment_manifest"]["path"]
    release_context, _raw = _load_json_object(release_context_path, "release context")
    ref_type = release_context.get("git_ref_type")
    ref_name = release_context.get("git_ref_name")
    context_source_ref = (
        f"refs/heads/{ref_name}"
        if ref_type == "branch"
        else f"refs/tags/{ref_name}"
        if ref_type == "tag"
        else None
    )
    if (
        release_context.get("repository") != identity["repository"]
        or release_context.get("git_commit") != identity["commit_sha"]
        or release_context.get("workflow_run_id") != identity["workflow_run_id"]
        or release_context.get("workflow_run_attempt")
        != str(identity["workflow_run_attempt"])
        or release_context.get("version") != identity["product_version"]
        or release_context.get("release_candidate") != identity["release_candidate"]
        or context_source_ref != identity["source_ref"]
        or release_context.get("candidate_only") is not True
        or release_context.get("public_release_created") is not False
    ):
        raise ValueError("release context identity does not match candidate-root")

    release_manifest_path = root / artifacts["release_manifest"]["path"]
    release_manifest, _raw = _load_json_object(
        release_manifest_path, "release manifest"
    )
    release_manifest_keys = {
        "schema_version",
        "product_version",
        "release_candidate",
        "compose_sha256",
        "images_sha256",
        "acl_script_sha256",
        "allowed_authenticode_signer_certificate_sha256",
    }
    allowed_signers = release_manifest.get(
        "allowed_authenticode_signer_certificate_sha256"
    )
    if (
        set(release_manifest) != release_manifest_keys
        or release_manifest.get("schema_version") != "1.2"
        or release_manifest.get("product_version") != identity["product_version"]
        or release_manifest.get("release_candidate")
        != identity["release_candidate"]
        or release_manifest.get("compose_sha256") != artifacts["compose"]["sha256"]
        or release_manifest.get("images_sha256")
        != artifacts["embedded_images_lock"]["sha256"]
        or release_manifest.get("acl_script_sha256")
        != artifacts["acl_helper"]["sha256"]
        or not isinstance(allowed_signers, list)
        or not 1 <= len(allowed_signers) <= 8
        or any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in allowed_signers
        )
        or allowed_signers != sorted(set(allowed_signers))
    ):
        raise ValueError(
            "final release manifest 1.2 does not bind candidate, resources and signer allowlist"
        )

    if (
        artifacts["images_lock"]["sha256"]
        != artifacts["embedded_images_lock"]["sha256"]
        or (root / artifacts["images_lock"]["path"]).read_bytes()
        != (root / artifacts["embedded_images_lock"]["path"]).read_bytes()
    ):
        raise ValueError("top-level and embedded image locks differ")

    _parse_image_lock(root / artifacts["images_lock"]["path"])
    _parse_image_lock(root / artifacts["embedded_images_lock"]["path"])
    linux_images_lock = _require_descriptor(
        inventory, "linux-evidence/images.release.env"
    )
    if (
        artifacts["images_lock"]["sha256"] != linux_images_lock["sha256"]
        or (root / artifacts["images_lock"]["path"]).read_bytes()
        != (root / linux_images_lock["path"]).read_bytes()
    ):
        raise ValueError(
            "candidate image lock is not bound to the Linux build evidence image lock"
        )
    _parse_image_lock(root / linux_images_lock["path"])
    _validate_linux_evidence_handoff(
        root=root,
        trusted_linux_evidence_directory=trusted_linux_evidence_directory,
    )

    catalog_path = root / artifacts["requirements_catalog"]["path"]
    _catalog, _entries, catalog_raw = load_catalog(catalog_path)
    catalog_sha256 = hashlib.sha256(catalog_raw).hexdigest()
    acceptance_path = root / artifacts["acceptance_manifest"]["path"]
    acceptance, _raw = _load_json_object(acceptance_path, "acceptance manifest")
    if (
        acceptance.get("schema_version") != "1.1"
        or acceptance.get("release_candidate") != identity["release_candidate"]
        or acceptance.get("commit_sha") != identity["commit_sha"]
        or acceptance.get("requirements_catalog_sha256") != catalog_sha256
        or acceptance.get("environment_manifest_sha256")
        != artifacts["acceptance_environment_manifest"]["sha256"]
        or acceptance.get("gate_result") == "PASS"
    ):
        raise ValueError(
            "acceptance manifest is not a blocked candidate bound to this root"
        )
    acceptance_validation = validate_acceptance_manifest(
        catalog_path=catalog_path,
        matrix_path=AUTHORITATIVE_MATRIX_PATH,
        manifest_path=acceptance_path,
        schema_path=AUTHORITATIVE_ACCEPTANCE_SCHEMA_PATH,
        oracle_schema_path=AUTHORITATIVE_ORACLE_SCHEMA_PATH,
        environment_manifest_path=(
            root / artifacts["acceptance_environment_manifest"]["path"]
        ),
        evidence_root=acceptance_path.parent,
        require_pass=False,
        expected_commit=identity["commit_sha"],
        expected_release_candidate=identity["release_candidate"],
    )
    if (
        acceptance_validation.get("release_approved") is not False
        or acceptance_validation.get("gate_result") != acceptance["gate_result"]
    ):
        raise ValueError("acceptance validator returned an unsafe candidate result")

    supply_chain = artifacts["supply_chain_index"]
    if supply_chain["kind"] != "SPDX_SBOM_INDEX":
        raise ValueError("unsupported supply-chain index kind")
    sbom_index_path = root / supply_chain["artifact"]["path"]
    sbom_index, _raw = _load_json_object(sbom_index_path, "SBOM index")
    raw_entries = sbom_index.get("entries")
    if sbom_index.get("schema_version") != "1.0" or not isinstance(raw_entries, list):
        raise ValueError("SBOM index shape is invalid")
    referenced: set[str] = set()
    index_parent = Path(supply_chain["artifact"]["path"]).parent
    for entry in raw_entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            raise TypeError("SBOM index entry is invalid")
        _validate_relative_path(entry["file"])
        relative = (index_parent / entry["file"]).as_posix()
        _validate_relative_path(relative)
        if relative in referenced or relative not in inventory:
            raise ValueError(
                "SBOM index references a duplicate or missing candidate file"
            )
        referenced.add(relative)
    expected_sboms = {(index_parent / item).as_posix() for item in _EXPECTED_SBOM_FILES}
    if referenced != expected_sboms:
        raise ValueError(
            "SBOM index does not bind the complete source and image SBOM set"
        )

    windows_environment_path = root / artifacts["windows_environment_manifest"]["path"]
    windows_environment, _raw = _load_json_object(
        windows_environment_path, "Windows environment manifest"
    )
    if (
        windows_environment.get("schema_version") != "1.0"
        or windows_environment.get("candidate_only") is not True
        or windows_environment.get("process_architecture") != "X64"
        or windows_environment.get("windows_installation_e2e") != "NOT_RUN"
    ):
        raise ValueError(
            "Windows environment manifest must remain an explicit non-E4 candidate"
        )


def _identity_document(
    *,
    workflow_run_id: str,
    workflow_run_attempt: int,
    source_ref: str,
    commit_sha: str,
    product_version: str,
    release_candidate: str,
) -> dict[str, Any]:
    return {
        "repository": EXPECTED_REPOSITORY,
        "workflow_path": EXPECTED_WORKFLOW_PATH,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "protected_environment": EXPECTED_PROTECTED_ENVIRONMENT,
        "source_ref": source_ref,
        "commit_sha": commit_sha,
        "release_tag": _expected_release_tag(source_ref),
        "product_version": product_version,
        "release_candidate": release_candidate,
    }


def generate_candidate_root(
    *,
    candidate_directory: Path,
    trusted_linux_evidence_directory: Path,
    schema_path: Path,
    workflow_run_id: str,
    workflow_run_attempt: int,
    source_ref: str,
    commit_sha: str,
    product_version: str,
    release_candidate: str,
    scenario_blocked_reasons: list[str],
) -> dict[str, Any]:
    _validate_external_identity(
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        source_ref=source_ref,
        commit_sha=commit_sha,
        product_version=product_version,
        release_candidate=release_candidate,
    )
    reasons = sorted(set(scenario_blocked_reasons))
    if not reasons or any(
        not reason.strip() or reason != reason.strip() for reason in reasons
    ):
        raise ValueError("scenario blocked reasons must be non-empty canonical strings")

    root = _resolve_candidate_directory(candidate_directory)
    output = root / CANDIDATE_ROOT_NAME
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"candidate root already exists: {output}")
    files = _scan_candidate_files(root)
    descriptors = _descriptor_by_path(files)
    identity = _identity_document(
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        source_ref=source_ref,
        commit_sha=commit_sha,
        product_version=product_version,
        release_candidate=release_candidate,
    )
    document = {
        "schema_version": "1.0",
        "artifact_kind": "WINDOWS_RELEASE_CANDIDATE_ROOT",
        "root_status": "BLOCKED",
        "release_approved": False,
        "identity": identity,
        "artifacts": _required_artifacts(
            descriptors=descriptors,
            product_version=product_version,
        ),
        "scenario_evidence": {
            "status": "BLOCKED",
            "scenario_profile_catalog": None,
            "scenario_result_catalog": None,
            "e3_e4_evidence_bundle": None,
            "windows_baseline_id": None,
            "harness_version": None,
            "started_at": None,
            "finished_at": None,
            "blocked_reasons": reasons,
        },
        "files": list(files),
    }
    schema = _load_schema(schema_path)
    _validate_schema(document, schema)
    _validate_blocked_root_semantics(document)
    _validate_cross_file_bindings(
        root=root,
        document=document,
        files=files,
        trusted_linux_evidence_directory=trusted_linux_evidence_directory,
    )
    raw = canonical_json_bytes(document)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    validated = validate_candidate_root(
        candidate_directory=root,
        trusted_linux_evidence_directory=trusted_linux_evidence_directory,
        schema_path=schema_path,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        source_ref=source_ref,
        commit_sha=commit_sha,
        product_version=product_version,
        release_candidate=release_candidate,
    )
    return {
        "ready": True,
        "code": "BLOCKED_CANDIDATE_ROOT_CREATED",
        "candidate_root": str(output),
        "candidate_root_sha256": validated["candidate_root_sha256"],
        "release_approved": False,
        "file_count": validated["file_count"],
    }


def validate_candidate_root(
    *,
    candidate_directory: Path,
    trusted_linux_evidence_directory: Path,
    schema_path: Path,
    workflow_run_id: str,
    workflow_run_attempt: int,
    source_ref: str,
    commit_sha: str,
    product_version: str,
    release_candidate: str,
) -> dict[str, Any]:
    _validate_external_identity(
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        source_ref=source_ref,
        commit_sha=commit_sha,
        product_version=product_version,
        release_candidate=release_candidate,
    )
    root = _resolve_candidate_directory(candidate_directory)
    candidate_root_path = root / CANDIDATE_ROOT_NAME
    metadata = os.lstat(candidate_root_path)
    _assert_non_reparse(metadata, "candidate root")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1:
        raise ValueError("candidate root must be a non-empty regular file")
    document, raw = _load_json_object(candidate_root_path, "candidate root")
    if raw != canonical_json_bytes(document):
        raise ValueError("candidate root is not canonical UTF-8 JSON")
    schema = _load_schema(schema_path)
    _validate_schema(document, schema)
    _validate_blocked_root_semantics(document)
    expected_identity = _identity_document(
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        source_ref=source_ref,
        commit_sha=commit_sha,
        product_version=product_version,
        release_candidate=release_candidate,
    )
    if document["identity"] != expected_identity:
        raise ValueError("candidate-root identity does not match trusted CI inputs")

    files = _scan_candidate_files(root)
    if document["files"] != list(files):
        expected_paths = {item["path"] for item in files}
        declared_paths = {item["path"] for item in document["files"]}
        missing = sorted(declared_paths - expected_paths)
        extra = sorted(expected_paths - declared_paths)
        raise ValueError(
            f"candidate file set or hash differs from root: missing={missing}, extra={extra}"
        )
    _validate_cross_file_bindings(
        root=root,
        document=document,
        files=files,
        trusted_linux_evidence_directory=trusted_linux_evidence_directory,
    )
    return {
        "ready": True,
        "code": "BLOCKED_CANDIDATE_ROOT_VALID",
        "candidate_root": str(candidate_root_path),
        "candidate_root_sha256": hashlib.sha256(raw).hexdigest(),
        "release_approved": False,
        "file_count": len(files),
    }


def main() -> int:
    arguments = _arguments()
    common = {
        "candidate_directory": arguments.candidate_directory,
        "trusted_linux_evidence_directory": arguments.trusted_linux_evidence_directory,
        "schema_path": arguments.schema,
        "workflow_run_id": arguments.workflow_run_id,
        "workflow_run_attempt": arguments.workflow_run_attempt,
        "source_ref": arguments.source_ref,
        "commit_sha": arguments.commit,
        "product_version": arguments.product_version,
        "release_candidate": arguments.release_candidate,
    }
    try:
        if arguments.command == "generate":
            result = generate_candidate_root(
                **common,
                scenario_blocked_reasons=arguments.scenario_blocked_reason,
            )
        else:
            result = validate_candidate_root(**common)
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
                    "code": "CANDIDATE_ROOT_INVALID",
                    "detail": str(exc),
                    "release_approved": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
