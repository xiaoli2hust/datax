#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

if __package__:
    from .candidate_root import (
        CANDIDATE_ROOT_NAME,
        EXPECTED_REPOSITORY,
        EXPECTED_WORKFLOW_PATH,
        validate_candidate_root,
    )
    from .semantic_evidence import reject_duplicate_object_pairs
else:
    from candidate_root import (
        CANDIDATE_ROOT_NAME,
        EXPECTED_REPOSITORY,
        EXPECTED_WORKFLOW_PATH,
        validate_candidate_root,
    )
    from semantic_evidence import reject_duplicate_object_pairs

EXPECTED_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
EXPECTED_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
EXPECTED_SIGNER_WORKFLOW = f"{EXPECTED_REPOSITORY}/{EXPECTED_WORKFLOW_PATH}"

Runner = Callable[..., subprocess.CompletedProcess[str]]


class TrustedAttestationVerifierTCBNotImplemented(ValueError):
    """The low-level policy matched, but the verifier binary TCB is not pinned."""


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a blocked candidate root with a GitHub-hosted artifact attestation. "
            "Success proves provenance only and never approves a release."
        )
    )
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument(
        "--trusted-gh-path",
        type=Path,
        required=True,
        help=(
            "Absolute GitHub CLI path whose provenance/version/hash is pinned by the "
            "hosted attestor workflow TCB; this wrapper cannot establish that trust."
        ),
    )
    parser.add_argument(
        "--trusted-linux-evidence-directory",
        type=Path,
        required=True,
        help=(
            "Independently downloaded Linux build evidence, kept outside the Windows "
            "handoff candidate."
        ),
    )
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", type=int, required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--release-candidate", required=True)
    return parser.parse_args()


def _is_reparse_point(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _trusted_regular_file(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} path must be absolute")
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise ValueError(f"{label} must not be a symlink or reparse point")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1:
        raise ValueError(f"{label} must be a non-empty regular file")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise ValueError(f"{label} path must not traverse a symlink or alias")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_gh_attestation_command(
    *,
    trusted_gh_executable: Path,
    candidate_root_path: Path,
    bundle_path: Path,
    source_ref: str,
    commit_sha: str,
) -> list[str]:
    return [
        str(trusted_gh_executable),
        "attestation",
        "verify",
        str(candidate_root_path),
        "--bundle",
        str(bundle_path),
        "--repo",
        EXPECTED_REPOSITORY,
        "--signer-workflow",
        EXPECTED_SIGNER_WORKFLOW,
        "--signer-digest",
        commit_sha,
        "--source-ref",
        source_ref,
        "--source-digest",
        commit_sha,
        "--cert-oidc-issuer",
        EXPECTED_OIDC_ISSUER,
        "--predicate-type",
        EXPECTED_PREDICATE_TYPE,
        "--deny-self-hosted-runners",
        "--format",
        "json",
        "--limit",
        "30",
    ]


def _parse_verification_output(raw: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_object_pairs)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "gh attestation verification output is not valid JSON"
        ) from exc
    if (
        not isinstance(document, list)
        or not document
        or any(not isinstance(entry, dict) for entry in document)
    ):
        raise ValueError(
            "gh attestation verification returned no verified attestations"
        )
    return document


def _validate_verified_attestations(
    *,
    attestations: list[dict[str, Any]],
    workflow_run_id: str,
    workflow_run_attempt: int,
    source_ref: str,
    commit_sha: str,
    candidate_root_sha256: str,
) -> None:
    expected_workflow_uri = f"https://github.com/{EXPECTED_REPOSITORY}/{EXPECTED_WORKFLOW_PATH}@{source_ref}"
    expected_repository_uri = f"https://github.com/{EXPECTED_REPOSITORY}"
    expected_run_uri = (
        f"{expected_repository_uri}/actions/runs/{workflow_run_id}"
        f"/attempts/{workflow_run_attempt}"
    )
    for entry in attestations:
        verification_result = entry.get("verificationResult")
        if not isinstance(verification_result, dict):
            raise TypeError("verified attestation is missing verificationResult")
        signature = verification_result.get("signature")
        certificate = (
            signature.get("certificate") if isinstance(signature, dict) else None
        )
        if not isinstance(certificate, dict):
            raise TypeError("verified attestation is missing its certificate summary")
        expected_certificate_fields = {
            "subjectAlternativeName": expected_workflow_uri,
            "issuer": EXPECTED_OIDC_ISSUER,
            "buildSignerURI": expected_workflow_uri,
            "buildSignerDigest": commit_sha,
            "runnerEnvironment": "github-hosted",
            "sourceRepositoryURI": expected_repository_uri,
            "sourceRepositoryDigest": commit_sha,
            "sourceRepositoryRef": source_ref,
            "runInvocationURI": expected_run_uri,
        }
        if any(
            certificate.get(name) != expected
            for name, expected in expected_certificate_fields.items()
        ):
            raise ValueError(
                "verified attestation certificate does not match the fixed "
                "repository/workflow/run/commit identity"
            )
        timestamps = verification_result.get("verifiedTimestamps")
        if not isinstance(timestamps, list) or not timestamps:
            raise ValueError("verified attestation contains no verified timestamp")
        statement = verification_result.get("statement")
        if (
            not isinstance(statement, dict)
            or statement.get("predicateType") != EXPECTED_PREDICATE_TYPE
        ):
            raise ValueError("verified attestation predicate type is invalid")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not any(
            isinstance(subject, dict)
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == candidate_root_sha256
            for subject in subjects
        ):
            raise ValueError(
                "verified attestation subject does not bind candidate-root SHA-256"
            )


def verify_candidate_attestation(
    *,
    candidate_root_path: Path,
    bundle_path: Path,
    trusted_gh_executable: Path,
    trusted_linux_evidence_directory: Path,
    schema_path: Path,
    workflow_run_id: str,
    workflow_run_attempt: int,
    source_ref: str,
    commit_sha: str,
    product_version: str,
    release_candidate: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Verify provenance assuming the caller already established the GH CLI TCB.

    File/path checks below prevent accidental aliasing but cannot prove the binary's
    publisher or provenance. The future hosted-attestor workflow must pin those facts.
    This foundation always raises the stable verifier-TCB blocker after exercising
    the complete low-level policy; the CLI reports ready=false/release_approved=false.
    """

    candidate_root_path = _trusted_regular_file(candidate_root_path, "candidate root")
    if candidate_root_path.name != CANDIDATE_ROOT_NAME:
        raise ValueError(f"candidate root file must be named {CANDIDATE_ROOT_NAME}")
    bundle_path = _trusted_regular_file(bundle_path, "attestation bundle")
    trusted_gh_executable = _trusted_regular_file(
        trusted_gh_executable, "hosted-attestor trusted GitHub CLI"
    )
    candidate_directory = candidate_root_path.parent
    if bundle_path.is_relative_to(candidate_directory):
        raise ValueError(
            "attestation bundle must remain outside the candidate directory to avoid "
            "a circular or unbound file set"
        )

    validation_arguments = {
        "candidate_directory": candidate_directory,
        "trusted_linux_evidence_directory": trusted_linux_evidence_directory,
        "schema_path": schema_path,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "source_ref": source_ref,
        "commit_sha": commit_sha,
        "product_version": product_version,
        "release_candidate": release_candidate,
    }
    root_validation = validate_candidate_root(**validation_arguments)
    candidate_root_sha256 = _sha256(candidate_root_path)
    if root_validation["candidate_root_sha256"] != candidate_root_sha256:
        raise ValueError("candidate root changed before attestation verification")

    command = build_gh_attestation_command(
        trusted_gh_executable=trusted_gh_executable,
        candidate_root_path=candidate_root_path,
        bundle_path=bundle_path,
        source_ref=source_ref,
        commit_sha=commit_sha,
    )
    completed = runner(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip()
        raise ValueError(
            "gh attestation verify failed closed" + (f": {detail}" if detail else "")
        )
    attestations = _parse_verification_output(completed.stdout)
    _validate_verified_attestations(
        attestations=attestations,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        source_ref=source_ref,
        commit_sha=commit_sha,
        candidate_root_sha256=candidate_root_sha256,
    )

    post_validation = validate_candidate_root(**validation_arguments)
    if (
        _sha256(candidate_root_path) != candidate_root_sha256
        or post_validation["candidate_root_sha256"] != candidate_root_sha256
    ):
        raise ValueError(
            "candidate root or referenced file set changed during verification"
        )
    raise TrustedAttestationVerifierTCBNotImplemented(
        "TRUSTED_ATTESTATION_VERIFIER_TCB_NOT_IMPLEMENTED: the candidate-root "
        f"attestation policy matched {len(attestations)} bundle(s) for "
        f"{candidate_root_sha256}, but this foundation cannot prove the GitHub CLI "
        "binary came from a path/version/digest pinned by the protected hosted-attestor "
        "workflow"
    )


def main() -> int:
    arguments = _arguments()
    try:
        result = verify_candidate_attestation(
            candidate_root_path=arguments.candidate_root,
            bundle_path=arguments.bundle,
            trusted_gh_executable=arguments.trusted_gh_path,
            trusted_linux_evidence_directory=(
                arguments.trusted_linux_evidence_directory
            ),
            schema_path=arguments.schema,
            workflow_run_id=arguments.workflow_run_id,
            workflow_run_attempt=arguments.workflow_run_attempt,
            source_ref=arguments.source_ref,
            commit_sha=arguments.commit,
            product_version=arguments.product_version,
            release_candidate=arguments.release_candidate,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except TrustedAttestationVerifierTCBNotImplemented as exc:
        print(
            json.dumps(
                {
                    "ready": False,
                    "code": "TRUSTED_ATTESTATION_VERIFIER_TCB_NOT_IMPLEMENTED",
                    "detail": str(exc),
                    "release_approved": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    except (
        OSError,
        UnicodeError,
        TypeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "ready": False,
                    "code": "CANDIDATE_ATTESTATION_INVALID",
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
