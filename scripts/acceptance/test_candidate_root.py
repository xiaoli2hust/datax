from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from jsonschema import Draft202012Validator

from scripts.acceptance.candidate_root import (
    CANDIDATE_ROOT_NAME,
    canonical_json_bytes,
    generate_candidate_root,
    validate_candidate_root,
)
from scripts.acceptance.verify_candidate_attestation import (
    EXPECTED_OIDC_ISSUER,
    EXPECTED_PREDICATE_TYPE,
    EXPECTED_SIGNER_WORKFLOW,
    TrustedAttestationVerifierTCBNotImplemented,
    verify_candidate_attestation,
)
from scripts.acceptance.verify_candidate_attestation import (
    main as attestation_main,
)

REPOSITORY = Path(__file__).resolve().parents[2]
SCHEMA = REPOSITORY / "docs/contracts/candidate-root.v1.schema.json"
CATALOG = REPOSITORY / "docs/contracts/requirements-catalog.v1.json"
COMMIT = "a" * 40
VERSION = "0.1.0"
CANDIDATE = f"{VERSION}-{COMMIT[:12]}"
RUN_ID = "123456789"
RUN_ATTEMPT = 2
SOURCE_REF = "refs/heads/main"


class CandidateFixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.candidate = self.root / "candidate"
        self.trusted_linux_evidence = self.root / "trusted-linux-evidence"
        self.candidate.mkdir()
        self._write_files()

    @staticmethod
    def _write_json(path: Path, document: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _write_files(self) -> None:
        (
            self.candidate / f"DataX-Enterprise-Studio-Setup-{VERSION}-x64.exe"
        ).write_bytes(b"signed setup candidate\n")
        (self.candidate / "launcher.exe").write_bytes(b"signed launcher candidate\n")

        images = self.candidate / "images.release.env"
        images.write_text(
            "\n".join(
                (
                    f"DES_POSTGRES_IMAGE=postgres@sha256:{'1' * 64}",
                    "DES_API_IMAGE=ghcr.io/xiaoli2hust/datax-studio-api@sha256:"
                    + "2" * 64,
                    "DES_EGRESS_GUARD_IMAGE="
                    "ghcr.io/xiaoli2hust/datax-studio-egress-guard@sha256:" + "3" * 64,
                    "DES_WORKER_IMAGE=ghcr.io/xiaoli2hust/datax-studio-worker@sha256:"
                    + "4" * 64,
                    "DES_WEB_IMAGE=ghcr.io/xiaoli2hust/datax-studio-web@sha256:"
                    + "5" * 64,
                    "",
                )
            ),
            encoding="utf-8",
        )
        images_sha256 = hashlib.sha256(images.read_bytes()).hexdigest()
        resources = self.candidate / "resources"
        resources.mkdir()
        compose = resources / "compose.yaml"
        compose.write_text("services: {}\n", encoding="utf-8")
        embedded_images = resources / "images.release.env"
        shutil.copyfile(images, embedded_images)
        acl_helper = resources / "secure-acl.ps1"
        acl_helper.write_text('$ErrorActionPreference = "Stop"\n', encoding="utf-8")
        self._write_json(
            resources / "release-manifest.json",
            {
                "schema_version": "1.2",
                "product_version": VERSION,
                "release_candidate": CANDIDATE,
                "compose_sha256": hashlib.sha256(compose.read_bytes()).hexdigest(),
                "images_sha256": images_sha256,
                "acl_script_sha256": hashlib.sha256(
                    acl_helper.read_bytes()
                ).hexdigest(),
                "allowed_authenticode_signer_certificate_sha256": ["8" * 64],
            },
        )

        linux_evidence = self.candidate / "linux-evidence"
        context = linux_evidence / "release-context.json"
        self._write_json(
            context,
            {
                "schema_version": "1.0",
                "artifact_kind": "WINDOWS_LOCAL_CANDIDATE",
                "candidate_only": True,
                "public_release_created": False,
                "repository": "xiaoli2hust/datax",
                "git_commit": COMMIT,
                "git_ref_name": "main",
                "git_ref_type": "branch",
                "trigger": "workflow_dispatch",
                "version": VERSION,
                "release_candidate": CANDIDATE,
                "workflow_run_id": RUN_ID,
                "workflow_run_attempt": str(RUN_ATTEMPT),
            },
        )
        shutil.copyfile(images, linux_evidence / "images.release.env")
        catalog = linux_evidence / "requirements-catalog.v1.json"
        catalog.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(CATALOG, catalog)
        subprocess.run(
            [
                sys.executable,
                str(REPOSITORY / "scripts/acceptance/build_blocked_manifest.py"),
                "--catalog",
                str(catalog),
                "--environment-manifest",
                str(context),
                "--release-candidate",
                CANDIDATE,
                "--commit",
                COMMIT,
                "--output",
                str(linux_evidence / "acceptance-manifest.json"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        sbom_names = (
            "source.spdx.json",
            "postgres.image.spdx.json",
            "api.image.spdx.json",
            "egress_guard.image.spdx.json",
            "worker.image.spdx.json",
            "web.image.spdx.json",
        )
        for name in sbom_names:
            self._write_json(
                linux_evidence / "sbom" / name, {"spdxVersion": "SPDX-2.3"}
            )
        self._write_json(
            linux_evidence / "sbom-index.json",
            {
                "schema_version": "1.0",
                "generator": "syft",
                "entries": [{"file": f"sbom/{name}"} for name in sbom_names],
            },
        )
        shutil.copytree(linux_evidence, self.trusted_linux_evidence)
        self._write_json(
            self.candidate / "windows-build-environment.json",
            {
                "schema_version": "1.0",
                "candidate_only": True,
                "process_architecture": "X64",
                "windows_installation_e2e": "NOT_RUN",
            },
        )

    def arguments(self) -> dict[str, object]:
        return {
            "candidate_directory": self.candidate,
            "trusted_linux_evidence_directory": self.trusted_linux_evidence,
            "schema_path": SCHEMA,
            "workflow_run_id": RUN_ID,
            "workflow_run_attempt": RUN_ATTEMPT,
            "source_ref": SOURCE_REF,
            "commit_sha": COMMIT,
            "product_version": VERSION,
            "release_candidate": CANDIDATE,
        }

    def generate(self) -> dict[str, object]:
        return generate_candidate_root(
            **self.arguments(),
            scenario_blocked_reasons=[
                "Machine-readable scenario profiles and trusted Windows E4 evidence are absent."
            ],
        )

    @property
    def root_file(self) -> Path:
        return self.candidate / CANDIDATE_ROOT_NAME

    def rewrite_root(self, document: dict[str, object]) -> None:
        os.chmod(self.root_file, 0o644)
        self.root_file.write_bytes(canonical_json_bytes(document))


class CandidateRootTests(unittest.TestCase):
    def test_schema_is_valid_and_blocked_candidate_root_round_trips(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            generated = fixture.generate()
            validated = validate_candidate_root(**fixture.arguments())

            self.assertEqual(generated["code"], "BLOCKED_CANDIDATE_ROOT_CREATED")
            self.assertEqual(validated["code"], "BLOCKED_CANDIDATE_ROOT_VALID")
            self.assertFalse(generated["release_approved"])
            self.assertEqual(
                generated["candidate_root_sha256"],
                validated["candidate_root_sha256"],
            )
            document = json.loads(fixture.root_file.read_text(encoding="utf-8"))
            self.assertEqual(document["root_status"], "BLOCKED")
            self.assertIsNone(document["scenario_evidence"]["scenario_profile_catalog"])
            self.assertEqual(
                [item["path"] for item in document["files"]],
                sorted(item["path"] for item in document["files"]),
            )

    def test_duplicate_json_keys_and_identity_tampering_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            fixture.generate()
            original = fixture.root_file.read_text(encoding="utf-8")
            os.chmod(fixture.root_file, 0o644)
            fixture.root_file.write_text(
                original.replace(
                    "{",
                    '{"schema_version":"1.0",',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
                validate_candidate_root(**fixture.arguments())

        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            fixture.generate()
            document = json.loads(fixture.root_file.read_text(encoding="utf-8"))
            document["identity"]["commit_sha"] = "b" * 40
            fixture.rewrite_root(document)
            with self.assertRaisesRegex(ValueError, "trusted CI inputs"):
                validate_candidate_root(**fixture.arguments())

    def test_extra_missing_and_modified_candidate_files_fail_closed(self) -> None:
        cases = ("extra", "missing", "modified")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = CandidateFixture(Path(directory))
                fixture.generate()
                if case == "extra":
                    (fixture.candidate / "late-evidence.json").write_text(
                        "{}\n", encoding="utf-8"
                    )
                elif case == "missing":
                    (fixture.candidate / "launcher.exe").unlink()
                else:
                    (
                        fixture.candidate
                        / f"DataX-Enterprise-Studio-Setup-{VERSION}-x64.exe"
                    ).write_bytes(b"tampered setup\n")
                with self.assertRaisesRegex(
                    ValueError, "candidate file set or hash differs"
                ):
                    validate_candidate_root(**fixture.arguments())

    def test_path_escape_required_file_loss_and_symlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            fixture.generate()
            document = json.loads(fixture.root_file.read_text(encoding="utf-8"))
            document["artifacts"]["launcher"]["path"] = "../launcher.exe"
            fixture.rewrite_root(document)
            with self.assertRaisesRegex(ValueError, "schema violation"):
                validate_candidate_root(**fixture.arguments())

        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            (fixture.candidate / "launcher.exe").unlink()
            with self.assertRaisesRegex(ValueError, "missing a required file"):
                fixture.generate()

        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            (fixture.candidate / "unsafe-link").symlink_to(
                fixture.candidate / "launcher.exe"
            )
            with self.assertRaisesRegex(ValueError, "symlink or reparse"):
                fixture.generate()

    def test_authoritative_schema_and_blocked_semantics_cannot_be_bypassed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            fixture.generate()
            permissive_schema = fixture.root / "permissive.schema.json"
            permissive_schema.write_text(
                '{"$schema":"https://json-schema.org/draft/2020-12/schema"}\n',
                encoding="utf-8",
            )
            arguments = fixture.arguments()
            arguments["schema_path"] = permissive_schema
            with self.assertRaisesRegex(ValueError, "authoritative schema"):
                validate_candidate_root(**arguments)

        tampered_documents = (
            ("release", "BLOCKED foundation"),
            ("scenario", "explicitly BLOCKED/null"),
        )
        for case, error in tampered_documents:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = CandidateFixture(Path(directory))
                fixture.generate()
                document = json.loads(fixture.root_file.read_text(encoding="utf-8"))
                if case == "release":
                    document["root_status"] = "PASS"
                    document["release_approved"] = True
                else:
                    document["scenario_evidence"]["status"] = "COMPLETE"
                    document["scenario_evidence"]["scenario_profile_catalog"] = {
                        "path": "self-asserted.json",
                        "size_bytes": 1,
                        "sha256": "0" * 64,
                    }
                fixture.rewrite_root(document)
                with (
                    mock.patch("scripts.acceptance.candidate_root._validate_schema"),
                    self.assertRaisesRegex(ValueError, error),
                ):
                    validate_candidate_root(**fixture.arguments())

    def test_final_release_manifest_12_candidate_resources_and_signers_are_required(self) -> None:
        cases = ("old-schema", "candidate", "resource-hash", "signer-order")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = CandidateFixture(Path(directory))
                manifest_path = fixture.candidate / "resources/release-manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if case == "old-schema":
                    manifest["schema_version"] = "1.0"
                elif case == "resource-hash":
                    manifest["compose_sha256"] = "f" * 64
                elif case == "candidate":
                    manifest["release_candidate"] = f"{VERSION}-{'b' * 12}"
                else:
                    manifest["allowed_authenticode_signer_certificate_sha256"] = [
                        "9" * 64,
                        "8" * 64,
                    ]
                self._write_manifest(manifest_path, manifest)
                with self.assertRaisesRegex(ValueError, "release manifest 1.2"):
                    fixture.generate()

    def test_candidate_image_lock_must_come_from_linux_build_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            candidate_lock = fixture.candidate / "images.release.env"
            altered = candidate_lock.read_text(encoding="utf-8").replace(
                "2" * 64,
                "a" * 64,
                1,
            )
            candidate_lock.write_text(altered, encoding="utf-8")
            shutil.copyfile(
                candidate_lock,
                fixture.candidate / "resources/images.release.env",
            )
            manifest_path = fixture.candidate / "resources/release-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["images_sha256"] = hashlib.sha256(
                candidate_lock.read_bytes()
            ).hexdigest()
            self._write_manifest(manifest_path, manifest)

            with self.assertRaisesRegex(
                ValueError, "not bound to the Linux build evidence"
            ):
                fixture.generate()

    def test_candidate_linux_evidence_must_match_an_external_hosted_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            sbom_path = fixture.candidate / "linux-evidence/sbom/source.spdx.json"
            sbom_path.write_text('{"spdxVersion":"SPDX-2.3","tampered":true}\n', encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "differs from independently downloaded Linux build evidence",
            ):
                fixture.generate()

        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            arguments = fixture.arguments()
            arguments["trusted_linux_evidence_directory"] = (
                fixture.candidate / "linux-evidence"
            )
            with self.assertRaisesRegex(ValueError, "must remain outside"):
                generate_candidate_root(
                    **arguments,
                    scenario_blocked_reasons=["Windows E4 evidence is absent."],
                )

    def test_candidate_root_rejects_schema_invalid_acceptance_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CandidateFixture(Path(directory))
            manifest_path = (
                fixture.candidate / "linux-evidence/acceptance-manifest.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.pop("generated_at")
            self._write_manifest(manifest_path, manifest)
            self._write_manifest(
                fixture.trusted_linux_evidence / "acceptance-manifest.json",
                manifest,
            )
            with self.assertRaisesRegex(
                ValueError, "acceptance schema violation.*generated_at"
            ):
                fixture.generate()

    @staticmethod
    def _write_manifest(path: Path, document: dict[str, object]) -> None:
        path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


class CandidateAttestationTests(unittest.TestCase):
    def _fixture_with_tools(self, root: Path) -> tuple[CandidateFixture, Path, Path]:
        root = root.resolve()
        fixture = CandidateFixture(root)
        fixture.generate()
        gh = root / "trusted-gh"
        gh.write_bytes(b"trusted gh executable\n")
        gh.chmod(0o755)
        bundle = root / "candidate-root.attestation.jsonl"
        bundle.write_text('{"bundle":"test"}\n', encoding="utf-8")
        return fixture, gh, bundle

    @staticmethod
    def _verified_output(fixture: CandidateFixture, *, run_id: str = RUN_ID) -> str:
        root_sha256 = hashlib.sha256(fixture.root_file.read_bytes()).hexdigest()
        workflow_uri = (
            "https://github.com/xiaoli2hust/datax/"
            f".github/workflows/release.yml@{SOURCE_REF}"
        )
        return json.dumps(
            [
                {
                    "attestation": {"bundle": "verified"},
                    "verificationResult": {
                        "signature": {
                            "certificate": {
                                "subjectAlternativeName": workflow_uri,
                                "issuer": EXPECTED_OIDC_ISSUER,
                                "buildSignerURI": workflow_uri,
                                "buildSignerDigest": COMMIT,
                                "runnerEnvironment": "github-hosted",
                                "sourceRepositoryURI": (
                                    "https://github.com/xiaoli2hust/datax"
                                ),
                                "sourceRepositoryDigest": COMMIT,
                                "sourceRepositoryRef": SOURCE_REF,
                                "runInvocationURI": (
                                    "https://github.com/xiaoli2hust/datax/actions/runs/"
                                    f"{run_id}/attempts/{RUN_ATTEMPT}"
                                ),
                            }
                        },
                        "verifiedTimestamps": [{"type": "TransparencyLog"}],
                        "statement": {
                            "predicateType": EXPECTED_PREDICATE_TYPE,
                            "subject": [
                                {
                                    "name": CANDIDATE_ROOT_NAME,
                                    "digest": {"sha256": root_sha256},
                                }
                            ],
                        },
                    },
                }
            ],
            separators=(",", ":"),
        )

    def test_wrapper_uses_exact_parameter_array_and_never_approves_release(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture, gh, bundle = self._fixture_with_tools(root)
            calls: list[tuple[list[str], dict[str, object]]] = []

            def runner(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                calls.append((command, kwargs))
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=self._verified_output(fixture),
                    stderr="",
                )

            with self.assertRaisesRegex(
                ValueError, "TRUSTED_ATTESTATION_VERIFIER_TCB_NOT_IMPLEMENTED"
            ):
                verify_candidate_attestation(
                    candidate_root_path=fixture.root_file,
                    bundle_path=bundle,
                    trusted_gh_executable=gh,
                    **{
                        key: value
                        for key, value in fixture.arguments().items()
                        if key != "candidate_directory"
                    },
                    runner=runner,
                )

            expected = [
                str(gh),
                "attestation",
                "verify",
                str(fixture.root_file),
                "--bundle",
                str(bundle),
                "--repo",
                "xiaoli2hust/datax",
                "--signer-workflow",
                EXPECTED_SIGNER_WORKFLOW,
                "--signer-digest",
                COMMIT,
                "--source-ref",
                SOURCE_REF,
                "--source-digest",
                COMMIT,
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
            self.assertEqual(calls[0][0], expected)
            self.assertEqual(
                calls[0][1],
                {
                    "check": False,
                    "capture_output": True,
                    "text": True,
                    "timeout": 120,
                },
            )

    def test_wrapper_fails_closed_on_cli_failure_or_empty_output(self) -> None:
        cases = (
            (
                "failure",
                subprocess.CompletedProcess([], 1, stdout="", stderr="bad signature"),
                "failed closed",
            ),
            (
                "empty",
                subprocess.CompletedProcess([], 0, stdout="[]", stderr=""),
                "no verified attestations",
            ),
        )
        for name, completed, error in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fixture, gh, bundle = self._fixture_with_tools(root)

                def runner(
                    _command: list[str],
                    _completed: subprocess.CompletedProcess[str] = completed,
                    **_kwargs: object,
                ) -> subprocess.CompletedProcess[str]:
                    return _completed

                with self.assertRaisesRegex(ValueError, error):
                    verify_candidate_attestation(
                        candidate_root_path=fixture.root_file,
                        bundle_path=bundle,
                        trusted_gh_executable=gh,
                        **{
                            key: value
                            for key, value in fixture.arguments().items()
                            if key != "candidate_directory"
                        },
                        runner=runner,
                    )

    def test_wrapper_rejects_an_attestation_from_another_workflow_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture, gh, bundle = self._fixture_with_tools(root)

            def runner(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=self._verified_output(fixture, run_id="999999999"),
                    stderr="",
                )

            with self.assertRaisesRegex(ValueError, "fixed repository/workflow/run"):
                verify_candidate_attestation(
                    candidate_root_path=fixture.root_file,
                    bundle_path=bundle,
                    trusted_gh_executable=gh,
                    **{
                        key: value
                        for key, value in fixture.arguments().items()
                        if key != "candidate_directory"
                    },
                    runner=runner,
                )

    def test_wrapper_rechecks_independent_linux_evidence_after_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture, gh, bundle = self._fixture_with_tools(root)

            def runner(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                source_sbom = (
                    fixture.trusted_linux_evidence / "sbom/source.spdx.json"
                )
                source_sbom.write_text(
                    '{"spdxVersion":"SPDX-2.3","changed":true}\n',
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=self._verified_output(fixture),
                    stderr="",
                )

            with self.assertRaisesRegex(
                ValueError,
                "differs from independently downloaded Linux build evidence",
            ):
                verify_candidate_attestation(
                    candidate_root_path=fixture.root_file,
                    bundle_path=bundle,
                    trusted_gh_executable=gh,
                    **{
                        key: value
                        for key, value in fixture.arguments().items()
                        if key != "candidate_directory"
                    },
                    runner=runner,
                )

    def test_bundle_inside_candidate_or_symlinked_gh_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture, gh, _bundle = self._fixture_with_tools(root)
            inside = fixture.candidate / "bundle.jsonl"
            inside.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "outside the candidate directory"):
                verify_candidate_attestation(
                    candidate_root_path=fixture.root_file,
                    bundle_path=inside,
                    trusted_gh_executable=gh,
                    **{
                        key: value
                        for key, value in fixture.arguments().items()
                        if key != "candidate_directory"
                    },
                )

    def test_cli_reports_the_stable_verifier_tcb_blocker(self) -> None:
        arguments = SimpleNamespace(
            candidate_root=Path("/unused/candidate-root.v1.json"),
            bundle=Path("/unused/bundle.jsonl"),
            trusted_gh_path=Path("/unused/gh"),
            trusted_linux_evidence_directory=Path("/unused/linux-evidence"),
            schema=SCHEMA,
            workflow_run_id=RUN_ID,
            workflow_run_attempt=RUN_ATTEMPT,
            source_ref=SOURCE_REF,
            commit=COMMIT,
            product_version=VERSION,
            release_candidate=CANDIDATE,
        )
        error = TrustedAttestationVerifierTCBNotImplemented(
            "TRUSTED_ATTESTATION_VERIFIER_TCB_NOT_IMPLEMENTED"
        )
        stderr = io.StringIO()
        with (
            mock.patch(
                "scripts.acceptance.verify_candidate_attestation._arguments",
                return_value=arguments,
            ),
            mock.patch(
                "scripts.acceptance.verify_candidate_attestation.verify_candidate_attestation",
                side_effect=error,
            ),
            redirect_stderr(stderr),
        ):
            self.assertEqual(attestation_main(), 1)
        result = json.loads(stderr.getvalue())
        self.assertEqual(
            result["code"], "TRUSTED_ATTESTATION_VERIFIER_TCB_NOT_IMPLEMENTED"
        )
        self.assertFalse(result["ready"])
        self.assertFalse(result["release_approved"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture, gh, bundle = self._fixture_with_tools(root)
            gh_link = root / "gh-link"
            gh_link.symlink_to(gh)
            with self.assertRaisesRegex(ValueError, "symlink or reparse"):
                verify_candidate_attestation(
                    candidate_root_path=fixture.root_file,
                    bundle_path=bundle,
                    trusted_gh_executable=gh_link,
                    **{
                        key: value
                        for key, value in fixture.arguments().items()
                        if key != "candidate_directory"
                    },
                )


if __name__ == "__main__":
    unittest.main()
