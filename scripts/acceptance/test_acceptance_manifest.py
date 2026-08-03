from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import rfc8785

from scripts.acceptance.catalog import (
    build_catalog_bytes,
    load_catalog,
    parse_requirements_matrix,
)
from scripts.acceptance.validate_acceptance_manifest import validate

REPOSITORY = Path(__file__).resolve().parents[2]
MATRIX = REPOSITORY / "docs/12_需求追踪矩阵.md"
CATALOG = REPOSITORY / "docs/contracts/requirements-catalog.v1.json"
SCHEMA = REPOSITORY / "docs/contracts/acceptance-manifest.v1.schema.json"
SCENARIO_PROFILE = (
    REPOSITORY / "docs/contracts/windows-e4-scenario-profile.v1.json"
)


class AcceptanceManifestTests(unittest.TestCase):
    def test_checked_in_catalog_is_canonical_and_matches_all_requirements(self) -> None:
        document, entries, raw = load_catalog(CATALOG)

        self.assertEqual(raw, build_catalog_bytes(MATRIX))
        self.assertEqual(document["schema_version"], "1.1")
        self.assertEqual(document["requirement_count"], 81)
        self.assertEqual(document["v1_must_count"], 80)
        self.assertEqual(document["post_v1_count"], 1)
        self.assertEqual(document["entry_count"], 107)
        self.assertEqual(len(entries), 107)
        self.assertTrue(
            {"PERF-001", "PERF-002", "SEC-001", "SEC-002", "SEC-003"}.isdisjoint(
                entry.test_id for entry in entries
            )
        )
        self.assertIn(
            ("NFR-PERF-001", "PERF-NFR-001"),
            {(entry.requirement_id, entry.test_id) for entry in entries},
        )
        new_e3_pairs = {
            ("PRD-BR-005", "E2E-F-023"),
            ("PRD-BR-018", "E2E-F-027"),
            ("NFR-SEC-001", "E2E-F-027"),
        }
        self.assertTrue(
            new_e3_pairs.issubset({(entry.requirement_id, entry.test_id) for entry in entries})
        )
        self.assertEqual(
            {
                entry.minimum_evidence_level
                for entry in entries
                if (entry.requirement_id, entry.test_id) in new_e3_pairs
            },
            {"E3"},
        )
        external_operation_pairs = {
            ("PRD-FR-DS-002", "SEC-DS-EXTERNAL-BOUNDARY-001"),
            ("PRD-FR-DS-003", "SEC-DS-EXTERNAL-BOUNDARY-001"),
            ("PRD-FR-JOB-005", "SEC-DS-EXTERNAL-BOUNDARY-001"),
            ("NFR-SEC-003", "SEC-DS-EXTERNAL-BOUNDARY-001"),
        }
        pairs = {(entry.requirement_id, entry.test_id) for entry in entries}
        self.assertTrue(external_operation_pairs.issubset(pairs))
        self.assertEqual(
            {
                entry.minimum_evidence_level
                for entry in entries
                if (entry.requirement_id, entry.test_id)
                in external_operation_pairs
            },
            {"E2", "E3"},
        )
        self.assertEqual(
            {
                entry.test_id
                for entry in entries
                if entry.requirement_id == "PRD-FR-WS-001"
            },
            {
                "E2E-WIN-001",
                "REC-WIN-INIT-001",
                "REC-WIN-WORKER-DB-001",
                "OPS-WIN-DISK-001",
                "SEC-WIN-STORAGE-PROBE-001",
                "OPS-WIN-WSL-001",
                "SEC-WIN-DOCKER-CLI-001",
                "SEC-WIN-COMPOSE-OWNERSHIP-001",
                "SEC-EGRESS-LEASE-001",
                "SEC-WIN-IMAGE-PULL-001",
                "SEC-WIN-SETUP-BYPASS-001",
                "SEC-WIN-SETUP-REPARSE-001",
                "SEC-WIN-TMPFS-001",
            },
        )
        self.assertEqual(
            {
                entry.test_id
                for entry in entries
                if entry.requirement_id == "ACC-PRD-014"
            },
            {"E2E-WIN-002", "SEC-WIN-IMAGE-PULL-001"},
        )

    def test_matrix_parser_rejects_shifted_columns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            matrix = self._mutated_matrix(
                root,
                "| `PRD-FR-AUTH-001` | V1-MUST | AuthSession；",
                "| `PRD-FR-AUTH-001` | V1-MUST AuthSession；",
            )
            with self.assertRaisesRegex(
                ValueError, "matrix requirement counts do not match"
            ):
                parse_requirements_matrix(matrix)

    def test_matrix_parser_never_extracts_test_id_from_another_column(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            matrix = self._mutated_matrix(
                root,
                "| V1-MUST | API 索引/连接池 | `PERF-NFR-001` |",
                "| V1-MUST | API 索引/连接池/`PERF-GHOST-999` | NOT-A-TEST |",
            )
            with self.assertRaisesRegex(ValueError, "invalid test ID cell"):
                parse_requirements_matrix(matrix)

    def test_matrix_parser_rejects_duplicate_test_and_requirement_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate_test = self._mutated_matrix(
                root,
                "`E2E-WIN-001`、`SEC-WIN-IMAGE-PULL-001`",
                ("`E2E-WIN-001`、`E2E-WIN-001`、`SEC-WIN-IMAGE-PULL-001`"),
                filename="duplicate-test.md",
            )
            with self.assertRaisesRegex(ValueError, "duplicate test ID in cell"):
                parse_requirements_matrix(duplicate_test)

            original = MATRIX.read_text(encoding="utf-8")
            row = next(
                line
                for line in original.splitlines()
                if line.startswith("| `PRD-FR-AUTH-001`")
            )
            duplicate_pair = root / "duplicate-pair.md"
            duplicate_pair.write_text(
                original.replace(row, f"{row}\n{row}", 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "invalid or duplicate matrix row"):
                parse_requirements_matrix(duplicate_pair)

    def test_blocked_candidate_is_complete_but_never_release_approved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "environment.json"
            environment.write_text('{"schema_version":"1.0"}\n', encoding="utf-8")
            manifest = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest)

            result = validate(
                catalog_path=CATALOG,
                matrix_path=MATRIX,
                manifest_path=manifest,
                schema_path=SCHEMA,
                environment_manifest_path=environment,
                evidence_root=root,
                require_pass=False,
            )
            self.assertEqual(result["gate_result"], "BLOCKED")
            self.assertFalse(result["release_approved"])
            with self.assertRaisesRegex(
                ValueError, "TRUSTED_RELEASE_ATTESTATION_NOT_IMPLEMENTED"
            ):
                validate(
                    catalog_path=CATALOG,
                    matrix_path=MATRIX,
                    manifest_path=manifest,
                    schema_path=SCHEMA,
                    environment_manifest_path=environment,
                    evidence_root=root,
                    require_pass=True,
                    expected_commit="a" * 40,
                    expected_release_candidate="0.1.0-test",
                )

    def test_require_pass_rejects_missing_or_mismatched_external_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "environment.json"
            environment.write_text('{"schema_version":"1.0"}\n', encoding="utf-8")
            manifest = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest)

            with self.assertRaisesRegex(
                ValueError, "requires externally supplied candidate identity"
            ):
                validate(
                    catalog_path=CATALOG,
                    matrix_path=MATRIX,
                    manifest_path=manifest,
                    schema_path=SCHEMA,
                    environment_manifest_path=environment,
                    evidence_root=root,
                    require_pass=True,
                )
            with self.assertRaisesRegex(
                ValueError, "commit_sha does not match the external candidate"
            ):
                validate(
                    catalog_path=CATALOG,
                    matrix_path=MATRIX,
                    manifest_path=manifest,
                    schema_path=SCHEMA,
                    environment_manifest_path=environment,
                    evidence_root=root,
                    require_pass=True,
                    expected_commit="b" * 40,
                    expected_release_candidate="0.1.0-test",
                )

    def test_old_catalog_hash_and_manifest_schema_are_invalidated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "environment.json"
            environment.write_text('{"schema_version":"1.0"}\n', encoding="utf-8")
            manifest_path = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

            old_catalog_sha256 = (
                "6edfe0840e956cb2dd30fc2f2fab450b361741ec6a3264b8ff85a801288eb5b1"
            )
            self.assertNotEqual(
                old_catalog_sha256,
                hashlib.sha256(CATALOG.read_bytes()).hexdigest(),
            )
            manifest["requirements_catalog_sha256"] = old_catalog_sha256
            self._write_manifest(manifest_path, manifest)
            with self.assertRaisesRegex(
                ValueError, "requirements catalog SHA-256 does not match"
            ):
                self._validate(manifest_path, environment, root)

            manifest["requirements_catalog_sha256"] = hashlib.sha256(
                CATALOG.read_bytes()
            ).hexdigest()
            manifest["schema_version"] = "1.0"
            self._write_manifest(manifest_path, manifest)
            with self.assertRaisesRegex(ValueError, "acceptance schema violation"):
                self._validate(manifest_path, environment, root)

    def test_evidence_hash_is_recomputed_and_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "environment.json"
            environment.write_text('{"schema_version":"1.0"}\n', encoding="utf-8")
            manifest_path = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = next(
                item
                for item in manifest["entries"]
                if item["minimum_evidence_level"] == "E1"
            )
            evidence = root / "reports/unit.txt"
            evidence.parent.mkdir()
            evidence.write_bytes(b"verified unit evidence\n")
            entry.update(
                {
                    "result": "PASS",
                    "evidence_level": "E1",
                    "evidence": [
                        {
                            "path": "reports/unit.txt",
                            "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                        }
                    ],
                    "executed_at": "2026-07-30T12:00:00Z",
                    "environment_id": "unit-linux",
                }
            )
            manifest_path.write_text(
                json.dumps(
                    manifest,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )

            validate(
                catalog_path=CATALOG,
                matrix_path=MATRIX,
                manifest_path=manifest_path,
                schema_path=SCHEMA,
                environment_manifest_path=environment,
                evidence_root=root,
                require_pass=False,
            )
            evidence.write_bytes(b"tampered\n")
            with self.assertRaisesRegex(ValueError, "evidence SHA-256 mismatch"):
                validate(
                    catalog_path=CATALOG,
                    matrix_path=MATRIX,
                    manifest_path=manifest_path,
                    schema_path=SCHEMA,
                    environment_manifest_path=environment,
                    evidence_root=root,
                    require_pass=False,
                )

    def test_pass_evidence_level_cannot_be_raised_above_catalog_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = self._write_environment(root)
            manifest_path = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = self._entry(manifest, "ACC-PRD-001", "E2E-ACC-PRD-001")
            report = root / "reports/rbac.json"
            report.parent.mkdir()
            report.write_text('{"result":"PASS"}\n', encoding="utf-8")
            self._promote_entry(entry, self._artifact(root, report), "E4")
            self._write_manifest(manifest_path, manifest)

            with self.assertRaisesRegex(ValueError, "acceptance schema violation"):
                self._validate(manifest_path, environment, root)

    def test_environment_capture_cannot_postdate_test_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = self._write_environment(
                root,
                captured_at="2026-07-30T12:30:00Z",
            )
            manifest_path = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = self._entry(manifest, "ACC-PRD-001", "E2E-ACC-PRD-001")
            report = root / "reports/rbac.json"
            report.parent.mkdir()
            report.write_text('{"result":"PASS"}\n', encoding="utf-8")
            self._promote_entry(entry, self._artifact(root, report), "E3")
            self._write_manifest(manifest_path, manifest)

            with self.assertRaisesRegex(
                ValueError, "environment was captured after the test executed_at"
            ):
                self._validate(manifest_path, environment, root)

    def test_plain_text_cannot_impersonate_a_passed_e3_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = self._write_environment(root)
            manifest_path = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = self._entry(manifest, "PRD-FR-RUN-001", "E2E-RUN-001")
            fake_oracle = root / "reports/fake-oracle.txt"
            fake_oracle.parent.mkdir()
            fake_oracle.write_text("PASSED\n", encoding="utf-8")
            binding = self._oracle_binding(manifest, entry)
            artifact = self._artifact(root, fake_oracle)
            self._promote_entry(entry, artifact, "E3")
            entry["oracle"] = {
                "schema_version": "1.0",
                "result": "PASSED",
                "binding": binding,
                "artifact": artifact,
            }
            self._write_manifest(manifest_path, manifest)

            with self.assertRaisesRegex(
                ValueError, "verification oracle artifact is not valid UTF-8 JSON"
            ):
                self._validate(manifest_path, environment, root)

    def test_oracle_schema_semantics_and_identity_are_bound_to_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = self._write_environment(root)
            manifest_path = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = self._entry(manifest, "PRD-FR-RUN-001", "E2E-RUN-001")
            oracle_path = root / "reports/oracle.json"
            oracle_path.parent.mkdir()
            oracle = self._oracle_document()
            self._write_manifest(oracle_path, oracle)
            artifact = self._artifact(root, oracle_path)
            self._promote_entry(entry, artifact, "E3")
            entry["oracle"] = {
                "schema_version": "1.0",
                "result": "PASSED",
                "binding": self._oracle_binding(manifest, entry),
                "artifact": artifact,
            }
            self._write_manifest(manifest_path, manifest)

            self._validate(manifest_path, environment, root)
            entry["oracle"]["binding"]["requirement_id"] = "PRD-BR-014"
            self._write_manifest(manifest_path, manifest)
            with self.assertRaisesRegex(
                ValueError, "oracle binding does not match entry field"
            ):
                self._validate(manifest_path, environment, root)

            entry["oracle"]["binding"]["requirement_id"] = "PRD-FR-RUN-001"
            oracle["target_result"]["distinct_row_digest_count"] = 2
            oracle.pop("artifact_sha256")
            oracle["artifact_sha256"] = hashlib.sha256(
                rfc8785.dumps(oracle)
            ).hexdigest()
            self._write_manifest(oracle_path, oracle)
            artifact = self._artifact(root, oracle_path)
            entry["oracle"]["artifact"] = artifact
            entry["evidence"] = [artifact]
            self._write_manifest(manifest_path, manifest)
            with self.assertRaisesRegex(
                ValueError, "target distinct_row_digest_count exceeds row_count"
            ):
                self._validate(manifest_path, environment, root)

            oracle["target_result"]["distinct_row_digest_count"] = 1
            oracle["source_result"]["read_started_at"] = "2026-07-30T12:01:00Z"
            oracle["source_result"]["read_finished_at"] = "2026-07-30T12:02:00Z"
            self._rehash_oracle(oracle)
            self._write_manifest(oracle_path, oracle)
            artifact = self._artifact(root, oracle_path)
            entry["oracle"]["artifact"] = artifact
            entry["evidence"] = [artifact]
            self._write_manifest(manifest_path, manifest)
            with self.assertRaisesRegex(
                ValueError, "source oracle read is outside the global oracle window"
            ):
                self._validate(manifest_path, environment, root)

            oracle["source_result"]["read_started_at"] = "2026-07-30T11:35:00Z"
            oracle["source_result"]["read_finished_at"] = "2026-07-30T11:36:00Z"
            self._rehash_oracle(oracle)
            self._write_manifest(oracle_path, oracle)
            artifact = self._artifact(root, oracle_path)
            entry["oracle"]["artifact"] = artifact
            entry["evidence"] = [artifact]
            entry["executed_at"] = "2026-07-30T11:43:00Z"
            self._write_manifest(manifest_path, manifest)
            with self.assertRaisesRegex(
                ValueError, "executed_at is earlier than oracle finished_at"
            ):
                self._validate(manifest_path, environment, root)

    def test_oracle_artifact_and_execution_cannot_be_replayed_across_entries(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = self._write_environment(root)
            manifest_path = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            oracle_path = root / "reports/oracle.json"
            oracle_path.parent.mkdir()
            self._write_manifest(oracle_path, self._oracle_document())
            artifact = self._artifact(root, oracle_path)

            for requirement_id, test_id in (
                ("PRD-FR-RUN-001", "E2E-RUN-001"),
                ("PRD-BR-008", "E2E-BR-008"),
            ):
                entry = self._entry(manifest, requirement_id, test_id)
                self._promote_entry(entry, artifact, "E3")
                entry["oracle"] = {
                    "schema_version": "1.0",
                    "result": "PASSED",
                    "binding": self._oracle_binding(manifest, entry),
                    "artifact": artifact,
                }
            self._write_manifest(manifest_path, manifest)

            with self.assertRaisesRegex(
                ValueError, "oracle artifact is replayed across entries"
            ):
                self._validate(manifest_path, environment, root)

            second = self._entry(manifest, "PRD-BR-008", "E2E-BR-008")
            oracle_copy = root / "reports/oracle-copy.json"
            oracle_copy.write_bytes(oracle_path.read_bytes())
            second_artifact = self._artifact(root, oracle_copy)
            second["oracle"]["artifact"] = second_artifact
            second["evidence"] = [second_artifact]
            self._write_manifest(manifest_path, manifest)
            with self.assertRaisesRegex(
                ValueError, "oracle execution_id is replayed across entries"
            ):
                self._validate(manifest_path, environment, root)

    def test_plain_text_cannot_impersonate_passed_windows_e4_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = self._write_environment(root)
            manifest_path = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = self._entry(manifest, "PRD-FR-WS-001", "E2E-WIN-001")
            listener_report = root / "reports/listeners.json"
            listener_report.parent.mkdir()
            listener_report.write_text('{"loopback_only":true}\n', encoding="utf-8")
            listener_artifact = self._artifact(root, listener_report)
            assertions = self._profile_assertions(
                profile_id="E2E-WIN-001",
                evidence=listener_artifact,
            )
            manifest["windows_scenario_catalogs"], _scenario = self._scenario_catalogs(
                root=root,
                manifest=manifest,
                profile_id="E2E-WIN-001",
                assertions=assertions,
            )
            fake_windows = root / "reports/fake-windows.txt"
            fake_windows.parent.mkdir(exist_ok=True)
            fake_windows.write_text("PASSED\n", encoding="utf-8")
            artifact = self._artifact(root, fake_windows)
            self._promote_entry(entry, artifact, "E4")
            entry["windows_evidence"] = {
                "schema_version": "1.0",
                "result": "PASSED",
                "binding": self._windows_binding(manifest, entry),
                "artifact": artifact,
            }
            self._write_manifest(manifest_path, manifest)

            with self.assertRaisesRegex(
                ValueError, "Windows E4 evidence artifact is not valid UTF-8 JSON"
            ):
                self._validate(manifest_path, environment, root)

    def test_structured_windows_e4_is_bound_but_cannot_approve_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = self._write_environment(root)
            manifest_path = root / "acceptance-manifest.json"
            self._build_blocked_manifest(environment, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = self._entry(manifest, "PRD-FR-WS-001", "E2E-WIN-001")
            listener_report = root / "reports/listeners.json"
            listener_report.parent.mkdir()
            listener_report.write_text('{"loopback_only":true}\n', encoding="utf-8")
            listener_artifact = self._artifact(root, listener_report)
            assertions = self._profile_assertions(
                profile_id="E2E-WIN-001",
                evidence=listener_artifact,
            )
            manifest["windows_scenario_catalogs"], scenario = self._scenario_catalogs(
                root=root,
                manifest=manifest,
                profile_id="E2E-WIN-001",
                assertions=assertions,
            )
            release_directory = root / "release"
            release_directory.mkdir()
            setup = release_directory / "Setup.exe"
            launcher = release_directory / "launcher.exe"
            setup.write_bytes(b"signed setup candidate\n")
            launcher.write_bytes(b"signed launcher candidate\n")
            binding = self._windows_binding(manifest, entry)
            windows_document = {
                "schema_version": "1.0",
                "artifact_kind": "WINDOWS_E4_TEST_RESULT",
                "result": "PASSED",
                "binding": binding,
                "executed_at": "2026-07-30T12:00:00Z",
                "windows": {
                    "edition": "Windows 11",
                    "build": "26100.4652",
                    "architecture": "X86_64",
                    "clean_vm": True,
                    "wsl_version": "2.5.10",
                    "docker_desktop_version": "4.43.2",
                    "docker_engine_version": "28.3.2",
                    "docker_compose_version": "2.38.2",
                    "exposed_host_ports": [
                        {
                            "address": "127.0.0.1",
                            "port": 17860,
                            "service": "web",
                        }
                    ],
                    "lan_reachable": False,
                },
                "release_artifacts": {
                    "setup": self._artifact(root, setup),
                    "launcher": self._artifact(root, launcher),
                    "setup_signature_status": "VALID",
                    "launcher_signature_status": "VALID",
                    "timestamp_status": "VALID",
                },
                "scenario": scenario,
                "assertions": assertions,
            }
            windows_path = root / "reports/windows-e4.json"
            self._write_manifest(windows_path, windows_document)
            artifact = self._artifact(root, windows_path)
            self._promote_entry(entry, artifact, "E4")
            entry["windows_evidence"] = {
                "schema_version": "1.0",
                "result": "PASSED",
                "binding": binding,
                "artifact": artifact,
            }
            self._write_manifest(manifest_path, manifest)

            self._validate(manifest_path, environment, root)
            with self.assertRaisesRegex(
                ValueError, "TRUSTED_RELEASE_ATTESTATION_NOT_IMPLEMENTED"
            ):
                validate(
                    catalog_path=CATALOG,
                    matrix_path=MATRIX,
                    manifest_path=manifest_path,
                    schema_path=SCHEMA,
                    environment_manifest_path=environment,
                    evidence_root=root,
                    require_pass=True,
                    expected_commit="a" * 40,
                    expected_release_candidate="0.1.0-test",
                )
            setup.write_bytes(b"tampered setup\n")
            with self.assertRaisesRegex(ValueError, "evidence SHA-256 mismatch"):
                self._validate(manifest_path, environment, root)
            setup.write_bytes(b"signed setup candidate\n")

            windows_document["assertions"][0]["assertion_id"] = "REC-WIN-INIT-001"
            self._write_manifest(windows_path, windows_document)
            entry["windows_evidence"]["artifact"] = self._artifact(root, windows_path)
            entry["evidence"] = [entry["windows_evidence"]["artifact"]]
            self._write_manifest(manifest_path, manifest)
            with self.assertRaisesRegex(
                ValueError, "assertions do not cover the bound test_id"
            ):
                self._validate(manifest_path, environment, root)

            windows_document["assertions"][0]["assertion_id"] = "E2E-WIN-001"
            windows_document["binding"] = {
                **windows_document["binding"],
                "environment_id": "different-environment",
            }
            self._write_manifest(windows_path, windows_document)
            entry["windows_evidence"]["artifact"] = self._artifact(root, windows_path)
            entry["evidence"] = [entry["windows_evidence"]["artifact"]]
            self._write_manifest(manifest_path, manifest)
            with self.assertRaisesRegex(
                ValueError, "Windows evidence artifact binding does not match"
            ):
                self._validate(manifest_path, environment, root)

    @staticmethod
    def _entry(
        manifest: dict[str, object], requirement_id: str, test_id: str
    ) -> dict[str, object]:
        return next(
            item
            for item in manifest["entries"]
            if item["requirement_id"] == requirement_id and item["test_id"] == test_id
        )

    @staticmethod
    def _mutated_matrix(
        root: Path,
        old: str,
        new: str,
        *,
        filename: str = "matrix.md",
    ) -> Path:
        original = MATRIX.read_text(encoding="utf-8")
        if original.count(old) != 1:
            raise AssertionError("matrix mutation target must be unique")
        output = root / filename
        output.write_text(original.replace(old, new, 1), encoding="utf-8")
        return output

    @staticmethod
    def _promote_entry(
        entry: dict[str, object], artifact: dict[str, str], evidence_level: str
    ) -> None:
        entry.update(
            {
                "result": "PASS",
                "evidence_level": evidence_level,
                "evidence": [artifact],
                "executed_at": "2026-07-30T12:00:00Z",
                "environment_id": "win11-clean-001",
            }
        )

    @staticmethod
    def _artifact(root: Path, path: Path) -> dict[str, str]:
        return {
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    @staticmethod
    def _write_manifest(path: Path, document: dict[str, object]) -> None:
        path.write_text(
            json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )

    def _write_environment(
        self, root: Path, *, captured_at: str = "2026-07-30T11:00:00Z"
    ) -> Path:
        environment = root / "environment.json"
        self._write_manifest(
            environment,
            {
                "schema_version": "1.0",
                "artifact_kind": "ACCEPTANCE_ENVIRONMENT",
                "environment_id": "win11-clean-001",
                "release_candidate": "0.1.0-test",
                "commit_sha": "a" * 40,
                "captured_at": captured_at,
                "system": {
                    "os_family": "WINDOWS",
                    "os_name": "Windows 11 Enterprise",
                    "os_version": "26100.4652",
                    "architecture": "X86_64",
                },
            },
        )
        return environment

    @staticmethod
    def _oracle_binding(
        manifest: dict[str, object], entry: dict[str, object]
    ) -> dict[str, object]:
        return {
            "release_candidate": manifest["release_candidate"],
            "commit_sha": manifest["commit_sha"],
            "requirement_id": entry["requirement_id"],
            "test_id": entry["test_id"],
            "environment_id": "win11-clean-001",
            "environment_manifest_sha256": manifest["environment_manifest_sha256"],
            "execution_id": "11111111-1111-4111-8111-111111111111",
            "job_version_id": "22222222-2222-4222-8222-222222222222",
        }

    @staticmethod
    def _windows_binding(
        manifest: dict[str, object], entry: dict[str, object]
    ) -> dict[str, object]:
        return {
            "release_candidate": manifest["release_candidate"],
            "commit_sha": manifest["commit_sha"],
            "requirement_id": entry["requirement_id"],
            "test_id": entry["test_id"],
            "environment_id": "win11-clean-001",
            "environment_manifest_sha256": manifest["environment_manifest_sha256"],
            "execution_ids": [],
        }

    @staticmethod
    def _profile_assertions(
        *, profile_id: str, evidence: dict[str, str]
    ) -> list[dict[str, object]]:
        profile = json.loads(SCENARIO_PROFILE.read_text(encoding="utf-8"))
        selected = next(
            item for item in profile["profiles"] if item["profile_id"] == profile_id
        )
        return [
            {
                "assertion_id": assertion_id,
                "result": "PASS",
                "evidence": [evidence],
            }
            for assertion_id in selected["required_assertion_ids"]
        ]

    @classmethod
    def _scenario_catalogs(
        cls,
        *,
        root: Path,
        manifest: dict[str, object],
        profile_id: str,
        assertions: list[dict[str, object]],
    ) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
        profile_path = root / "reports/windows-e4-scenario-profile.v1.json"
        profile_path.parent.mkdir(exist_ok=True)
        profile_path.write_bytes(SCENARIO_PROFILE.read_bytes())
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        selected = next(
            item for item in profile["profiles"] if item["profile_id"] == profile_id
        )
        profile_artifact = cls._artifact(root, profile_path)
        profile_sha256 = profile_artifact["sha256"]
        assertions_sha256 = hashlib.sha256(rfc8785.dumps(assertions)).hexdigest()
        results = []
        for item in profile["profiles"]:
            if item["profile_id"] == profile_id:
                results.append(
                    {
                        "profile_id": profile_id,
                        "result": "PASSED",
                        "executed_at": "2026-07-30T12:00:00Z",
                        "environment_id": "win11-clean-001",
                        "environment_manifest_sha256": manifest[
                            "environment_manifest_sha256"
                        ],
                        "windows_baseline_id": "windows11-clean-golden-v1",
                        "harness_version": "windows-e4-harness/v1",
                        "assertion_ids": selected["required_assertion_ids"],
                        "assertions_sha256": assertions_sha256,
                    }
                )
            else:
                results.append(
                    {
                        "profile_id": item["profile_id"],
                        "result": "NOT_RUN",
                        "executed_at": None,
                        "environment_id": None,
                        "environment_manifest_sha256": None,
                        "windows_baseline_id": None,
                        "harness_version": None,
                        "assertion_ids": [],
                        "assertions_sha256": None,
                    }
                )
        result_path = root / "reports/windows-e4-scenario-results.v1.json"
        cls._write_manifest(
            result_path,
            {
                "schema_version": "1.0",
                "artifact_kind": "WINDOWS_E4_SCENARIO_RESULT_CATALOG",
                "profile_catalog_sha256": profile_sha256,
                "release_candidate": manifest["release_candidate"],
                "commit_sha": manifest["commit_sha"],
                "results": results,
            },
        )
        result_artifact = cls._artifact(root, result_path)
        return (
            {"profile": profile_artifact, "result": result_artifact},
            {
                "profile_id": profile_id,
                "profile_catalog_sha256": profile_sha256,
                "result_catalog_sha256": result_artifact["sha256"],
            },
        )

    @staticmethod
    def _oracle_document() -> dict[str, object]:
        document = {
            "schema_version": "1.0",
            "oracle_version": "oracle-v1.0",
            "execution_id": "11111111-1111-4111-8111-111111111111",
            "job_version_id": "22222222-2222-4222-8222-222222222222",
            "started_at": "2026-07-30T11:30:00Z",
            "finished_at": "2026-07-30T11:44:00Z",
            "source_quiescence": {
                "mode": "OPERATOR_QUIESCED",
                "operator_confirmed_at": "2026-07-30T11:00:00Z",
                "preflight_fingerprint": "b" * 64,
                "post_verification_fingerprint": "b" * 64,
                "unchanged": True,
            },
            "target_lock": {
                "lock_key_hash": "e" * 64,
                "fence_epoch": 1,
                "held_through_verification": True,
            },
            "target_exclusivity": {
                "mode": "OPERATOR_OR_DBA_CONFIRMED",
                "statement_version": "1.0",
                "responsible_party": "DBA",
                "confirmed_at": "2026-07-30T11:00:00Z",
                "valid_until": "2026-07-30T12:00:00Z",
                "status": "ACTIVE",
                "revoked_at": None,
                "revocation_reason": None,
                "target_empty_checked_at": "2026-07-30T11:31:00Z",
                "target_snapshot_id": "snapshot-1",
                "valid_through_target_snapshot": True,
                "confirmation_evidence_sha256": "d" * 64,
            },
            "normalization": {
                "row_algorithm": "SHA-256",
                "row_preimage": "DOMAIN_NUL_FIELD_COUNT_U32_BE_FIELDS",
                "field_encoding": "TAG_LENGTH_U16_BE_TAG_VALUE_LENGTH_U64_BE_VALUE",
                "collection_semantics": "MULTISET_WITH_COUNTS",
                "stable_order": "ROW_DIGEST_ASC_THEN_COUNT",
                "multiset_preimage": "DOMAIN_NUL_ROW_DIGEST_RAW32_COUNT_U64_BE",
                "null_encoding": "TYPE_TAGGED_NULL",
                "text_encoding": "UTF-8",
                "unicode_normalization": "NFC",
                "trim_text": False,
                "decimal_encoding": "CANONICAL_BASE10_NO_EXPONENT_NO_INSIGNIFICANT_ZERO",
                "negative_zero": "NORMALIZE_TO_ZERO",
                "session_timezone": "UTC",
                "timestamp_encoding": "RFC3339_UTC_MICROSECONDS",
                "boolean_encoding": "LOWERCASE_TRUE_FALSE",
                "binary_encoding": "BASE64_RFC4648",
                "field_separator": "LENGTH_PREFIXED",
            },
            "mapping_order": [
                {
                    "ordinal": 1,
                    "source_column": "id",
                    "target_column": "id",
                    "logical_type": "INTEGER",
                }
            ],
            "source_result": {
                "row_count": 1,
                "distinct_row_digest_count": 1,
                "multiset_sha256": "c" * 64,
                "read_started_at": "2026-07-30T11:35:00Z",
                "read_finished_at": "2026-07-30T11:36:00Z",
            },
            "target_result": {
                "row_count": 1,
                "distinct_row_digest_count": 1,
                "multiset_sha256": "c" * 64,
                "read_started_at": "2026-07-30T11:41:00Z",
                "read_finished_at": "2026-07-30T11:42:00Z",
                "snapshot_mode": "SINGLE_CONSISTENT_READ_TRANSACTION",
                "snapshot_id": "snapshot-1",
                "snapshot_started_at": "2026-07-30T11:40:00Z",
                "snapshot_finished_at": "2026-07-30T11:43:00Z",
            },
            "difference": {
                "missing_row_count": 0,
                "unexpected_row_count": 0,
                "row_count_equal": True,
                "multiset_sha256_equal": True,
                "sample_digest_pairs": [],
            },
            "result": "PASSED",
        }
        document["artifact_sha256"] = hashlib.sha256(
            rfc8785.dumps(document)
        ).hexdigest()
        return document

    @staticmethod
    def _rehash_oracle(document: dict[str, object]) -> None:
        document.pop("artifact_sha256", None)
        document["artifact_sha256"] = hashlib.sha256(
            rfc8785.dumps(document)
        ).hexdigest()

    @staticmethod
    def _validate(manifest: Path, environment: Path, root: Path) -> dict[str, object]:
        return validate(
            catalog_path=CATALOG,
            matrix_path=MATRIX,
            manifest_path=manifest,
            schema_path=SCHEMA,
            environment_manifest_path=environment,
            evidence_root=root,
            require_pass=False,
        )

    @staticmethod
    def _build_blocked_manifest(environment: Path, output: Path) -> None:
        subprocess.run(
            [
                sys.executable,
                str(REPOSITORY / "scripts/acceptance/build_blocked_manifest.py"),
                "--catalog",
                str(CATALOG),
                "--environment-manifest",
                str(environment),
                "--release-candidate",
                "0.1.0-test",
                "--commit",
                "a" * 40,
                "--output",
                str(output),
            ],
            cwd=REPOSITORY,
            check=True,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
