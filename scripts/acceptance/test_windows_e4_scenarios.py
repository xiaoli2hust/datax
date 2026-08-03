from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import rfc8785

from scripts.acceptance.catalog import load_catalog
from scripts.acceptance.windows_e4_scenarios import (
    validate_evidence_scenario,
    validate_profile_catalog,
    validate_result_catalog,
)

REPOSITORY = Path(__file__).resolve().parents[2]
CATALOG = REPOSITORY / "docs/contracts/requirements-catalog.v1.json"
PROFILE = REPOSITORY / "docs/contracts/windows-e4-scenario-profile.v1.json"
RELEASE_CANDIDATE = "0.1.0-test"
COMMIT_SHA = "a" * 40
ENVIRONMENT_ID = "win11-clean-001"
ENVIRONMENT_MANIFEST_SHA256 = "b" * 64
EXECUTED_AT = "2026-08-02T12:00:00Z"


class WindowsE4ScenarioTests(unittest.TestCase):
    def test_authoritative_profile_is_valid_and_exactly_covers_windows_e4_pairs(
        self,
    ) -> None:
        profile, profile_raw = validate_profile_catalog(
            profile_path=PROFILE,
            catalog_path=CATALOG,
            require_authoritative=True,
        )

        _catalog, entries, _catalog_raw = load_catalog(CATALOG)
        expected_pairs = {
            (entry.requirement_id, entry.test_id)
            for entry in entries
            if "WINDOWS_E4" in entry.evidence_requirements
        }
        actual_pairs = {
            (binding["requirement_id"], binding["test_id"])
            for item in profile["profiles"]
            for binding in item["requirement_bindings"]
        }
        profile_ids = [item["profile_id"] for item in profile["profiles"]]

        self.assertEqual(profile_raw, PROFILE.read_bytes())
        self.assertEqual(actual_pairs, expected_pairs)
        self.assertEqual(profile_ids, sorted(profile_ids))
        self.assertEqual(len(profile_ids), len(set(profile_ids)))
        for item in profile["profiles"]:
            self.assertEqual(
                item["required_assertion_ids"],
                sorted(item["required_assertion_ids"]),
            )
            self.assertIn(item["profile_id"], item["required_assertion_ids"])

    def test_profile_rejects_missing_or_mismatched_binding(self) -> None:
        source = json.loads(PROFILE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            non_authoritative_path = root / "non-authoritative.json"
            non_authoritative_path.write_bytes(PROFILE.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                ValueError, "does not match the authoritative profile"
            ):
                validate_profile_catalog(
                    profile_path=non_authoritative_path,
                    catalog_path=CATALOG,
                    require_authoritative=True,
                )

            missing = copy.deepcopy(source)
            missing["profiles"].pop()
            missing_path = root / "missing.json"
            self._write_json(missing_path, missing)
            with self.assertRaisesRegex(
                ValueError, "does not exactly cover the requirements catalog"
            ):
                validate_profile_catalog(
                    profile_path=missing_path,
                    catalog_path=CATALOG,
                )

            mismatched = copy.deepcopy(source)
            target = next(
                item
                for item in mismatched["profiles"]
                if item["profile_id"] == "E2E-WIN-001"
            )
            target["requirement_bindings"][0]["test_id"] = "E2E-WIN-999"
            mismatched_path = root / "mismatched.json"
            self._write_json(mismatched_path, mismatched)
            with self.assertRaisesRegex(
                ValueError, "binding test_id does not match profile"
            ):
                validate_profile_catalog(
                    profile_path=mismatched_path,
                    catalog_path=CATALOG,
                )

    def test_all_not_run_results_are_valid(self) -> None:
        profile, profile_raw = self._valid_profile()
        document = self._result_catalog(profile, profile_raw)
        with tempfile.TemporaryDirectory() as directory:
            results_path = Path(directory) / "results.json"
            self._write_json(results_path, document)

            actual, actual_raw = validate_result_catalog(
                results_path=results_path,
                profile_document=profile,
                profile_raw=profile_raw,
                release_candidate=RELEASE_CANDIDATE,
                commit_sha=COMMIT_SHA,
            )

        self.assertEqual(actual, document)
        self.assertEqual(actual_raw, self._json_bytes(document))
        self.assertTrue(
            all(item["result"] == "NOT_RUN" for item in actual["results"])
        )

    def test_result_catalog_rejects_identity_assertion_and_not_run_evidence_errors(
        self,
    ) -> None:
        profile, profile_raw = self._valid_profile()
        base = self._result_catalog(profile, profile_raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            wrong_identity = copy.deepcopy(base)
            wrong_identity["release_candidate"] = "0.1.0-other"
            identity_path = root / "wrong-identity.json"
            self._write_json(identity_path, wrong_identity)
            with self.assertRaisesRegex(ValueError, "identity does not match"):
                self._validate_results(identity_path, profile, profile_raw)

            wrong_assertions = copy.deepcopy(base)
            self._set_executed_result(
                wrong_assertions["results"][0],
                assertion_ids=[],
                assertions_sha256="c" * 64,
            )
            assertions_path = root / "wrong-assertions.json"
            self._write_json(assertions_path, wrong_assertions)
            with self.assertRaisesRegex(ValueError, "assertion IDs do not match"):
                self._validate_results(assertions_path, profile, profile_raw)

            not_run_with_evidence = copy.deepcopy(base)
            not_run_with_evidence["results"][0]["environment_id"] = ENVIRONMENT_ID
            not_run_path = root / "not-run-evidence.json"
            self._write_json(not_run_path, not_run_with_evidence)
            with self.assertRaisesRegex(
                ValueError, "NOT_RUN Windows E4 scenario result must not contain"
            ):
                self._validate_results(not_run_path, profile, profile_raw)

    def test_evidence_rejects_scenario_hash_and_assertion_mismatches(self) -> None:
        profile, profile_raw = self._valid_profile()
        profile_id = "E2E-WIN-002"
        expected_assertion_ids = next(
            item["required_assertion_ids"]
            for item in profile["profiles"]
            if item["profile_id"] == profile_id
        )
        self.assertGreater(len(expected_assertion_ids), 1)
        assertions = [
            {
                "assertion_id": assertion_id,
                "result": "PASS",
                "evidence": [
                    {
                        "path": f"assertions/{assertion_id}.json",
                        "sha256": "d" * 64,
                    }
                ],
            }
            for assertion_id in expected_assertion_ids
        ]
        result_document = self._result_catalog(profile, profile_raw)
        selected_result = next(
            item for item in result_document["results"] if item["profile_id"] == profile_id
        )
        self._set_executed_result(
            selected_result,
            assertion_ids=expected_assertion_ids,
            assertions_sha256=hashlib.sha256(rfc8785.dumps(assertions)).hexdigest(),
        )

        with tempfile.TemporaryDirectory() as directory:
            results_path = Path(directory) / "executed-results.json"
            self._write_json(results_path, result_document)
            results, results_raw = self._validate_results(
                results_path,
                profile,
                profile_raw,
            )

        artifact = {
            "result": "PASSED",
            "binding": {
                "test_id": profile_id,
                "environment_id": ENVIRONMENT_ID,
                "environment_manifest_sha256": ENVIRONMENT_MANIFEST_SHA256,
            },
            "executed_at": EXECUTED_AT,
            "scenario": {
                "profile_id": profile_id,
                "profile_catalog_sha256": hashlib.sha256(profile_raw).hexdigest(),
                "result_catalog_sha256": hashlib.sha256(results_raw).hexdigest(),
            },
            "assertions": assertions,
        }
        validate_evidence_scenario(
            artifact=artifact,
            profile_document=profile,
            profile_raw=profile_raw,
            result_document=results,
            result_raw=results_raw,
        )

        wrong_hash = copy.deepcopy(artifact)
        wrong_hash["scenario"]["result_catalog_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "scenario binding does not match"):
            validate_evidence_scenario(
                artifact=wrong_hash,
                profile_document=profile,
                profile_raw=profile_raw,
                result_document=results,
                result_raw=results_raw,
            )

        wrong_assertions = copy.deepcopy(artifact)
        wrong_assertions["assertions"].reverse()
        with self.assertRaisesRegex(
            ValueError, "assertions do not exactly match profile"
        ):
            validate_evidence_scenario(
                artifact=wrong_assertions,
                profile_document=profile,
                profile_raw=profile_raw,
                result_document=results,
                result_raw=results_raw,
            )

    @staticmethod
    def _json_bytes(document: dict[str, object]) -> bytes:
        return (
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    @classmethod
    def _write_json(cls, path: Path, document: dict[str, object]) -> None:
        path.write_bytes(cls._json_bytes(document))

    @staticmethod
    def _valid_profile() -> tuple[dict[str, object], bytes]:
        return validate_profile_catalog(
            profile_path=PROFILE,
            catalog_path=CATALOG,
            require_authoritative=True,
        )

    @staticmethod
    def _result_catalog(
        profile: dict[str, object], profile_raw: bytes
    ) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "artifact_kind": "WINDOWS_E4_SCENARIO_RESULT_CATALOG",
            "profile_catalog_sha256": hashlib.sha256(profile_raw).hexdigest(),
            "release_candidate": RELEASE_CANDIDATE,
            "commit_sha": COMMIT_SHA,
            "results": [
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
                for item in profile["profiles"]
            ],
        }

    @staticmethod
    def _set_executed_result(
        result: dict[str, object],
        *,
        assertion_ids: list[str],
        assertions_sha256: str,
    ) -> None:
        result.update(
            {
                "result": "PASSED",
                "executed_at": EXECUTED_AT,
                "environment_id": ENVIRONMENT_ID,
                "environment_manifest_sha256": ENVIRONMENT_MANIFEST_SHA256,
                "windows_baseline_id": "windows11-clean-golden-v1",
                "harness_version": "windows-e4-harness/v1",
                "assertion_ids": assertion_ids,
                "assertions_sha256": assertions_sha256,
            }
        )

    @staticmethod
    def _validate_results(
        path: Path,
        profile: dict[str, object],
        profile_raw: bytes,
    ) -> tuple[dict[str, object], bytes]:
        return validate_result_catalog(
            results_path=path,
            profile_document=profile,
            profile_raw=profile_raw,
            release_candidate=RELEASE_CANDIDATE,
            commit_sha=COMMIT_SHA,
        )


if __name__ == "__main__":
    unittest.main()
