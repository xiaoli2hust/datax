from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from runtime.build_capability_target_set import (
    TargetSetError,
    build_target_set,
    build_target_set_bytes,
    canonical_target_set_bytes,
    check_target_set,
    validate_target_set_document,
)

REPOSITORY = Path(__file__).resolve().parents[1]
CATALOG = REPOSITORY / "runtime" / "capability-target-set.v1.json"
SCHEMA = REPOSITORY / "docs" / "contracts" / "capability-target-set.v1.schema.json"


class CapabilityTargetSetTests(unittest.TestCase):
    def test_checked_in_target_set_is_source_locked_canonical_and_schema_valid(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        document = json.loads(CATALOG.read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
        validate_target_set_document(document)
        self.assertEqual(CATALOG.read_bytes(), build_target_set_bytes(REPOSITORY))
        self.assertEqual(
            document["counts"],
            {
                "CORE_EXECUTION_SURFACE": 5,
                "NATIVE_TRANSFORMER": 6,
                "READER_PLUGIN": 31,
                "WRITER_PLUGIN": 41,
                "explicitly_unsupported_v1": 6,
                "item_count": 83,
                "windows_e4_certified_count": 0,
            },
        )
        self.assertTrue(all(item["ordinary_user_executable"] is False for item in document["items"]))
        self.assertEqual(
            {item["name"] for item in document["items"] if item["kind"] == "NATIVE_TRANSFORMER"},
            {"dx_digest", "dx_filter", "dx_groovy", "dx_pad", "dx_replace", "dx_substr"},
        )

    def test_promoting_or_exposing_target_item_is_rejected(self) -> None:
        document = build_target_set(REPOSITORY)
        exposed = copy.deepcopy(document)
        exposed["items"][0]["ordinary_user_executable"] = True
        with self.assertRaisesRegex(TargetSetError, "exposes an uncertified capability"):
            validate_target_set_document(exposed)

        promoted = copy.deepcopy(document)
        promoted["items"][0]["source_evidence_level"] = "WINDOWS_E4_CERTIFIED"
        with self.assertRaisesRegex(TargetSetError, "exceeds source evidence"):
            validate_target_set_document(promoted)

    def test_tamper_and_noncanonical_checked_in_catalog_are_rejected(self) -> None:
        document = build_target_set(REPOSITORY)
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "capability-target-set.v1.json"
            catalog.write_bytes(canonical_target_set_bytes(document))
            check_target_set(REPOSITORY, catalog)

            tampered = copy.deepcopy(document)
            tampered["items"][0]["source_files"][0]["sha256"] = "f" * 64
            catalog.write_bytes(canonical_target_set_bytes(tampered))
            with self.assertRaisesRegex(TargetSetError, "stale or tampered"):
                check_target_set(REPOSITORY, catalog)

            catalog.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(TargetSetError, "not canonical JSON"):
                check_target_set(REPOSITORY, catalog)

    def test_duplicate_id_invalid_test_plan_and_unordered_sources_are_rejected(self) -> None:
        document = build_target_set(REPOSITORY)

        duplicate = copy.deepcopy(document)
        duplicate["items"][1]["id"] = duplicate["items"][0]["id"]
        with self.assertRaisesRegex(TargetSetError, "identifiers must be sorted and unique"):
            validate_target_set_document(duplicate)

        invalid_test = copy.deepcopy(document)
        invalid_test["items"][0]["required_e3_test_id"] = "not-a-test-id"
        with self.assertRaisesRegex(TargetSetError, "E3 test ID is invalid"):
            validate_target_set_document(invalid_test)

        mismatched_evidence_level = copy.deepcopy(document)
        mismatched_evidence_level["items"][0]["required_e3_test_id"] = "E4-CAP-INVALID"
        with self.assertRaisesRegex(TargetSetError, "E3 test ID is invalid"):
            validate_target_set_document(mismatched_evidence_level)

        unordered = copy.deepcopy(document)
        item = next(entry for entry in unordered["items"] if len(entry["source_files"]) > 1)
        item["source_files"].reverse()
        with self.assertRaisesRegex(TargetSetError, "source files must be sorted and unique"):
            validate_target_set_document(unordered)


if __name__ == "__main__":
    unittest.main()
