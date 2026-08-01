from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.acceptance.catalog import (
    build_catalog_bytes,
    load_catalog,
)
from scripts.acceptance.validate_acceptance_manifest import validate

REPOSITORY = Path(__file__).resolve().parents[2]
MATRIX = REPOSITORY / "docs/12_需求追踪矩阵.md"
CATALOG = REPOSITORY / "docs/contracts/requirements-catalog.v1.json"
SCHEMA = REPOSITORY / "docs/contracts/acceptance-manifest.v1.schema.json"


class AcceptanceManifestTests(unittest.TestCase):
    def test_checked_in_catalog_is_canonical_and_matches_all_requirements(self) -> None:
        document, entries, raw = load_catalog(CATALOG)

        self.assertEqual(raw, build_catalog_bytes(MATRIX))
        self.assertEqual(document["requirement_count"], 81)
        self.assertEqual(document["v1_must_count"], 80)
        self.assertEqual(document["post_v1_count"], 1)
        self.assertEqual(document["entry_count"], 90)
        self.assertEqual(len(entries), 90)

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
            with self.assertRaisesRegex(ValueError, "public release requires"):
                validate(
                    catalog_path=CATALOG,
                    matrix_path=MATRIX,
                    manifest_path=manifest,
                    schema_path=SCHEMA,
                    environment_manifest_path=environment,
                    evidence_root=root,
                    require_pass=True,
                )

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
