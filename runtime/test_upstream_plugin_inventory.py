from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from runtime.build_upstream_plugin_inventory import (
    INTERNAL_SMOKE_CANDIDATES,
    V1_BUSINESS_CANDIDATES,
    InventoryError,
    build_inventory,
    build_inventory_bytes,
    canonical_inventory_bytes,
    check_inventory,
    validate_inventory_document,
)

REPOSITORY = Path(__file__).resolve().parents[1]
CATALOG = REPOSITORY / "runtime" / "upstream-plugin-inventory.v1.json"
SCHEMA = REPOSITORY / "docs" / "contracts" / "upstream-plugin-inventory.v1.schema.json"

MAVEN_NAMESPACE = "http://maven.apache.org/POM/4.0.0"
BASE_MODULES = sorted(V1_BUSINESS_CANDIDATES | INTERNAL_SMOKE_CANDIDATES)


class UpstreamPluginInventoryTests(unittest.TestCase):
    def test_checked_in_inventory_is_canonical_complete_and_schema_valid(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        document = json.loads(CATALOG.read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
        validate_inventory_document(document)

        expected = build_inventory_bytes(REPOSITORY)
        self.assertEqual(CATALOG.read_bytes(), expected)
        self.assertEqual(document["plugin_count"], 72)
        self.assertEqual(document["direction_counts"], {"READER": 31, "WRITER": 41})
        self.assertEqual(
            sum(plugin["candidate_scope"] == "V1_BUSINESS" for plugin in document["plugins"]),
            4,
        )
        self.assertEqual(
            sum(plugin["candidate_scope"] == "INTERNAL_SMOKE" for plugin in document["plugins"]),
            2,
        )
        self.assertTrue(
            all(
                plugin["certification_state"] == "SOURCE_PRESENT"
                and plugin["ordinary_user_executable"] is False
                for plugin in document["plugins"]
            )
        )

    def test_missing_reader_writer_plugin_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._fixture_repository(Path(directory))
            plugin_json = (
                repository
                / "third_party"
                / "alibaba-datax"
                / "mysqlreader"
                / "src"
                / "main"
                / "resources"
                / "plugin.json"
            )
            plugin_json.unlink()
            self._refresh_source_lock(repository)
            with self.assertRaisesRegex(InventoryError, "missing plugin.json: mysqlreader"):
                build_inventory(repository)

    def test_duplicate_plugin_name_is_rejected_case_insensitively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._fixture_repository(
                Path(directory),
                plugin_names={
                    "mysqlwriter": "SharedWriter",
                    "postgresqlwriter": "sharedwriter",
                },
            )
            with self.assertRaisesRegex(InventoryError, "duplicate plugin name"):
                build_inventory(repository)

    def test_plugin_module_with_illegal_direction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._fixture_repository(
                Path(directory),
                modules=[*BASE_MODULES, "unsafeplugin"],
            )
            with self.assertRaisesRegex(InventoryError, "illegal direction"):
                build_inventory(repository)

    def test_upstream_source_tampering_is_rejected_against_source_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._fixture_repository(Path(directory))
            plugin_json = (
                repository
                / "third_party"
                / "alibaba-datax"
                / "streamwriter"
                / "src"
                / "main"
                / "resources"
                / "plugin.json"
            )
            document = json.loads(plugin_json.read_text(encoding="utf-8"))
            document["description"] = "tampered after the source lock"
            plugin_json.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(InventoryError, "upstream source hash mismatch"):
                build_inventory(repository)

    def test_checked_catalog_tampering_and_noncanonical_json_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._fixture_repository(Path(directory))
            document = build_inventory(repository)
            catalog = repository / "runtime" / "upstream-plugin-inventory.v1.json"

            catalog.write_bytes(canonical_inventory_bytes(document))
            check_inventory(repository, catalog)

            tampered = copy.deepcopy(document)
            tampered["plugins"][0]["plugin_json_sha256"] = "f" * 64
            catalog.write_bytes(canonical_inventory_bytes(tampered))
            with self.assertRaisesRegex(InventoryError, "stale or tampered"):
                check_inventory(repository, catalog)

            catalog.write_text(
                json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(InventoryError, "not canonical JSON"):
                check_inventory(repository, catalog)

    def test_certification_promotion_or_user_execution_is_rejected(self) -> None:
        document = build_inventory(REPOSITORY)
        promoted = copy.deepcopy(document)
        promoted["plugins"][0]["certification_state"] = "PACKAGED"
        with self.assertRaisesRegex(InventoryError, "exceeds source evidence"):
            validate_inventory_document(promoted)

        executable = copy.deepcopy(document)
        executable["plugins"][0]["ordinary_user_executable"] = True
        with self.assertRaisesRegex(InventoryError, "exposes uncertified plugin"):
            validate_inventory_document(executable)

    def test_malformed_upstream_binding_is_rejected_by_standalone_validator(self) -> None:
        document = build_inventory(REPOSITORY)
        outside_root = copy.deepcopy(document)
        outside_root["upstream"]["root_pom_path"] = "third_party/other/pom.xml"
        with self.assertRaisesRegex(InventoryError, "root_pom_path is invalid"):
            canonical_inventory_bytes(outside_root)

        invalid_tree = copy.deepcopy(document)
        invalid_tree["upstream"]["source_tree"] = "not-a-git-tree"
        with self.assertRaisesRegex(InventoryError, "source_tree is invalid"):
            validate_inventory_document(invalid_tree)

    @staticmethod
    def _fixture_repository(
        repository: Path,
        *,
        modules: list[str] | None = None,
        plugin_names: dict[str, str] | None = None,
    ) -> Path:
        modules = modules or BASE_MODULES
        plugin_names = plugin_names or {}
        source_root = repository / "third_party" / "alibaba-datax"
        runtime = repository / "runtime"
        source_root.mkdir(parents=True)
        runtime.mkdir(parents=True)

        root_pom = (
            f'<project xmlns="{MAVEN_NAMESPACE}">\n'
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <modules>\n"
            + "".join(f"    <module>{module}</module>\n" for module in modules)
            + "  </modules>\n"
            "</project>\n"
        )
        (source_root / "pom.xml").write_text(root_pom, encoding="utf-8")

        for module in modules:
            module_root = source_root / module
            resources = module_root / "src" / "main" / "resources"
            resources.mkdir(parents=True)
            module_pom = (
                f'<project xmlns="{MAVEN_NAMESPACE}">\n'
                "  <modelVersion>4.0.0</modelVersion>\n"
                f"  <artifactId>{module}</artifactId>\n"
                "</project>\n"
            )
            (module_root / "pom.xml").write_text(module_pom, encoding="utf-8")
            plugin_name = plugin_names.get(module, module)
            plugin_document = {
                "class": f"example.datax.plugin.{module}.Plugin",
                "developer": "fixture",
                "name": plugin_name,
            }
            (resources / "plugin.json").write_text(
                json.dumps(plugin_document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        UpstreamPluginInventoryTests._refresh_source_lock(repository)
        return repository

    @staticmethod
    def _refresh_source_lock(repository: Path) -> None:
        source_root = repository / "third_party" / "alibaba-datax"
        runtime = repository / "runtime"
        source_files = sorted(path for path in source_root.rglob("*") if path.is_file())
        manifest_lines = []
        for path in source_files:
            relative = path.relative_to(source_root).as_posix()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest_lines.append(f"{digest}  ./{relative}")
        manifest_path = runtime / "upstream-files.sha256"
        manifest_path.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
        lock = {
            "commit": "a" * 40,
            "repository": "https://github.com/alibaba/DataX.git",
            "schema_version": "1.0",
            "source_file_count": len(source_files),
            "source_manifest": "upstream-files.sha256",
            "source_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "source_tree": "b" * 40,
            "tag": "fixture-tag",
        }
        (runtime / "upstream.lock.json").write_text(
            json.dumps(lock, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
