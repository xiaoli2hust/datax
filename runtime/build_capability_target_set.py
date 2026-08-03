#!/usr/bin/env python3
"""Build the canonical *target* set for the complete DataX desktop product.

This is deliberately not a capability or release manifest.  It is a
source-locked answer to the narrower but essential question: which upstream
DataX user-facing surfaces would need an explicit product decision before the
product could truthfully claim "all DataX functionality"?  Every entry starts
non-executable; the catalog therefore cannot promote a plugin or turn on a
generic JSON/SQL/code escape hatch.

The existing ``upstream-plugin-inventory.v1`` remains the authoritative
Reader/Writer SOURCE_PRESENT inventory.  This file consumes that inventory and
adds DataX native transformers plus the source-visible arbitrary execution
surfaces (SQL, external transformer loading and arbitrary job JSON).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

try:  # ``python -m runtime...``
    from runtime.build_upstream_plugin_inventory import (
        InventoryError,
        _load_json,
        _load_source_manifest,
        _repo_relative,
        _validate_lock_identity,
        _verified_source_hash,
        build_inventory,
    )
except ModuleNotFoundError:  # ``python runtime/build_capability_target_set.py``
    from build_upstream_plugin_inventory import (  # type: ignore[no-redef]
        InventoryError,
        _load_json,
        _load_source_manifest,
        _repo_relative,
        _validate_lock_identity,
        _verified_source_hash,
        build_inventory,
    )


SCHEMA_VERSION = "1.0"
TARGET_SET_FILENAME = "capability-target-set.v1.json"
TARGET_SET_KIND = "DATAX_COMPLETE_CAPABILITY_TARGET_SET"
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_E3_TEST_ID = re.compile(r"^(?:E2E|E3)-[A-Z0-9][A-Z0-9-]{2,95}$")
_E4_TEST_ID = re.compile(r"^(?:E2E|E4)-[A-Z0-9][A-Z0-9-]{2,95}$")
_TRANSFORMER_REGISTRATION = re.compile(r"registTransformer\(new ([A-Za-z][A-Za-z0-9]*)\(\)\);")
_TRANSFORMER_NAME = re.compile(r'setTransformerName\("([A-Za-z][A-Za-z0-9_.-]{1,63})"\);')

_TRANSFORMER_DIRECTORY = "core/src/main/java/com/alibaba/datax/core/transport/transformer"
_TRANSFORMER_REGISTRY = f"{_TRANSFORMER_DIRECTORY}/TransformerRegistry.java"

# These are not a hand-written list of plugins.  They are the deliberately
# small set of *escape surfaces* outside a plugin parameter contract.  Each is
# pinned to the source file that shows the surface exists.  All are explicitly
# unavailable in V1; recording them avoids silently omitting them from a later
# claim of complete DataX support.
_NON_PLUGIN_SURFACES: tuple[dict[str, object], ...] = (
    {
        "id": "CORE_ARBITRARY_JOB_JSON",
        "name": "Arbitrary DataX job JSON",
        "source_paths": ("core/src/main/java/com/alibaba/datax/core/Engine.java",),
        "risk_category": "ARBITRARY_EXECUTION_CONFIGURATION",
        "v1_disposition": "EXPLICITLY_UNSUPPORTED_V1",
    },
    {
        "id": "CORE_EXTERNAL_TRANSFORMER_LOADING",
        "name": "External transformer JAR loading",
        "source_paths": (_TRANSFORMER_REGISTRY,),
        "risk_category": "USER_SUPPLIED_CODE",
        "v1_disposition": "EXPLICITLY_UNSUPPORTED_V1",
    },
    {
        "id": "CORE_POST_SQL",
        "name": "Plugin postSql hooks",
        "source_paths": (
            "postgresqlwriter/src/main/resources/plugin_job_template.json",
            "odpsreader/src/main/java/com/alibaba/datax/plugin/reader/odpsreader/OdpsReader.java",
        ),
        "risk_category": "ARBITRARY_SQL",
        "v1_disposition": "EXPLICITLY_UNSUPPORTED_V1",
    },
    {
        "id": "CORE_PRE_SQL",
        "name": "Plugin preSql hooks",
        "source_paths": (
            "mysqlwriter/src/main/resources/plugin_job_template.json",
            "postgresqlwriter/src/main/resources/plugin_job_template.json",
        ),
        "risk_category": "ARBITRARY_SQL",
        "v1_disposition": "EXPLICITLY_UNSUPPORTED_V1",
    },
    {
        "id": "CORE_QUERY_SQL",
        "name": "Reader querySql",
        "source_paths": (
            "rdbmsreader/src/main/resources/plugin_job_template.json",
            "tdenginereader/src/main/java/com/alibaba/datax/plugin/reader/TDengineReader.java",
        ),
        "risk_category": "ARBITRARY_SQL",
        "v1_disposition": "EXPLICITLY_UNSUPPORTED_V1",
    },
)


class TargetSetError(ValueError):
    """The frozen complete-capability target set is malformed or stale."""


def _source_file(
    *, repo_root: Path, source_root: Path, manifest_entries: dict[str, str], relative: str
) -> dict[str, str]:
    path = source_root / relative
    if not path.is_file() or path.is_symlink():
        raise TargetSetError(f"required upstream capability source is missing: {relative}")
    try:
        digest = _verified_source_hash(
            source_root=source_root,
            path=path,
            manifest_entries=manifest_entries,
        )
    except InventoryError as exc:
        raise TargetSetError(str(exc)) from exc
    return {"path": _repo_relative(repo_root, path), "sha256": digest}


def _source_files(
    *, repo_root: Path, source_root: Path, manifest_entries: dict[str, str], paths: tuple[str, ...]
) -> list[dict[str, str]]:
    files = [
        _source_file(
            repo_root=repo_root,
            source_root=source_root,
            manifest_entries=manifest_entries,
            relative=path,
        )
        for path in paths
    ]
    if files != sorted(files, key=lambda item: item["path"]):
        files.sort(key=lambda item: item["path"])
    if len({item["path"] for item in files}) != len(files):
        raise TargetSetError("capability source file declarations must be unique")
    return files


def _native_transformers(
    *, repo_root: Path, source_root: Path, manifest_entries: dict[str, str]
) -> list[dict[str, object]]:
    registry = source_root / _TRANSFORMER_REGISTRY
    try:
        registry_text = registry.read_text(encoding="utf-8")
    except OSError as exc:
        raise TargetSetError("native TransformerRegistry is unavailable") from exc
    class_names = _TRANSFORMER_REGISTRATION.findall(registry_text)
    if not class_names or len(class_names) != len(set(class_names)):
        raise TargetSetError("native TransformerRegistry registrations are invalid")

    items: list[dict[str, object]] = []
    for class_name in class_names:
        source_relative = f"{_TRANSFORMER_DIRECTORY}/{class_name}.java"
        source_path = source_root / source_relative
        try:
            source_text = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise TargetSetError(f"native transformer source is unavailable: {class_name}") from exc
        names = _TRANSFORMER_NAME.findall(source_text)
        if len(names) != 1 or not names[0].startswith("dx_"):
            raise TargetSetError(f"native transformer name is invalid: {class_name}")
        transformer_name = names[0]
        identifier = "NATIVE_TRANSFORMER_" + transformer_name.removeprefix("dx_").upper()
        disposition = (
            "EXPLICITLY_UNSUPPORTED_V1"
            if transformer_name == "dx_groovy"
            else "FUTURE_CERTIFICATION_REQUIRED"
        )
        items.append(
            {
                "id": identifier,
                "kind": "NATIVE_TRANSFORMER",
                "name": transformer_name,
                "module": "core",
                "plugin_name": None,
                "risk_category": (
                    "USER_SUPPLIED_CODE" if transformer_name == "dx_groovy" else "DATA_TRANSFORMATION"
                ),
                "source_evidence_level": "SOURCE_PRESENT",
                "v1_disposition": disposition,
                "ordinary_user_executable": False,
                "required_e3_test_id": f"E3-CAP-NATIVE-{transformer_name.removeprefix('dx_').upper()}",
                "required_e4_test_id": f"E4-CAP-NATIVE-{transformer_name.removeprefix('dx_').upper()}",
                "source_files": _source_files(
                    repo_root=repo_root,
                    source_root=source_root,
                    manifest_entries=manifest_entries,
                    paths=(_TRANSFORMER_REGISTRY, source_relative),
                ),
            }
        )
    return sorted(items, key=lambda item: str(item["id"]))


def _plugin_targets(inventory: dict[str, Any]) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for plugin in inventory["plugins"]:
        module = str(plugin["module"])
        direction = str(plugin["direction"])
        is_v1_candidate = plugin["candidate_scope"] == "V1_BUSINESS"
        items.append(
            {
                "id": f"{direction}_PLUGIN_{module.removesuffix(direction.lower()).upper()}",
                "kind": f"{direction}_PLUGIN",
                "name": str(plugin["plugin_name"]),
                "module": module,
                "plugin_name": str(plugin["plugin_name"]),
                "risk_category": "EXTERNAL_DATA_ENDPOINT",
                "source_evidence_level": "SOURCE_PRESENT",
                "v1_disposition": (
                    "V1_SCOPE_CANDIDATE" if is_v1_candidate else "FUTURE_CERTIFICATION_REQUIRED"
                ),
                "ordinary_user_executable": False,
                "required_e3_test_id": (
                    "E2E-RUN-001" if is_v1_candidate else f"E3-CAP-{direction}-{module.upper()}"
                ),
                "required_e4_test_id": (
                    "E2E-WIN-DX-001" if is_v1_candidate else f"E4-CAP-{direction}-{module.upper()}"
                ),
                "source_files": [
                    {"path": plugin["module_pom_path"], "sha256": plugin["module_pom_sha256"]},
                    {"path": plugin["plugin_json_path"], "sha256": plugin["plugin_json_sha256"]},
                ],
            }
        )
    return sorted(items, key=lambda item: str(item["id"]))


def _non_plugin_targets(
    *, repo_root: Path, source_root: Path, manifest_entries: dict[str, str]
) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for declared in _NON_PLUGIN_SURFACES:
        identifier = str(declared["id"])
        items.append(
            {
                "id": identifier,
                "kind": "CORE_EXECUTION_SURFACE",
                "name": str(declared["name"]),
                "module": "core",
                "plugin_name": None,
                "risk_category": str(declared["risk_category"]),
                "source_evidence_level": "SOURCE_PRESENT",
                "v1_disposition": str(declared["v1_disposition"]),
                "ordinary_user_executable": False,
                "required_e3_test_id": (
                    "E3-CAP-" + identifier.removeprefix("CORE_").replace("_", "-")
                ),
                "required_e4_test_id": (
                    "E4-CAP-" + identifier.removeprefix("CORE_").replace("_", "-")
                ),
                "source_files": _source_files(
                    repo_root=repo_root,
                    source_root=source_root,
                    manifest_entries=manifest_entries,
                    paths=tuple(str(path) for path in declared["source_paths"]),
                ),
            }
        )
    return sorted(items, key=lambda item: str(item["id"]))


def build_target_set(repo_root: Path) -> dict[str, Any]:
    """Derive the complete-product target set from locked upstream source facts."""

    repo_root = repo_root.resolve()
    source_root = repo_root / "third_party" / "alibaba-datax"
    lock_path = repo_root / "runtime" / "upstream.lock.json"
    try:
        lock = _load_json(lock_path)
        _validate_lock_identity(lock)
        _manifest_path, manifest_entries = _load_source_manifest(
            lock=lock,
            lock_path=lock_path,
            source_root=source_root,
        )
        inventory = build_inventory(repo_root)
    except InventoryError as exc:
        raise TargetSetError(str(exc)) from exc

    items = [
        *_plugin_targets(inventory),
        *_native_transformers(
            repo_root=repo_root,
            source_root=source_root,
            manifest_entries=manifest_entries,
        ),
        *_non_plugin_targets(
            repo_root=repo_root,
            source_root=source_root,
            manifest_entries=manifest_entries,
        ),
    ]
    items.sort(key=lambda item: str(item["id"]))
    if len({item["id"] for item in items}) != len(items):
        raise TargetSetError("complete target set contains duplicate identifiers")

    counts = Counter(str(item["kind"]) for item in items)
    explicitly_unsupported = sum(
        item["v1_disposition"] == "EXPLICITLY_UNSUPPORTED_V1" for item in items
    )
    document: dict[str, Any] = {
        "catalog_kind": TARGET_SET_KIND,
        "completion_rule": {
            "ordinary_user_execution_requires": [
                "BUILD_VERIFIED",
                "LICENSE_REVIEWED",
                "CONTRACTED",
                "E3_CERTIFIED",
                "WINDOWS_E4_CERTIFIED",
                "RELEASE_PROMOTED_FOR_SAME_FINAL_PACKAGE",
            ],
            "statement_rule": (
                "Every target item not explicitly unsupported by an accepted ADR must "
                "be Windows E4 certified and release promoted for the same final package."
            ),
        },
        "counts": {
            "CORE_EXECUTION_SURFACE": counts["CORE_EXECUTION_SURFACE"],
            "NATIVE_TRANSFORMER": counts["NATIVE_TRANSFORMER"],
            "READER_PLUGIN": counts["READER_PLUGIN"],
            "WRITER_PLUGIN": counts["WRITER_PLUGIN"],
            "explicitly_unsupported_v1": explicitly_unsupported,
            "item_count": len(items),
            "windows_e4_certified_count": 0,
        },
        "items": items,
        "schema_version": SCHEMA_VERSION,
        "upstream": inventory["upstream"],
    }
    validate_target_set_document(document)
    return document


def validate_target_set_document(document: dict[str, Any]) -> None:
    required_top_level = {
        "catalog_kind",
        "completion_rule",
        "counts",
        "items",
        "schema_version",
        "upstream",
    }
    if not isinstance(document, dict) or set(document) != required_top_level:
        raise TargetSetError("target set has unexpected or missing top-level fields")
    if document["catalog_kind"] != TARGET_SET_KIND or document["schema_version"] != SCHEMA_VERSION:
        raise TargetSetError("target set identity is invalid")
    completion_rule = document["completion_rule"]
    if not isinstance(completion_rule, dict) or set(completion_rule) != {
        "ordinary_user_execution_requires",
        "statement_rule",
    }:
        raise TargetSetError("target set completion rule is invalid")
    if completion_rule["ordinary_user_execution_requires"] != [
        "BUILD_VERIFIED",
        "LICENSE_REVIEWED",
        "CONTRACTED",
        "E3_CERTIFIED",
        "WINDOWS_E4_CERTIFIED",
        "RELEASE_PROMOTED_FOR_SAME_FINAL_PACKAGE",
    ]:
        raise TargetSetError("target set completion gate is invalid")
    if not isinstance(completion_rule["statement_rule"], str) or not completion_rule["statement_rule"]:
        raise TargetSetError("target set completion statement is invalid")

    # Reuse the upstream shape already validated by the source inventory.  It
    # is a direct frozen copy, so regenerating the target set detects any
    # tamper or source/lock drift.
    upstream = document["upstream"]
    if not isinstance(upstream, dict) or not all(
        isinstance(upstream.get(field), str)
        for field in ("commit", "repository", "tag", "source_tree", "upstream_lock_sha256")
    ):
        raise TargetSetError("target set upstream binding is invalid")

    items = document["items"]
    if not isinstance(items, list) or not items:
        raise TargetSetError("target set items are invalid")
    required_item_fields = {
        "id",
        "kind",
        "module",
        "name",
        "ordinary_user_executable",
        "plugin_name",
        "required_e3_test_id",
        "required_e4_test_id",
        "risk_category",
        "source_evidence_level",
        "source_files",
        "v1_disposition",
    }
    valid_kinds = {
        "READER_PLUGIN",
        "WRITER_PLUGIN",
        "NATIVE_TRANSFORMER",
        "CORE_EXECUTION_SURFACE",
    }
    valid_dispositions = {
        "V1_SCOPE_CANDIDATE",
        "FUTURE_CERTIFICATION_REQUIRED",
        "EXPLICITLY_UNSUPPORTED_V1",
    }
    identifiers: list[str] = []
    counts: Counter[str] = Counter()
    explicitly_unsupported = 0
    for item in items:
        if not isinstance(item, dict) or set(item) != required_item_fields:
            raise TargetSetError("target set item has unexpected or missing fields")
        identifier = item["id"]
        if not isinstance(identifier, str) or _IDENTIFIER.fullmatch(identifier) is None:
            raise TargetSetError("target set identifier is invalid")
        identifiers.append(identifier)
        kind = item["kind"]
        if kind not in valid_kinds:
            raise TargetSetError(f"target set kind is invalid: {identifier}")
        counts[str(kind)] += 1
        if not isinstance(item["name"], str) or not item["name"]:
            raise TargetSetError(f"target set name is invalid: {identifier}")
        if item["module"] is not None and not isinstance(item["module"], str):
            raise TargetSetError(f"target set module is invalid: {identifier}")
        if item["plugin_name"] is not None and not isinstance(item["plugin_name"], str):
            raise TargetSetError(f"target set plugin name is invalid: {identifier}")
        if item["ordinary_user_executable"] is not False:
            raise TargetSetError(f"target set exposes an uncertified capability: {identifier}")
        if item["source_evidence_level"] != "SOURCE_PRESENT":
            raise TargetSetError(f"target set exceeds source evidence: {identifier}")
        if item["v1_disposition"] not in valid_dispositions:
            raise TargetSetError(f"target set disposition is invalid: {identifier}")
        if item["v1_disposition"] == "EXPLICITLY_UNSUPPORTED_V1":
            explicitly_unsupported += 1
        if not isinstance(item["risk_category"], str) or not _IDENTIFIER.fullmatch(
            item["risk_category"]
        ):
            raise TargetSetError(f"target set risk category is invalid: {identifier}")
        e3_test_id = item["required_e3_test_id"]
        e4_test_id = item["required_e4_test_id"]
        if not isinstance(e3_test_id, str) or _E3_TEST_ID.fullmatch(e3_test_id) is None:
            raise TargetSetError(f"target set E3 test ID is invalid: {identifier}")
        if not isinstance(e4_test_id, str) or _E4_TEST_ID.fullmatch(e4_test_id) is None:
            raise TargetSetError(f"target set E4 test ID is invalid: {identifier}")
        source_files = item["source_files"]
        if not isinstance(source_files, list) or not source_files:
            raise TargetSetError(f"target set source files are invalid: {identifier}")
        paths: list[str] = []
        for source in source_files:
            if not isinstance(source, dict) or set(source) != {"path", "sha256"}:
                raise TargetSetError(f"target set source file shape is invalid: {identifier}")
            path = source["path"]
            if (
                not isinstance(path, str)
                or not path.startswith("third_party/alibaba-datax/")
                or path.startswith("/")
                or "\\" in path
                or ".." in PurePosixPath(path).parts
            ):
                raise TargetSetError(f"target set source path is invalid: {identifier}")
            digest = source["sha256"]
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                raise TargetSetError(f"target set source hash is invalid: {identifier}")
            paths.append(path)
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise TargetSetError(f"target set source files must be sorted and unique: {identifier}")
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise TargetSetError("target set identifiers must be sorted and unique")

    expected_counts = {
        "CORE_EXECUTION_SURFACE": counts["CORE_EXECUTION_SURFACE"],
        "NATIVE_TRANSFORMER": counts["NATIVE_TRANSFORMER"],
        "READER_PLUGIN": counts["READER_PLUGIN"],
        "WRITER_PLUGIN": counts["WRITER_PLUGIN"],
        "explicitly_unsupported_v1": explicitly_unsupported,
        "item_count": len(items),
        "windows_e4_certified_count": 0,
    }
    if document["counts"] != expected_counts:
        raise TargetSetError("target set counts are invalid")


def canonical_target_set_bytes(document: dict[str, Any]) -> bytes:
    validate_target_set_document(document)
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode("utf-8")


def build_target_set_bytes(repo_root: Path) -> bytes:
    return canonical_target_set_bytes(build_target_set(repo_root))


def check_target_set(repo_root: Path, output_path: Path) -> bytes:
    expected = build_target_set_bytes(repo_root)
    actual_document = _load_json(output_path)
    actual = output_path.read_bytes()
    if actual != canonical_target_set_bytes(actual_document):
        raise TargetSetError("checked-in capability target set is not canonical JSON")
    if actual != expected:
        raise TargetSetError("checked-in capability target set is stale or tampered")
    return actual


def _write_atomically(output_path: Path, payload: bytes) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=output_path.parent, prefix=f".{output_path.name}.", delete=False
        ) as stream:
            temporary_name = stream.name
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, output_path)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _arguments() -> argparse.Namespace:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Generate the complete DataX capability target set from locked source"
    )
    parser.add_argument("--repo-root", type=Path, default=repository)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    output = arguments.output or arguments.repo_root / "runtime" / TARGET_SET_FILENAME
    try:
        if arguments.check:
            payload = check_target_set(arguments.repo_root, output)
            code = "CAPABILITY_TARGET_SET_VALID"
        else:
            payload = build_target_set_bytes(arguments.repo_root)
            _write_atomically(output, payload)
            code = "CAPABILITY_TARGET_SET_WRITTEN"
        document = json.loads(payload)
        print(
            json.dumps(
                {
                    "code": code,
                    "item_count": document["counts"]["item_count"],
                    "ready": True,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
                sort_keys=True,
            )
        )
        return 0
    except (InventoryError, TargetSetError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {"code": "CAPABILITY_TARGET_SET_INVALID", "detail": str(exc), "ready": False},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
