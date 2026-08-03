#!/usr/bin/env python3
"""Generate the fail-closed Reader/Writer inventory from the locked DataX tree."""

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
from xml.etree import ElementTree

SCHEMA_VERSION = "1.0"
INVENTORY_FILENAME = "upstream-plugin-inventory.v1.json"
SHA1_PATTERN = re.compile(r"^[a-f0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
MODULE_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")
PLUGIN_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,63}$")
PLUGIN_CLASS_PATTERN = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]{2,255}$")
TAG_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SOURCE_MANIFEST_LINE = re.compile(r"^([a-f0-9]{64})  \./(.+)$")
UPSTREAM_REPOSITORY = "https://github.com/alibaba/DataX.git"

V1_BUSINESS_CANDIDATES = frozenset(
    {"mysqlreader", "mysqlwriter", "postgresqlreader", "postgresqlwriter"}
)
INTERNAL_SMOKE_CANDIDATES = frozenset({"streamreader", "streamwriter"})


class InventoryError(ValueError):
    """The locked source or generated inventory violates the inventory contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise InventoryError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
    )
    if not isinstance(value, dict):
        raise InventoryError(f"JSON document must be an object: {path}")
    return value


def _repo_relative(repo_root: Path, path: Path) -> str:
    try:
        relative = path.resolve().relative_to(repo_root.resolve())
    except ValueError as exc:
        raise InventoryError(f"inventory input is outside repository: {path}") from exc
    return relative.as_posix()


def _source_relative(source_root: Path, path: Path) -> str:
    try:
        relative = path.resolve().relative_to(source_root.resolve())
    except ValueError as exc:
        raise InventoryError(f"plugin input is outside upstream source: {path}") from exc
    return relative.as_posix()


def _validate_safe_relative_path(value: str, label: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise InventoryError(f"{label} must be a canonical repository-relative path")


def _load_source_manifest(
    *, lock: dict[str, Any], lock_path: Path, source_root: Path
) -> tuple[Path, dict[str, str]]:
    source_manifest_name = lock.get("source_manifest")
    if not isinstance(source_manifest_name, str):
        raise InventoryError("upstream lock source_manifest must be a string")
    _validate_safe_relative_path(source_manifest_name, "source_manifest")
    if PurePosixPath(source_manifest_name).parent != PurePosixPath("."):
        raise InventoryError("upstream lock source_manifest must be next to the lock")

    manifest_path = lock_path.parent / source_manifest_name
    expected_hash = lock.get("source_manifest_sha256")
    if not isinstance(expected_hash, str) or not SHA256_PATTERN.fullmatch(expected_hash):
        raise InventoryError("upstream lock source_manifest_sha256 is invalid")
    if _sha256(manifest_path) != expected_hash:
        raise InventoryError("upstream source manifest hash does not match the lock")

    entries: dict[str, str] = {}
    for line_number, line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        match = SOURCE_MANIFEST_LINE.fullmatch(line)
        if match is None:
            raise InventoryError(f"invalid source manifest line {line_number}")
        digest, relative_path = match.groups()
        _validate_safe_relative_path(relative_path, "source manifest path")
        if relative_path in entries:
            raise InventoryError(f"duplicate source manifest path: {relative_path}")
        entries[relative_path] = digest

    expected_count = lock.get("source_file_count")
    if not isinstance(expected_count, int) or isinstance(expected_count, bool):
        raise InventoryError("upstream lock source_file_count must be an integer")
    if len(entries) != expected_count:
        raise InventoryError("upstream source manifest file count does not match the lock")
    if not source_root.is_dir():
        raise InventoryError("locked upstream source directory is missing")
    actual_paths: set[str] = set()
    for path in sorted(source_root.rglob("*")):
        if path.is_symlink():
            raise InventoryError(f"upstream source contains a symbolic link: {path}")
        if path.is_file():
            actual_paths.add(_source_relative(source_root, path))
    missing = sorted(entries.keys() - actual_paths)
    unexpected = sorted(actual_paths - entries.keys())
    if missing:
        raise InventoryError(f"upstream source files are missing: {', '.join(missing)}")
    if unexpected:
        raise InventoryError(
            f"upstream source files are absent from the manifest: {', '.join(unexpected)}"
        )
    for relative_path, expected_hash in sorted(entries.items()):
        actual_hash = _sha256(source_root / relative_path)
        if actual_hash != expected_hash:
            raise InventoryError(f"upstream source hash mismatch: {relative_path}")
    return manifest_path, entries


def _verified_source_hash(
    *, source_root: Path, path: Path, manifest_entries: dict[str, str]
) -> str:
    relative_path = _source_relative(source_root, path)
    expected = manifest_entries.get(relative_path)
    if expected is None:
        raise InventoryError(f"upstream file is absent from source manifest: {relative_path}")
    actual = _sha256(path)
    if actual != expected:
        raise InventoryError(f"upstream source hash mismatch: {relative_path}")
    return actual


def _xml_root(path: Path) -> ElementTree.Element:
    try:
        return ElementTree.fromstring(path.read_text(encoding="utf-8"))
    except ElementTree.ParseError as exc:
        raise InventoryError(f"invalid Maven POM: {path}") from exc


def _maven_namespace(root: ElementTree.Element, path: Path) -> str:
    if not root.tag.startswith("{") or "}" not in root.tag:
        raise InventoryError(f"Maven POM has no XML namespace: {path}")
    return root.tag[1 : root.tag.index("}")]


def _root_modules(root_pom: Path) -> list[str]:
    root = _xml_root(root_pom)
    namespace = _maven_namespace(root, root_pom)
    modules_element = root.find(f"{{{namespace}}}modules")
    if modules_element is None:
        raise InventoryError("upstream root POM has no modules list")

    modules: list[str] = []
    seen: set[str] = set()
    for element in modules_element.findall(f"{{{namespace}}}module"):
        module = (element.text or "").strip()
        if MODULE_PATTERN.fullmatch(module) is None:
            raise InventoryError(f"invalid Maven module name: {module!r}")
        folded = module.casefold()
        if folded in seen:
            raise InventoryError(f"duplicate Maven module: {module}")
        seen.add(folded)
        modules.append(module)
    if not modules:
        raise InventoryError("upstream root POM modules list is empty")
    return modules


def _artifact_id(module_pom: Path) -> str:
    root = _xml_root(module_pom)
    namespace = _maven_namespace(root, module_pom)
    artifact_element = root.find(f"{{{namespace}}}artifactId")
    artifact_id = (artifact_element.text or "").strip() if artifact_element is not None else ""
    if MODULE_PATTERN.fullmatch(artifact_id) is None:
        raise InventoryError(f"invalid Maven artifactId in {module_pom}")
    return artifact_id


def _direction(module: str) -> str:
    folded = module.casefold()
    if folded.endswith("reader"):
        return "READER"
    if folded.endswith("writer"):
        return "WRITER"
    raise InventoryError(f"illegal Reader/Writer direction for module: {module}")


def _candidate_scope(module: str) -> str:
    if module in V1_BUSINESS_CANDIDATES:
        return "V1_BUSINESS"
    if module in INTERNAL_SMOKE_CANDIDATES:
        return "INTERNAL_SMOKE"
    return "NONE"


def _discover_plugin_manifests(source_root: Path) -> dict[str, Path]:
    manifests: dict[str, Path] = {}
    for path in sorted(source_root.rglob("plugin.json")):
        relative = Path(_source_relative(source_root, path))
        if relative.parts[1:] != ("src", "main", "resources", "plugin.json"):
            raise InventoryError(f"plugin.json is outside canonical module location: {relative}")
        module = relative.parts[0]
        if module in manifests:
            raise InventoryError(f"duplicate plugin.json for module: {module}")
        manifests[module] = path
    return manifests


def _plugin_json_facts(paths: dict[str, Path]) -> dict[str, tuple[str, str]]:
    facts: dict[str, tuple[str, str]] = {}
    names: dict[str, str] = {}
    for module, path in sorted(paths.items()):
        document = _load_json(path)
        plugin_name = document.get("name")
        plugin_class = document.get("class")
        if not isinstance(plugin_name, str) or PLUGIN_NAME_PATTERN.fullmatch(plugin_name) is None:
            raise InventoryError(f"invalid plugin name in {path}")
        if not isinstance(plugin_class, str) or PLUGIN_CLASS_PATTERN.fullmatch(plugin_class) is None:
            raise InventoryError(f"invalid plugin class in {path}")
        folded_name = plugin_name.casefold()
        if folded_name in names:
            raise InventoryError(
                f"duplicate plugin name: {plugin_name} ({names[folded_name]}, {module})"
            )
        names[folded_name] = module
        facts[module] = (plugin_name, plugin_class)
    return facts


def _validate_lock_identity(lock: dict[str, Any]) -> None:
    string_fields = ("repository", "tag", "commit", "source_tree")
    for field in string_fields:
        if not isinstance(lock.get(field), str) or not lock[field]:
            raise InventoryError(f"upstream lock {field} must be a non-empty string")
    if SHA1_PATTERN.fullmatch(lock["commit"]) is None:
        raise InventoryError("upstream lock commit must be a lowercase Git SHA-1")
    if SHA1_PATTERN.fullmatch(lock["source_tree"]) is None:
        raise InventoryError("upstream lock source_tree must be a lowercase Git SHA-1")
    if lock.get("schema_version") != "1.0":
        raise InventoryError("upstream lock schema_version is invalid")
    if lock["repository"] != UPSTREAM_REPOSITORY:
        raise InventoryError("upstream lock repository is not Alibaba DataX")
    if TAG_PATTERN.fullmatch(lock["tag"]) is None:
        raise InventoryError("upstream lock tag is invalid")


def build_inventory(repo_root: Path) -> dict[str, Any]:
    """Build the inventory from the repository's locked upstream source facts."""

    repo_root = repo_root.resolve()
    source_root = repo_root / "third_party" / "alibaba-datax"
    lock_path = repo_root / "runtime" / "upstream.lock.json"
    root_pom = source_root / "pom.xml"

    lock = _load_json(lock_path)
    _validate_lock_identity(lock)
    manifest_path, manifest_entries = _load_source_manifest(
        lock=lock,
        lock_path=lock_path,
        source_root=source_root,
    )
    root_pom_hash = _verified_source_hash(
        source_root=source_root,
        path=root_pom,
        manifest_entries=manifest_entries,
    )

    modules = _root_modules(root_pom)
    plugin_modules = {
        module for module in modules if module.casefold().endswith(("reader", "writer"))
    }
    manifests = _discover_plugin_manifests(source_root)
    missing = sorted(plugin_modules - manifests.keys())
    unexpected = sorted(manifests.keys() - plugin_modules)
    if missing:
        raise InventoryError(f"Reader/Writer modules missing plugin.json: {', '.join(missing)}")
    if unexpected:
        raise InventoryError(
            "plugin.json modules have illegal direction or are absent from root POM: "
            + ", ".join(unexpected)
        )

    facts = _plugin_json_facts(manifests)
    missing_candidates = sorted(
        (V1_BUSINESS_CANDIDATES | INTERNAL_SMOKE_CANDIDATES) - plugin_modules
    )
    if missing_candidates:
        raise InventoryError(
            "candidate classification references absent upstream modules: "
            + ", ".join(missing_candidates)
        )

    plugins: list[dict[str, Any]] = []
    for module in sorted(plugin_modules):
        plugin_name, plugin_class = facts[module]
        if plugin_name.casefold() != module.casefold():
            raise InventoryError(
                f"plugin name does not match Maven module: {plugin_name} != {module}"
            )
        module_pom = source_root / module / "pom.xml"
        artifact_id = _artifact_id(module_pom)
        if artifact_id != module:
            raise InventoryError(
                f"Maven artifactId does not match module: {artifact_id} != {module}"
            )
        plugin_json = manifests[module]
        plugins.append(
            {
                "candidate_scope": _candidate_scope(module),
                "certification_state": "SOURCE_PRESENT",
                "direction": _direction(module),
                "maven_artifact_id": artifact_id,
                "module": module,
                "module_pom_path": _repo_relative(repo_root, module_pom),
                "module_pom_sha256": _verified_source_hash(
                    source_root=source_root,
                    path=module_pom,
                    manifest_entries=manifest_entries,
                ),
                "ordinary_user_executable": False,
                "plugin_class": plugin_class,
                "plugin_json_path": _repo_relative(repo_root, plugin_json),
                "plugin_json_sha256": _verified_source_hash(
                    source_root=source_root,
                    path=plugin_json,
                    manifest_entries=manifest_entries,
                ),
                "plugin_name": plugin_name,
            }
        )

    direction_counts = Counter(plugin["direction"] for plugin in plugins)
    document: dict[str, Any] = {
        "certification_policy": {
            "candidate_classification_is_certification": False,
            "maximum_proven_state": "SOURCE_PRESENT",
            "ordinary_user_executable": False,
        },
        "direction_counts": {
            "READER": direction_counts["READER"],
            "WRITER": direction_counts["WRITER"],
        },
        "plugin_count": len(plugins),
        "plugins": plugins,
        "schema_version": SCHEMA_VERSION,
        "upstream": {
            "commit": lock["commit"],
            "repository": lock["repository"],
            "root_pom_path": _repo_relative(repo_root, root_pom),
            "root_pom_sha256": root_pom_hash,
            "source_manifest_path": _repo_relative(repo_root, manifest_path),
            "source_manifest_sha256": lock["source_manifest_sha256"],
            "source_tree": lock["source_tree"],
            "tag": lock["tag"],
            "upstream_lock_path": _repo_relative(repo_root, lock_path),
            "upstream_lock_sha256": _sha256(lock_path),
        },
    }
    validate_inventory_document(document)
    return document


def validate_inventory_document(document: dict[str, Any]) -> None:
    """Validate cross-field invariants that JSON Schema cannot express."""

    required_top_level = {
        "certification_policy",
        "direction_counts",
        "plugin_count",
        "plugins",
        "schema_version",
        "upstream",
    }
    if set(document) != required_top_level:
        raise InventoryError("inventory has unexpected or missing top-level fields")
    if document["schema_version"] != SCHEMA_VERSION:
        raise InventoryError("inventory schema_version is invalid")
    if document["certification_policy"] != {
        "candidate_classification_is_certification": False,
        "maximum_proven_state": "SOURCE_PRESENT",
        "ordinary_user_executable": False,
    }:
        raise InventoryError("inventory certification policy is invalid")

    upstream = document["upstream"]
    required_upstream_fields = {
        "commit",
        "repository",
        "root_pom_path",
        "root_pom_sha256",
        "source_manifest_path",
        "source_manifest_sha256",
        "source_tree",
        "tag",
        "upstream_lock_path",
        "upstream_lock_sha256",
    }
    if not isinstance(upstream, dict) or set(upstream) != required_upstream_fields:
        raise InventoryError("inventory upstream has unexpected or missing fields")
    if upstream["repository"] != UPSTREAM_REPOSITORY:
        raise InventoryError("inventory upstream repository is not Alibaba DataX")
    for field in ("commit", "source_tree"):
        value = upstream[field]
        if not isinstance(value, str) or SHA1_PATTERN.fullmatch(value) is None:
            raise InventoryError(f"inventory upstream {field} is invalid")
    tag = upstream["tag"]
    if not isinstance(tag, str) or TAG_PATTERN.fullmatch(tag) is None:
        raise InventoryError("inventory upstream tag is invalid")
    expected_upstream_paths = {
        "root_pom_path": "third_party/alibaba-datax/pom.xml",
        "source_manifest_path": "runtime/upstream-files.sha256",
        "upstream_lock_path": "runtime/upstream.lock.json",
    }
    for field, expected_path in expected_upstream_paths.items():
        if upstream[field] != expected_path:
            raise InventoryError(f"inventory upstream {field} is invalid")
    for field in (
        "root_pom_sha256",
        "source_manifest_sha256",
        "upstream_lock_sha256",
    ):
        value = upstream[field]
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            raise InventoryError(f"inventory upstream {field} is invalid")

    plugins = document["plugins"]
    if not isinstance(plugins, list) or not plugins:
        raise InventoryError("inventory plugins must be a non-empty list")
    plugin_count = document["plugin_count"]
    if not isinstance(plugin_count, int) or isinstance(plugin_count, bool):
        raise InventoryError("inventory plugin_count must be an integer")
    if plugin_count != len(plugins):
        raise InventoryError("inventory plugin_count does not match plugins")
    modules: set[str] = set()
    names: set[str] = set()
    paths: set[str] = set()
    modules_in_order: list[str] = []

    direction_counts: Counter[str] = Counter()
    required_plugin_fields = {
        "candidate_scope",
        "certification_state",
        "direction",
        "maven_artifact_id",
        "module",
        "module_pom_path",
        "module_pom_sha256",
        "ordinary_user_executable",
        "plugin_class",
        "plugin_json_path",
        "plugin_json_sha256",
        "plugin_name",
    }
    for plugin in plugins:
        if not isinstance(plugin, dict) or set(plugin) != required_plugin_fields:
            raise InventoryError("inventory plugin has unexpected or missing fields")
        module = plugin["module"]
        plugin_name = plugin["plugin_name"]
        if not isinstance(module, str) or not isinstance(plugin_name, str):
            raise InventoryError("inventory module and plugin_name must be strings")
        if MODULE_PATTERN.fullmatch(module) is None:
            raise InventoryError(f"inventory module is invalid: {module}")
        if PLUGIN_NAME_PATTERN.fullmatch(plugin_name) is None:
            raise InventoryError(f"inventory plugin name is invalid: {module}")
        plugin_class = plugin["plugin_class"]
        if (
            not isinstance(plugin_class, str)
            or PLUGIN_CLASS_PATTERN.fullmatch(plugin_class) is None
        ):
            raise InventoryError(f"inventory plugin class is invalid: {module}")
        modules_in_order.append(module)
        if module in modules or plugin_name.casefold() in names:
            raise InventoryError("inventory contains duplicate modules or plugin names")
        modules.add(module)
        names.add(plugin_name.casefold())
        if plugin["direction"] != _direction(module):
            raise InventoryError(f"inventory direction does not match module: {module}")
        direction_counts[plugin["direction"]] += 1
        if plugin["maven_artifact_id"] != module:
            raise InventoryError(f"inventory Maven artifact does not match module: {module}")
        if plugin_name.casefold() != module.casefold():
            raise InventoryError(f"inventory plugin name does not match module: {module}")
        expected_pom_path = f"third_party/alibaba-datax/{module}/pom.xml"
        expected_plugin_path = (
            f"third_party/alibaba-datax/{module}/src/main/resources/plugin.json"
        )
        if plugin["module_pom_path"] != expected_pom_path:
            raise InventoryError(f"inventory module POM path is invalid: {module}")
        if plugin["plugin_json_path"] != expected_plugin_path:
            raise InventoryError(f"inventory plugin.json path is invalid: {module}")
        for field in ("module_pom_sha256", "plugin_json_sha256"):
            value = plugin[field]
            if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
                raise InventoryError(f"inventory {field} is invalid: {module}")
        if plugin["plugin_json_path"] in paths:
            raise InventoryError("inventory contains duplicate plugin.json paths")
        paths.add(plugin["plugin_json_path"])
        if plugin["certification_state"] != "SOURCE_PRESENT":
            raise InventoryError(f"inventory certification exceeds source evidence: {module}")
        if plugin["ordinary_user_executable"] is not False:
            raise InventoryError(f"inventory exposes uncertified plugin: {module}")
        if plugin["candidate_scope"] != _candidate_scope(module):
            raise InventoryError(f"inventory candidate scope is invalid: {module}")

    if modules_in_order != sorted(modules_in_order):
        raise InventoryError("inventory plugins must be sorted by module")

    expected_direction_counts = {
        "READER": direction_counts["READER"],
        "WRITER": direction_counts["WRITER"],
    }
    raw_direction_counts = document["direction_counts"]
    if not isinstance(raw_direction_counts, dict) or set(raw_direction_counts) != {
        "READER",
        "WRITER",
    }:
        raise InventoryError("inventory direction_counts fields are invalid")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 1
        for value in raw_direction_counts.values()
    ):
        raise InventoryError("inventory direction_counts values are invalid")
    if raw_direction_counts != expected_direction_counts:
        raise InventoryError("inventory direction_counts do not match plugins")


def canonical_inventory_bytes(document: dict[str, Any]) -> bytes:
    validate_inventory_document(document)
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("utf-8")


def build_inventory_bytes(repo_root: Path) -> bytes:
    return canonical_inventory_bytes(build_inventory(repo_root))


def check_inventory(repo_root: Path, output_path: Path) -> bytes:
    expected = build_inventory_bytes(repo_root)
    actual_document = _load_json(output_path)
    actual = output_path.read_bytes()
    if actual != canonical_inventory_bytes(actual_document):
        raise InventoryError("checked-in upstream plugin inventory is not canonical JSON")
    if actual != expected:
        raise InventoryError("checked-in upstream plugin inventory is stale or tampered")
    return actual


def _write_atomically(output_path: Path, payload: bytes) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            delete=False,
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
        description="Generate the canonical inventory from locked upstream DataX source"
    )
    parser.add_argument("--repo-root", type=Path, default=repository)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
    )
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    output = arguments.output or arguments.repo_root / "runtime" / INVENTORY_FILENAME
    try:
        if arguments.check:
            payload = check_inventory(arguments.repo_root, output)
            code = "UPSTREAM_PLUGIN_INVENTORY_VALID"
        else:
            payload = build_inventory_bytes(arguments.repo_root)
            _write_atomically(output, payload)
            code = "UPSTREAM_PLUGIN_INVENTORY_WRITTEN"
        print(
            json.dumps(
                {
                    "code": code,
                    "plugin_count": json.loads(payload)["plugin_count"],
                    "ready": True,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
                sort_keys=True,
            )
        )
        return 0
    except (
        InventoryError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        print(
            json.dumps(
                {
                    "code": "UPSTREAM_PLUGIN_INVENTORY_INVALID",
                    "detail": str(exc),
                    "ready": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
