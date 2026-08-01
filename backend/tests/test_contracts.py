from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator
from openapi_spec_validator import validate
from openapi_spec_validator.readers import read_from_filename

from datax_studio.api.app import create_app

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = REPOSITORY_ROOT / "docs" / "contracts"
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def test_openapi_is_structurally_valid_with_all_local_references() -> None:
    specification, base_uri = read_from_filename(
        str(CONTRACT_ROOT / "openapi.yaml")
    )

    validate(specification, base_uri=base_uri)


def test_openapi_operation_set_exactly_matches_registered_routes() -> None:
    specification, _ = read_from_filename(
        str(CONTRACT_ROOT / "openapi.yaml")
    )
    methods = {"get", "post", "put", "patch", "delete"}
    contracted = {
        (method.upper(), path)
        for path, path_item in specification["paths"].items()
        for method in path_item
        if method in methods
    }
    generated = create_app().openapi()
    assert all(path.startswith("/api/v1/") for path in generated["paths"])
    registered = {
        (method.upper(), path.removeprefix("/api/v1"))
        for path, path_item in generated["paths"].items()
        for method in path_item
        if method in methods
    }
    assert registered == contracted


def test_datasource_patch_and_pagination_contract_cover_immutable_edits() -> None:
    specification, _ = read_from_filename(
        str(CONTRACT_ROOT / "openapi.yaml")
    )
    patch_properties = set(
        specification["components"]["schemas"]["DatasourcePatch"][
            "properties"
        ]
    )
    assert {
        "endpoint_policy_id",
        "engine",
        "host",
        "port",
        "database_name",
        "default_schema",
        "username",
        "ssl_mode",
        "password",
    } <= patch_properties
    for path in (
        "/projects/{project_id}/datasources",
        "/datasources/{datasource_id}/schema/tables",
    ):
        parameters = specification["paths"][path]["get"]["parameters"]
        assert any(
            item.get("$ref") == "#/components/parameters/Cursor"
            for item in parameters
        )
    metadata_parameters = specification["paths"][
        "/datasources/{datasource_id}/schema/tables"
    ]["get"]["parameters"]
    usage = next(item for item in metadata_parameters if item.get("name") == "usage")
    assert usage["required"] is True
    assert usage["schema"]["enum"] == ["SOURCE_USE", "TARGET_USE"]


def test_all_json_schemas_are_valid_draft_2020_12_schemas() -> None:
    schema_paths = sorted(CONTRACT_ROOT.glob("*.schema.json"))
    assert schema_paths

    for schema_path in schema_paths:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)


def test_runtime_generation_schema_separates_legacy_and_generation_objects() -> None:
    schema = json.loads(
        (CONTRACT_ROOT / "runtime-generation.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    generation_id = "a" * 32
    base = {
        "schema_version": "1.0",
        "generation_id": generation_id,
        "installation_id": "b" * 64,
        "source": "FRESH",
        "restore_journal_id": None,
        "secret_directory": f"generations/{generation_id}/secrets",
        "volumes": {
            "postgres": f"des-postgres-{generation_id}",
            "logs": f"des-log-{generation_id}",
            "workspace": f"des-workspace-{generation_id}",
        },
        "committed_at": "2026-08-01T09:30:00Z",
        "state_sha256": "c" * 64,
    }
    assert validator.is_valid(base)

    fresh_with_legacy_objects = {
        **base,
        "secret_directory": "secrets",
        "volumes": {
            "postgres": "des-postgres-data",
            "logs": "des-log-data",
            "workspace": "des-workspace-data",
        },
    }
    assert not validator.is_valid(fresh_with_legacy_objects)

    legacy_with_generation_objects = {**base, "source": "LEGACY"}
    assert not validator.is_valid(legacy_with_generation_objects)


def test_literal_audit_actions_are_declared_by_the_machine_contract() -> None:
    schema = json.loads(
        (CONTRACT_ROOT / "audit-event.v1.schema.json").read_text(encoding="utf-8")
    )
    allowed = set(schema["properties"]["action"]["enum"])
    used: set[str] = set()
    dynamic: list[str] = []

    def literal_values(node: ast.expr) -> set[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, ast.IfExp):
            return literal_values(node.body) | literal_values(node.orelse)
        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            dynamic.append(ast.unparse(node))
        return set()

    for source_path in (REPOSITORY_ROOT / "backend" / "src").rglob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            function_name = (
                call.func.attr
                if isinstance(call.func, ast.Attribute)
                else call.func.id
                if isinstance(call.func, ast.Name)
                else ""
            )
            if function_name != "_append_audit":
                continue
            for keyword in call.keywords:
                if keyword.arg != "action":
                    continue
                used.update(literal_values(keyword.value))
    assert used
    assert not dynamic, sorted(dynamic)
    assert used <= allowed, sorted(used - allowed)


def test_repository_markdown_local_links_resolve() -> None:
    excluded_parts = {
        ".git",
        ".runtime",
        ".venv",
        "node_modules",
        "target",
        "third_party",
    }
    missing: list[str] = []
    for markdown_path in REPOSITORY_ROOT.rglob("*.md"):
        relative = markdown_path.relative_to(REPOSITORY_ROOT)
        if any(part in excluded_parts for part in relative.parts):
            continue
        text = markdown_path.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(text):
            target = match.group(1).strip()
            if target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            if " " in target and not target.startswith("<"):
                target = target.split(" ", 1)[0]
            path_part = target.strip("<>").split("#", 1)[0]
            if path_part and not (markdown_path.parent / path_part).exists():
                missing.append(f"{relative}: {target}")
    assert not missing, "\n".join(missing)
