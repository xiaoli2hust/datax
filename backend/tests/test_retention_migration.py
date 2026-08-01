from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from datax_studio.settings import Settings


def _migration_module() -> ModuleType:
    path = (
        Path(__file__).parents[1] / "migrations" / "versions" / "20260731_0014_retention_holds.py"
    )
    spec = importlib.util.spec_from_file_location(
        "retention_holds_0014",
        path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0014_is_linear_and_settings_require_it() -> None:
    module = _migration_module()

    assert module.revision == "20260731_0014"
    assert module.down_revision == "20260731_0013"
    assert Settings().database_schema_revision == "20260731_0014"


def test_0014_persists_hold_scope_release_and_expiry_constraints() -> None:
    source = (
        Path(__file__).parents[1] / "migrations" / "versions" / "20260731_0014_retention_holds.py"
    ).read_text(encoding="utf-8")

    assert "retention_holds" in source
    assert "ORGANIZATION" in source
    assert "PROJECT" in source
    assert "EXECUTION" in source
    assert "AUDIT_EVENT" in source
    assert "ck_retention_holds_release_pair" in source
    assert "ck_retention_holds_expiry" in source
