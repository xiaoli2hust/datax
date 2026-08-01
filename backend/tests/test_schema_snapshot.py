from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from datax_studio.schema_snapshot import (
    schema_snapshot_hash,
    validate_schema_snapshot,
)


def _snapshot() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "normalization_version": "1.0",
        "engine": "POSTGRESQL_15",
        "physical_endpoint_identity_id": "11111111-1111-4111-8111-111111111111",
        "physical_table_identity_hash": "1" * 64,
        "identifier_case_mode": "POSTGRESQL_FOLDED_OR_QUOTED",
        "catalog_name": "app",
        "schema_name": "public",
        "table_name": "orders",
        "table_kind": "BASE_TABLE",
        "columns": [
            {
                "ordinal_position": 1,
                "name": "id",
                "native_type": "bigint",
                "logical_type": "INTEGER",
                "nullable": False,
                "unsigned": False,
                "generated": False,
                "identity": False,
                "character_maximum_length": None,
                "numeric_precision": 64,
                "numeric_scale": 0,
                "datetime_precision": None,
                "character_set_name": None,
                "collation_name": None,
                "default_present": False,
                "default_expression_sha256": None,
            }
        ],
        "constraints": [
            {
                "kind": "PRIMARY_KEY",
                "columns": ["id"],
                "enforced": True,
                "definition_sha256": "2" * 64,
                "referenced_physical_table_identity_hash": None,
            }
        ],
        "triggers": [],
        "table_options": {
            "partitioned": False,
            "row_security_enabled": False,
        },
    }


def test_hash_is_domain_separated_and_deterministic() -> None:
    first = _snapshot()
    reordered = {key: first[key] for key in reversed(first)}

    assert schema_snapshot_hash(first) == schema_snapshot_hash(reordered)
    assert schema_snapshot_hash(first) == (
        "ff45da03215ca94bc0af20658f0db971e9e70bc9057440671a1b527a068cb8ff"
    )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("columns", 0, "ordinal_position"), 2),
        (("columns", 0, "logical_type"), "FLOAT"),
        (("table_options", "row_security_enabled"), None),
    ],
)
def test_ambiguous_or_unverifiable_shapes_are_rejected(
    path: tuple[str | int, ...],
    value: object,
) -> None:
    snapshot = deepcopy(_snapshot())
    target: object = snapshot
    for segment in path[:-1]:
        target = target[segment]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]

    with pytest.raises(ValidationError):
        validate_schema_snapshot(snapshot)


def test_unknown_constraint_column_is_rejected() -> None:
    snapshot = _snapshot()
    constraints = snapshot["constraints"]
    assert isinstance(constraints, list)
    constraints[0]["columns"] = ["missing"]

    with pytest.raises(ValidationError, match="unknown column"):
        validate_schema_snapshot(snapshot)
