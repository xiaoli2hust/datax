from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

import pytest

from datax_studio.core.schemas import JobSpecV1
from datax_studio.schema_snapshot import SchemaSnapshot, schema_snapshot_hash
from datax_studio.worker.schema_probe import (
    SchemaProbeError,
    assert_snapshot_matches_job,
    logical_type_for_native,
    physical_table_identity_hash,
)


def _snapshot() -> SchemaSnapshot:
    return SchemaSnapshot.model_validate(
        {
            "schema_version": "1.0",
            "normalization_version": "1.0",
            "engine": "POSTGRESQL_15",
            "physical_endpoint_identity_id": str(uuid4()),
            "physical_table_identity_hash": "a" * 64,
            "identifier_case_mode": "POSTGRESQL_FOLDED_OR_QUOTED",
            "catalog_name": "warehouse",
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
            "constraints": [],
            "triggers": [],
            "table_options": {
                "partitioned": False,
                "row_security_enabled": False,
            },
        }
    )


def _spec() -> JobSpecV1:
    return JobSpecV1.model_validate(
        {
            "schema_version": "1.0",
            "source": {
                "datasource_id": str(uuid4()),
                "datasource_revision_id": str(uuid4()),
                "plugin_name": "postgresqlreader",
                "table": {"schema_name": "public", "table_name": "source"},
            },
            "target": {
                "datasource_id": str(uuid4()),
                "datasource_revision_id": str(uuid4()),
                "plugin_name": "postgresqlwriter",
                "table": {"schema_name": "public", "table_name": "orders"},
            },
            "selection_mode": "ALL_COLUMNS",
            "mappings": [
                {
                    "source_column": "id",
                    "source_ordinal": 1,
                    "source_type": "bigint",
                    "source_nullable": False,
                    "target_column": "id",
                    "target_ordinal": 1,
                    "target_type": "bigint",
                    "target_nullable": False,
                    "oracle_logical_type": "INTEGER",
                    "compatibility": "EXACT",
                }
            ],
            "source_consistency_mode": "OPERATOR_QUIESCED",
            "target_precondition": "EMPTY_AND_VERIFIABLE",
            "write_semantics": "INSERT_ONLY_ONCE",
            "duplicate_policy": "REJECT_NONEMPTY_TARGET",
            "partial_write_policy": "MANUAL_REMEDIATE",
            "write_policy": {
                "mode": "INSERT",
                "target_table_must_exist": True,
                "target_table_must_be_empty": True,
                "platform_may_mutate_target_before_run": False,
            },
            "execution_policy": {
                "channel": 1,
                "timeout_seconds": 600,
                "dirty_data_limit": {"record_count": 0, "percentage": 0},
            },
        }
    )


@pytest.mark.parametrize(
    ("engine", "native_type", "logical_type"),
    [
        ("MYSQL_8", "tinyint(1)", "BOOLEAN"),
        ("MYSQL_8", "decimal(38, 10) unsigned", "DECIMAL"),
        ("POSTGRESQL_15", "timestamp(6) without time zone", "TIMESTAMP"),
        ("POSTGRESQL_15", "character varying(128)", "TEXT"),
        ("POSTGRESQL_15", "bytea", "BINARY"),
    ],
)
def test_native_type_mapping_is_closed_and_deterministic(
    engine: str,
    native_type: str,
    logical_type: str,
) -> None:
    assert logical_type_for_native(engine, native_type) == logical_type  # type: ignore[arg-type]


@pytest.mark.parametrize("native_type", ["float", "double precision", "jsonb", "uuid"])
def test_uncertified_types_fail_closed(native_type: str) -> None:
    with pytest.raises(SchemaProbeError):
        logical_type_for_native("POSTGRESQL_15", native_type)


def test_physical_table_hash_is_domain_separated_and_identifier_sensitive() -> None:
    endpoint_id = uuid4()
    first = physical_table_identity_hash(
        physical_endpoint_identity_id=endpoint_id,
        engine="POSTGRESQL_15",
        catalog_name="warehouse",
        schema_name="public",
        table_name="orders",
    )
    second = physical_table_identity_hash(
        physical_endpoint_identity_id=endpoint_id,
        engine="POSTGRESQL_15",
        catalog_name="warehouse",
        schema_name="public",
        table_name="Orders",
    )

    assert len(first) == 64
    assert first != second


def test_preflight_recomputes_hash_and_mapping_contract() -> None:
    snapshot = _snapshot()

    assert_snapshot_matches_job(
        snapshot,
        expected_hash=schema_snapshot_hash(snapshot),
        spec=_spec(),
        side="target",
    )

    drifted = deepcopy(snapshot.model_dump(mode="json"))
    drifted["columns"][0]["logical_type"] = "TEXT"
    drifted_snapshot = SchemaSnapshot.model_validate(drifted)
    with pytest.raises(SchemaProbeError, match="SCHEMA_DRIFT_DETECTED"):
        assert_snapshot_matches_job(
            drifted_snapshot,
            expected_hash=schema_snapshot_hash(snapshot),
            spec=_spec(),
            side="target",
        )
