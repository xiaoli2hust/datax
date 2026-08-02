from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

from datax_studio.settings import Settings


def _migration_module() -> ModuleType:
    path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "20260802_0018_audit_chain_watermarks.py"
    )
    spec = importlib.util.spec_from_file_location("audit_chain_watermarks_0018", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0018_backfills_only_audit_heads_as_pending_and_is_reversible() -> None:
    engine = sa.create_engine("sqlite+pysqlite://")
    metadata = sa.MetaData()
    organizations = sa.Table(
        "organizations",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
    )
    audit_events = sa.Table(
        "audit_events",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("organization_sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
    )
    metadata.create_all(engine)
    organization_with_history = str(uuid4())
    organization_without_history = str(uuid4())
    with engine.begin() as connection:
        connection.execute(
            organizations.insert(),
            [
                {"id": organization_with_history},
                {"id": organization_without_history},
            ],
        )
        connection.execute(
            audit_events.insert(),
            [
                {
                    "id": str(uuid4()),
                    "organization_id": organization_with_history,
                    "organization_sequence": 1,
                    "event_hash": "a" * 64,
                },
                {
                    "id": str(uuid4()),
                    "organization_id": organization_with_history,
                    "organization_sequence": 2,
                    "event_hash": "b" * 64,
                },
            ],
        )

    module = _migration_module()
    with engine.begin() as connection:
        module.op = Operations(MigrationContext.configure(connection))
        module.upgrade()
        rows = connection.execute(
            sa.text(
                """
                SELECT organization_id, head_sequence, head_hash,
                       verified_sequence, verified_hash,
                       full_replay_sequence, full_replay_hash,
                       full_replay_finished_at, integrity_status,
                       failure_code, failure_sequence, mutation_epoch
                FROM audit_chain_watermarks
                ORDER BY organization_id
                """
            )
        ).mappings()
        state = {str(row["organization_id"]): row for row in rows}

        history = state[organization_with_history]
        assert history["head_sequence"] == 2
        assert history["head_hash"] == "b" * 64
        assert history["verified_sequence"] == 0
        assert history["verified_hash"] is None
        assert history["full_replay_sequence"] == 0
        assert history["full_replay_hash"] is None
        assert history["full_replay_finished_at"] is None
        assert history["integrity_status"] == "PENDING"
        assert history["failure_code"] is None
        assert history["failure_sequence"] is None
        assert history["mutation_epoch"] == 0

        empty = state[organization_without_history]
        assert empty["head_sequence"] == 0
        assert empty["head_hash"] is None
        assert empty["integrity_status"] == "PENDING"

        module.downgrade()
        assert "audit_chain_watermarks" not in sa.inspect(connection).get_table_names()

    assert module.revision == "20260802_0018"
    assert module.down_revision == "20260802_0017"
    assert Settings().database_schema_revision == "20260802_0021"
