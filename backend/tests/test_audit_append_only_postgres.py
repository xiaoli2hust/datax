from __future__ import annotations

import os
from uuid import UUID

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

POSTGRES_URL = os.getenv("DATAX_MIGRATION_POSTGRES_TEST_URL")
pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="DATAX_MIGRATION_POSTGRES_TEST_URL is not configured",
)


def test_audit_events_reject_update_delete_and_truncate() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    organization_id = UUID("00000000-0000-0000-0000-000000000101")
    event_id = UUID("00000000-0000-0000-0000-000000000102")

    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO organizations
                    (id, name, status, created_at, updated_at, row_version)
                VALUES
                    (:id, 'append-only-test', 'ACTIVE',
                     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)
                """
            ),
            {"id": organization_id},
        )
        connection.execute(
            text(
                """
                INSERT INTO audit_events
                    (
                        id, organization_id, organization_sequence, project_id,
                        event_json, canonicalization_version, previous_hash,
                        event_hash, occurred_at, expires_at
                    )
                VALUES
                    (
                        :event_id, :organization_id, 1, NULL,
                        CAST('{}' AS jsonb), 'RFC8785-v1', NULL,
                        repeat('0', 64), CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP + interval '730 days'
                    )
                """
            ),
            {
                "event_id": event_id,
                "organization_id": organization_id,
            },
        )

    statements = (
        "UPDATE audit_events SET organization_sequence = 2",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    )
    for statement in statements:
        with (
            pytest.raises(DBAPIError, match="audit_events is append-only"),
            engine.begin() as connection,
        ):
            connection.execute(text(statement))

    with engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one()
            == 1
        )
