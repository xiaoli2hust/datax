from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import rfc8785
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from datax_studio.api.models import HealthStatus
from datax_studio.api.readiness import SystemReadinessProvider
from datax_studio.auth.db import AuditChainWatermark, AuditEvent, Base, Organization
from datax_studio.settings import Settings

POSTGRES_URL = os.getenv("DATAX_MIGRATION_POSTGRES_TEST_URL")
pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="DATAX_MIGRATION_POSTGRES_TEST_URL is not configured",
)


def _valid_event(
    *, organization_id: str, event_id: str, occurred_at: datetime
) -> tuple[dict[str, object], str]:
    event_json: dict[str, object] = {
        "schema_version": "1.0",
        "event_id": event_id,
        "organization_id": organization_id,
        "sequence": 1,
        "project_id": None,
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
        "action": "SYSTEM_BOOTSTRAP_ADMIN",
        "actor": {"kind": "SYSTEM", "user_id": None, "display_name": None},
        "target": {"type": "USER", "id": None, "name": None},
        "request": {
            "request_id": str(uuid4()),
            "source_ip": None,
            "user_agent": None,
        },
        "outcome": "SUCCEEDED",
        "reason_code": None,
        "changes": {
            "before_hash": None,
            "after_hash": None,
            "changed_fields": [],
        },
        "metadata": {},
        "integrity": {
            "algorithm": "SHA-256",
            "canonicalization": "RFC8785",
            "chain_scope": "ORGANIZATION_SEQUENCE",
            "previous_hash": None,
        },
    }
    prefix = f"DXAUDITv1\n{organization_id}\n1\n{'0' * 64}\n".encode()
    event_hash = hashlib.sha256(prefix + rfc8785.dumps(event_json)).hexdigest()
    integrity = event_json["integrity"]
    assert isinstance(integrity, dict)
    integrity["event_hash"] = event_hash
    return event_json, event_hash


def test_postgres_readiness_replays_pending_watermark_in_repeatable_read() -> None:
    assert POSTGRES_URL is not None
    schema = f"audit_readiness_{uuid4().hex}"
    administration = create_engine(POSTGRES_URL, pool_pre_ping=True)
    engine: Engine | None = None
    try:
        with administration.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_engine(
            POSTGRES_URL,
            pool_pre_ping=True,
            connect_args={"options": f"-csearch_path={schema}"},
        )
        Base.metadata.create_all(
            engine,
            tables=[
                Organization.__table__,
                AuditEvent.__table__,
                AuditChainWatermark.__table__,
            ],
        )
        sessions = sessionmaker(bind=engine, expire_on_commit=False)
        now = datetime.now(UTC)
        organization_id = uuid4()
        event_id = uuid4()
        event_json, event_hash = _valid_event(
            organization_id=str(organization_id),
            event_id=str(event_id),
            occurred_at=now,
        )
        with sessions.begin() as session:
            session.add(
                Organization(
                    id=organization_id,
                    name="PostgreSQL audit readiness",
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                )
            )
            session.flush()
            session.add(
                AuditEvent(
                    id=event_id,
                    organization_id=organization_id,
                    organization_sequence=1,
                    project_id=None,
                    event_json=event_json,
                    canonicalization_version="RFC8785-v1",
                    previous_hash=None,
                    event_hash=event_hash,
                    occurred_at=now,
                    expires_at=now + timedelta(days=730),
                )
            )
            session.add(
                AuditChainWatermark(
                    organization_id=organization_id,
                    head_sequence=1,
                    head_hash=event_hash,
                    verified_sequence=0,
                    verified_hash=None,
                    full_replay_sequence=0,
                    full_replay_hash=None,
                    full_replay_finished_at=None,
                    integrity_status="PENDING",
                    failure_code=None,
                    failure_sequence=None,
                    mutation_epoch=0,
                    updated_at=now,
                )
            )

        statements: list[str] = []

        def capture_sql(
            _connection: object,
            _cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: object,
        ) -> None:
            statements.append(statement.lower())

        provider = SystemReadinessProvider(
            Settings(
                app_version="test",
                audit_integrity_full_replay_max_age_seconds=60,
                audit_integrity_replay_timeout_seconds=5,
            ),
            engine=engine,
        )
        event.listen(engine, "before_cursor_execute", capture_sql)
        try:
            health = provider._audit_chain()
        finally:
            event.remove(engine, "before_cursor_execute", capture_sql)

        assert health.status == HealthStatus.UP
        assert health.code == "AUDIT_CHAIN_FULL_REPLAY_VERIFIED"
        assert any("set_config" in statement for statement in statements)
        with sessions() as session:
            watermark = session.get(AuditChainWatermark, organization_id)
            assert watermark is not None
            assert watermark.integrity_status == "PASSED"
            assert watermark.verified_sequence == watermark.full_replay_sequence == 1
            assert watermark.verified_hash == watermark.full_replay_hash == event_hash
            assert watermark.full_replay_finished_at is not None
    finally:
        if engine is not None:
            engine.dispose()
        with administration.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        administration.dispose()
