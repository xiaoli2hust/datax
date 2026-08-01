from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import rfc8785
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from datax_studio.api.models import HealthStatus
from datax_studio.api.readiness import SystemReadinessProvider
from datax_studio.auth.db import AuditEvent, Base, Organization
from datax_studio.settings import Settings


def test_readiness_verifies_empty_valid_and_tampered_audit_chains() -> None:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    provider = SystemReadinessProvider(
        Settings(app_version="test"),
        engine=engine,
    )

    empty = provider._audit_chain()
    assert empty.status == HealthStatus.UP
    assert empty.code == "AUDIT_CHAIN_EMPTY_BOOTSTRAP_ALLOWED"

    now = datetime.now(UTC)
    organization_id = uuid4()
    event_id = uuid4()
    event = {
        "schema_version": "1.0",
        "event_id": str(event_id),
        "organization_id": str(organization_id),
        "sequence": 1,
        "project_id": None,
        "occurred_at": now.isoformat().replace("+00:00", "Z"),
        "action": "SYSTEM_BOOTSTRAP_ADMIN",
        "actor": {
            "kind": "SYSTEM",
            "user_id": None,
            "display_name": None,
        },
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
    prefix = (
        "DXAUDITv1\n"
        f"{organization_id}\n"
        "1\n"
        f"{'0' * 64}\n"
    ).encode()
    event_hash = hashlib.sha256(prefix + rfc8785.dumps(event)).hexdigest()
    event["integrity"]["event_hash"] = event_hash
    with sessions.begin() as session:
        session.add(
            Organization(
                id=organization_id,
                name="Audit Test",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
                row_version=1,
            )
        )
        session.add(
            AuditEvent(
                id=event_id,
                organization_id=organization_id,
                organization_sequence=1,
                project_id=None,
                event_json=event,
                canonicalization_version="RFC8785-v1",
                previous_hash=None,
                event_hash=event_hash,
                occurred_at=now,
                expires_at=now + timedelta(days=730),
            )
        )

    valid = provider._audit_chain()
    assert valid.status == HealthStatus.UP, valid
    assert valid.code == "AUDIT_CHAIN_VERIFIED"

    with sessions.begin() as session:
        row = session.get(AuditEvent, event_id)
        assert row is not None
        tampered = dict(row.event_json)
        tampered["metadata"] = {"tampered": True}
        row.event_json = tampered

    invalid = provider._audit_chain()
    assert invalid.status == HealthStatus.DOWN
    assert invalid.code == "AUDIT_CHAIN_HASH_INVALID"
