from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import UUID, uuid4

import pytest
import rfc8785
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from datax_studio.api.models import ComponentHealth, HealthResponse, HealthStatus
from datax_studio.api.readiness import SystemReadinessProvider, _AuditReplayResult
from datax_studio.auth.db import AuditChainWatermark, AuditEvent, Base, Organization
from datax_studio.settings import Settings


def _audit_event(
    *,
    organization_id: UUID,
    event_id: UUID,
    now: datetime,
) -> tuple[dict[str, object], str]:
    event_json: dict[str, object] = {
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
    event_hash = hashlib.sha256(prefix + rfc8785.dumps(event_json)).hexdigest()
    integrity = event_json["integrity"]
    assert isinstance(integrity, dict)
    integrity["event_hash"] = event_hash
    return event_json, event_hash


def test_readiness_uses_watermarks_and_periodically_replays_audit_history() -> None:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    provider = SystemReadinessProvider(
        Settings(
            app_version="test",
            audit_integrity_full_replay_max_age_seconds=10,
        ),
        engine=engine,
    )

    empty = provider._audit_chain()
    assert empty.status == HealthStatus.UP
    assert empty.code == "AUDIT_CHAIN_EMPTY_BOOTSTRAP_ALLOWED"

    now = datetime.now(UTC)
    organization_id = uuid4()
    event_id = uuid4()
    event_json, event_hash = _audit_event(
        organization_id=organization_id,
        event_id=event_id,
        now=now,
    )
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
                event_json=event_json,
                canonicalization_version="RFC8785-v1",
                previous_hash=None,
                event_hash=event_hash,
                occurred_at=now,
                expires_at=now + timedelta(days=730),
            )
        )
        # Migration backfill is deliberately unverified.  The first readiness
        # replay, rather than the migration itself, is allowed to mark PASS.
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

    initial = provider._audit_chain()
    assert initial.status == HealthStatus.UP, initial
    assert initial.code == "AUDIT_CHAIN_FULL_REPLAY_VERIFIED"

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

    event.listen(engine, "before_cursor_execute", capture_sql)
    try:
        normal = provider._audit_chain()
    finally:
        event.remove(engine, "before_cursor_execute", capture_sql)
    assert normal.status == HealthStatus.UP
    assert normal.code == "AUDIT_CHAIN_VERIFIED_WATERMARK"
    audit_queries = [statement for statement in statements if "audit_events" in statement]
    assert audit_queries
    assert all("event_json" not in statement for statement in audit_queries)

    # A tail-only read cannot detect old-history tampering.  Expire the durable
    # full-replay proof and prove that the bounded full replay fails closed.
    with sessions.begin() as session:
        watermark = session.get(AuditChainWatermark, organization_id)
        row = session.get(AuditEvent, event_id)
        assert watermark is not None and row is not None
        watermark.full_replay_finished_at = now - timedelta(seconds=11)
        tampered = dict(row.event_json)
        tampered["metadata"] = {"tampered": True}
        row.event_json = tampered

    # The prior successful full replay legitimately scheduled the next periodic
    # replay.  Simulate that cadence window elapsing before exercising the
    # corruption detection path below.
    provider._next_full_audit_replay_at = 0.0
    invalid = provider._audit_chain()
    assert invalid.status == HealthStatus.DOWN
    assert invalid.code == "AUDIT_CHAIN_HASH_INVALID"

    sticky_failure = provider._audit_chain()
    assert sticky_failure.status == HealthStatus.DOWN
    assert sticky_failure.code == "AUDIT_CHAIN_VERIFICATION_FAILED"


def test_readiness_fails_closed_when_organization_has_no_watermark() -> None:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(UTC)
    with sessions.begin() as session:
        session.add(
            Organization(
                id=uuid4(),
                name="Missing State",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
                row_version=1,
            )
        )

    health = SystemReadinessProvider(Settings(app_version="test"), engine=engine)._audit_chain()

    assert health.status == HealthStatus.DOWN
    assert health.code == "AUDIT_CHAIN_STATE_MISSING"


def test_failed_full_replay_is_throttled_before_another_expensive_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(UTC)
    organization_id = uuid4()
    with sessions.begin() as session:
        session.add(
            Organization(
                id=organization_id,
                name="Replay throttle",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
                row_version=1,
            )
        )
        session.add(
            AuditChainWatermark(
                organization_id=organization_id,
                head_sequence=0,
                head_hash=None,
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
    provider = SystemReadinessProvider(
        Settings(
            app_version="test",
            audit_integrity_full_replay_max_age_seconds=60,
        ),
        engine=engine,
    )
    attempted: list[bool] = []

    def timeout_replay(*_args: object, **_kwargs: object) -> _AuditReplayResult:
        attempted.append(True)
        return _AuditReplayResult(
            success=False,
            code="AUDIT_CHAIN_REPLAY_TIMEOUT",
        )

    monkeypatch.setattr(provider, "_validate_audit_snapshot", timeout_replay)

    first = provider._audit_chain()
    second = provider._audit_chain()

    assert first.code == "AUDIT_CHAIN_REPLAY_TIMEOUT"
    assert second.status == HealthStatus.DOWN
    assert second.code == "AUDIT_CHAIN_FULL_REPLAY_THROTTLED"
    assert attempted == [True]


def test_audit_watermark_replay_result_is_compare_and_set() -> None:
    """A stale verification cannot overwrite a newer append watermark."""

    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(UTC)
    organization_id = uuid4()
    event_id = uuid4()
    event_json, event_hash = _audit_event(
        organization_id=organization_id,
        event_id=event_id,
        now=now,
    )
    with sessions.begin() as session:
        session.add(
            Organization(
                id=organization_id,
                name="CAS State",
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

    provider = SystemReadinessProvider(Settings(app_version="test"), engine=engine)
    snapshot = provider._read_audit_snapshot()
    with sessions.begin() as session:
        watermark = session.get(AuditChainWatermark, organization_id)
        assert watermark is not None
        watermark.mutation_epoch += 1

    assert not provider._publish_verified_audit_snapshot(snapshot, full_replay=True)
    with sessions() as session:
        watermark = session.scalar(
            select(AuditChainWatermark).where(
                AuditChainWatermark.organization_id == organization_id
            )
        )
    assert watermark is not None
    assert watermark.integrity_status == "PENDING"
    assert watermark.verified_sequence == 0


def test_readiness_check_is_singleflight_and_caches_a_fresh_result(
    monkeypatch: object,
) -> None:
    provider = SystemReadinessProvider(
        Settings(app_version="test", readiness_cache_seconds=5),
        engine=create_engine("sqlite+pysqlite://"),
    )
    started = Event()
    release = Event()
    calls = 0
    expected = HealthResponse(
        status=HealthStatus.UP,
        version="test",
        checked_at=datetime.now(UTC),
        components={
            "audit_chain": ComponentHealth(
                status=HealthStatus.UP,
                code="AUDIT_CHAIN_VERIFIED_WATERMARK",
            )
        },
    )

    def slow_check_once() -> HealthResponse:
        nonlocal calls
        calls += 1
        started.set()
        assert release.wait(timeout=2)
        return expected

    monkeypatch.setattr(provider, "_check_once", slow_check_once)  # type: ignore[attr-defined]
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(provider.check)
        assert started.wait(timeout=1)
        rejected = provider.check()
        release.set()
        assert first.result(timeout=2) is expected

    assert rejected.status == HealthStatus.DOWN
    assert rejected.components["readiness"].code == "READINESS_CHECK_IN_PROGRESS"
    assert provider.check() is expected
    assert calls == 1
