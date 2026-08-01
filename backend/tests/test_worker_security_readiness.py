from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

import datax_studio.api.readiness as readiness_module
from datax_studio.api.models import HealthStatus
from datax_studio.api.readiness import SystemReadinessProvider
from datax_studio.auth.db import Base
from datax_studio.core.db import SystemControl
from datax_studio.credentials.db import CredentialSecret
from datax_studio.egress_attestation import (
    EgressAttestationError,
    EgressVerification,
)
from datax_studio.settings import Settings


class _FixedEgressVerifier:
    def __init__(
        self,
        outcome: EgressVerification | EgressAttestationError,
    ) -> None:
        self.outcome = outcome
        self.calls = 0

    def verify_runtime(self) -> EgressVerification:
        self.calls += 1
        if isinstance(self.outcome, EgressAttestationError):
            raise self.outcome
        return self.outcome


def _egress_verification(
    *,
    now: datetime,
    policy_set_hash: str = "7" * 64,
    ruleset_hash: str = "8" * 64,
) -> EgressVerification:
    return EgressVerification(
        policy_engine_version="des-nftables-egress-v1",
        resolver_policy_version="des-system-dns-v1",
        network_namespace_id="net:[1234]",
        policy_set_hash=policy_set_hash,
        ruleset_hash=ruleset_hash,
        checked_at=now,
    )


def _readiness_engine(
    *,
    now: datetime,
    storage_checked_at: datetime | None = None,
    egress_checked_at: datetime | None = None,
):
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    assert SystemControl.__table__.metadata is Base.metadata
    # WorkTerminationRequest has a real foreign key to credential_secrets.
    # Register that owning model explicitly so this standalone SQLite fixture
    # represents the complete metadata dependency rather than relying on test
    # collection order from another credentials module.
    assert CredentialSecret.__table__.metadata is Base.metadata
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE alembic_version (
                    version_num TEXT PRIMARY KEY
                )
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO alembic_version (version_num)
                VALUES ('20260802_0017')
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE worker_heartbeats (
                    worker_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    code TEXT NOT NULL,
                    runtime_code TEXT NOT NULL,
                    oracle_code TEXT NOT NULL,
                    datax_release TEXT,
                    runtime_sha256 TEXT,
                    mysqlreader_plugin_sha256 TEXT,
                    postgresqlreader_plugin_sha256 TEXT,
                    mysqlwriter_plugin_sha256 TEXT,
                    postgresqlwriter_plugin_sha256 TEXT,
                    oracle_sha256 TEXT,
                    host_boot_id TEXT,
                    reconcile_epoch TEXT,
                    reconciled_at TIMESTAMP,
                    storage_code TEXT NOT NULL,
                    log_mount_identity_hash TEXT,
                    workspace_mount_identity_hash TEXT,
                    log_free_bytes BIGINT,
                    workspace_free_bytes BIGINT,
                    storage_checked_at TIMESTAMP,
                    egress_policy_set_hash TEXT,
                    egress_ruleset_hash TEXT,
                    egress_evidence_hash TEXT,
                    egress_checked_at TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL
                )
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO system_control (
                    singleton_id,
                    draining,
                    reason,
                    host_boot_id,
                    reconcile_epoch,
                    reconciled_at,
                    updated_at
                ) VALUES (
                    1,
                    false,
                    'READY',
                    'boot-security',
                    'epoch-security',
                    :reconciled_at,
                    :updated_at
                )
                """
            ),
            {"reconciled_at": now, "updated_at": now},
        )
        connection.execute(
            text(
                """
                INSERT INTO worker_heartbeats (
                    worker_id,
                    status,
                    code,
                    runtime_code,
                    oracle_code,
                    datax_release,
                    runtime_sha256,
                    mysqlreader_plugin_sha256,
                    postgresqlreader_plugin_sha256,
                    mysqlwriter_plugin_sha256,
                    postgresqlwriter_plugin_sha256,
                    oracle_sha256,
                    host_boot_id,
                    reconcile_epoch,
                    reconciled_at,
                    storage_code,
                    log_mount_identity_hash,
                    workspace_mount_identity_hash,
                    log_free_bytes,
                    workspace_free_bytes,
                    storage_checked_at,
                    egress_policy_set_hash,
                    egress_ruleset_hash,
                    egress_evidence_hash,
                    egress_checked_at,
                    updated_at
                ) VALUES (
                    'worker-1',
                    'READY',
                    'WORKER_READY',
                    'RUNTIME_OK',
                    'ORACLE_OK',
                    'datax_v202309',
                    :runtime_sha256,
                    :mysqlreader,
                    :postgresqlreader,
                    :mysqlwriter,
                    :postgresqlwriter,
                    :oracle_sha256,
                    'boot-security',
                    'epoch-security',
                    :reconciled_at,
                    'STORAGE_OK',
                    :log_mount_hash,
                    :workspace_mount_hash,
                    :log_free_bytes,
                    :workspace_free_bytes,
                    :storage_checked_at,
                    :egress_policy_set_hash,
                    :egress_ruleset_hash,
                    :egress_evidence_hash,
                    :egress_checked_at,
                    :updated_at
                )
                """
            ),
            {
                "runtime_sha256": "1" * 64,
                "mysqlreader": "2" * 64,
                "postgresqlreader": "3" * 64,
                "mysqlwriter": "4" * 64,
                "postgresqlwriter": "5" * 64,
                "oracle_sha256": "6" * 64,
                "reconciled_at": now,
                "log_mount_hash": "a" * 64,
                "workspace_mount_hash": "b" * 64,
                "log_free_bytes": 2 * 1024 * 1024 * 1024,
                "workspace_free_bytes": 2 * 1024 * 1024 * 1024,
                "storage_checked_at": storage_checked_at or now,
                "egress_policy_set_hash": "7" * 64,
                "egress_ruleset_hash": "8" * 64,
                "egress_evidence_hash": "9" * 64,
                "egress_checked_at": egress_checked_at or now,
                "updated_at": now,
            },
        )
    return engine


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        app_version="test",
        log_volume_path=tmp_path / "api-must-not-read-log-volume",
        workspace_volume_path=(
            tmp_path / "api-must-not-read-workspace-volume"
        ),
    )


def test_readiness_uses_fresh_worker_volume_and_egress_facts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    now = datetime.now(UTC)
    engine = _readiness_engine(now=now)
    verifier = _FixedEgressVerifier(_egress_verification(now=now))
    monkeypatch.setattr(
        readiness_module,
        "_current_boot_id",
        lambda: "boot-security",
    )
    settings = _settings(tmp_path)
    assert not settings.log_volume_path.exists()
    assert not settings.workspace_volume_path.exists()

    health = SystemReadinessProvider(
        settings,
        engine=engine,
        egress_verifier=verifier,
    ).check()

    assert verifier.calls == 1
    assert health.status == HealthStatus.UP
    assert health.components["log_volume"].code == "LOG_VOLUME_OK"
    assert (
        health.components["workspace_volume"].code
        == "WORKSPACE_VOLUME_OK"
    )
    assert health.components["egress_policy"].code == "EGRESS_POLICY_VERIFIED"


def test_direct_egress_recheck_failure_keeps_management_plane_degraded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    now = datetime.now(UTC)
    engine = _readiness_engine(now=now)
    verifier = _FixedEgressVerifier(
        EgressAttestationError("EGRESS_NETWORK_NAMESPACE_MISMATCH")
    )
    monkeypatch.setattr(
        readiness_module,
        "_current_boot_id",
        lambda: "boot-security",
    )

    health = SystemReadinessProvider(
        _settings(tmp_path),
        engine=engine,
        egress_verifier=verifier,
    ).check()

    assert verifier.calls == 1
    assert health.status == HealthStatus.DEGRADED
    assert health.components["postgres"].status == HealthStatus.UP
    assert health.components["egress_policy"].status == HealthStatus.DOWN
    assert (
        health.components["egress_policy"].code
        == "EGRESS_NETWORK_NAMESPACE_MISMATCH"
    )


def test_readiness_rejects_divergent_or_stale_worker_security_facts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    now = datetime.now(UTC)
    stale_engine = _readiness_engine(
        now=now,
        storage_checked_at=now - timedelta(minutes=1),
    )
    monkeypatch.setattr(
        readiness_module,
        "_current_boot_id",
        lambda: "boot-security",
    )
    stale = SystemReadinessProvider(
        _settings(tmp_path),
        engine=stale_engine,
        egress_verifier=_FixedEgressVerifier(
            _egress_verification(now=now)
        ),
    ).check()
    assert stale.status == HealthStatus.DEGRADED
    assert (
        stale.components["log_volume"].code
        == "LOG_VOLUME_ATTESTATION_STALE"
    )
    assert stale.components["worker"].status == HealthStatus.DOWN

    diverged_engine = _readiness_engine(now=now)
    diverged = SystemReadinessProvider(
        _settings(tmp_path),
        engine=diverged_engine,
        egress_verifier=_FixedEgressVerifier(
            _egress_verification(now=now, ruleset_hash="f" * 64)
        ),
    ).check()
    assert diverged.status == HealthStatus.DEGRADED
    assert (
        diverged.components["egress_policy"].code
        == "EGRESS_ATTESTATION_DIVERGED"
    )
