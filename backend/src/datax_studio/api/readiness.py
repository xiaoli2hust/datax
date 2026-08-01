from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from uuid import UUID

import rfc8785
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from datax_studio.api.models import ComponentHealth, HealthResponse, HealthStatus
from datax_studio.egress_attestation import (
    EgressAttestationError,
    EgressVerifier,
    LoopbackEgressAttestationClient,
)
from datax_studio.settings import Settings


class ReadinessProvider(Protocol):
    def check(self) -> HealthResponse: ...


@dataclass(frozen=True)
class _PersistedWorkerReadiness:
    postgres: ComponentHealth
    migrations: ComponentHealth
    worker: ComponentHealth
    runtime: ComponentHealth
    oracle: ComponentHealth
    lifecycle: ComponentHealth
    log_volume: ComponentHealth
    workspace_volume: ComponentHealth
    egress: ComponentHealth
    egress_policy_set_hash: str | None = None
    egress_ruleset_hash: str | None = None


def _as_utc_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return (
            value.replace(tzinfo=UTC)
            if value.tzinfo is None
            else value.astimezone(UTC)
        )
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return (
            parsed.replace(tzinfo=UTC)
            if parsed.tzinfo is None
            else parsed.astimezone(UTC)
        )
    return None


def _is_fresh(
    value: object,
    *,
    now: datetime,
    maximum_age_seconds: float,
) -> bool:
    checked_at = _as_utc_datetime(value)
    if checked_at is None:
        return False
    age = (now - checked_at).total_seconds()
    return -2 <= age <= maximum_age_seconds


def _valid_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[a-f0-9]{64}", value) is not None
    )


def _current_boot_id() -> str:
    try:
        return (
            Path("/proc/sys/kernel/random/boot_id")
            .read_text(encoding="ascii")
            .strip()
        )
    except OSError:
        return ""


class SystemReadinessProvider:
    def __init__(
        self,
        settings: Settings,
        engine: Engine | None = None,
        egress_verifier: EgressVerifier | None = None,
    ) -> None:
        self.settings = settings
        self._engine = engine
        self.egress_verifier = egress_verifier or LoopbackEgressAttestationClient(
            url=settings.egress_attestation_url,
            timeout_seconds=settings.egress_attestation_timeout_seconds,
            max_age_seconds=settings.egress_attestation_max_age_seconds,
            policy_engine_version=settings.egress_policy_version,
            resolver_policy_version=settings.resolver_policy_version,
            lease_creation_capability_file=settings.egress_lease_creation_capability_file,
        )

    @property
    def engine(self) -> Engine:
        if self._engine is None:
            self._engine = create_engine(
                self.settings.database_url,
                pool_pre_ping=True,
                pool_size=2,
                max_overflow=0,
            )
        return self._engine

    def _postgres_migrations_and_worker(
        self,
    ) -> _PersistedWorkerReadiness:
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
                schema_revision = connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar_one_or_none()
                row = (
                    connection.execute(
                        text(
                            """
                        SELECT
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
                        FROM worker_heartbeats
                        WHERE worker_id = :worker_id
                        """
                        ),
                        {"worker_id": self.settings.worker_id},
                    )
                    .mappings()
                    .one_or_none()
                )
                lifecycle_row = (
                    connection.execute(
                        text(
                            """
                        SELECT
                            draining,
                            reason,
                            host_boot_id,
                            reconcile_epoch,
                            reconciled_at
                        FROM system_control
                        WHERE singleton_id = 1
                        """
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except (SQLAlchemyError, OSError, ValueError):
            return _PersistedWorkerReadiness(
                postgres=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="POSTGRES_UNAVAILABLE",
                ),
                migrations=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="MIGRATIONS_UNKNOWN",
                ),
                worker=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="WORKER_UNKNOWN",
                ),
                runtime=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="RUNTIME_UNKNOWN",
                ),
                oracle=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="ORACLE_UNKNOWN",
                ),
                lifecycle=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="LIFECYCLE_UNKNOWN",
                ),
                log_volume=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="LOG_VOLUME_ATTESTATION_UNKNOWN",
                ),
                workspace_volume=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="WORKSPACE_VOLUME_ATTESTATION_UNKNOWN",
                ),
                egress=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="EGRESS_ATTESTATION_UNKNOWN",
                ),
            )

        postgres = ComponentHealth(status=HealthStatus.UP, code="POSTGRES_OK")
        migrations = (
            ComponentHealth(status=HealthStatus.UP, code="MIGRATIONS_CURRENT")
            if schema_revision == self.settings.database_schema_revision
            else ComponentHealth(status=HealthStatus.DOWN, code="MIGRATIONS_OUTDATED")
        )
        if lifecycle_row is None:
            lifecycle = ComponentHealth(
                status=HealthStatus.DOWN,
                code="LIFECYCLE_STATE_MISSING",
            )
        elif lifecycle_row["draining"]:
            lifecycle = ComponentHealth(
                status=HealthStatus.DOWN,
                code="LIFECYCLE_DRAINING",
            )
        else:
            lifecycle = ComponentHealth(
                status=HealthStatus.UP,
                code="LIFECYCLE_ACCEPTING_EXECUTIONS",
            )
        if row is None:
            return _PersistedWorkerReadiness(
                postgres=postgres,
                migrations=migrations,
                worker=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="WORKER_HEARTBEAT_MISSING",
                ),
                runtime=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="RUNTIME_ATTESTATION_MISSING",
                ),
                oracle=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="ORACLE_ATTESTATION_MISSING",
                ),
                lifecycle=lifecycle,
                log_volume=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="LOG_VOLUME_ATTESTATION_MISSING",
                ),
                workspace_volume=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="WORKSPACE_VOLUME_ATTESTATION_MISSING",
                ),
                egress=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="EGRESS_ATTESTATION_MISSING",
                ),
            )

        now = datetime.now(UTC)
        if not _is_fresh(
            row["updated_at"],
            now=now,
            maximum_age_seconds=self.settings.worker_stale_seconds,
        ):
            return _PersistedWorkerReadiness(
                postgres=postgres,
                migrations=migrations,
                worker=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="WORKER_HEARTBEAT_STALE",
                ),
                runtime=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="RUNTIME_ATTESTATION_STALE",
                ),
                oracle=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="ORACLE_ATTESTATION_STALE",
                ),
                lifecycle=lifecycle,
                log_volume=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="LOG_VOLUME_ATTESTATION_STALE",
                ),
                workspace_volume=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="WORKSPACE_VOLUME_ATTESTATION_STALE",
                ),
                egress=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="EGRESS_ATTESTATION_STALE",
                ),
            )
        current_boot_id = _current_boot_id()
        heartbeat_reconciled_at = _as_utc_datetime(row["reconciled_at"])
        lifecycle_reconciled_at = (
            _as_utc_datetime(lifecycle_row["reconciled_at"])
            if lifecycle_row is not None
            else None
        )
        if (
            not current_boot_id
            or row["host_boot_id"] != current_boot_id
            or lifecycle_row is None
            or lifecycle_row["host_boot_id"] != current_boot_id
            or row["reconcile_epoch"] is None
            or row["reconcile_epoch"] != lifecycle_row["reconcile_epoch"]
            or heartbeat_reconciled_at is None
            or lifecycle_reconciled_at is None
            or heartbeat_reconciled_at != lifecycle_reconciled_at
        ):
            return _PersistedWorkerReadiness(
                postgres=postgres,
                migrations=migrations,
                worker=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="WORKER_RECONCILIATION_EPOCH_MISMATCH",
                ),
                runtime=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="RUNTIME_ATTESTATION_EPOCH_MISMATCH",
                ),
                oracle=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="ORACLE_ATTESTATION_EPOCH_MISMATCH",
                ),
                lifecycle=lifecycle,
                log_volume=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="LOG_VOLUME_ATTESTATION_EPOCH_MISMATCH",
                ),
                workspace_volume=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="WORKSPACE_VOLUME_ATTESTATION_EPOCH_MISMATCH",
                ),
                egress=ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="EGRESS_ATTESTATION_EPOCH_MISMATCH",
                ),
            )
        attestation_hashes = (
            row["runtime_sha256"],
            row["mysqlreader_plugin_sha256"],
            row["postgresqlreader_plugin_sha256"],
            row["mysqlwriter_plugin_sha256"],
            row["postgresqlwriter_plugin_sha256"],
            row["oracle_sha256"],
        )
        attestation_valid = (
            row["datax_release"] == "datax_v202309"
            and all(_valid_hash(value) for value in attestation_hashes)
        )
        runtime = ComponentHealth(
            status=(
                HealthStatus.UP
                if row["runtime_code"] == "RUNTIME_OK" and attestation_valid
                else HealthStatus.DOWN
            ),
            code=(
                row["runtime_code"]
                if attestation_valid
                else "RUNTIME_ATTESTATION_INCOMPLETE"
            ),
        )
        oracle = ComponentHealth(
            status=(
                HealthStatus.UP
                if row["oracle_code"] == "ORACLE_OK" and attestation_valid
                else HealthStatus.DOWN
            ),
            code=(
                row["oracle_code"]
                if attestation_valid
                else "ORACLE_ATTESTATION_INCOMPLETE"
            ),
        )
        raw_storage_code = row["storage_code"]
        storage_code = (
            raw_storage_code
            if isinstance(raw_storage_code, str)
            and re.fullmatch(r"[A-Z0-9_]{1,64}", raw_storage_code)
            else "STORAGE_ATTESTATION_INCOMPLETE"
        )
        storage_fresh = _is_fresh(
            row["storage_checked_at"],
            now=now,
            maximum_age_seconds=self.settings.worker_stale_seconds,
        )
        log_mount_hash = row["log_mount_identity_hash"]
        workspace_mount_hash = row["workspace_mount_identity_hash"]
        mount_hashes_valid = (
            _valid_hash(log_mount_hash)
            and _valid_hash(workspace_mount_hash)
            and log_mount_hash != workspace_mount_hash
        )
        log_free_bytes = row["log_free_bytes"]
        workspace_free_bytes = row["workspace_free_bytes"]
        log_free_valid = (
            isinstance(log_free_bytes, int)
            and not isinstance(log_free_bytes, bool)
            and log_free_bytes >= self.settings.worker_log_min_free_bytes
        )
        workspace_free_valid = (
            isinstance(workspace_free_bytes, int)
            and not isinstance(workspace_free_bytes, bool)
            and workspace_free_bytes
            >= self.settings.worker_workspace_min_free_bytes
        )
        if storage_code != "STORAGE_OK":
            log_volume = ComponentHealth(
                status=HealthStatus.DOWN,
                code=storage_code,
            )
            workspace_volume = ComponentHealth(
                status=HealthStatus.DOWN,
                code=storage_code,
            )
        elif not storage_fresh:
            log_volume = ComponentHealth(
                status=HealthStatus.DOWN,
                code="LOG_VOLUME_ATTESTATION_STALE",
            )
            workspace_volume = ComponentHealth(
                status=HealthStatus.DOWN,
                code="WORKSPACE_VOLUME_ATTESTATION_STALE",
            )
        else:
            log_volume = ComponentHealth(
                status=(
                    HealthStatus.UP
                    if mount_hashes_valid and log_free_valid
                    else HealthStatus.DOWN
                ),
                code=(
                    "LOG_VOLUME_OK"
                    if mount_hashes_valid and log_free_valid
                    else (
                        "LOG_VOLUME_SPACE_LOW"
                        if mount_hashes_valid
                        else "LOG_VOLUME_ATTESTATION_INCOMPLETE"
                    )
                ),
            )
            workspace_volume = ComponentHealth(
                status=(
                    HealthStatus.UP
                    if mount_hashes_valid and workspace_free_valid
                    else HealthStatus.DOWN
                ),
                code=(
                    "WORKSPACE_VOLUME_OK"
                    if mount_hashes_valid and workspace_free_valid
                    else (
                        "WORKSPACE_VOLUME_SPACE_LOW"
                        if mount_hashes_valid
                        else "WORKSPACE_VOLUME_ATTESTATION_INCOMPLETE"
                    )
                ),
            )
        egress_hashes_valid = all(
            _valid_hash(row[field])
            for field in (
                "egress_policy_set_hash",
                "egress_ruleset_hash",
                "egress_evidence_hash",
            )
        )
        egress_fresh = _is_fresh(
            row["egress_checked_at"],
            now=now,
            maximum_age_seconds=self.settings.egress_attestation_max_age_seconds,
        )
        raw_worker_code = row["code"]
        worker_code = (
            raw_worker_code
            if isinstance(raw_worker_code, str)
            and re.fullmatch(r"[A-Z0-9_]{1,64}", raw_worker_code)
            else "WORKER_STATUS_INVALID"
        )
        if row["status"] == "BLOCKED_EGRESS":
            egress = ComponentHealth(
                status=HealthStatus.DOWN,
                code=worker_code,
            )
        elif not egress_fresh:
            egress = ComponentHealth(
                status=HealthStatus.DOWN,
                code="EGRESS_ATTESTATION_STALE",
            )
        elif not egress_hashes_valid:
            egress = ComponentHealth(
                status=HealthStatus.DOWN,
                code="EGRESS_ATTESTATION_INCOMPLETE",
            )
        else:
            egress = ComponentHealth(
                status=HealthStatus.UP,
                code="EGRESS_POLICY_VERIFIED_BY_WORKER",
            )
        worker_security_ready = all(
            item.status == HealthStatus.UP
            for item in (runtime, oracle, log_volume, workspace_volume, egress)
        )
        if row["status"] != "READY":
            worker = ComponentHealth(
                status=HealthStatus.DOWN,
                code=worker_code,
            )
        elif not worker_security_ready:
            worker = ComponentHealth(
                status=HealthStatus.DOWN,
                code="WORKER_READY_ATTESTATION_INVALID",
            )
        else:
            worker = ComponentHealth(
                status=HealthStatus.UP,
                code="WORKER_READY",
            )
        return _PersistedWorkerReadiness(
            postgres=postgres,
            migrations=migrations,
            worker=worker,
            runtime=runtime,
            oracle=oracle,
            lifecycle=lifecycle,
            log_volume=log_volume,
            workspace_volume=workspace_volume,
            egress=egress,
            egress_policy_set_hash=(
                str(row["egress_policy_set_hash"])
                if egress_hashes_valid
                else None
            ),
            egress_ruleset_hash=(
                str(row["egress_ruleset_hash"])
                if egress_hashes_valid
                else None
            ),
        )

    def _audit_chain(self) -> ComponentHealth:
        try:
            with self.engine.connect() as connection:
                rows = connection.execute(
                    text(
                        """
                        SELECT
                            id,
                            organization_id,
                            organization_sequence,
                            event_json,
                            canonicalization_version,
                            previous_hash,
                            event_hash
                        FROM audit_events
                        ORDER BY organization_id, organization_sequence
                        """
                    )
                ).mappings()
                current_organization: str | None = None
                expected_sequence = 0
                expected_previous: str | None = None
                count = 0
                for row in rows:
                    organization_id = str(
                        UUID(str(row["organization_id"]))
                    ).lower()
                    event_id = str(UUID(str(row["id"]))).lower()
                    sequence = int(row["organization_sequence"])
                    if organization_id != current_organization:
                        current_organization = organization_id
                        expected_sequence = 1
                        expected_previous = None
                    if (
                        sequence != expected_sequence
                        or row["canonicalization_version"] != "RFC8785-v1"
                        or row["previous_hash"] != expected_previous
                    ):
                        return ComponentHealth(
                            status=HealthStatus.DOWN,
                            code="AUDIT_CHAIN_SEQUENCE_INVALID",
                        )
                    raw_event = row["event_json"]
                    if isinstance(raw_event, str):
                        raw_event = json.loads(raw_event)
                    if not isinstance(raw_event, dict):
                        return ComponentHealth(
                            status=HealthStatus.DOWN,
                            code="AUDIT_CHAIN_EVENT_INVALID",
                        )
                    event = copy.deepcopy(raw_event)
                    integrity = event.get("integrity")
                    if (
                        not isinstance(integrity, dict)
                        or event.get("event_id") != event_id
                        or event.get("organization_id") != organization_id
                        or event.get("sequence") != sequence
                        or integrity.get("algorithm") != "SHA-256"
                        or integrity.get("canonicalization") != "RFC8785"
                        or integrity.get("chain_scope")
                        != "ORGANIZATION_SEQUENCE"
                        or integrity.get("previous_hash") != expected_previous
                        or integrity.get("event_hash") != row["event_hash"]
                    ):
                        return ComponentHealth(
                            status=HealthStatus.DOWN,
                            code="AUDIT_CHAIN_EVENT_INVALID",
                        )
                    event_hash = integrity.pop("event_hash")
                    prefix = (
                        "DXAUDITv1\n"
                        f"{organization_id}\n"
                        f"{sequence}\n"
                        f"{expected_previous or ('0' * 64)}\n"
                    ).encode()
                    calculated = hashlib.sha256(
                        prefix + rfc8785.dumps(event)
                    ).hexdigest()
                    if calculated != event_hash:
                        return ComponentHealth(
                            status=HealthStatus.DOWN,
                            code="AUDIT_CHAIN_HASH_INVALID",
                        )
                    expected_previous = calculated
                    expected_sequence += 1
                    count += 1
        except (
            SQLAlchemyError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            return ComponentHealth(
                status=HealthStatus.DOWN,
                code="AUDIT_CHAIN_UNAVAILABLE",
            )
        return ComponentHealth(
            status=HealthStatus.UP,
            code=(
                "AUDIT_CHAIN_VERIFIED"
                if count
                else "AUDIT_CHAIN_EMPTY_BOOTSTRAP_ALLOWED"
            ),
        )

    def _egress_policy(
        self,
        persisted: _PersistedWorkerReadiness,
    ) -> ComponentHealth:
        try:
            verification = self.egress_verifier.verify_runtime()
        except EgressAttestationError as exc:
            return ComponentHealth(status=HealthStatus.DOWN, code=exc.code)
        except (OSError, TypeError, ValueError):
            return ComponentHealth(
                status=HealthStatus.DOWN,
                code="EGRESS_ATTESTATION_UNAVAILABLE",
            )
        if persisted.egress.status != HealthStatus.UP:
            return persisted.egress
        if (
            verification.policy_set_hash
            != persisted.egress_policy_set_hash
            or verification.ruleset_hash
            != persisted.egress_ruleset_hash
        ):
            return ComponentHealth(
                status=HealthStatus.DOWN,
                code="EGRESS_ATTESTATION_DIVERGED",
            )
        return ComponentHealth(
            status=HealthStatus.UP,
            code="EGRESS_POLICY_VERIFIED",
        )

    def check(self) -> HealthResponse:
        persisted = self._postgres_migrations_and_worker()
        components = {
            "postgres": persisted.postgres,
            "migrations": persisted.migrations,
            "log_volume": persisted.log_volume,
            "worker": persisted.worker,
            "runtime": persisted.runtime,
            "oracle": persisted.oracle,
            "lifecycle": persisted.lifecycle,
            "dispatcher": ComponentHealth(
                status=persisted.worker.status,
                code=(
                    "DISPATCHER_READY"
                    if persisted.worker.status == HealthStatus.UP
                    else "DISPATCHER_NOT_READY"
                ),
            ),
            "reconciler": ComponentHealth(
                status=(
                    HealthStatus.UP
                    if persisted.worker.status == HealthStatus.UP
                    and persisted.lifecycle.status == HealthStatus.UP
                    else HealthStatus.DOWN
                ),
                code=(
                    "RECONCILIATION_EPOCH_CURRENT"
                    if persisted.worker.status == HealthStatus.UP
                    and persisted.lifecycle.status == HealthStatus.UP
                    else "RECONCILIATION_NOT_CURRENT"
                ),
            ),
            "worker_fencing": ComponentHealth(
                status=persisted.worker.status,
                code=(
                    "FENCED_FACT_QUEUE_READY"
                    if persisted.worker.status == HealthStatus.UP
                    else "FENCED_FACT_QUEUE_NOT_READY"
                ),
            ),
            "workspace_volume": persisted.workspace_volume,
            "egress_policy": self._egress_policy(persisted),
            "keyrings": ComponentHealth(
                status=persisted.worker.status,
                code=(
                    "KEYRING_VALIDATED_BY_WORKER"
                    if persisted.worker.status == HealthStatus.UP
                    else "KEYRING_NOT_READY"
                ),
            ),
            "audit_chain": self._audit_chain(),
        }
        critical_components = (
            "postgres",
            "migrations",
            "audit_chain",
        )
        if any(
            components[name].status == HealthStatus.DOWN
            for name in critical_components
        ):
            status = HealthStatus.DOWN
        elif all(
            item.status == HealthStatus.UP for item in components.values()
        ):
            status = HealthStatus.UP
        else:
            status = HealthStatus.DEGRADED
        return HealthResponse(
            status=status,
            version=self.settings.app_version,
            checked_at=datetime.now(UTC),
            components=components,
        )
