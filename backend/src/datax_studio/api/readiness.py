from __future__ import annotations

import copy
import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Protocol
from uuid import UUID

import rfc8785
from sqlalchemy import Engine, create_engine, select, text, update
from sqlalchemy.exc import SQLAlchemyError

from datax_studio.api.models import ComponentHealth, HealthResponse, HealthStatus
from datax_studio.auth.db import AuditChainWatermark, AuditEvent, Organization
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


@dataclass(frozen=True)
class _AuditWatermark:
    organization_id: UUID
    head_sequence: int
    head_hash: str | None
    verified_sequence: int
    verified_hash: str | None
    full_replay_sequence: int
    full_replay_hash: str | None
    full_replay_finished_at: datetime | None
    integrity_status: str
    failure_code: str | None
    failure_sequence: int | None
    mutation_epoch: int


@dataclass(frozen=True)
class _AuditSnapshot:
    watermarks: tuple[_AuditWatermark, ...]


@dataclass(frozen=True)
class _AuditReplayResult:
    success: bool
    code: str
    failure_organization_id: UUID | None = None
    failure_sequence: int | None = None


class _AuditIntegrityError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _AuditSnapshotChanged(RuntimeError):
    pass


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
        # V1 deploys one API process.  These locks are therefore an admission
        # boundary for the supported Compose topology, while the watermarks and
        # compare-and-set publication remain durable across restarts.
        self._audit_replay_lock = Lock()
        self._readiness_check_lock = Lock()
        self._readiness_cache_lock = Lock()
        # A failed full replay must not turn a high-frequency public health
        # poll into one expensive retry after another.  The watermark remains
        # PENDING/DOWN; this process-local cadence gate only bounds repeated
        # work in V1's one-API-process deployment.
        self._next_full_audit_replay_at = 0.0
        self._cached_readiness: HealthResponse | None = None
        self._cached_readiness_until = 0.0

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

    @staticmethod
    def _watermark_pair_is_valid(sequence: int, value: str | None) -> bool:
        return (sequence == 0 and value is None) or (
            sequence > 0 and _valid_hash(value)
        )

    def _read_audit_snapshot(self) -> _AuditSnapshot:
        with self.engine.connect() as connection:
            organization_ids = tuple(
                connection.execute(
                    select(Organization.id).order_by(Organization.id)
                ).scalars()
            )
            rows = connection.execute(
                select(
                    AuditChainWatermark.organization_id,
                    AuditChainWatermark.head_sequence,
                    AuditChainWatermark.head_hash,
                    AuditChainWatermark.verified_sequence,
                    AuditChainWatermark.verified_hash,
                    AuditChainWatermark.full_replay_sequence,
                    AuditChainWatermark.full_replay_hash,
                    AuditChainWatermark.full_replay_finished_at,
                    AuditChainWatermark.integrity_status,
                    AuditChainWatermark.failure_code,
                    AuditChainWatermark.failure_sequence,
                    AuditChainWatermark.mutation_epoch,
                ).order_by(AuditChainWatermark.organization_id)
            ).mappings()
            state_by_organization: dict[UUID, _AuditWatermark] = {}
            for row in rows:
                try:
                    organization_id = UUID(str(row["organization_id"]))
                    head_sequence = int(row["head_sequence"])
                    verified_sequence = int(row["verified_sequence"])
                    full_replay_sequence = int(row["full_replay_sequence"])
                    mutation_epoch = int(row["mutation_epoch"])
                    failure_sequence = (
                        int(row["failure_sequence"])
                        if row["failure_sequence"] is not None
                        else None
                    )
                except (TypeError, ValueError) as exc:
                    raise _AuditIntegrityError("AUDIT_CHAIN_STATE_INVALID") from exc
                if organization_id in state_by_organization:
                    raise _AuditIntegrityError("AUDIT_CHAIN_STATE_INVALID")
                full_replay_finished_at = _as_utc_datetime(
                    row["full_replay_finished_at"]
                )
                if (
                    row["full_replay_finished_at"] is not None
                    and full_replay_finished_at is None
                ):
                    raise _AuditIntegrityError("AUDIT_CHAIN_STATE_INVALID")
                head_hash = (
                    str(row["head_hash"]) if row["head_hash"] is not None else None
                )
                verified_hash = (
                    str(row["verified_hash"])
                    if row["verified_hash"] is not None
                    else None
                )
                full_replay_hash = (
                    str(row["full_replay_hash"])
                    if row["full_replay_hash"] is not None
                    else None
                )
                integrity_status = str(row["integrity_status"])
                failure_code = (
                    str(row["failure_code"])
                    if row["failure_code"] is not None
                    else None
                )
                watermark = _AuditWatermark(
                    organization_id=organization_id,
                    head_sequence=head_sequence,
                    head_hash=head_hash,
                    verified_sequence=verified_sequence,
                    verified_hash=verified_hash,
                    full_replay_sequence=full_replay_sequence,
                    full_replay_hash=full_replay_hash,
                    full_replay_finished_at=full_replay_finished_at,
                    integrity_status=integrity_status,
                    failure_code=failure_code,
                    failure_sequence=failure_sequence,
                    mutation_epoch=mutation_epoch,
                )
                if not self._watermark_is_well_formed(watermark):
                    raise _AuditIntegrityError("AUDIT_CHAIN_STATE_INVALID")
                state_by_organization[organization_id] = watermark

            organization_set = set(organization_ids)
            if set(state_by_organization) - organization_set:
                raise _AuditIntegrityError("AUDIT_CHAIN_STATE_ORPHAN")
            if organization_set - set(state_by_organization):
                raise _AuditIntegrityError("AUDIT_CHAIN_STATE_MISSING")

            for watermark in state_by_organization.values():
                tail = connection.execute(
                    select(
                        AuditEvent.organization_sequence,
                        AuditEvent.event_hash,
                    )
                    .where(AuditEvent.organization_id == watermark.organization_id)
                    .order_by(AuditEvent.organization_sequence.desc())
                    .limit(1)
                ).one_or_none()
                tail_sequence = int(tail[0]) if tail is not None else 0
                tail_hash = str(tail[1]) if tail is not None else None
                if (
                    tail_sequence != watermark.head_sequence
                    or tail_hash != watermark.head_hash
                ):
                    raise _AuditIntegrityError("AUDIT_CHAIN_HEAD_DIVERGED")
        return _AuditSnapshot(
            watermarks=tuple(
                state_by_organization[organization_id]
                for organization_id in sorted(state_by_organization)
            )
        )

    def _watermark_is_well_formed(self, watermark: _AuditWatermark) -> bool:
        if (
            watermark.head_sequence < 0
            or watermark.verified_sequence < 0
            or watermark.full_replay_sequence < 0
            or watermark.mutation_epoch < 0
            or watermark.verified_sequence > watermark.head_sequence
            or watermark.full_replay_sequence > watermark.verified_sequence
        ):
            return False
        if not all(
            (
                self._watermark_pair_is_valid(
                    watermark.head_sequence,
                    watermark.head_hash,
                ),
                self._watermark_pair_is_valid(
                    watermark.verified_sequence,
                    watermark.verified_hash,
                ),
                self._watermark_pair_is_valid(
                    watermark.full_replay_sequence,
                    watermark.full_replay_hash,
                ),
                watermark.integrity_status in {"PENDING", "PASSED", "FAILED"},
            )
        ):
            return False
        if watermark.failure_sequence is not None and not (
            0 < watermark.failure_sequence <= watermark.head_sequence
        ):
            return False
        if watermark.integrity_status == "FAILED":
            return (
                watermark.failure_code is not None
                and re.fullmatch(r"[A-Z0-9_]{1,64}", watermark.failure_code)
                is not None
            )
        return watermark.failure_code is None and watermark.failure_sequence is None

    def _full_replay_is_fresh(
        self,
        watermark: _AuditWatermark,
        *,
        now: datetime,
    ) -> bool:
        return _is_fresh(
            watermark.full_replay_finished_at,
            now=now,
            maximum_age_seconds=self.settings.audit_integrity_full_replay_max_age_seconds,
        )

    def _snapshot_is_ready(self, snapshot: _AuditSnapshot, *, now: datetime) -> bool:
        return bool(snapshot.watermarks) and all(
            watermark.integrity_status == "PASSED"
            and watermark.verified_sequence == watermark.head_sequence
            and watermark.verified_hash == watermark.head_hash
            and self._full_replay_is_fresh(watermark, now=now)
            for watermark in snapshot.watermarks
        )

    @staticmethod
    def _replay_failure(
        code: str,
        *,
        organization_id: UUID | None = None,
        sequence: int | None = None,
    ) -> _AuditReplayResult:
        return _AuditReplayResult(
            success=False,
            code=code,
            failure_organization_id=organization_id,
            failure_sequence=sequence,
        )

    def _verify_audit_row(
        self,
        row: object,
        *,
        organization_id: UUID,
        expected_sequence: int,
        expected_previous: str | None,
    ) -> tuple[str | None, str | None]:
        try:
            mapping = row  # SQLAlchemy RowMapping, kept local for type narrowing.
            sequence = int(mapping["organization_sequence"])  # type: ignore[index]
            event_id = str(UUID(str(mapping["id"]))).lower()  # type: ignore[index]
            canonical_organization_id = str(organization_id).lower()
            if (
                sequence != expected_sequence
                or mapping["canonicalization_version"] != "RFC8785-v1"  # type: ignore[index]
                or mapping["previous_hash"] != expected_previous  # type: ignore[index]
            ):
                return None, "AUDIT_CHAIN_SEQUENCE_INVALID"
            raw_event = mapping["event_json"]  # type: ignore[index]
            if isinstance(raw_event, str):
                raw_event = json.loads(raw_event)
            if not isinstance(raw_event, dict):
                return None, "AUDIT_CHAIN_EVENT_INVALID"
            event = copy.deepcopy(raw_event)
            integrity = event.get("integrity")
            if (
                not isinstance(integrity, dict)
                or event.get("event_id") != event_id
                or event.get("organization_id") != canonical_organization_id
                or event.get("sequence") != sequence
                or integrity.get("algorithm") != "SHA-256"
                or integrity.get("canonicalization") != "RFC8785"
                or integrity.get("chain_scope") != "ORGANIZATION_SEQUENCE"
                or integrity.get("previous_hash") != expected_previous
                or integrity.get("event_hash") != mapping["event_hash"]  # type: ignore[index]
            ):
                return None, "AUDIT_CHAIN_EVENT_INVALID"
            event_hash = integrity.pop("event_hash")
            prefix = (
                "DXAUDITv1\n"
                f"{canonical_organization_id}\n"
                f"{sequence}\n"
                f"{expected_previous or ('0' * 64)}\n"
            ).encode()
            calculated = hashlib.sha256(prefix + rfc8785.dumps(event)).hexdigest()
            if calculated != event_hash:
                return None, "AUDIT_CHAIN_HASH_INVALID"
            return calculated, None
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None, "AUDIT_CHAIN_EVENT_INVALID"

    def _validate_full_replay(
        self,
        connection: object,
        snapshot: _AuditSnapshot,
        *,
        started_at: float,
    ) -> _AuditReplayResult:
        watermarks = {
            watermark.organization_id: watermark for watermark in snapshot.watermarks
        }
        expected = {
            organization_id: (1, None) for organization_id in watermarks
        }
        rows = connection.execute(  # type: ignore[union-attr]
            select(
                AuditEvent.id,
                AuditEvent.organization_id,
                AuditEvent.organization_sequence,
                AuditEvent.event_json,
                AuditEvent.canonicalization_version,
                AuditEvent.previous_hash,
                AuditEvent.event_hash,
            ).order_by(AuditEvent.organization_id, AuditEvent.organization_sequence)
        ).mappings()
        for row in rows:
            if (
                time.monotonic() - started_at
                > self.settings.audit_integrity_replay_timeout_seconds
            ):
                return self._replay_failure("AUDIT_CHAIN_REPLAY_TIMEOUT")
            try:
                organization_id = UUID(str(row["organization_id"]))
                sequence = int(row["organization_sequence"])
            except (TypeError, ValueError):
                return self._replay_failure("AUDIT_CHAIN_EVENT_INVALID")
            watermark = watermarks.get(organization_id)
            # A row beyond the snapshot head is a concurrent append.  Its
            # mutation epoch will make publication fail closed below.
            if watermark is None or sequence > watermark.head_sequence:
                continue
            expected_sequence, expected_previous = expected[organization_id]
            calculated, error_code = self._verify_audit_row(
                row,
                organization_id=organization_id,
                expected_sequence=expected_sequence,
                expected_previous=expected_previous,
            )
            if error_code is not None:
                return self._replay_failure(
                    error_code,
                    organization_id=organization_id,
                    sequence=sequence,
                )
            expected[organization_id] = (expected_sequence + 1, calculated)
        for organization_id, watermark in watermarks.items():
            expected_sequence, expected_hash = expected[organization_id]
            if (
                expected_sequence - 1 != watermark.head_sequence
                or expected_hash != watermark.head_hash
            ):
                return self._replay_failure(
                    "AUDIT_CHAIN_SEQUENCE_INVALID",
                    organization_id=organization_id,
                    sequence=min(expected_sequence, max(1, watermark.head_sequence)),
                )
        return _AuditReplayResult(success=True, code="AUDIT_CHAIN_FULL_REPLAY_VERIFIED")

    def _validate_suffix_replay(
        self,
        connection: object,
        snapshot: _AuditSnapshot,
        *,
        started_at: float,
    ) -> _AuditReplayResult:
        for watermark in snapshot.watermarks:
            expected_sequence = watermark.verified_sequence + 1
            expected_previous = watermark.verified_hash
            rows = connection.execute(  # type: ignore[union-attr]
                select(
                    AuditEvent.id,
                    AuditEvent.organization_id,
                    AuditEvent.organization_sequence,
                    AuditEvent.event_json,
                    AuditEvent.canonicalization_version,
                    AuditEvent.previous_hash,
                    AuditEvent.event_hash,
                )
                .where(
                    AuditEvent.organization_id == watermark.organization_id,
                    AuditEvent.organization_sequence > watermark.verified_sequence,
                    AuditEvent.organization_sequence <= watermark.head_sequence,
                )
                .order_by(AuditEvent.organization_sequence)
            ).mappings()
            for row in rows:
                if (
                    time.monotonic() - started_at
                    > self.settings.audit_integrity_replay_timeout_seconds
                ):
                    return self._replay_failure("AUDIT_CHAIN_REPLAY_TIMEOUT")
                try:
                    sequence = int(row["organization_sequence"])
                except (TypeError, ValueError):
                    return self._replay_failure(
                        "AUDIT_CHAIN_EVENT_INVALID",
                        organization_id=watermark.organization_id,
                    )
                calculated, error_code = self._verify_audit_row(
                    row,
                    organization_id=watermark.organization_id,
                    expected_sequence=expected_sequence,
                    expected_previous=expected_previous,
                )
                if error_code is not None:
                    return self._replay_failure(
                        error_code,
                        organization_id=watermark.organization_id,
                        sequence=sequence,
                    )
                expected_sequence += 1
                expected_previous = calculated
            if (
                expected_sequence - 1 != watermark.head_sequence
                or expected_previous != watermark.head_hash
            ):
                return self._replay_failure(
                    "AUDIT_CHAIN_SEQUENCE_INVALID",
                    organization_id=watermark.organization_id,
                    sequence=min(expected_sequence, max(1, watermark.head_sequence)),
                )
        return _AuditReplayResult(success=True, code="AUDIT_CHAIN_SUFFIX_VERIFIED")

    def _validate_audit_snapshot(
        self,
        snapshot: _AuditSnapshot,
        *,
        full_replay: bool,
    ) -> _AuditReplayResult:
        started_at = time.monotonic()
        statement_timeout = (
            f"{max(1, int(self.settings.audit_integrity_replay_timeout_seconds * 1000))}ms"
        )
        try:
            with self.engine.connect() as connection:
                if connection.dialect.name == "postgresql":
                    connection = connection.execution_options(
                        isolation_level="REPEATABLE READ"
                    )
                with connection.begin():
                    if connection.dialect.name == "postgresql":
                        connection.execute(
                            text(
                                "SELECT set_config("
                                "'statement_timeout', :timeout, true)"
                            ),
                            {"timeout": statement_timeout},
                        )
                    if full_replay:
                        return self._validate_full_replay(
                            connection,
                            snapshot,
                            started_at=started_at,
                        )
                    return self._validate_suffix_replay(
                        connection,
                        snapshot,
                        started_at=started_at,
                    )
        except (OSError, SQLAlchemyError, TypeError, ValueError):
            return self._replay_failure("AUDIT_CHAIN_UNAVAILABLE")

    @staticmethod
    def _watermark_matches_snapshot(watermark: _AuditWatermark) -> tuple[object, ...]:
        return (
            AuditChainWatermark.organization_id == watermark.organization_id,
            AuditChainWatermark.head_sequence == watermark.head_sequence,
            AuditChainWatermark.head_hash.is_not_distinct_from(watermark.head_hash),
            AuditChainWatermark.mutation_epoch == watermark.mutation_epoch,
        )

    def _publish_verified_audit_snapshot(
        self,
        snapshot: _AuditSnapshot,
        *,
        full_replay: bool,
    ) -> bool:
        now = datetime.now(UTC)
        try:
            with self.engine.begin() as connection:
                for watermark in snapshot.watermarks:
                    values: dict[str, object] = {
                        "verified_sequence": watermark.head_sequence,
                        "verified_hash": watermark.head_hash,
                        "integrity_status": "PASSED",
                        "failure_code": None,
                        "failure_sequence": None,
                        "updated_at": now,
                    }
                    if full_replay:
                        values.update(
                            {
                                "full_replay_sequence": watermark.head_sequence,
                                "full_replay_hash": watermark.head_hash,
                                "full_replay_finished_at": now,
                            }
                        )
                    result = connection.execute(
                        update(AuditChainWatermark)
                        .where(*self._watermark_matches_snapshot(watermark))
                        .values(**values)
                    )
                    if result.rowcount != 1:
                        raise _AuditSnapshotChanged
        except (_AuditSnapshotChanged, SQLAlchemyError):
            return False
        return True

    def _record_audit_failure_if_stable(
        self,
        snapshot: _AuditSnapshot,
        result: _AuditReplayResult,
    ) -> None:
        if result.failure_organization_id is None:
            return
        watermark = next(
            (
                item
                for item in snapshot.watermarks
                if item.organization_id == result.failure_organization_id
            ),
            None,
        )
        if watermark is None:
            return
        failure_sequence = result.failure_sequence
        if failure_sequence is not None and watermark.head_sequence > 0:
            failure_sequence = min(max(1, failure_sequence), watermark.head_sequence)
        elif watermark.head_sequence == 0:
            failure_sequence = None
        try:
            with self.engine.begin() as connection:
                connection.execute(
                    update(AuditChainWatermark)
                    .where(*self._watermark_matches_snapshot(watermark))
                    .values(
                        integrity_status="FAILED",
                        failure_code=result.code,
                        failure_sequence=failure_sequence,
                        updated_at=datetime.now(UTC),
                    )
                )
        except SQLAlchemyError:
            return

    def _audit_chain(self) -> ComponentHealth:
        try:
            snapshot = self._read_audit_snapshot()
        except _AuditIntegrityError as exc:
            return ComponentHealth(status=HealthStatus.DOWN, code=exc.code)
        except (OSError, SQLAlchemyError, TypeError, ValueError):
            return ComponentHealth(
                status=HealthStatus.DOWN,
                code="AUDIT_CHAIN_UNAVAILABLE",
            )
        if not snapshot.watermarks:
            return ComponentHealth(
                status=HealthStatus.UP,
                code="AUDIT_CHAIN_EMPTY_BOOTSTRAP_ALLOWED",
            )
        now = datetime.now(UTC)
        if self._snapshot_is_ready(snapshot, now=now):
            return ComponentHealth(
                status=HealthStatus.UP,
                code="AUDIT_CHAIN_VERIFIED_WATERMARK",
            )
        if any(
            watermark.integrity_status == "FAILED"
            for watermark in snapshot.watermarks
        ):
            return ComponentHealth(
                status=HealthStatus.DOWN,
                code="AUDIT_CHAIN_VERIFICATION_FAILED",
            )
        if not self._audit_replay_lock.acquire(blocking=False):
            return ComponentHealth(
                status=HealthStatus.DOWN,
                code="AUDIT_CHAIN_VERIFICATION_IN_PROGRESS",
            )
        try:
            try:
                snapshot = self._read_audit_snapshot()
            except _AuditIntegrityError as exc:
                return ComponentHealth(status=HealthStatus.DOWN, code=exc.code)
            except (OSError, SQLAlchemyError, TypeError, ValueError):
                return ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="AUDIT_CHAIN_UNAVAILABLE",
                )
            now = datetime.now(UTC)
            if self._snapshot_is_ready(snapshot, now=now):
                return ComponentHealth(
                    status=HealthStatus.UP,
                    code="AUDIT_CHAIN_VERIFIED_WATERMARK",
                )
            if any(
                watermark.integrity_status == "FAILED"
                for watermark in snapshot.watermarks
            ):
                return ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="AUDIT_CHAIN_VERIFICATION_FAILED",
                )
            full_replay = any(
                not self._full_replay_is_fresh(watermark, now=now)
                for watermark in snapshot.watermarks
            )
            if full_replay:
                monotonic_now = time.monotonic()
                if monotonic_now < self._next_full_audit_replay_at:
                    return ComponentHealth(
                        status=HealthStatus.DOWN,
                        code="AUDIT_CHAIN_FULL_REPLAY_THROTTLED",
                    )
                self._next_full_audit_replay_at = (
                    monotonic_now
                    + self.settings.audit_integrity_full_replay_max_age_seconds
                )
            result = self._validate_audit_snapshot(
                snapshot,
                full_replay=full_replay,
            )
            if not result.success:
                self._record_audit_failure_if_stable(snapshot, result)
                return ComponentHealth(status=HealthStatus.DOWN, code=result.code)
            if not self._publish_verified_audit_snapshot(
                snapshot,
                full_replay=full_replay,
            ):
                return ComponentHealth(
                    status=HealthStatus.DOWN,
                    code="AUDIT_CHAIN_SNAPSHOT_CHANGED",
                )
            return ComponentHealth(status=HealthStatus.UP, code=result.code)
        finally:
            self._audit_replay_lock.release()

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

    def _check_once(self) -> HealthResponse:
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

    def _cached_response(self, *, now: float) -> HealthResponse | None:
        with self._readiness_cache_lock:
            if (
                self._cached_readiness is not None
                and now < self._cached_readiness_until
            ):
                return self._cached_readiness
        return None

    def check(self) -> HealthResponse:
        now = time.monotonic()
        cached = self._cached_response(now=now)
        if cached is not None:
            return cached
        if not self._readiness_check_lock.acquire(blocking=False):
            # Do not queue unbounded public /ready callers behind an expensive
            # replay.  Returning DOWN is truthful: this request did not obtain
            # a fresh readiness proof, and the one in progress may still fail.
            return HealthResponse(
                status=HealthStatus.DOWN,
                version=self.settings.app_version,
                checked_at=datetime.now(UTC),
                components={
                    "readiness": ComponentHealth(
                        status=HealthStatus.DOWN,
                        code="READINESS_CHECK_IN_PROGRESS",
                    )
                },
            )
        try:
            cached = self._cached_response(now=time.monotonic())
            if cached is not None:
                return cached
            response = self._check_once()
            with self._readiness_cache_lock:
                self._cached_readiness = response
                self._cached_readiness_until = (
                    time.monotonic() + self.settings.readiness_cache_seconds
                )
            return response
        finally:
            self._readiness_check_lock.release()
