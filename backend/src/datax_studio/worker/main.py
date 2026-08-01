from __future__ import annotations

import logging
import signal
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Event
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from datax_studio.api.problems import ProblemException
from datax_studio.core.service import build_control_service
from datax_studio.credentials.service import build_credential_service
from datax_studio.egress_attestation import (
    EgressAttestationError,
    EgressVerification,
    EgressVerifier,
    LoopbackEgressAttestationClient,
)
from datax_studio.lifecycle import is_draining
from datax_studio.recovery.service import RecoveryService
from datax_studio.runtime_manifest import (
    RuntimeCheck,
    RuntimeManifest,
    run_datax_smoke,
)
from datax_studio.settings import Settings, get_settings
from datax_studio.worker.executor import ExecutionWorker
from datax_studio.worker.reconcile import RuntimeIdentity, WorkerReconciler
from datax_studio.worker.recovery_probe import RecoveryProbeWorker
from datax_studio.worker.sensitive_runtime import SensitiveRuntimeError
from datax_studio.worker.storage_attestation import (
    StorageAttestationError,
    StorageVerification,
    WorkerStorageVerifier,
)

LOGGER = logging.getLogger("datax_studio.worker")
STOP = Event()


@dataclass(frozen=True)
class RuntimeAttestation:
    datax_release: str
    runtime_sha256: str
    mysqlreader_plugin_sha256: str
    postgresqlreader_plugin_sha256: str
    mysqlwriter_plugin_sha256: str
    postgresqlwriter_plugin_sha256: str
    oracle_sha256: str

    @classmethod
    def from_validated_manifest(
        cls,
        settings: Settings,
        check: RuntimeCheck,
    ) -> RuntimeAttestation | None:
        if not check.ready:
            return None
        manifest = RuntimeManifest.model_validate_json(
            settings.runtime_manifest_path.read_text(encoding="utf-8")
        )
        manifest.validate_contract()
        return cls(
            datax_release=manifest.datax_release,
            runtime_sha256=manifest.runtime_sha256,
            mysqlreader_plugin_sha256=(manifest.plugins["mysqlreader"].sha256),
            postgresqlreader_plugin_sha256=(manifest.plugins["postgresqlreader"].sha256),
            mysqlwriter_plugin_sha256=(manifest.plugins["mysqlwriter"].sha256),
            postgresqlwriter_plugin_sha256=(manifest.plugins["postgresqlwriter"].sha256),
            oracle_sha256=manifest.oracle.sha256,
        )


@dataclass(frozen=True)
class WorkerLoopDecision:
    status: str
    code: str
    reconcile_expired_leases: bool
    dispatch: bool


class StorageVerifier(Protocol):
    def verify_runtime(self) -> StorageVerification: ...


@dataclass(frozen=True)
class DynamicWorkerAttestation:
    egress: EgressVerification | None
    egress_code: str
    storage: StorageVerification | None
    storage_code: str

    @property
    def egress_verified(self) -> bool:
        return self.egress is not None and self.egress_code == "EGRESS_POLICY_VERIFIED"

    @property
    def storage_verified(self) -> bool:
        return self.storage is not None and self.storage_code == "STORAGE_OK"


def collect_dynamic_worker_attestation(
    *,
    egress_verifier: EgressVerifier,
    storage_verifier: StorageVerifier,
) -> DynamicWorkerAttestation:
    try:
        egress = egress_verifier.verify_runtime()
        egress_code = "EGRESS_POLICY_VERIFIED"
    except EgressAttestationError as exc:
        egress = None
        egress_code = exc.code
    except (OSError, TypeError, ValueError):
        egress = None
        egress_code = "EGRESS_ATTESTATION_UNAVAILABLE"
    try:
        storage = storage_verifier.verify_runtime()
        storage_code = "STORAGE_OK"
    except StorageAttestationError as exc:
        storage = None
        storage_code = exc.code
    except (OSError, TypeError, ValueError):
        storage = None
        storage_code = "STORAGE_ATTESTATION_UNAVAILABLE"
    return DynamicWorkerAttestation(
        egress=egress,
        egress_code=egress_code,
        storage=storage,
        storage_code=storage_code,
    )


def startup_reconciliation_allowed(
    *,
    runtime_ready: bool,
    dynamic_attestation: DynamicWorkerAttestation,
    dispatcher_available: bool,
) -> bool:
    return (
        runtime_ready
        and dynamic_attestation.egress_verified
        and dynamic_attestation.storage_verified
        and dispatcher_available
    )


def decide_worker_loop(
    *,
    runtime_ready: bool,
    runtime_code: str,
    egress_verified: bool,
    egress_code: str = "EGRESS_POLICY_UNVERIFIED",
    storage_verified: bool = True,
    storage_code: str = "STORAGE_OK",
    dispatcher_available: bool,
    reconciliation_current: bool = True,
    draining: bool,
) -> WorkerLoopDecision:
    if not runtime_ready:
        return WorkerLoopDecision(
            status="BLOCKED_RUNTIME",
            code=runtime_code,
            reconcile_expired_leases=False,
            dispatch=False,
        )
    if not egress_verified:
        return WorkerLoopDecision(
            status="BLOCKED_EGRESS",
            code=egress_code,
            reconcile_expired_leases=False,
            dispatch=False,
        )
    if not storage_verified:
        return WorkerLoopDecision(
            status="BLOCKED_STORAGE",
            code=storage_code,
            reconcile_expired_leases=False,
            dispatch=False,
        )
    if not dispatcher_available:
        return WorkerLoopDecision(
            status="DRAINING",
            code="WORKER_DISPATCHER_INITIALIZATION_FAILED",
            reconcile_expired_leases=False,
            dispatch=False,
        )
    if not reconciliation_current:
        return WorkerLoopDecision(
            status="DRAINING",
            code="STARTUP_RECONCILIATION_REQUIRED",
            reconcile_expired_leases=False,
            dispatch=False,
        )
    if draining:
        return WorkerLoopDecision(
            status="DRAINING",
            code="LIFECYCLE_DRAINING",
            reconcile_expired_leases=False,
            dispatch=False,
        )
    return WorkerLoopDecision(
        status="READY",
        code="WORKER_READY",
        reconcile_expired_leases=True,
        dispatch=True,
    )


def _stop(_signum: int, _frame: object) -> None:
    STOP.set()


def _upsert_heartbeat(
    engine: Engine,
    *,
    settings: Settings,
    status: str,
    code: str,
    runtime: RuntimeCheck,
    attestation: RuntimeAttestation | None,
    dynamic_attestation: DynamicWorkerAttestation,
    identity: RuntimeIdentity,
    reconcile_epoch: UUID,
) -> None:
    checked_at = datetime.now(UTC)
    with engine.begin() as connection:
        reconciled_at = connection.execute(
            text(
                """
                SELECT reconciled_at
                FROM system_control
                WHERE singleton_id = 1
                  AND host_boot_id = :host_boot_id
                  AND reconcile_epoch = :reconcile_epoch
                """
            ),
            {
                "host_boot_id": identity.host_boot_id,
                "reconcile_epoch": reconcile_epoch,
            },
        ).scalar_one_or_none()
        connection.execute(
            text(
                """
                INSERT INTO worker_heartbeats
                    (
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
                        checked_at,
                        updated_at
                    )
                VALUES
                    (
                        :worker_id,
                        :status,
                        :code,
                        :runtime_code,
                        :oracle_code,
                        :datax_release,
                        :runtime_sha256,
                        :mysqlreader_plugin_sha256,
                        :postgresqlreader_plugin_sha256,
                        :mysqlwriter_plugin_sha256,
                        :postgresqlwriter_plugin_sha256,
                        :oracle_sha256,
                        :host_boot_id,
                        :reconcile_epoch,
                        :reconciled_at,
                        :storage_code,
                        :log_mount_identity_hash,
                        :workspace_mount_identity_hash,
                        :log_free_bytes,
                        :workspace_free_bytes,
                        :storage_checked_at,
                        :egress_policy_set_hash,
                        :egress_ruleset_hash,
                        :egress_evidence_hash,
                        :egress_checked_at,
                        :checked_at,
                        :updated_at
                    )
                ON CONFLICT (worker_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    code = EXCLUDED.code,
                    runtime_code = EXCLUDED.runtime_code,
                    oracle_code = EXCLUDED.oracle_code,
                    datax_release = EXCLUDED.datax_release,
                    runtime_sha256 = EXCLUDED.runtime_sha256,
                    mysqlreader_plugin_sha256 =
                        EXCLUDED.mysqlreader_plugin_sha256,
                    postgresqlreader_plugin_sha256 =
                        EXCLUDED.postgresqlreader_plugin_sha256,
                    mysqlwriter_plugin_sha256 =
                        EXCLUDED.mysqlwriter_plugin_sha256,
                    postgresqlwriter_plugin_sha256 =
                        EXCLUDED.postgresqlwriter_plugin_sha256,
                    oracle_sha256 = EXCLUDED.oracle_sha256,
                    host_boot_id = EXCLUDED.host_boot_id,
                    reconcile_epoch = EXCLUDED.reconcile_epoch,
                    reconciled_at = EXCLUDED.reconciled_at,
                    storage_code = EXCLUDED.storage_code,
                    log_mount_identity_hash =
                        EXCLUDED.log_mount_identity_hash,
                    workspace_mount_identity_hash =
                        EXCLUDED.workspace_mount_identity_hash,
                    log_free_bytes = EXCLUDED.log_free_bytes,
                    workspace_free_bytes = EXCLUDED.workspace_free_bytes,
                    storage_checked_at = EXCLUDED.storage_checked_at,
                    egress_policy_set_hash =
                        EXCLUDED.egress_policy_set_hash,
                    egress_ruleset_hash = EXCLUDED.egress_ruleset_hash,
                    egress_evidence_hash = EXCLUDED.egress_evidence_hash,
                    egress_checked_at = EXCLUDED.egress_checked_at,
                    checked_at = EXCLUDED.checked_at,
                    updated_at = EXCLUDED.updated_at
                """
            ),
            {
                "worker_id": settings.worker_id,
                "status": status,
                "code": code,
                "runtime_code": runtime.runtime_code,
                "oracle_code": runtime.oracle_code,
                "datax_release": (attestation.datax_release if attestation else None),
                "runtime_sha256": (attestation.runtime_sha256 if attestation else None),
                "mysqlreader_plugin_sha256": (
                    attestation.mysqlreader_plugin_sha256 if attestation else None
                ),
                "postgresqlreader_plugin_sha256": (
                    attestation.postgresqlreader_plugin_sha256 if attestation else None
                ),
                "mysqlwriter_plugin_sha256": (
                    attestation.mysqlwriter_plugin_sha256 if attestation else None
                ),
                "postgresqlwriter_plugin_sha256": (
                    attestation.postgresqlwriter_plugin_sha256 if attestation else None
                ),
                "oracle_sha256": (attestation.oracle_sha256 if attestation else None),
                "host_boot_id": identity.host_boot_id,
                "reconcile_epoch": reconcile_epoch,
                "reconciled_at": reconciled_at,
                "storage_code": dynamic_attestation.storage_code,
                "log_mount_identity_hash": (
                    dynamic_attestation.storage.log_mount_identity_hash
                    if dynamic_attestation.storage
                    else None
                ),
                "workspace_mount_identity_hash": (
                    dynamic_attestation.storage.workspace_mount_identity_hash
                    if dynamic_attestation.storage
                    else None
                ),
                "log_free_bytes": (
                    dynamic_attestation.storage.log_free_bytes
                    if dynamic_attestation.storage
                    else None
                ),
                "workspace_free_bytes": (
                    dynamic_attestation.storage.workspace_free_bytes
                    if dynamic_attestation.storage
                    else None
                ),
                "storage_checked_at": (
                    dynamic_attestation.storage.checked_at if dynamic_attestation.storage else None
                ),
                "egress_policy_set_hash": (
                    dynamic_attestation.egress.policy_set_hash
                    if dynamic_attestation.egress
                    else None
                ),
                "egress_ruleset_hash": (
                    dynamic_attestation.egress.ruleset_hash if dynamic_attestation.egress else None
                ),
                "egress_evidence_hash": (
                    dynamic_attestation.egress.evidence_hash if dynamic_attestation.egress else None
                ),
                "egress_checked_at": (
                    dynamic_attestation.egress.checked_at if dynamic_attestation.egress else None
                ),
                "checked_at": checked_at,
                "updated_at": checked_at,
            },
        )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = get_settings()
    engine = create_engine(settings.database_url, pool_pre_ping=True)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    identity = RuntimeIdentity.current()
    reconcile_epoch = uuid4()
    runtime = run_datax_smoke(
        settings.runtime_manifest_path,
        expected_java_path=settings.java_binary_path,
    )
    attestation = RuntimeAttestation.from_validated_manifest(
        settings,
        runtime,
    )
    control = build_control_service(settings)
    reconciler = WorkerReconciler(
        control=control,
        sessions=control.sessions,
    )
    runtime_manifest = (
        RuntimeManifest.model_validate_json(
            settings.runtime_manifest_path.read_text(encoding="utf-8")
        )
        if runtime.ready
        else None
    )
    egress_verifier = LoopbackEgressAttestationClient(
        url=settings.egress_attestation_url,
        timeout_seconds=settings.egress_attestation_timeout_seconds,
        max_age_seconds=settings.egress_attestation_max_age_seconds,
        policy_engine_version=settings.egress_policy_version,
        resolver_policy_version=settings.resolver_policy_version,
    )
    storage_verifier = WorkerStorageVerifier(
        log_volume_path=settings.log_volume_path,
        workspace_volume_path=settings.workspace_volume_path,
        log_min_free_bytes=settings.worker_log_min_free_bytes,
        workspace_min_free_bytes=settings.worker_workspace_min_free_bytes,
    )
    dynamic_attestation = collect_dynamic_worker_attestation(
        egress_verifier=egress_verifier,
        storage_verifier=storage_verifier,
    )
    execution_worker = None
    recovery_probe_worker = None

    def initialize_dispatchers() -> tuple[
        ExecutionWorker | None,
        RecoveryProbeWorker | None,
    ]:
        if runtime_manifest is None:
            return None, None
        try:
            credentials = build_credential_service(settings)
            recovery = RecoveryService(control)
            return (
                ExecutionWorker(
                    settings=settings,
                    control=control,
                    credentials=credentials,
                    reconciler=reconciler,
                    runtime_manifest=runtime_manifest,
                ),
                RecoveryProbeWorker(
                    settings=settings,
                    control=control,
                    credentials=credentials,
                    recovery=recovery,
                ),
            )
        except (OSError, ValueError, ProblemException, SensitiveRuntimeError):
            LOGGER.exception("worker credential or dispatcher initialization failed")
            return None, None

    if (
        runtime.ready
        and dynamic_attestation.egress_verified
        and dynamic_attestation.storage_verified
    ):
        execution_worker, recovery_probe_worker = initialize_dispatchers()
    dispatcher_available = execution_worker is not None and recovery_probe_worker is not None
    startup_reconciled = False
    if startup_reconciliation_allowed(
        runtime_ready=runtime.ready,
        dynamic_attestation=dynamic_attestation,
        dispatcher_available=dispatcher_available,
    ):
        try:
            reconciler.reconcile_startup(
                identity=identity,
                reconcile_epoch=reconcile_epoch,
                accepting=True,
                completion_reason="ACCEPTING_EXECUTIONS",
            )
        except SQLAlchemyError:
            LOGGER.exception("worker startup reconciliation failed closed")
        else:
            startup_reconciled = True

    dispatch_thread: threading.Thread | None = None

    def dispatch_once() -> None:
        try:
            assert recovery_probe_worker is not None
            assert execution_worker is not None
            execution_worker.prepare_admission()
            if recovery_probe_worker.claim_and_run(identity=identity):
                return
            execution_worker.claim_and_run(
                host_boot_id=identity.host_boot_id,
                cgroup_identity=identity.cgroup_identity,
            )
        except BaseException:
            LOGGER.exception("worker dispatch iteration failed closed")

    while not STOP.is_set():
        try:
            # Safety stops are intentionally independent from admission and
            # runtime-attestation gates: a degraded Worker must still release
            # queued work and terminate any locally provable active process.
            reconciler.reconcile_pending_work_terminations(identity=identity)
            dynamic_attestation = collect_dynamic_worker_attestation(
                egress_verifier=egress_verifier,
                storage_verifier=storage_verifier,
            )
            dynamic_gates_ready = (
                runtime.ready
                and dynamic_attestation.egress_verified
                and dynamic_attestation.storage_verified
            )
            if dynamic_gates_ready and not dispatcher_available:
                execution_worker, recovery_probe_worker = initialize_dispatchers()
                dispatcher_available = (
                    execution_worker is not None and recovery_probe_worker is not None
                )
            dispatch_idle = dispatch_thread is None or not dispatch_thread.is_alive()
            if dynamic_gates_ready and dispatcher_available and dispatch_idle:
                assert execution_worker is not None
                try:
                    execution_worker.prepare_admission()
                except SensitiveRuntimeError:
                    LOGGER.exception("sensitive runtime cleanup blocked Worker admission")
                    execution_worker = None
                    recovery_probe_worker = None
                    dispatcher_available = False
            if (
                startup_reconciliation_allowed(
                    runtime_ready=runtime.ready,
                    dynamic_attestation=dynamic_attestation,
                    dispatcher_available=dispatcher_available,
                )
                and not startup_reconciled
            ):
                reconciler.reconcile_startup(
                    identity=identity,
                    reconcile_epoch=reconcile_epoch,
                    accepting=True,
                    completion_reason="ACCEPTING_EXECUTIONS",
                )
                startup_reconciled = True
            draining = is_draining(engine)
            decision = decide_worker_loop(
                runtime_ready=runtime.ready,
                runtime_code=runtime.runtime_code,
                egress_verified=dynamic_attestation.egress_verified,
                egress_code=dynamic_attestation.egress_code,
                storage_verified=dynamic_attestation.storage_verified,
                storage_code=dynamic_attestation.storage_code,
                dispatcher_available=dispatcher_available,
                reconciliation_current=startup_reconciled,
                draining=draining,
            )
            if decision.reconcile_expired_leases:
                reconciler.reconcile_expired_leases(identity=identity)
            if decision.dispatch and dispatch_idle:
                if execution_worker is None or recovery_probe_worker is None:
                    raise RuntimeError("dispatcher gate allowed missing Worker components")
                dispatch_thread = threading.Thread(
                    target=dispatch_once,
                    name="worker-dispatch",
                    daemon=True,
                )
                dispatch_thread.start()
            _upsert_heartbeat(
                engine,
                settings=settings,
                status=decision.status,
                code=decision.code,
                runtime=runtime,
                attestation=attestation,
                dynamic_attestation=dynamic_attestation,
                identity=identity,
                reconcile_epoch=reconcile_epoch,
            )
        except SQLAlchemyError:
            LOGGER.exception("worker heartbeat or reconciliation failed")
        STOP.wait(settings.worker_heartbeat_seconds)

    try:
        _upsert_heartbeat(
            engine,
            settings=settings,
            status="STOPPED",
            code="WORKER_STOPPED",
            runtime=runtime,
            attestation=attestation,
            dynamic_attestation=dynamic_attestation,
            identity=identity,
            reconcile_epoch=reconcile_epoch,
        )
    except SQLAlchemyError:
        LOGGER.exception("final worker heartbeat failed")


if __name__ == "__main__":
    main()
