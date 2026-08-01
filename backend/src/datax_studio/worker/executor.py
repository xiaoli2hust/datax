from __future__ import annotations

import copy
import hashlib
import ipaddress
import shutil
import threading
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import rfc8785
from sqlalchemy import select

from datax_studio.api.problems import ProblemException
from datax_studio.auth.security import ensure_aware
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    EndpointPolicyRevision,
    Execution,
    ExecutionAttempt,
    JobVersion,
    PhysicalEndpointIdentity,
    Project,
    TargetCopyLock,
    TargetNamespace,
)
from datax_studio.core.schemas import (
    ClaimedExecution,
    ExecutionRuntimeSnapshot,
    JobSpecV1,
    RuntimePreflight,
    TargetEmptyEvidence,
)
from datax_studio.core.service import ControlService
from datax_studio.credentials.network import ResolvedEndpoint
from datax_studio.credentials.service import CredentialService
from datax_studio.datax_runner import build_datax_command
from datax_studio.logs.service import ExecutionLogService
from datax_studio.runtime_manifest import RuntimeManifest
from datax_studio.settings import Settings
from datax_studio.worker.job_builder import (
    RuntimeConnection,
    build_datax_job,
    build_oracle_mappings,
    write_job_file,
)
from datax_studio.worker.oracle_database import (
    SideRead,
    capture_source_preflight,
    count_target_rows,
    load_oracle_module,
    verify_databases,
)
from datax_studio.worker.process import (
    ManagedProcessResult,
    ProcessAction,
    ProcessEndReason,
    run_managed_process,
)
from datax_studio.worker.reconcile import WorkerReconciler
from datax_studio.worker.schema_probe import (
    TableIdentity,
    assert_snapshot_matches_job,
    probe_schema_snapshot,
)
from datax_studio.worker.sensitive_runtime import (
    SensitiveRuntimeError,
    SensitiveRuntimeStore,
)


@dataclass(frozen=True)
class ExecutionContext:
    execution: Execution
    version: JobVersion
    source_revision: DatasourceRevision
    target_revision: DatasourceRevision
    source_policy: EndpointPolicyRevision
    target_policy: EndpointPolicyRevision
    source_datasource: Datasource
    target_datasource: Datasource
    target_namespace: TargetNamespace
    organization_id: UUID
    target_lock: TargetCopyLock
    spec: JobSpecV1


@dataclass(frozen=True)
class PreflightResult:
    source_summary: SideRead
    source_resolved: ResolvedEndpoint
    target_resolved: ResolvedEndpoint
    source_evidence_id: UUID
    target_evidence_id: UUID
    target_empty: TargetEmptyEvidence
    resolved_config_hash: str
    datax_job: dict[str, Any]


@dataclass
class VerificationRun:
    oracle_started: bool = False


class VerificationCanceled(RuntimeError):
    """Internal control signal after the Worker acknowledges cancellation."""


class LeaseKeeper:
    def __init__(
        self,
        *,
        control: ControlService,
        claim: ClaimedExecution,
        lease_seconds: int,
    ) -> None:
        self.control = control
        self.claim = claim
        self.lease_seconds = lease_seconds
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"lease-{claim.execution_id}",
            daemon=True,
        )

    def __enter__(self) -> LeaseKeeper:
        self._thread.start()
        return self

    def __exit__(
        self,
        _type: object,
        _value: object,
        _traceback: object,
    ) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, self.lease_seconds / 2))

    def assert_owned(self) -> None:
        if self._lost.is_set():
            raise ProblemException(
                status=409,
                code="EXECUTION_FENCE_LOST",
                title="Execution 围栏已失效",
                detail="旧 Worker 已停止推进当前 Execution。",
            )

    def _run(self) -> None:
        interval = max(1.0, min(10.0, self.lease_seconds / 3))
        while not self._stop.wait(interval):
            try:
                self.control.heartbeat_execution(
                    claim=self.claim,
                    lease_seconds=self.lease_seconds,
                )
            except BaseException:
                self._lost.set()
                return


class ExecutionWorker:
    def __init__(
        self,
        *,
        settings: Settings,
        control: ControlService,
        credentials: CredentialService,
        reconciler: WorkerReconciler,
        runtime_manifest: RuntimeManifest,
    ) -> None:
        self.settings = settings
        self.control = control
        self.credentials = credentials
        self.reconciler = reconciler
        self.runtime_manifest = runtime_manifest
        self.sensitive_runtime = SensitiveRuntimeStore(
            settings.sensitive_runtime_root,
            required_parent=Path("/tmp"),
        )
        self.sensitive_runtime.prepare_and_cleanup()
        self.logs = ExecutionLogService(
            settings=settings,
            control=control,
        )
        self.oracle = load_oracle_module(
            settings.runtime_manifest_path.parent / runtime_manifest.oracle.path
        )

    def claim_and_run(
        self,
        *,
        host_boot_id: str,
        cgroup_identity: str,
    ) -> bool:
        self.prepare_admission()
        claim = self.control.claim_next_execution(
            worker_id=self.settings.worker_id,
            host_boot_id=host_boot_id,
            cgroup_identity=cgroup_identity,
            credential_selector=self.credentials.select_active_binding,
            lease_seconds=self.settings.worker_lease_seconds,
        )
        if claim is None:
            return False
        self.run_claimed(claim)
        return True

    def prepare_admission(self) -> None:
        self.sensitive_runtime.prepare_and_cleanup()

    def run_claimed(self, claim: ClaimedExecution) -> None:
        context = self._load_context(claim)
        workspace = self._create_workspace(claim)
        state = "STARTING"
        log_path = (
            self.settings.log_volume_path / str(claim.execution_id) / f"{claim.attempt_id}.log"
        )
        cleanup_succeeded = False
        verification_run = VerificationRun()
        try:
            sensitive_attempt = self.sensitive_runtime.create_attempt(
                execution_id=claim.execution_id,
                attempt_id=claim.attempt_id,
            )
        except SensitiveRuntimeError:
            cleanup_succeeded = self._cleanup_attempt_artifacts(
                claim=claim,
                workspace=workspace,
            )
            self._fail_current_state(
                claim=claim,
                state=state,
                code="SENSITIVE_RUNTIME_UNAVAILABLE",
                oracle_started=False,
            )
            with suppress(Exception):
                self._record_workspace_cleanup(
                    claim=claim,
                    succeeded=cleanup_succeeded,
                )
            return
        job_file = sensitive_attempt.job_file
        with LeaseKeeper(
            control=self.control,
            claim=claim,
            lease_seconds=self.settings.worker_lease_seconds,
        ) as lease:
            try:
                with (
                    self.control.sessions() as secret_session,
                    ExitStack() as stack,
                ):
                    source_password = stack.enter_context(
                        self.credentials.decrypted_password(
                            secret_session,
                            datasource_id=context.source_datasource.id,
                            secret_id=self._required(context.execution.source_secret_id),
                            envelope_id=self._required(context.execution.source_secret_envelope_id),
                        )
                    )
                    target_password = stack.enter_context(
                        self.credentials.decrypted_password(
                            secret_session,
                            datasource_id=context.target_datasource.id,
                            secret_id=self._required(context.execution.target_secret_id),
                            envelope_id=self._required(context.execution.target_secret_envelope_id),
                        )
                    )
                    preflight = self._preflight(
                        claim=claim,
                        context=context,
                        workspace=workspace,
                        source_password=source_password,
                        target_password=target_password,
                    )
                    lease.assert_owned()
                    cancel_action = self.reconciler.poll_claim_action(claim)
                    if cancel_action == ProcessAction.CANCEL:
                        self.reconciler.complete_claimed_cancel(
                            claim=claim,
                            oracle_started=False,
                        )
                        return
                    if cancel_action == ProcessAction.FENCE_LOST:
                        lease.assert_owned()
                        raise RuntimeError("execution fence was lost")
                    self.control.record_claimed_preflight(
                        claim=claim,
                        runtime_preflight=RuntimePreflight(
                            datax_release=(self.runtime_manifest.datax_release),
                            runtime_sha256=(self.runtime_manifest.runtime_sha256),
                            reader_plugin_sha256=(context.version.reader_plugin_sha256),
                            writer_plugin_sha256=(context.version.writer_plugin_sha256),
                            resolved_config_hash=(preflight.resolved_config_hash),
                            source_connection_evidence_id=(preflight.source_evidence_id),
                            target_connection_evidence_id=(preflight.target_evidence_id),
                            target_empty_evidence=preflight.target_empty,
                        ),
                        evidence_validator=(self.credentials.validate_preflight_evidence),
                    )
                    write_job_file(job_file, preflight.datax_job)
                    preflight.datax_job.clear()
                    self.control.transition_claimed_execution(
                        claim=claim,
                        expected_state="STARTING",
                        new_state="RUNNING",
                        data_effect="NONE",
                        verification_state="NOT_STARTED",
                    )
                    state = "RUNNING"
                    process_result = self._run_datax(
                        claim=claim,
                        context=context,
                        job_file=job_file,
                        runtime_log_directory=sensitive_attempt.runtime_log_directory,
                        runtime_workspace=sensitive_attempt.process_working_directory,
                        log_path=log_path,
                        source_password=source_password,
                        target_password=target_password,
                        lease=lease,
                        source_resolved=preflight.source_resolved,
                        target_resolved=preflight.target_resolved,
                    )
                    self._record_process_result(
                        claim=claim,
                        result=process_result,
                    )
                    if process_result.end_reason == ProcessEndReason.FENCE_LOST:
                        return
                    if process_result.end_reason == ProcessEndReason.EGRESS_LOST:
                        self.control.transition_claimed_execution(
                            claim=claim,
                            expected_state="RUNNING",
                            new_state="FAILED",
                            data_effect="UNKNOWN",
                            verification_state="NOT_STARTED",
                            exit_code=process_result.returncode,
                            failure_code="EGRESS_LEASE_LOST",
                            failure_message=(
                                "Exact-IP egress lease renewal failed; "
                                "the DataX process was terminated."
                            ),
                            summary_parse_status="FAILED",
                        )
                        return
                    if process_result.end_reason == ProcessEndReason.CANCELED:
                        self.reconciler.complete_claimed_cancel(
                            claim=claim,
                            oracle_started=False,
                        )
                        return
                    if process_result.end_reason == ProcessEndReason.TIMED_OUT:
                        self.control.transition_claimed_execution(
                            claim=claim,
                            expected_state="RUNNING",
                            new_state="TIMED_OUT",
                            data_effect="UNKNOWN",
                            verification_state="NOT_STARTED",
                            exit_code=process_result.returncode,
                            failure_code="DATAX_TIMEOUT",
                            failure_message=("DataX exceeded the immutable execution timeout."),
                            summary_parse_status="FAILED",
                        )
                        return
                    if process_result.returncode != 0:
                        self.control.transition_claimed_execution(
                            claim=claim,
                            expected_state="RUNNING",
                            new_state="FAILED",
                            data_effect="UNKNOWN",
                            verification_state="NOT_STARTED",
                            exit_code=process_result.returncode,
                            failure_code="DATAX_PROCESS_FAILED",
                            failure_message=("DataX exited non-zero; target effect is unknown."),
                            summary_parse_status="FAILED",
                        )
                        return
                    self.control.transition_claimed_execution(
                        claim=claim,
                        expected_state="RUNNING",
                        new_state="VERIFYING",
                        data_effect="POSSIBLE",
                        verification_state="NOT_STARTED",
                        exit_code=0,
                        summary_parse_status="FAILED",
                    )
                    state = "VERIFYING"
                    report = self._verify(
                        claim=claim,
                        context=context,
                        workspace=workspace,
                        source_password=source_password,
                        target_password=target_password,
                        preflight=preflight,
                        verification_run=verification_run,
                        lease=lease,
                    )
                    # Recheck immediately before choosing a terminal branch.
                    # Every non-cancel terminal transaction repeats the active
                    # cancel check under the Execution row lock to close the
                    # final API-request/terminal-write race.
                    self._poll_verification_control(claim=claim, lease=lease)
                    artifact_hash = str(report["artifact_sha256"])
                    if report["result"] == "PASSED":
                        self.control.transition_claimed_execution(
                            claim=claim,
                            expected_state="VERIFYING",
                            new_state="SUCCEEDED",
                            data_effect="CONFIRMED",
                            verification_state="PASSED",
                            exit_code=0,
                            verification_report=report,
                            verification_evidence_hash=artifact_hash,
                        )
                    elif report["result"] == "FAILED":
                        self.control.transition_claimed_execution(
                            claim=claim,
                            expected_state="VERIFYING",
                            new_state="FAILED",
                            data_effect="POSSIBLE",
                            verification_state="FAILED",
                            exit_code=0,
                            verification_report=report,
                            verification_evidence_hash=artifact_hash,
                            failure_code="ORACLE_MISMATCH",
                            failure_message=("Independent row-multiset verification failed."),
                        )
                    else:
                        self.control.transition_claimed_execution(
                            claim=claim,
                            expected_state="VERIFYING",
                            new_state="FAILED",
                            data_effect="UNKNOWN",
                            verification_state="INCONCLUSIVE",
                            exit_code=0,
                            verification_report=report,
                            verification_evidence_hash=artifact_hash,
                            failure_code=str(
                                report.get("inconclusive_reason") or "ORACLE_INCONCLUSIVE"
                            ),
                            failure_message=("Independent verification was inconclusive."),
                        )
            except VerificationCanceled:
                self.reconciler.complete_claimed_cancel(
                    claim=claim,
                    oracle_started=verification_run.oracle_started,
                )
                return
            except ProblemException as exc:
                if exc.code == "EXECUTION_CANCEL_PENDING":
                    # transition_claimed_execution observed a cancel request
                    # under the same row lock that would otherwise publish a
                    # non-cancel terminal outcome. Finish the accepted cancel
                    # instead, regardless of which terminal branch raced it.
                    self._converge_accepted_cancel(
                        claim=claim,
                        oracle_started=verification_run.oracle_started,
                    )
                    return
                if exc.code in {
                    "EXECUTION_FENCE_LOST",
                    "FENCE_STATE_CONFLICT",
                }:
                    return
                self._fail_current_state(
                    claim=claim,
                    state=state,
                    code=exc.code,
                    oracle_started=verification_run.oracle_started,
                )
            except BaseException:
                self._fail_current_state(
                    claim=claim,
                    state=state,
                    code="WORKER_INTERNAL_FAILURE",
                    oracle_started=verification_run.oracle_started,
                )
            finally:
                cleanup_succeeded = self._cleanup_attempt_artifacts(
                    claim=claim,
                    workspace=workspace,
                )
                with suppress(Exception):
                    self._record_workspace_cleanup(
                        claim=claim,
                        succeeded=cleanup_succeeded,
                    )

    def _preflight(
        self,
        *,
        claim: ClaimedExecution,
        context: ExecutionContext,
        workspace: Path,
        source_password: bytearray,
        target_password: bytearray,
    ) -> PreflightResult:
        source_resolved = self.credentials.guard.resolve(
            context.source_policy,
            host=context.source_revision.host,
            port=context.source_revision.port,
        )
        target_resolved = self.credentials.guard.resolve(
            context.target_policy,
            host=context.target_revision.host,
            port=context.target_revision.port,
        )
        self._assert_datax_endpoint_pinning(
            revision=context.source_revision,
            policy=context.source_policy,
            resolved=source_resolved,
        )
        self._assert_datax_endpoint_pinning(
            revision=context.target_revision,
            policy=context.target_policy,
            resolved=target_resolved,
        )
        source_probe = self.credentials.connector.probe(
            context.source_revision,
            password=source_password,
            resolved=source_resolved,
        )
        target_probe = self.credentials.connector.probe(
            context.target_revision,
            password=target_password,
            resolved=target_resolved,
        )
        self._assert_physical_endpoint(
            context=context,
            revision=context.source_revision,
            server_identity=source_probe.server_identity,
            server_version=source_probe.server_version,
        )
        self._assert_physical_endpoint(
            context=context,
            revision=context.target_revision,
            server_identity=target_probe.server_identity,
            server_version=target_probe.server_version,
        )
        source_identity = TableIdentity(
            physical_endpoint_identity_id=(context.source_revision.physical_endpoint_identity_id),
            physical_table_identity_hash=(context.version.source_physical_table_identity_hash),
            catalog_name=context.source_revision.database_name,
            schema_name=(
                context.spec.source.table.schema_name
                if context.source_revision.engine == "POSTGRESQL_15"
                else ""
            ),
            table_name=context.spec.source.table.table_name,
        )
        target_identity = TableIdentity(
            physical_endpoint_identity_id=(context.target_namespace.physical_endpoint_identity_id),
            physical_table_identity_hash=(context.target_namespace.physical_table_identity_hash),
            catalog_name=context.target_namespace.normalized_catalog_name,
            schema_name=context.target_namespace.normalized_schema_name,
            table_name=context.target_namespace.normalized_table_name,
        )
        with self.credentials.connector.connection(
            context.source_revision,
            password=source_password,
            resolved=source_resolved,
            read_only=True,
        ) as connection:
            source_snapshot = probe_schema_snapshot(
                connection,
                engine=context.source_revision.engine,
                identity=source_identity,
            )
        with self.credentials.connector.connection(
            context.target_revision,
            password=target_password,
            resolved=target_resolved,
            read_only=True,
        ) as connection:
            target_snapshot = probe_schema_snapshot(
                connection,
                engine=context.target_revision.engine,
                identity=target_identity,
            )
        assert_snapshot_matches_job(
            source_snapshot,
            expected_hash=context.version.source_schema_hash,
            spec=context.spec,
            side="source",
        )
        assert_snapshot_matches_job(
            target_snapshot,
            expected_hash=context.version.target_schema_hash,
            spec=context.spec,
            side="target",
        )
        mappings = build_oracle_mappings(
            context.spec,
            source_engine=context.source_revision.engine,
            target_engine=context.target_revision.engine,
        )
        with self.credentials.connector.connection(
            context.source_revision,
            password=source_password,
            resolved=source_resolved,
            stream=True,
        ) as connection:
            source_peer = self.credentials.connector.connection_peer_ip(
                connection,
                engine=context.source_revision.engine,
            )
            source_observed_at = datetime.now(UTC)
            source_summary = capture_source_preflight(
                connection,
                engine=context.source_revision.engine,
                schema_name=context.spec.source.table.schema_name,
                table_name=context.spec.source.table.table_name,
                mappings=mappings,
                spool_directory=workspace / "oracle-preflight",
                oracle=self.oracle,
            )
        source_evidence_id = self._persist_connection_evidence(
            claim=claim,
            operation_kind="PREFLIGHT",
            revision_id=context.source_revision.id,
            resolved=source_resolved,
            peer_ip=source_peer,
            observed_at=source_observed_at,
        )
        with self.credentials.connector.connection(
            context.target_revision,
            password=target_password,
            resolved=target_resolved,
        ) as connection:
            target_peer = self.credentials.connector.connection_peer_ip(
                connection,
                engine=context.target_revision.engine,
            )
            target_observed_at = datetime.now(UTC)
            target_count, target_checked_at = count_target_rows(
                connection,
                engine=context.target_revision.engine,
                schema_name=context.spec.target.table.schema_name,
                table_name=context.spec.target.table.table_name,
            )
        target_evidence_id = self._persist_connection_evidence(
            claim=claim,
            operation_kind="PREFLIGHT",
            revision_id=context.target_revision.id,
            resolved=target_resolved,
            peer_ip=target_peer,
            observed_at=target_observed_at,
        )
        if target_count != 0:
            raise ProblemException(
                status=409,
                code="TARGET_NOT_EMPTY",
                title="目标表不是空表",
                detail="V1 不会向非空目标追加、清空或覆盖数据。",
            )
        target_empty_document: dict[str, Any] = {
            "result": "EMPTY",
            "checked_at": target_checked_at.isoformat().replace(
                "+00:00",
                "Z",
            ),
            "observed_row_count": 0,
            "target_datasource_revision_id": str(context.target_revision.id),
            "target_endpoint_policy_revision_id": str(context.target_policy.id),
            "target_namespace_id": str(context.target_namespace.id),
            "physical_table_identity_hash": (context.target_namespace.physical_table_identity_hash),
            "connection_evidence_id": str(target_evidence_id),
        }
        target_empty_document["evidence_hash"] = self._domain_hash(
            "DXTARGETEMPTYv1",
            target_empty_document,
        )
        target_empty = TargetEmptyEvidence.model_validate(target_empty_document)
        source_connection = RuntimeConnection(
            engine=context.source_revision.engine,
            host=context.source_revision.host,
            port=context.source_revision.port,
            database_name=context.source_revision.database_name,
            username=context.source_revision.username,
            password=source_password,
            ssl_mode=context.source_revision.ssl_mode,
        )
        target_connection = RuntimeConnection(
            engine=context.target_revision.engine,
            host=context.target_revision.host,
            port=context.target_revision.port,
            database_name=context.target_revision.database_name,
            username=context.target_revision.username,
            password=target_password,
            ssl_mode=context.target_revision.ssl_mode,
        )
        datax_job = build_datax_job(
            context.spec,
            source=source_connection,
            target=target_connection,
        )
        redacted_job = copy.deepcopy(datax_job)
        content = redacted_job["job"]["content"][0]
        content["reader"]["parameter"]["password"] = "[SECRET_REFERENCE]"
        content["writer"]["parameter"]["password"] = "[SECRET_REFERENCE]"
        resolved_config_hash = self._domain_hash(
            "DXRESOLVEDCONFIGv1",
            {
                "job": redacted_job,
                "source_connection_evidence_id": str(source_evidence_id),
                "target_connection_evidence_id": str(target_evidence_id),
                "attempt_id": str(claim.attempt_id),
                "fence_epoch": claim.fence_epoch,
            },
        )
        return PreflightResult(
            source_summary=source_summary,
            source_resolved=source_resolved,
            target_resolved=target_resolved,
            source_evidence_id=source_evidence_id,
            target_evidence_id=target_evidence_id,
            target_empty=target_empty,
            resolved_config_hash=resolved_config_hash,
            datax_job=datax_job,
        )

    @staticmethod
    def _assert_datax_endpoint_pinning(
        *,
        revision: DatasourceRevision,
        policy: EndpointPolicyRevision,
        resolved: ResolvedEndpoint,
    ) -> None:
        """Fail closed until the certified JDBC runtime can pin FQDN sockets.

        The shared netns must allow control-plane traffic to PostgreSQL. A JVM
        resolving an external FQDN a second time could otherwise reach that
        control subnet without using the selected-IP lease. Exact IP URLs have
        no second DNS decision and are therefore the only certified V1 DataX
        endpoint shape in the current runtime.
        """

        try:
            revision_ip = ipaddress.ip_address(revision.host).compressed
            policy_ip = ipaddress.ip_address(policy.host_value).compressed
        except ValueError as exc:
            raise ProblemException(
                status=409,
                code="DATAX_ENDPOINT_PINNING_UNSUPPORTED",
                title="DataX 端点尚不能安全固定",
                detail=(
                    "当前固定 Runtime 只允许 EXACT_IP 数据源进入 DataX；"
                    "FQDN 仍可用于连接测试和元数据，但不能启动复制。"
                ),
            ) from exc
        if (
            policy.host_kind != "EXACT_IP"
            or revision_ip != policy_ip
            or revision_ip != resolved.selected_ip
            or resolved.resolved_ips != (resolved.selected_ip,)
        ):
            raise ProblemException(
                status=409,
                code="DATAX_ENDPOINT_PINNING_UNSUPPORTED",
                title="DataX 端点尚不能安全固定",
                detail="DataX 只能连接当前 EndpointPolicy 唯一选定的精确 IP。",
            )
        if revision.ssl_mode == "VERIFY_FULL":
            raise ProblemException(
                status=409,
                code="DATAX_VERIFY_FULL_IP_UNCERTIFIED",
                title="DataX IP 身份校验尚未认证",
                detail=(
                    "当前固定 JDBC Runtime 尚未完成 IP SAN 的 VERIFY_FULL 认证；"
                    "本次执行已在启动 DataX 前安全阻断。"
                ),
            )

    def _run_datax(
        self,
        *,
        claim: ClaimedExecution,
        context: ExecutionContext,
        job_file: Path,
        runtime_log_directory: Path,
        runtime_workspace: Path,
        log_path: Path,
        source_password: bytearray,
        target_password: bytearray,
        lease: LeaseKeeper,
        source_resolved: ResolvedEndpoint,
        target_resolved: ResolvedEndpoint,
    ) -> ManagedProcessResult:
        self.credentials.guard.verify_rebinding(
            context.source_policy,
            source_resolved,
        )
        self.credentials.guard.verify_rebinding(
            context.target_policy,
            target_resolved,
        )
        runtime_root = self.settings.runtime_manifest_path.parent
        command = build_datax_command(
            java_path=self.settings.java_binary_path,
            datax_home=runtime_root / self.runtime_manifest.datax_home,
            job_path=job_file,
            job_root=job_file.parent,
            log_directory=runtime_log_directory,
            workspace=runtime_workspace,
            job_id=str(claim.execution_id.int & ((1 << 63) - 1)),
        )

        with (
            self.credentials.guard.lease(source_resolved) as source_egress,
            self.credentials.guard.lease(target_resolved) as target_egress,
        ):
            source_egress.assert_active()
            target_egress.assert_active()
            evidence_observed_at = datetime.now(UTC)
            self._persist_connection_evidence(
                claim=claim,
                operation_kind="DATAX",
                revision_id=context.source_revision.id,
                resolved=source_resolved,
                peer_ip=None,
                peer_observation_status="ENFORCED_NOT_OBSERVED",
                observed_at=evidence_observed_at,
            )
            self._persist_connection_evidence(
                claim=claim,
                operation_kind="DATAX",
                revision_id=context.target_revision.id,
                resolved=target_resolved,
                peer_ip=None,
                peer_observation_status="ENFORCED_NOT_OBSERVED",
                observed_at=evidence_observed_at,
            )

            def tick() -> ProcessAction:
                if lease._lost.is_set():  # noqa: SLF001
                    return ProcessAction.FENCE_LOST
                if source_egress.lost or target_egress.lost:
                    return ProcessAction.EGRESS_LOST
                return self.reconciler.poll_claim_action(claim)

            result = run_managed_process(
                command,
                workspace=runtime_workspace,
                log_path=log_path,
                secrets=[source_password, target_password],
                timeout_seconds=context.execution.timeout_seconds,
                tick=tick,
                process_started=lambda process_identity: self.reconciler.record_process_identity(
                    claim=claim,
                    identity=process_identity,
                    workspace_path_hash=self._workspace_hash(runtime_workspace),
                ),
                maximum_log_bytes=self.settings.execution_log_limit_bytes,
                maximum_line_bytes=(self.settings.execution_log_line_limit_bytes),
                poll_seconds=self.settings.worker_control_poll_seconds,
            )
            if result.end_reason != ProcessEndReason.EGRESS_LOST:
                source_egress.assert_active()
                target_egress.assert_active()
            return result

    def _verify(
        self,
        *,
        claim: ClaimedExecution,
        context: ExecutionContext,
        workspace: Path,
        source_password: bytearray,
        target_password: bytearray,
        preflight: PreflightResult,
        verification_run: VerificationRun,
        lease: LeaseKeeper,
    ) -> dict[str, Any]:
        self._poll_verification_control(claim=claim, lease=lease)
        source_resolved = self.credentials.guard.resolve(
            context.source_policy,
            host=context.source_revision.host,
            port=context.source_revision.port,
        )
        target_resolved = self.credentials.guard.resolve(
            context.target_policy,
            host=context.target_revision.host,
            port=context.target_revision.port,
        )
        mappings = build_oracle_mappings(
            context.spec,
            source_engine=context.source_revision.engine,
            target_engine=context.target_revision.engine,
        )
        self._assert_current_schemas(
            context=context,
            source_password=source_password,
            target_password=target_password,
            source_resolved=source_resolved,
            target_resolved=target_resolved,
        )
        self._poll_verification_control(claim=claim, lease=lease)
        with (
            self.credentials.connector.connection(
                context.source_revision,
                password=source_password,
                resolved=source_resolved,
                stream=True,
            ) as source_connection,
            self.credentials.connector.connection(
                context.target_revision,
                password=target_password,
                resolved=target_resolved,
                stream=True,
            ) as target_connection,
        ):
            source_peer = self.credentials.connector.connection_peer_ip(
                source_connection,
                engine=context.source_revision.engine,
            )
            target_peer = self.credentials.connector.connection_peer_ip(
                target_connection,
                engine=context.target_revision.engine,
            )
            source_observed_at = datetime.now(UTC)
            target_observed_at = datetime.now(UTC)
            self._persist_connection_evidence(
                claim=claim,
                operation_kind="ORACLE",
                revision_id=context.source_revision.id,
                resolved=source_resolved,
                peer_ip=source_peer,
                observed_at=source_observed_at,
            )
            self._persist_connection_evidence(
                claim=claim,
                operation_kind="ORACLE",
                revision_id=context.target_revision.id,
                resolved=target_resolved,
                peer_ip=target_peer,
                observed_at=target_observed_at,
            )
            self._poll_verification_control(claim=claim, lease=lease)
            self.control.mark_claimed_oracle_started(claim=claim)
            verification_run.oracle_started = True
            reads = verify_databases(
                source_connection,
                target_connection,
                source_engine=context.source_revision.engine,
                target_engine=context.target_revision.engine,
                source_schema_name=context.spec.source.table.schema_name,
                source_table_name=context.spec.source.table.table_name,
                target_schema_name=context.spec.target.table.schema_name,
                target_table_name=context.spec.target.table.table_name,
                mappings=mappings,
                spool_directory=workspace / "oracle-verification",
                oracle=self.oracle,
                control_callback=lambda: self._poll_verification_control(
                    claim=claim,
                    lease=lease,
                ),
            )
        facts = self._verification_facts(claim)
        runtime_snapshot = ExecutionRuntimeSnapshot.model_validate(
            facts["execution"].runtime_snapshot
        )
        confirmation = dict(facts["execution"].target_exclusivity_confirmation)
        confirmation.update(
            {
                "status": facts["execution"].target_exclusivity_status,
                "revoked_at": facts["execution"].target_exclusivity_revoked_at,
                "revocation_reason": facts["execution"].target_exclusivity_revocation_reason,
            }
        )
        finished_at = datetime.now(UTC)
        return self.oracle.build_verification_report(
            execution_id=str(claim.execution_id),
            job_version_id=str(context.version.id),
            started_at=preflight.source_summary.read_started_at,
            finished_at=finished_at,
            operator_confirmed_at=self._as_datetime(
                facts["execution"].source_quiescence_confirmation["confirmed_at"]
            ),
            preflight_source_summary=preflight.source_summary.summary,
            post_source_summary=reads.source.summary,
            target_summary=reads.target.summary,
            difference=reads.difference,
            source_read_started_at=reads.source.read_started_at,
            source_read_finished_at=reads.source.read_finished_at,
            target_read_started_at=reads.target.read_started_at,
            target_read_finished_at=reads.target.read_finished_at,
            target_snapshot_id=reads.target.snapshot_id,
            target_snapshot_started_at=reads.target.snapshot_started_at,
            target_snapshot_finished_at=reads.target.snapshot_finished_at,
            target_lock_key_hash=(facts["lock"].physical_table_identity_hash),
            fence_epoch=claim.fence_epoch,
            target_lock_held=facts["lock_held"],
            target_exclusivity=confirmation,
            target_empty_checked_at=(runtime_snapshot.target_empty_evidence.checked_at),
            confirmation_evidence_sha256=(runtime_snapshot.target_exclusivity_confirmation_sha256),
            mappings=[
                {
                    "ordinal": mapping.ordinal,
                    "source_column": mapping.source_column,
                    "target_column": mapping.target_column,
                    "logical_type": mapping.logical_type,
                }
                for mapping in mappings
            ],
        )

    def _poll_verification_control(
        self,
        *,
        claim: ClaimedExecution,
        lease: LeaseKeeper,
    ) -> None:
        """Fail closed on every bounded oracle batch control boundary."""

        lease.assert_owned()
        action = self.reconciler.poll_claim_action(claim)
        if action == ProcessAction.CANCEL:
            raise VerificationCanceled
        if action == ProcessAction.FENCE_LOST:
            raise ProblemException(
                status=409,
                code="EXECUTION_FENCE_LOST",
                title="Execution 围栏已失效",
                detail="旧 Worker 已停止推进当前 Execution。",
            )
        self.control.assert_claimed_verification_exclusivity(claim=claim)

    def _assert_current_schemas(
        self,
        *,
        context: ExecutionContext,
        source_password: bytearray,
        target_password: bytearray,
        source_resolved: ResolvedEndpoint,
        target_resolved: ResolvedEndpoint,
    ) -> None:
        source_identity = TableIdentity(
            physical_endpoint_identity_id=(context.source_revision.physical_endpoint_identity_id),
            physical_table_identity_hash=(context.version.source_physical_table_identity_hash),
            catalog_name=context.source_revision.database_name,
            schema_name=(
                context.spec.source.table.schema_name
                if context.source_revision.engine == "POSTGRESQL_15"
                else ""
            ),
            table_name=context.spec.source.table.table_name,
        )
        target_identity = TableIdentity(
            physical_endpoint_identity_id=(context.target_namespace.physical_endpoint_identity_id),
            physical_table_identity_hash=(context.target_namespace.physical_table_identity_hash),
            catalog_name=context.target_namespace.normalized_catalog_name,
            schema_name=context.target_namespace.normalized_schema_name,
            table_name=context.target_namespace.normalized_table_name,
        )
        with self.credentials.connector.connection(
            context.source_revision,
            password=source_password,
            resolved=source_resolved,
            read_only=True,
        ) as connection:
            source_snapshot = probe_schema_snapshot(
                connection,
                engine=context.source_revision.engine,
                identity=source_identity,
            )
        with self.credentials.connector.connection(
            context.target_revision,
            password=target_password,
            resolved=target_resolved,
            read_only=True,
        ) as connection:
            target_snapshot = probe_schema_snapshot(
                connection,
                engine=context.target_revision.engine,
                identity=target_identity,
            )
        assert_snapshot_matches_job(
            source_snapshot,
            expected_hash=context.version.source_schema_hash,
            spec=context.spec,
            side="source",
        )
        assert_snapshot_matches_job(
            target_snapshot,
            expected_hash=context.version.target_schema_hash,
            spec=context.spec,
            side="target",
        )

    def _persist_connection_evidence(
        self,
        *,
        claim: ClaimedExecution,
        operation_kind: str,
        revision_id: UUID,
        resolved: ResolvedEndpoint,
        peer_ip: str | None,
        observed_at: datetime,
        peer_observation_status: str = "OBSERVED",
    ) -> UUID:
        with self.credentials.sessions.begin() as session:
            revision = session.get(DatasourceRevision, revision_id)
            if revision is None:
                raise RuntimeError("datasource revision disappeared")
            evidence = self.credentials.persist_worker_connection_evidence(
                session,
                operation_kind=operation_kind,
                datasource_revision=revision,
                resolved=resolved,
                peer_ip=peer_ip,
                peer_observation_status=peer_observation_status,
                tls_peer_spki_sha256=None,
                observed_at=observed_at,
                execution_id=claim.execution_id,
                recovery_probe_id=None,
                attempt_id=claim.attempt_id,
                fence_epoch=claim.fence_epoch,
            )
            return evidence.id

    def _load_context(self, claim: ClaimedExecution) -> ExecutionContext:
        with self.control.sessions() as session:
            execution = session.get(Execution, claim.execution_id)
            if (
                execution is None
                or execution.active_attempt_id != claim.attempt_id
                or execution.fence_epoch != claim.fence_epoch
                or execution.process_state != "STARTING"
            ):
                raise RuntimeError("claimed execution context is stale")
            version = session.get(JobVersion, execution.job_version_id)
            source_revision = session.get(
                DatasourceRevision,
                execution.source_datasource_revision_id,
            )
            target_revision = session.get(
                DatasourceRevision,
                execution.target_datasource_revision_id,
            )
            source_policy = session.get(
                EndpointPolicyRevision,
                execution.source_endpoint_policy_revision_id,
            )
            target_policy = session.get(
                EndpointPolicyRevision,
                execution.target_endpoint_policy_revision_id,
            )
            target_namespace = session.get(
                TargetNamespace,
                execution.target_namespace_id,
            )
            target_lock = session.scalar(
                select(TargetCopyLock).where(TargetCopyLock.execution_id == execution.id)
            )
            project = session.get(Project, execution.project_id)
            if (
                version is None
                or source_revision is None
                or target_revision is None
                or source_policy is None
                or target_policy is None
                or target_namespace is None
                or target_lock is None
                or project is None
            ):
                raise RuntimeError("claimed immutable binding is missing")
            source_datasource = session.get(
                Datasource,
                source_revision.datasource_id,
            )
            target_datasource = session.get(
                Datasource,
                target_revision.datasource_id,
            )
            if source_datasource is None or target_datasource is None:
                raise RuntimeError("claimed datasource binding is missing")
            return ExecutionContext(
                execution=execution,
                version=version,
                source_revision=source_revision,
                target_revision=target_revision,
                source_policy=source_policy,
                target_policy=target_policy,
                source_datasource=source_datasource,
                target_datasource=target_datasource,
                target_namespace=target_namespace,
                organization_id=project.organization_id,
                target_lock=target_lock,
                spec=JobSpecV1.model_validate(version.spec_json),
            )

    def _assert_physical_endpoint(
        self,
        *,
        context: ExecutionContext,
        revision: DatasourceRevision,
        server_identity: str,
        server_version: str,
    ) -> None:
        expected_major = "8." if revision.engine == "MYSQL_8" else "15."
        if not server_version.startswith(expected_major):
            raise ProblemException(
                status=409,
                code="DATABASE_MAJOR_VERSION_MISMATCH",
                title="数据库主版本不匹配",
                detail="V1 仅认证 MySQL 8 与 PostgreSQL 15。",
            )
        identity_scheme = (
            "MYSQL_SERVER_UUID" if revision.engine == "MYSQL_8" else "POSTGRES_SYSTEM_IDENTIFIER"
        )
        actual_hash = hashlib.sha256(
            (
                "DXPHYSICALENDPOINTv1\n"
                f"{str(context.organization_id).lower()}\n"
                f"{revision.engine}\n"
                f"{identity_scheme}\n"
                f"{server_identity}"
            ).encode()
        ).hexdigest()
        with self.control.sessions() as session:
            identity = session.get(
                PhysicalEndpointIdentity,
                revision.physical_endpoint_identity_id,
            )
            if (
                identity is None
                or identity.engine != revision.engine
                or identity.identity_scheme != identity_scheme
                or identity.server_identity_hash != actual_hash
            ):
                raise ProblemException(
                    status=409,
                    code="PHYSICAL_ENDPOINT_IDENTITY_MISMATCH",
                    title="数据库物理身份不匹配",
                    detail="不会在与已授权物理端点不一致的服务器上执行。",
                )

    def _verification_facts(
        self,
        claim: ClaimedExecution,
    ) -> dict[str, Any]:
        with self.control.sessions() as session:
            execution = session.get(Execution, claim.execution_id)
            lock = session.scalar(
                select(TargetCopyLock).where(TargetCopyLock.execution_id == claim.execution_id)
            )
            if execution is None or lock is None:
                raise RuntimeError("verification control facts are missing")
            lock_held = (
                execution.process_state == "VERIFYING"
                and execution.active_attempt_id == claim.attempt_id
                and execution.fence_epoch == claim.fence_epoch
                and lock.state == "ACTIVE"
                and lock.attempt_id == claim.attempt_id
                and lock.fence_epoch == claim.fence_epoch
            )
            return {
                "execution": execution,
                "lock": lock,
                "lock_held": lock_held,
            }

    def _record_process_result(
        self,
        *,
        claim: ClaimedExecution,
        result: ManagedProcessResult,
    ) -> None:
        self.logs.persist_claimed_process_log(
            claim=claim,
            result=result.log,
        )
        with self.control.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            _execution, attempt = self.control._current_fenced_attempt(  # noqa: SLF001
                session,
                claim=claim,
                now=now,
                lock=True,
            )
            attempt.exit_code = result.returncode

    def _fail_current_state(
        self,
        *,
        claim: ClaimedExecution,
        state: str,
        code: str,
        oracle_started: bool,
    ) -> None:
        if state not in {"STARTING", "RUNNING", "VERIFYING"}:
            return
        try:
            self.control.transition_claimed_execution(
                claim=claim,
                expected_state=state,
                new_state="FAILED",
                data_effect="NONE" if state == "STARTING" else "UNKNOWN",
                verification_state=(
                    "INCONCLUSIVE" if state == "VERIFYING" and oracle_started else "NOT_STARTED"
                ),
                exit_code=0 if state == "VERIFYING" else None,
                failure_code=code,
                failure_message=("Worker failed closed without exposing external error text."),
                summary_parse_status=("FAILED" if state != "STARTING" else None),
            )
        except ProblemException as exc:
            if exc.code == "EXECUTION_CANCEL_PENDING":
                self._converge_accepted_cancel(
                    claim=claim,
                    oracle_started=oracle_started,
                )
            return
        except ValueError:
            return

    def _converge_accepted_cancel(
        self,
        *,
        claim: ClaimedExecution,
        oracle_started: bool,
    ) -> bool:
        """Acknowledge and atomically consume a cancel that won terminal ordering."""

        if self.reconciler.poll_claim_action(claim) != ProcessAction.CANCEL:
            return False
        self.reconciler.complete_claimed_cancel(
            claim=claim,
            oracle_started=oracle_started,
        )
        return True

    def _create_workspace(self, claim: ClaimedExecution) -> Path:
        root = self.settings.workspace_volume_path.resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.settings.workspace_volume_path.is_symlink():
            raise RuntimeError("workspace root must not be a symbolic link")
        workspace = root / str(claim.execution_id) / str(claim.attempt_id)
        workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
        return workspace

    def _cleanup_workspace(
        self,
        *,
        workspace: Path,
    ) -> bool:
        root = self.settings.workspace_volume_path.resolve()
        try:
            resolved = workspace.resolve()
            if workspace.is_symlink() or not resolved.is_relative_to(root) or resolved == root:
                return False
            shutil.rmtree(resolved)
            return True
        except OSError:
            return False

    def _cleanup_attempt_artifacts(
        self,
        *,
        claim: ClaimedExecution,
        workspace: Path,
    ) -> bool:
        sensitive_succeeded = True
        try:
            self.sensitive_runtime.remove_attempt(
                execution_id=claim.execution_id,
                attempt_id=claim.attempt_id,
            )
        except SensitiveRuntimeError:
            sensitive_succeeded = False
        workspace_succeeded = self._cleanup_workspace(workspace=workspace)
        return sensitive_succeeded and workspace_succeeded

    def _record_workspace_cleanup(
        self,
        *,
        claim: ClaimedExecution,
        succeeded: bool,
    ) -> None:
        with self.control.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            execution = session.get(Execution, claim.execution_id)
            attempt = session.get(ExecutionAttempt, claim.attempt_id)
            if execution is None or attempt is None:
                return
            if succeeded:
                attempt.workspace_deleted_at = now
                return
            self.control._append_execution_event(  # noqa: SLF001
                session,
                execution,
                event_type="WORKSPACE_CLEANUP_FAILED",
                from_state=execution.process_state,
                to_state=execution.process_state,
                attempt_id=attempt.id,
                payload={
                    "workspace_path_hash": attempt.workspace_path_hash,
                    "manual_cleanup_required": True,
                },
                now=now,
            )

    @staticmethod
    def _required(value: UUID | None) -> UUID:
        if value is None:
            raise RuntimeError("claimed credential binding is incomplete")
        return value

    @staticmethod
    def _workspace_hash(path: Path) -> str:
        return hashlib.sha256(
            b"DXWORKSPACEPATHv1\n" + str(path.resolve()).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _domain_hash(domain: str, value: object) -> str:
        return hashlib.sha256(domain.encode("ascii") + b"\n" + rfc8785.dumps(value)).hexdigest()

    @staticmethod
    def _as_datetime(value: str | datetime) -> datetime:
        parsed = (
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            if isinstance(value, str)
            else value
        )
        return ensure_aware(parsed).astimezone(UTC)
