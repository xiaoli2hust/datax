from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID, uuid4

import rfc8785
from sqlalchemy import (
    DateTime,
    Engine,
    String,
    Uuid,
    and_,
    cast,
    create_engine,
    func,
    or_,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from datax_studio.api.problems import ProblemException
from datax_studio.audit_integrity import advance_audit_chain_watermark
from datax_studio.auth.db import (
    AuditEvent,
    IdempotencyRecord,
    MembershipStatus,
    Organization,
    OrganizationMember,
    Role,
    ScopeType,
    User,
)
from datax_studio.auth.security import ensure_aware, utc_now
from datax_studio.auth.service import (
    IDEMPOTENCY_HASH_SCHEME,
    AuditContext,
    OperationResult,
    Principal,
)
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    DatasourceUsageGrant,
    EndpointPolicy,
    EndpointPolicyRevision,
    Execution,
    ExecutionAttempt,
    ExecutionCancelRequest,
    ExecutionEvent,
    JobVersion,
    PhysicalEndpointIdentity,
    Project,
    ProjectQueueServiceCursor,
    QueueSchedulerState,
    SyncJob,
    SystemControl,
    TargetCopyLock,
    TargetNamespace,
    TransferPolicy,
    WorkTerminationRequest,
)
from datax_studio.core.schemas import (
    AuditPage,
    CancelRequestResponse,
    ClaimedExecution,
    CredentialBinding,
    DashboardDataEffectCounts,
    DashboardDrilldown,
    DashboardDrilldownFilters,
    DashboardExecutionCounts,
    DashboardExecutionItem,
    DashboardJobCounts,
    DashboardResponse,
    DashboardRuntime,
    DashboardSuccessRate,
    DashboardTrendBucket,
    DashboardVerificationCounts,
    DashboardVerifiedRecords,
    DashboardWindow,
    EndpointPolicyCreate,
    EndpointPolicyPage,
    EndpointPolicyResponse,
    EndpointPolicyRevisionResponse,
    ExecutionCreate,
    ExecutionPage,
    ExecutionResponse,
    ExecutionRuntimeSnapshot,
    JobCreate,
    JobPage,
    JobPatch,
    JobPreview,
    JobResponse,
    JobSpecV1,
    JobVersionPage,
    JobVersionResponse,
    PhysicalEndpointIdentityResponse,
    PluginAccess,
    PluginArtifact,
    PluginCapabilities,
    PluginConnectionField,
    PluginDependency,
    PluginEvidence,
    PluginFieldConstraints,
    PluginManifest,
    PluginOracle,
    PluginPage,
    PluginRuntime,
    PluginSupplyChain,
    PluginUpstream,
    ProjectCreate,
    ProjectPage,
    ProjectPatch,
    ProjectResponse,
    RunSummary,
    RuntimePreflight,
    TargetCopyLockSummary,
    TargetEmptyEvidence,
    TargetExclusivityRevocationRequest,
    TargetNamespaceSnapshot,
    ValidationIssue,
    ValidationReport,
    VerificationSummary,
)
from datax_studio.egress_attestation import (
    POLICY_ENGINE_VERSION,
    RESOLVER_POLICY_VERSION,
)
from datax_studio.plugin_certification import (
    DenyAllPluginCertificationSource,
    PluginCertificationSource,
    e4_qualification_block_reasons,
    ordinary_user_execution_block_reasons,
    release_promotion_ref_block_reason,
    require_ordinary_user_execution_pair,
)
from datax_studio.recovery.gates import ensure_recovery_gate
from datax_studio.schema_snapshot import (
    schema_snapshot_hash,
    validate_schema_snapshot,
)
from datax_studio.settings import Settings
from datax_studio.worker.job_builder import (
    RuntimeConnection,
    UnsafeJobSpec,
    build_datax_job,
)

_IDEMPOTENCY_HASH_DOMAIN = b"DataXEnterpriseStudio\x00IdempotencyRequestHash\x00v1\x00"
_AUDIT_USER_AGENT_HASH_DOMAIN = b"DataXEnterpriseStudio\x00AuditUserAgentHash\x00v1\x00"
_CURSOR_DOMAIN = b"DataXEnterpriseStudio\x00Cursor\x00v1\x00"
_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED", "LOST"}
_ACTIVE_LOCK_STATES = {"RESERVED", "ACTIVE", "RECOVERY_REQUIRED"}
_ACTIVE_WORK_TERMINATION_STATUSES = ("PENDING", "ACKNOWLEDGED")
_TERMINATION_REASON_PRIORITY = {
    "SECRET_COMPROMISED": 0,
    "SECRET_REVOKED": 1,
    "TARGET_EXCLUSIVITY_REVOKED": 2,
    "TARGET_EXCLUSIVITY_EXPIRED": 3,
}
_TERMINATION_FAILURE_CODES = {
    "SECRET_COMPROMISED": "CREDENTIAL_SECRET_COMPROMISED",
    "SECRET_REVOKED": "CREDENTIAL_SECRET_REVOKED",
    "TARGET_EXCLUSIVITY_REVOKED": "TARGET_EXCLUSIVITY_BROKEN",
    "TARGET_EXCLUSIVITY_EXPIRED": "TARGET_EXCLUSIVITY_BROKEN",
}
_PROCESS_STATES = (
    "QUEUED",
    "STARTING",
    "RUNNING",
    "VERIFYING",
    "CANCEL_REQUESTED",
    "SUCCEEDED",
    "FAILED",
    "TIMED_OUT",
    "CANCELED",
    "LOST",
)
_VERIFICATION_STATES = (
    "NOT_STARTED",
    "VERIFYING",
    "PASSED",
    "FAILED",
    "INCONCLUSIVE",
)
_DATA_EFFECTS = ("NONE", "POSSIBLE", "CONFIRMED", "UNKNOWN")
_DASHBOARD_FAILURE_STATES = ("FAILED", "TIMED_OUT", "LOST")
_ORACLE_NORMALIZATION_V1: dict[str, Any] = {
    "row_algorithm": "SHA-256",
    "row_preimage": "DOMAIN_NUL_FIELD_COUNT_U32_BE_FIELDS",
    "field_encoding": "TAG_LENGTH_U16_BE_TAG_VALUE_LENGTH_U64_BE_VALUE",
    "collection_semantics": "MULTISET_WITH_COUNTS",
    "stable_order": "ROW_DIGEST_ASC_THEN_COUNT",
    "multiset_preimage": "DOMAIN_NUL_ROW_DIGEST_RAW32_COUNT_U64_BE",
    "null_encoding": "TYPE_TAGGED_NULL",
    "text_encoding": "UTF-8",
    "unicode_normalization": "NFC",
    "trim_text": False,
    "decimal_encoding": "CANONICAL_BASE10_NO_EXPONENT_NO_INSIGNIFICANT_ZERO",
    "negative_zero": "NORMALIZE_TO_ZERO",
    "session_timezone": "UTC",
    "timestamp_encoding": "RFC3339_UTC_MICROSECONDS",
    "boolean_encoding": "LOWERCASE_TRUE_FALSE",
    "binary_encoding": "BASE64_RFC4648",
    "field_separator": "LENGTH_PREFIXED",
}


@dataclass(frozen=True)
class ValidationMaterial:
    """Output of a real metadata/egress validation component.

    This object is not produced by a built-in fake. Until the real validator is
    configured, the HTTP validate endpoint fails closed.
    """

    source_schema_snapshot: dict[str, Any]
    target_schema_snapshot: dict[str, Any]
    source_schema_hash: str
    target_schema_hash: str
    source_physical_table_identity_hash: str
    target_namespace_id: UUID
    transfer_policy_id: UUID
    transfer_policy_scope_hash: str
    runtime_sha256: str
    reader_plugin_sha256: str
    writer_plugin_sha256: str


@dataclass(frozen=True)
class RuntimeValidationMaterial:
    runtime_sha256: str
    reader_plugin_sha256: str
    writer_plugin_sha256: str


class CredentialBindingSelector(Protocol):
    def __call__(
        self,
        session: Session,
        *,
        source_datasource_id: UUID,
        target_datasource_id: UUID,
    ) -> CredentialBinding: ...


class PreflightEvidenceValidator(Protocol):
    def __call__(
        self,
        session: Session,
        *,
        claim: ClaimedExecution,
        source_evidence_id: UUID,
        target_evidence_id: UUID,
        source_revision_id: UUID,
        target_revision_id: UUID,
        source_policy_revision_id: UUID,
        target_policy_revision_id: UUID,
    ) -> None: ...


def build_control_service(
    settings: Settings,
    *,
    engine: Engine | None = None,
) -> ControlService:
    """Build the control service, optionally on a caller-owned Engine.

    The API owns its normal pool, while the single Worker process passes its
    bounded pool here. That keeps independently constructed Worker services
    from each reserving a default SQLAlchemy pool under the Worker login.
    """

    if engine is None:
        engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    key = settings.idempotency_hmac_key_file.read_bytes()
    return ControlService(
        sessions=sessions,
        integrity_hmac_key=key,
        worker_id=settings.worker_id,
        worker_stale_seconds=settings.worker_stale_seconds,
        resolver_policy_version=settings.resolver_policy_version,
        egress_policy_version=settings.egress_policy_version,
    )


class ControlService:
    def __init__(
        self,
        *,
        sessions: sessionmaker[Session],
        integrity_hmac_key: bytes,
        worker_id: str = "worker-1",
        worker_stale_seconds: float = 20.0,
        resolver_policy_version: str = RESOLVER_POLICY_VERSION,
        egress_policy_version: str = POLICY_ENGINE_VERSION,
        plugin_certification_source: PluginCertificationSource | None = None,
    ) -> None:
        if len(integrity_hmac_key) < 32:
            raise ValueError("control-plane integrity HMAC key must contain at least 32 bytes")
        self.sessions = sessions
        self._integrity_hmac_key = bytes(integrity_hmac_key)
        self._worker_id = worker_id
        self._worker_stale_seconds = worker_stale_seconds
        self._resolver_policy_version = resolver_policy_version
        self._egress_policy_version = egress_policy_version
        self._plugin_certification_source = (
            plugin_certification_source or DenyAllPluginCertificationSource()
        )

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------
    def create_project(
        self,
        *,
        principal: Principal,
        request: ProjectCreate,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[ProjectResponse]:
        self._require_admin(principal)
        now = utc_now()
        body = request.model_dump(mode="json")
        try:
            with self.sessions.begin() as session:
                organization = self._lock_organization(session, principal.organization_id)
                replay = self._claim_idempotency(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /projects",
                    key=idempotency_key,
                    body=body,
                    now=now,
                )
                if replay is not None:
                    return OperationResult(
                        ProjectResponse.model_validate(replay.response_body),
                        replayed=True,
                    )
                normalized_name = request.name.strip()
                if not normalized_name:
                    self._validation_problem("name", "项目名称不能为空。")
                conflict = session.scalar(
                    select(Project.id).where(
                        Project.organization_id == principal.organization_id,
                        or_(
                            func.lower(Project.name) == normalized_name.casefold(),
                            Project.slug == request.slug,
                        ),
                    )
                )
                if conflict is not None:
                    raise ProblemException(
                        status=409,
                        code="PROJECT_NAME_OR_SLUG_CONFLICT",
                        title="项目名称或标识已存在",
                        detail="请使用新的项目名称和 slug。",
                    )
                self._require_scheduler_state(session)
                project = Project(
                    id=uuid4(),
                    organization_id=principal.organization_id,
                    name=normalized_name,
                    slug=request.slug,
                    description=_clean_optional(request.description),
                    status="ACTIVE",
                    created_by=principal.user_id,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                )
                session.add(project)
                session.add(
                    ProjectQueueServiceCursor(
                        project_id=project.id,
                        last_service_sequence=0,
                        served_execution_count=0,
                        served_recovery_probe_count=0,
                        row_version=1,
                        updated_at=now,
                    )
                )
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=project.id,
                    action="PROJECT_CREATED",
                    actor_id=principal.user_id,
                    target_type="PROJECT",
                    target_id=project.id,
                    target_name=project.name,
                    changed_fields=["name", "slug", "description", "status"],
                    audit=audit,
                )
                response = self._project_response(project)
                self._complete_idempotency(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /projects",
                    key=idempotency_key,
                    status=201,
                    body=response.model_dump(mode="json"),
                    resource_type="PROJECT",
                    resource_id=project.id,
                )
                return OperationResult(response)
        except IntegrityError as exc:
            raise ProblemException(
                status=409,
                code="PROJECT_NAME_OR_SLUG_CONFLICT",
                title="项目名称或标识已存在",
                detail="请刷新后重试。",
            ) from exc

    def list_projects(
        self,
        *,
        principal: Principal,
        limit: int,
        cursor: str | None,
    ) -> ProjectPage:
        with self.sessions() as session:
            statement = select(Project).where(Project.organization_id == principal.organization_id)
            if not principal.is_admin:
                project_ids = self._visible_project_ids(principal)
                if not project_ids:
                    return ProjectPage(items=[], next_cursor=None, has_more=False)
                statement = statement.where(Project.id.in_(project_ids))
            if cursor:
                created_at, project_id = self._decode_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    scope="GET /projects",
                )
                statement = statement.where(
                    or_(
                        Project.created_at < created_at,
                        and_(Project.created_at == created_at, Project.id < project_id),
                    )
                )
            rows = list(
                session.scalars(
                    statement.order_by(
                        Project.created_at.desc(),
                        Project.id.desc(),
                    ).limit(limit + 1)
                )
            )
            has_more = len(rows) > limit
            rows = rows[:limit]
            next_cursor = None
            if has_more and rows:
                next_cursor = self._encode_cursor(
                    actor_id=principal.user_id,
                    scope="GET /projects",
                    created_at=ensure_aware(rows[-1].created_at),
                    resource_id=rows[-1].id,
                )
            return ProjectPage(
                items=[self._project_response(row) for row in rows],
                next_cursor=next_cursor,
                has_more=has_more,
            )

    def get_project(self, *, principal: Principal, project_id: UUID) -> ProjectResponse:
        with self.sessions() as session:
            return self._project_response(self._visible_project(session, principal, project_id))

    def get_project_dashboard(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        window_from: datetime,
        window_to: datetime,
    ) -> DashboardResponse:
        try:
            window_from = ensure_aware(window_from).astimezone(UTC)
            window_to = ensure_aware(window_to).astimezone(UTC)
        except ValueError:
            self._validation_problem(
                "from",
                "from/to 必须包含明确时区。",
            )
        if window_from >= window_to:
            self._validation_problem("to", "to 必须晚于 from。")
        if window_to - window_from > timedelta(days=31):
            self._validation_problem("to", "项目概览时间窗不能超过 31 天。")

        now = utc_now()
        with self.sessions() as session:
            self._visible_project(session, principal, project_id)
            job_counts = _dashboard_group_counts(
                session,
                SyncJob.status,
                (SyncJob.project_id == project_id,),
                ("DRAFT", "VALID", "PUBLISHED", "ARCHIVED"),
            )
            executable = int(
                session.scalar(
                    select(func.count(func.distinct(SyncJob.id)))
                    .join(JobVersion, JobVersion.job_id == SyncJob.id)
                    .where(
                        SyncJob.project_id == project_id,
                        SyncJob.status != "ARCHIVED",
                    )
                )
                or 0
            )
            execution_window = (
                Execution.project_id == project_id,
                Execution.queued_at >= window_from,
                Execution.queued_at < window_to,
            )
            process_counts = _dashboard_group_counts(
                session,
                Execution.process_state,
                execution_window,
                _PROCESS_STATES,
            )
            verification_counts = _dashboard_group_counts(
                session,
                Execution.verification_state,
                execution_window,
                _VERIFICATION_STATES,
            )
            effect_counts = _dashboard_group_counts(
                session,
                Execution.data_effect,
                execution_window,
                _DATA_EFFECTS,
            )
            execution_total = sum(process_counts.values())
            success_numerator = int(
                session.scalar(
                    select(func.count(Execution.id)).where(
                        *execution_window,
                        Execution.process_state == "SUCCEEDED",
                        Execution.verification_state == "PASSED",
                    )
                )
                or 0
            )
            success_denominator = sum(
                process_counts[state]
                for state in ("SUCCEEDED", "FAILED", "TIMED_OUT", "LOST")
            )
            unresolved_failure_count = int(
                session.scalar(
                    select(func.count(Execution.id))
                    .outerjoin(
                        TargetCopyLock,
                        TargetCopyLock.execution_id == Execution.id,
                    )
                    .where(
                        *execution_window,
                        Execution.process_state.in_(_DASHBOARD_FAILURE_STATES),
                        or_(
                            TargetCopyLock.id.is_(None),
                            TargetCopyLock.state != "RELEASED",
                        ),
                    )
                )
                or 0
            )
            verified_reports = list(
                session.scalars(
                    select(Execution.verification_report).where(
                        *execution_window,
                        Execution.process_state == "SUCCEEDED",
                        Execution.verification_state == "PASSED",
                    )
                )
            )
            verified_value, missing_verification_count = (
                _dashboard_verified_record_count(verified_reports)
            )
            recent_rows = session.execute(
                select(Execution, SyncJob.name)
                .join(SyncJob, SyncJob.id == Execution.job_id)
                .where(*execution_window)
                .order_by(Execution.queued_at.desc(), Execution.id.desc())
                .limit(10)
            ).all()
            recent_failure_rows = session.execute(
                select(Execution, SyncJob.name)
                .join(SyncJob, SyncJob.id == Execution.job_id)
                .where(
                    *execution_window,
                    Execution.process_state.in_(_DASHBOARD_FAILURE_STATES),
                )
                .order_by(Execution.queued_at.desc(), Execution.id.desc())
                .limit(10)
            ).all()
            trend: list[DashboardTrendBucket] = []
            bucket_start = window_from
            while bucket_start < window_to:
                bucket_end = min(bucket_start + timedelta(days=1), window_to)
                bucket_process = {state: 0 for state in _PROCESS_STATES}
                bucket_verification = {
                    state: 0 for state in _VERIFICATION_STATES
                }
                for process_state, verification_state, count in session.execute(
                    select(
                        Execution.process_state,
                        Execution.verification_state,
                        func.count(Execution.id),
                    )
                    .where(
                        Execution.project_id == project_id,
                        Execution.queued_at >= bucket_start,
                        Execution.queued_at < bucket_end,
                    )
                    .group_by(
                        Execution.process_state,
                        Execution.verification_state,
                    )
                ):
                    if (
                        process_state not in bucket_process
                        or verification_state not in bucket_verification
                    ):
                        raise RuntimeError(
                            "execution contains a state outside the V1 contract"
                        )
                    bucket_process[process_state] += int(count)
                    bucket_verification[verification_state] += int(count)
                trend.append(
                    DashboardTrendBucket(
                        bucket_start=bucket_start,
                        bucket_end=bucket_end,
                        process_counts=DashboardExecutionCounts(
                            **bucket_process
                        ),
                        verification_counts=DashboardVerificationCounts(
                            **bucket_verification
                        ),
                    )
                )
                bucket_start = bucket_end
            runtime = self._dashboard_runtime(session, now=now)

        return DashboardResponse(
            project_id=project_id,
            window=DashboardWindow(from_=window_from, to=window_to),
            job_counts=DashboardJobCounts(
                total=sum(job_counts.values()),
                draft=job_counts["DRAFT"],
                valid=job_counts["VALID"],
                published=job_counts["PUBLISHED"],
                archived=job_counts["ARCHIVED"],
                executable=executable,
            ),
            execution_total=execution_total,
            execution_state_counts=DashboardExecutionCounts(
                **process_counts
            ),
            verification_state_counts=DashboardVerificationCounts(
                **verification_counts
            ),
            data_effect_counts=DashboardDataEffectCounts(**effect_counts),
            success_rate=DashboardSuccessRate(
                numerator=success_numerator,
                denominator=success_denominator,
                ratio=(
                    success_numerator / success_denominator
                    if success_denominator
                    else None
                ),
            ),
            unresolved_failure_count=unresolved_failure_count,
            verified_records=DashboardVerifiedRecords(
                value=verified_value,
                complete=missing_verification_count == 0,
                missing_verification_count=missing_verification_count,
            ),
            recent_executions=[
                _dashboard_execution_item(execution, job_name)
                for execution, job_name in recent_rows
            ],
            recent_failures=[
                _dashboard_execution_item(execution, job_name)
                for execution, job_name in recent_failure_rows
            ],
            trend=trend,
            runtime=runtime,
            drilldowns=_dashboard_drilldowns(
                project_id=project_id,
                window_from=window_from,
                window_to=window_to,
            ),
            generated_at=now,
        )

    def _dashboard_runtime(
        self,
        session: Session,
        *,
        now: datetime,
    ) -> DashboardRuntime:
        try:
            row = session.execute(
                text(
                    """
                    SELECT
                        status,
                        runtime_code,
                        oracle_code,
                        datax_release,
                        updated_at,
                        host_boot_id,
                        reconcile_epoch,
                        reconciled_at
                    FROM worker_heartbeats
                    ORDER BY updated_at DESC, worker_id
                    LIMIT 1
                    """
                )
            ).mappings().one_or_none()
        except SQLAlchemyError:
            row = None
        if row is None:
            return DashboardRuntime(
                worker_online=False,
                runtime_ready=False,
                oracle_ready=False,
                datax_release=None,
                version_match=False,
            )
        updated_at = ensure_aware(row["updated_at"]).astimezone(UTC)
        release = row["datax_release"]
        if release not in {None, "datax_v202309"}:
            release = None
        online = (now - updated_at).total_seconds() <= self._worker_stale_seconds
        reconciled = (
            bool(row["host_boot_id"])
            and row["reconcile_epoch"] is not None
            and row["reconciled_at"] is not None
        )
        runtime_ready = (
            online
            and reconciled
            and row["status"] == "READY"
            and row["runtime_code"] == "RUNTIME_OK"
        )
        oracle_ready = (
            online
            and reconciled
            and row["status"] == "READY"
            and row["oracle_code"] == "ORACLE_OK"
        )
        return DashboardRuntime(
            worker_online=online,
            runtime_ready=runtime_ready,
            oracle_ready=oracle_ready,
            datax_release=release,
            version_match=runtime_ready and release == "datax_v202309",
        )

    def update_project(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        request: ProjectPatch,
        expected_version: int,
        audit: AuditContext,
    ) -> ProjectResponse:
        self._require_admin(principal)
        now = utc_now()
        with self.sessions.begin() as session:
            organization = self._lock_organization(session, principal.organization_id)
            project = session.scalar(
                select(Project)
                .where(
                    Project.id == project_id,
                    Project.organization_id == principal.organization_id,
                )
                .with_for_update()
            )
            if project is None:
                self._not_found()
            if project.row_version != expected_version:
                self._version_conflict()
            changed: list[str] = []
            if "name" in request.model_fields_set and request.name is not None:
                name = request.name.strip()
                if not name:
                    self._validation_problem("name", "项目名称不能为空。")
                existing = session.scalar(
                    select(Project.id).where(
                        Project.organization_id == project.organization_id,
                        func.lower(Project.name) == name.casefold(),
                        Project.id != project.id,
                    )
                )
                if existing is not None:
                    raise ProblemException(
                        status=409,
                        code="PROJECT_NAME_OR_SLUG_CONFLICT",
                        title="项目名称已存在",
                        detail="请使用新的项目名称。",
                    )
                project.name = name
                changed.append("name")
            if "description" in request.model_fields_set:
                project.description = _clean_optional(request.description)
                changed.append("description")
            if request.status == "ARCHIVED" and project.status != "ARCHIVED":
                active = session.scalar(
                    select(func.count(Execution.id)).where(
                        Execution.project_id == project.id,
                        Execution.process_state.in_(
                            (
                                "QUEUED",
                                "STARTING",
                                "RUNNING",
                                "VERIFYING",
                                "CANCEL_REQUESTED",
                            )
                        ),
                    )
                )
                if active:
                    raise ProblemException(
                        status=409,
                        code="PROJECT_HAS_ACTIVE_EXECUTIONS",
                        title="项目仍有活动执行",
                        detail="请先完成或取消活动执行。",
                    )
                project.status = "ARCHIVED"
                project.archived_by = principal.user_id
                project.archived_at = now
                changed.append("status")
            if not changed:
                return self._project_response(project)
            project.updated_at = now
            project.row_version += 1
            action = "PROJECT_ARCHIVED" if "status" in changed else "PROJECT_UPDATED"
            self._append_audit(
                session,
                organization=organization,
                project_id=project.id,
                action=action,
                actor_id=principal.user_id,
                target_type="PROJECT",
                target_id=project.id,
                target_name=project.name,
                changed_fields=changed,
                audit=audit,
            )
            return self._project_response(project)

    # ------------------------------------------------------------------
    # Plugin capability catalog derived from current runtime facts. Runtime
    # readiness can prove PACKAGED, never Windows E4 certification by itself.
    # ------------------------------------------------------------------
    def list_plugin_capabilities(
        self,
        *,
        principal: Principal,
    ) -> PluginPage:
        if principal.must_change_password:
            raise ProblemException(
                status=403,
                code="PASSWORD_CHANGE_REQUIRED",
                title="必须先修改临时密码",
                detail="完成本人密码修改后才能访问业务接口。",
            )
        with self.sessions() as session:
            try:
                row = session.execute(
                    text(
                        """
                        SELECT
                            wh.status,
                            wh.runtime_code,
                            wh.oracle_code,
                            wh.datax_release,
                            wh.runtime_sha256,
                            wh.mysqlreader_plugin_sha256,
                            wh.postgresqlreader_plugin_sha256,
                            wh.mysqlwriter_plugin_sha256,
                            wh.postgresqlwriter_plugin_sha256,
                            wh.host_boot_id,
                            wh.reconcile_epoch,
                            wh.reconciled_at,
                            wh.updated_at,
                            sc.draining,
                            sc.host_boot_id AS control_host_boot_id,
                            sc.reconcile_epoch AS control_reconcile_epoch,
                            sc.reconciled_at AS control_reconciled_at
                        FROM worker_heartbeats AS wh
                        CROSS JOIN system_control AS sc
                        WHERE wh.worker_id = :worker_id
                          AND sc.singleton_id = 1
                        """
                    ).columns(
                        reconcile_epoch=Uuid(as_uuid=True),
                        control_reconcile_epoch=Uuid(as_uuid=True),
                        reconciled_at=DateTime(timezone=True),
                        control_reconciled_at=DateTime(timezone=True),
                        updated_at=DateTime(timezone=True),
                    ),
                    {"worker_id": self._worker_id},
                ).mappings().one_or_none()
            except SQLAlchemyError:
                self._runtime_attestation_unavailable()
        if row is None:
            self._runtime_attestation_unavailable()
        plugin_hash_columns = {
            "mysqlreader": "mysqlreader_plugin_sha256",
            "mysqlwriter": "mysqlwriter_plugin_sha256",
            "postgresqlreader": "postgresqlreader_plugin_sha256",
            "postgresqlwriter": "postgresqlwriter_plugin_sha256",
        }
        plugin_hashes = {
            name: str(row[column] or "")
            for name, column in plugin_hash_columns.items()
        }
        reconciled_at = row["reconciled_at"]
        control_reconciled_at = row["control_reconciled_at"]
        current = (
            row["status"] == "READY"
            and row["runtime_code"] == "RUNTIME_OK"
            and row["oracle_code"] == "ORACLE_OK"
            and row["datax_release"] == "datax_v202309"
            and re.fullmatch(r"[a-f0-9]{64}", str(row["runtime_sha256"] or ""))
            and not bool(row["draining"])
            and row["host_boot_id"] is not None
            and row["host_boot_id"] == row["control_host_boot_id"]
            and row["reconcile_epoch"] is not None
            and row["reconcile_epoch"] == row["control_reconcile_epoch"]
            and reconciled_at is not None
            and control_reconciled_at is not None
            and ensure_aware(reconciled_at)
            == ensure_aware(control_reconciled_at)
            and ensure_aware(row["updated_at"])
            >= utc_now()
            - timedelta(seconds=self._worker_stale_seconds)
            and all(
                re.fullmatch(r"[a-f0-9]{64}", value)
                for value in plugin_hashes.values()
            )
        )
        if not current:
            self._runtime_attestation_unavailable()

        connection_fields = [
            PluginConnectionField(
                key="host",
                label="主机地址",
                value_type="STRING",
                required=True,
                sensitive=False,
                constraints=PluginFieldConstraints(
                    min_length=1,
                    max_length=253,
                ),
            ),
            PluginConnectionField(
                key="port",
                label="端口",
                value_type="INTEGER",
                required=True,
                sensitive=False,
                constraints=PluginFieldConstraints(
                    minimum=1,
                    maximum=65535,
                ),
            ),
            PluginConnectionField(
                key="database_name",
                label="数据库",
                value_type="STRING",
                required=True,
                sensitive=False,
                constraints=PluginFieldConstraints(
                    min_length=1,
                    max_length=128,
                ),
            ),
            PluginConnectionField(
                key="default_schema",
                label="默认 Schema",
                value_type="STRING",
                required=True,
                sensitive=False,
                constraints=PluginFieldConstraints(
                    min_length=1,
                    max_length=128,
                ),
            ),
            PluginConnectionField(
                key="username",
                label="用户名",
                value_type="STRING",
                required=True,
                sensitive=False,
                constraints=PluginFieldConstraints(
                    min_length=1,
                    max_length=128,
                ),
            ),
            PluginConnectionField(
                key="password",
                label="密码",
                value_type="SECRET",
                required=True,
                sensitive=True,
            ),
            PluginConnectionField(
                key="ssl_mode",
                label="TLS 模式",
                value_type="ENUM",
                required=True,
                sensitive=False,
                enum_values=[
                    "DISABLE",
                    "REQUIRE",
                    "VERIFY_CA",
                    "VERIFY_FULL",
                ],
            ),
        ]
        definitions = (
            (
                "mysqlreader",
                "MySQL 8 Reader",
                "MYSQL_8",
                "READER",
                "datax/plugin/reader/mysqlreader/"
                "mysqlreader-0.0.1-SNAPSHOT.jar",
                "c4ffc40c90af4068999178ac7297bb2066de59b8dccfa6e8e956b48327487206",
                "86ef9813bfc558048a99e32ffaf4889a48f2f082b0f692dc73770f5385161e8f",
            ),
            (
                "mysqlwriter",
                "MySQL 8 Writer",
                "MYSQL_8",
                "WRITER",
                "datax/plugin/writer/mysqlwriter/"
                "mysqlwriter-0.0.1-SNAPSHOT.jar",
                "b83fe2a8eb0d1e535b84914e5fa169722bd085686eb11d63841e92a6d7cf1b2c",
                "2c5914e3625f3c32e79d661407ec4644e94905037c78e1aa21391e0174c2d3ed",
            ),
            (
                "postgresqlreader",
                "PostgreSQL 15 Reader",
                "POSTGRESQL_15",
                "READER",
                "datax/plugin/reader/postgresqlreader/"
                "postgresqlreader-0.0.1-SNAPSHOT.jar",
                "f14129fe23f6ca90bfc36b3c3bf64ff8d53288053af26e666411dde47211a835",
                "5f298fb97165625ae5de9c32cb8454128feaa9c7ef8856f943f7683191291b32",
            ),
            (
                "postgresqlwriter",
                "PostgreSQL 15 Writer",
                "POSTGRESQL_15",
                "WRITER",
                "datax/plugin/writer/postgresqlwriter/"
                "postgresqlwriter-0.0.1-SNAPSHOT.jar",
                "d29dcd149b37c269e8e741184172a69ce80cd6ffc69503440fdd9d4afe49e4c4",
                "1ea3e7ef4deebb90b36e4c7b1cb1e91852abbe9d6db0d52eee7a42fa037589f6",
            ),
        )
        now = utc_now()
        runtime_sha256 = str(row["runtime_sha256"])
        # Read the candidate evidence only once.  Besides providing a
        # deterministic catalog snapshot, this keeps a pluggable source from
        # returning mutually inconsistent records within one response.
        records = {
            name: self._plugin_certification_source.get_record(name)
            for name, *_unused in definitions
        }
        qualification_block_reasons_by_name: dict[str, list[str]] = {}
        e4_certified_by_name: dict[str, bool] = {}
        for (
            name,
            _display_name,
            _engine,
            _direction,
            _path,
            _module_pom_sha256,
            _plugin_json_sha256,
        ) in definitions:
            record = records[name]
            qualification_block_reasons = (
                e4_qualification_block_reasons(
                    record,
                    expected_plugin_name=name,
                    expected_plugin_sha256=plugin_hashes[name],
                    expected_runtime_sha256=runtime_sha256,
                    current_candidate_id=(
                        self._plugin_certification_source.current_candidate_id
                    ),
                    current_candidate_commit=(
                        self._plugin_certification_source.current_candidate_commit
                    ),
                    current_worker_image_digest=(
                        self._plugin_certification_source.current_worker_image_digest
                    ),
                    now=now,
                )
                if record is not None
                else [
                    "DEPENDENCY_INVENTORY_INCOMPLETE",
                    "LICENSE_REVIEW_REQUIRED",
                    "E3_EVIDENCE_MISSING",
                    "WINDOWS_E4_EVIDENCE_MISSING",
                ]
            )
            qualification_block_reasons_by_name[name] = qualification_block_reasons
            e4_certified_by_name[name] = (
                record is not None
                and record.source == "TRUSTED_RELEASE_ATTESTATION"
                and not qualification_block_reasons
            )

        # A release promotion is candidate-level evidence.  If trusted E4
        # records disagree about it, no plugin may be advertised as ordinarily
        # executable.  The raw values are not returned in that state: a
        # syntactically valid but mismatched opaque reference is not a usable
        # public promotion.
        trusted_e4_promotion_refs = [
            records[name].release_promotion_ref
            for name, certified in e4_certified_by_name.items()
            if certified and records[name] is not None
        ]
        promotion_refs_coherent = True
        first_promotion_ref: str | None = None
        for promotion_ref in trusted_e4_promotion_refs:
            if release_promotion_ref_block_reason(promotion_ref) is not None:
                promotion_refs_coherent = False
                break
            assert isinstance(promotion_ref, str)
            if first_promotion_ref is None:
                first_promotion_ref = promotion_ref
            elif promotion_ref != first_promotion_ref:
                promotion_refs_coherent = False
                break

        manifests: list[PluginManifest] = []
        for (
            name,
            display_name,
            engine,
            direction,
            path,
            module_pom_sha256,
            plugin_json_sha256,
        ) in definitions:
            record = records[name]
            qualification_block_reasons = qualification_block_reasons_by_name[name]
            execution_block_reasons = (
                ordinary_user_execution_block_reasons(
                    record,
                    expected_plugin_name=name,
                    expected_plugin_sha256=plugin_hashes[name],
                    expected_runtime_sha256=runtime_sha256,
                    current_candidate_id=(
                        self._plugin_certification_source.current_candidate_id
                    ),
                    current_candidate_commit=(
                        self._plugin_certification_source.current_candidate_commit
                    ),
                    current_worker_image_digest=(
                        self._plugin_certification_source.current_worker_image_digest
                    ),
                    now=now,
                )
                if record is not None
                else qualification_block_reasons
            )
            e4_certified = e4_certified_by_name[name]
            if (
                e4_certified
                and release_promotion_ref_block_reason(
                    record.release_promotion_ref if record is not None else None
                )
                is None
                and not promotion_refs_coherent
            ):
                execution_block_reasons = [
                    *execution_block_reasons,
                    "PAIR_RELEASE_PROMOTION_MISMATCH",
                ]
            public_block_reasons = list(dict.fromkeys(execution_block_reasons))
            if record is not None and record.source == "TEST_INJECTION":
                public_block_reasons = [
                    *public_block_reasons,
                    "NON_RELEASE_TEST_EVIDENCE",
                ]
            ordinary_user_executable = e4_certified and not execution_block_reasons
            manifests.append(
                PluginManifest(
                    schema_version="2.0",
                    name=name,
                    display_name=display_name,
                    engine=engine,
                    direction=direction,
                    datax_plugin_name=name,
                    datax_release="datax_v202309",
                    upstream=PluginUpstream(
                        repository="https://github.com/alibaba/DataX.git",
                        tag="datax_v202309",
                        commit="9a1f88751e24314b083a74f1b83ef56d69ce98bd",
                        tree="534508f96331c4b9f3737ea4e8294cc56aedc67d",
                        module=name,
                        module_pom_sha256=module_pom_sha256,
                        plugin_json_sha256=plugin_json_sha256,
                    ),
                    artifact=PluginArtifact(
                        relative_path=path,
                        sha256=plugin_hashes[name],
                    ),
                    runtime=PluginRuntime(jdk_major=8, python_major=3),
                    supply_chain=PluginSupplyChain(
                        dependency_inventory_status=(
                            "COMPLETE" if e4_certified else "INCOMPLETE"
                        ),
                        license_review_status=(
                            "CLEARED" if e4_certified else "REVIEW_REQUIRED"
                        ),
                        dependency_inventory_ref=(
                            record.dependency_inventory_ref if e4_certified else None
                        ),
                        license_review_ref=(
                            record.license_review_ref if e4_certified else None
                        ),
                        dependencies=(
                            [
                                PluginDependency(
                                    name=item.name,
                                    version=item.version,
                                    license_expression=item.license_expression,
                                    license_file=item.license_file,
                                    redistribution_status=item.redistribution_status,
                                )
                                for item in record.dependencies
                            ]
                            if e4_certified
                            else []
                        ),
                    ),
                    connection_fields=connection_fields,
                    capabilities=PluginCapabilities(
                        schema_introspection=True,
                        full_table_selection=True,
                        column_selection=True,
                        direct_mapping_only=True,
                        target_table_must_exist=True,
                        write_modes=(
                            [] if direction == "READER" else ["INSERT"]
                        ),
                        supports_free_sql=False,
                        supports_pre_sql=False,
                        supports_post_sql=False,
                        supports_transformer=False,
                        supports_custom_parameters=False,
                    ),
                    access=PluginAccess(
                        network_scope="APPROVED_DATABASE_ENDPOINT_ONLY",
                        filesystem_scope="PRIVATE_RUNTIME_ONLY",
                        allows_arbitrary_sql=False,
                        allows_host_paths=False,
                        allows_shell=False,
                        allows_user_plugins=False,
                    ),
                    oracle=PluginOracle(
                        kind="RELATIONAL_MULTISET_V1",
                        schema_version="1.0",
                        required_for_e3=True,
                    ),
                    certification_state=(
                        "WINDOWS_E4_CERTIFIED"
                        if e4_certified
                        else ("BLOCKED" if record is not None else "PACKAGED")
                    ),
                    ordinary_user_executable=ordinary_user_executable,
                    evidence=PluginEvidence(
                        source=(
                            "TRUSTED_RELEASE_ATTESTATION"
                            if e4_certified
                            else "CURRENT_RUNTIME_ATTESTATION"
                        ),
                        candidate_id=(record.candidate_id if e4_certified else None),
                        candidate_commit=(
                            record.candidate_commit if e4_certified else None
                        ),
                        worker_image_digest=(
                            record.worker_image_digest if e4_certified else None
                        ),
                        runtime_sha256=runtime_sha256,
                        e3_evidence_ref=(
                            record.e3_evidence_ref if e4_certified else None
                        ),
                        windows_e4_evidence_ref=(
                            record.windows_e4_evidence_ref if e4_certified else None
                        ),
                        release_promotion_ref=(
                            record.release_promotion_ref
                            if ordinary_user_executable
                            else None
                        ),
                        valid_until=(record.valid_until if e4_certified else None),
                    ),
                    block_reasons=(
                        [] if ordinary_user_executable else public_block_reasons
                    ),
                )
            )
        return PluginPage(items=manifests)

    def require_job_version_plugin_certification(
        self,
        *,
        version: JobVersion,
        now: datetime | None = None,
    ) -> None:
        check_time = now or utc_now()
        reader, writer = self._plugin_certification_source.require_job_version(
            version=version,
            now=check_time,
        )
        require_ordinary_user_execution_pair(
            reader=reader,
            writer=writer,
            version=version,
            current_candidate_id=self._plugin_certification_source.current_candidate_id,
            current_candidate_commit=(
                self._plugin_certification_source.current_candidate_commit
            ),
            current_worker_image_digest=(
                self._plugin_certification_source.current_worker_image_digest
            ),
            now=check_time,
        )

    # ------------------------------------------------------------------
    # Endpoint policy revisions (non-secret, no network connection)
    # ------------------------------------------------------------------
    def create_endpoint_policy(
        self,
        *,
        principal: Principal,
        request: EndpointPolicyCreate,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[EndpointPolicyResponse]:
        self._require_admin(principal)
        normalized = self._normalize_endpoint_policy(request)
        now = utc_now()
        try:
            with self.sessions.begin() as session:
                organization = self._lock_organization(session, principal.organization_id)
                replay = self._claim_idempotency(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /endpoint-policies",
                    key=idempotency_key,
                    body=request.model_dump(mode="json"),
                    now=now,
                )
                if replay is not None:
                    return OperationResult(
                        EndpointPolicyResponse.model_validate(replay.response_body),
                        replayed=True,
                    )
                if session.scalar(
                    select(EndpointPolicy.id).where(
                        EndpointPolicy.organization_id == principal.organization_id,
                        func.lower(EndpointPolicy.name) == request.name.strip().casefold(),
                    )
                ):
                    raise ProblemException(
                        status=409,
                        code="ENDPOINT_POLICY_NAME_CONFLICT",
                        title="端点策略名称已存在",
                        detail="请使用新的端点策略名称。",
                    )
                policy = EndpointPolicy(
                    id=uuid4(),
                    organization_id=principal.organization_id,
                    name=request.name.strip(),
                    current_revision_id=None,
                    status="ACTIVE",
                    created_by=principal.user_id,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                )
                session.add(policy)
                session.flush()
                revision = EndpointPolicyRevision(
                    id=uuid4(),
                    endpoint_policy_id=policy.id,
                    revision_no=1,
                    created_by=principal.user_id,
                    created_at=now,
                    **normalized,
                )
                session.add(revision)
                session.flush()
                policy.current_revision_id = revision.id
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=None,
                    action="ENDPOINT_POLICY_CREATED",
                    actor_id=principal.user_id,
                    target_type="ENDPOINT_POLICY",
                    target_id=policy.id,
                    target_name=policy.name,
                    changed_fields=[
                        "name",
                        "status",
                        "current_revision_id",
                        "policy_hash",
                    ],
                    audit=audit,
                    metadata={"policy_hash": revision.policy_hash, "revision_no": 1},
                )
                response = self._endpoint_policy_response(policy, revision)
                self._complete_idempotency(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /endpoint-policies",
                    key=idempotency_key,
                    status=201,
                    body=response.model_dump(mode="json"),
                    resource_type="ENDPOINT_POLICY",
                    resource_id=policy.id,
                )
                return OperationResult(response)
        except IntegrityError as exc:
            raise ProblemException(
                status=409,
                code="ENDPOINT_POLICY_CONFLICT",
                title="端点策略冲突",
                detail="请刷新后重试。",
            ) from exc

    def list_endpoint_policies(
        self,
        *,
        principal: Principal,
        limit: int,
        cursor: str | None,
    ) -> EndpointPolicyPage:
        self._require_admin(principal)
        with self.sessions() as session:
            statement = select(EndpointPolicy).where(
                EndpointPolicy.organization_id == principal.organization_id
            )
            if cursor:
                created_at, policy_id = self._decode_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    scope="GET /endpoint-policies",
                )
                statement = statement.where(
                    or_(
                        EndpointPolicy.created_at < created_at,
                        and_(
                            EndpointPolicy.created_at == created_at,
                            EndpointPolicy.id < policy_id,
                        ),
                    )
                )
            rows = list(
                session.scalars(
                    statement.order_by(
                        EndpointPolicy.created_at.desc(),
                        EndpointPolicy.id.desc(),
                    ).limit(limit + 1)
                )
            )
            has_more = len(rows) > limit
            rows = rows[:limit]
            items = [
                self._endpoint_policy_response(
                    policy,
                    self._current_endpoint_policy_revision(session, policy),
                )
                for policy in rows
            ]
            next_cursor = None
            if has_more and rows:
                next_cursor = self._encode_cursor(
                    actor_id=principal.user_id,
                    scope="GET /endpoint-policies",
                    created_at=ensure_aware(rows[-1].created_at),
                    resource_id=rows[-1].id,
                )
            return EndpointPolicyPage(
                items=items,
                next_cursor=next_cursor,
                has_more=has_more,
            )

    def get_endpoint_policy(
        self,
        *,
        principal: Principal,
        endpoint_policy_id: UUID,
    ) -> EndpointPolicyResponse:
        self._require_admin(principal)
        with self.sessions() as session:
            policy = session.scalar(
                select(EndpointPolicy).where(
                    EndpointPolicy.id == endpoint_policy_id,
                    EndpointPolicy.organization_id == principal.organization_id,
                )
            )
            if policy is None:
                self._not_found()
            return self._endpoint_policy_response(
                policy,
                self._current_endpoint_policy_revision(session, policy),
            )

    def get_physical_endpoint_identity(
        self,
        *,
        principal: Principal,
        physical_endpoint_identity_id: UUID,
    ) -> PhysicalEndpointIdentityResponse:
        self._require_admin(principal)
        with self.sessions() as session:
            identity = session.scalar(
                select(PhysicalEndpointIdentity).where(
                    PhysicalEndpointIdentity.id
                    == physical_endpoint_identity_id,
                    PhysicalEndpointIdentity.organization_id
                    == principal.organization_id,
                )
            )
            if identity is None:
                self._not_found()
            return PhysicalEndpointIdentityResponse(
                id=identity.id,
                organization_id=identity.organization_id,
                engine=identity.engine,
                identity_scheme=identity.identity_scheme,
                server_identity_hash=identity.server_identity_hash,
                verification_evidence_hash=(
                    identity.verification_evidence_hash
                ),
                created_by=identity.created_by,
                created_at=ensure_aware(identity.created_at),
            )

    def get_target_namespace(
        self,
        *,
        principal: Principal,
        target_namespace_id: UUID,
    ) -> TargetNamespaceSnapshot:
        self._require_admin(principal)
        with self.sessions() as session:
            row = session.execute(
                select(TargetNamespace, PhysicalEndpointIdentity)
                .join(
                    PhysicalEndpointIdentity,
                    PhysicalEndpointIdentity.id
                    == TargetNamespace.physical_endpoint_identity_id,
                )
                .where(
                    TargetNamespace.id == target_namespace_id,
                    PhysicalEndpointIdentity.organization_id
                    == principal.organization_id,
                )
            ).one_or_none()
            if row is None:
                self._not_found()
            namespace, _identity = row
            return TargetNamespaceSnapshot(
                target_namespace_id=namespace.id,
                physical_endpoint_identity_id=(
                    namespace.physical_endpoint_identity_id
                ),
                engine=namespace.engine,
                normalized_catalog_name=namespace.normalized_catalog_name,
                normalized_schema_name=namespace.normalized_schema_name,
                normalized_table_name=namespace.normalized_table_name,
                normalization_version=namespace.normalization_version,
                physical_table_identity_hash=(
                    namespace.physical_table_identity_hash
                ),
            )

    # ------------------------------------------------------------------
    # Job drafts. Validation/publish material must come from a real validator.
    # ------------------------------------------------------------------
    def create_job(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        request: JobCreate,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[JobResponse]:
        self._require_project_role(principal, project_id, {Role.DEVELOPER})
        now = utc_now()
        canonical_spec = request.draft_spec.model_dump(mode="json")
        spec_hash = _domain_hash("DXJOBSPECv1", canonical_spec)
        try:
            with self.sessions.begin() as session:
                organization = self._lock_organization(session, principal.organization_id)
                project = self._visible_project(session, principal, project_id, lock=True)
                if project.status != "ACTIVE":
                    raise ProblemException(
                        status=409,
                        code="PROJECT_ARCHIVED",
                        title="项目已归档",
                        detail="归档项目不能创建任务。",
                    )
                replay = self._claim_idempotency(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /projects/{project_id}/jobs",
                    key=idempotency_key,
                    body=request.model_dump(mode="json"),
                    now=now,
                )
                if replay is not None:
                    return OperationResult(
                        JobResponse.model_validate(replay.response_body),
                        replayed=True,
                    )
                if session.scalar(
                    select(SyncJob.id).where(
                        SyncJob.project_id == project_id,
                        func.lower(SyncJob.name) == request.name.strip().casefold(),
                    )
                ):
                    raise ProblemException(
                        status=409,
                        code="JOB_NAME_CONFLICT",
                        title="任务名称已存在",
                        detail="请使用新的任务名称。",
                    )
                self._check_job_spec_resources(session, project_id, request.draft_spec)
                job = SyncJob(
                    id=uuid4(),
                    project_id=project_id,
                    name=request.name.strip(),
                    description=_clean_optional(request.description),
                    status="DRAFT",
                    draft_spec_json=canonical_spec,
                    draft_spec_hash=spec_hash,
                    validated_spec_hash=None,
                    validation_report=None,
                    latest_published_version_id=None,
                    created_by=principal.user_id,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                )
                session.add(job)
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=project.id,
                    action="JOB_CREATED",
                    actor_id=principal.user_id,
                    target_type="SYNC_JOB",
                    target_id=job.id,
                    target_name=job.name,
                    changed_fields=["name", "description", "draft_spec_hash", "status"],
                    audit=audit,
                    metadata={"draft_spec_hash": spec_hash},
                )
                response = self._job_response(session, job)
                self._complete_idempotency(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /projects/{project_id}/jobs",
                    key=idempotency_key,
                    status=201,
                    body=response.model_dump(mode="json"),
                    resource_type="SYNC_JOB",
                    resource_id=job.id,
                )
                return OperationResult(response)
        except IntegrityError as exc:
            raise ProblemException(
                status=409,
                code="JOB_NAME_CONFLICT",
                title="任务名称冲突",
                detail="请刷新后重试。",
            ) from exc

    def list_jobs(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        limit: int,
        cursor: str | None,
        query: str | None = None,
        status: str | None = None,
        exclude_status: str | None = None,
        has_published_version: bool | None = None,
        reader_plugin: str | None = None,
        writer_plugin: str | None = None,
        latest_execution_state: str | None = None,
    ) -> JobPage:
        with self.sessions() as session:
            self._visible_project(session, principal, project_id)
            statement = select(SyncJob).where(SyncJob.project_id == project_id)
            normalized_query = query.strip().casefold() if query is not None else None
            if normalized_query:
                pattern = _contains_pattern(normalized_query)
                statement = statement.where(
                    or_(
                        func.lower(SyncJob.name).like(pattern, escape="\\"),
                        func.lower(
                            SyncJob.draft_spec_json["source"]["table"][
                                "table_name"
                            ].as_string()
                        ).like(pattern, escape="\\"),
                        func.lower(
                            SyncJob.draft_spec_json["target"]["table"][
                                "table_name"
                            ].as_string()
                        ).like(pattern, escape="\\"),
                    )
                )
            if status is not None:
                statement = statement.where(SyncJob.status == status)
            if exclude_status is not None:
                statement = statement.where(SyncJob.status != exclude_status)
            if has_published_version is True:
                statement = statement.where(
                    SyncJob.latest_published_version_id.is_not(None)
                )
            elif has_published_version is False:
                statement = statement.where(
                    SyncJob.latest_published_version_id.is_(None)
                )
            if reader_plugin is not None:
                statement = statement.where(
                    SyncJob.draft_spec_json["source"]["plugin_name"].as_string()
                    == reader_plugin
                )
            if writer_plugin is not None:
                statement = statement.where(
                    SyncJob.draft_spec_json["target"]["plugin_name"].as_string()
                    == writer_plugin
                )
            if latest_execution_state is not None:
                latest_state = (
                    select(Execution.process_state)
                    .where(Execution.job_id == SyncJob.id)
                    .order_by(Execution.queued_at.desc(), Execution.id.desc())
                    .limit(1)
                    .correlate(SyncJob)
                    .scalar_subquery()
                )
                statement = statement.where(latest_state == latest_execution_state)
            scope = _filtered_cursor_scope(
                f"GET /projects/{project_id}/jobs",
                {
                    "q": normalized_query,
                    "status": status,
                    "exclude_status": exclude_status,
                    "has_published_version": has_published_version,
                    "reader_plugin": reader_plugin,
                    "writer_plugin": writer_plugin,
                    "latest_execution_state": latest_execution_state,
                },
            )
            if cursor:
                updated_at, job_id = self._decode_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    scope=scope,
                )
                statement = statement.where(
                    or_(
                        SyncJob.updated_at < updated_at,
                        and_(SyncJob.updated_at == updated_at, SyncJob.id < job_id),
                    )
                )
            rows = list(
                session.scalars(
                    statement.order_by(
                        SyncJob.updated_at.desc(),
                        SyncJob.id.desc(),
                    ).limit(limit + 1)
                )
            )
            has_more = len(rows) > limit
            rows = rows[:limit]
            next_cursor = None
            if has_more and rows:
                next_cursor = self._encode_cursor(
                    actor_id=principal.user_id,
                    scope=scope,
                    created_at=ensure_aware(rows[-1].updated_at),
                    resource_id=rows[-1].id,
                )
            return JobPage(
                items=[self._job_response(session, row) for row in rows],
                next_cursor=next_cursor,
                has_more=has_more,
            )

    def get_job(self, *, principal: Principal, job_id: UUID) -> JobResponse:
        with self.sessions() as session:
            job = self._visible_job(session, principal, job_id)
            return self._job_response(session, job)

    def update_job(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        request: JobPatch,
        expected_version: int,
        audit: AuditContext,
    ) -> JobResponse:
        now = utc_now()
        try:
            with self.sessions.begin() as session:
                organization = self._lock_organization(
                    session,
                    principal.organization_id,
                )
                job = self._visible_job(
                    session,
                    principal,
                    job_id,
                    lock=True,
                )
                self._require_project_role(
                    principal,
                    job.project_id,
                    {Role.DEVELOPER},
                )
                if job.row_version != expected_version:
                    raise ProblemException(
                        status=409,
                        code="RESOURCE_VERSION_CONFLICT",
                        title="任务已被其他请求修改",
                        detail="请刷新任务后再提交修改。",
                    )
                fields = request.model_fields_set
                if job.status == "ARCHIVED" and fields != {"status"}:
                    raise ProblemException(
                        status=409,
                        code="JOB_ARCHIVED",
                        title="任务已归档",
                        detail="归档任务不能再修改元数据或草稿。",
                    )

                changed_fields: list[str] = []
                if "name" in fields:
                    normalized_name = (request.name or "").strip()
                    if not normalized_name:
                        self._validation_problem("name", "任务名称不能为空。")
                    conflict = session.scalar(
                        select(SyncJob.id).where(
                            SyncJob.project_id == job.project_id,
                            SyncJob.id != job.id,
                            func.lower(SyncJob.name)
                            == normalized_name.casefold(),
                        )
                    )
                    if conflict is not None:
                        raise ProblemException(
                            status=409,
                            code="JOB_NAME_CONFLICT",
                            title="任务名称已存在",
                            detail="请使用新的任务名称。",
                        )
                    if normalized_name != job.name:
                        job.name = normalized_name
                        changed_fields.append("name")
                if "description" in fields:
                    description = _clean_optional(request.description)
                    if description != job.description:
                        job.description = description
                        changed_fields.append("description")
                if "draft_spec" in fields:
                    if request.draft_spec is None:
                        self._validation_problem(
                            "draft_spec",
                            "任务草稿不能为空。",
                        )
                    self._check_job_spec_resources(
                        session,
                        job.project_id,
                        request.draft_spec,
                    )
                    canonical_spec = request.draft_spec.model_dump(mode="json")
                    spec_hash = _domain_hash("DXJOBSPECv1", canonical_spec)
                    if spec_hash != job.draft_spec_hash:
                        job.draft_spec_json = canonical_spec
                        job.draft_spec_hash = spec_hash
                        job.validated_spec_hash = None
                        job.validation_report = None
                        job.status = "DRAFT"
                        changed_fields.extend(
                            [
                                "draft_spec_hash",
                                "status",
                                "validated_spec_hash",
                            ]
                        )
                if request.status == "ARCHIVED" and job.status != "ARCHIVED":
                    active_execution = session.scalar(
                        select(Execution.id).where(
                            Execution.job_id == job.id,
                            Execution.process_state.not_in(_TERMINAL_STATES),
                        )
                    )
                    if active_execution is not None:
                        raise ProblemException(
                            status=409,
                            code="JOB_ACTIVE_EXECUTION",
                            title="任务仍有进行中的执行",
                            detail="请等待执行结束或完成取消对账后再归档任务。",
                        )
                    job.status = "ARCHIVED"
                    job.archived_by = principal.user_id
                    job.archived_at = now
                    changed_fields.append("status")

                if not changed_fields:
                    return self._job_response(session, job)
                job.updated_at = now
                job.row_version += 1
                action = (
                    "JOB_ARCHIVED"
                    if job.status == "ARCHIVED"
                    else "JOB_DRAFT_UPDATED"
                )
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=job.project_id,
                    action=action,
                    actor_id=principal.user_id,
                    target_type="SYNC_JOB",
                    target_id=job.id,
                    target_name=job.name,
                    changed_fields=changed_fields,
                    audit=audit,
                    metadata={"draft_spec_hash": job.draft_spec_hash},
                )
                return self._job_response(session, job)
        except IntegrityError as exc:
            raise ProblemException(
                status=409,
                code="JOB_NAME_CONFLICT",
                title="任务名称冲突",
                detail="请刷新后重试。",
            ) from exc

    def runtime_validation_material(
        self,
        *,
        principal: Principal,
        job_id: UUID,
    ) -> RuntimeValidationMaterial:
        with self.sessions() as session:
            job = self._visible_job(session, principal, job_id)
            self._require_project_role(
                principal,
                job.project_id,
                {Role.DEVELOPER},
            )
            spec = JobSpecV1.model_validate(job.draft_spec_json)
            try:
                row = session.execute(
                    text(
                        """
                        SELECT
                            wh.status,
                            wh.runtime_code,
                            wh.oracle_code,
                            wh.datax_release,
                            wh.runtime_sha256,
                            wh.mysqlreader_plugin_sha256,
                            wh.postgresqlreader_plugin_sha256,
                            wh.mysqlwriter_plugin_sha256,
                            wh.postgresqlwriter_plugin_sha256,
                            wh.host_boot_id,
                            wh.reconcile_epoch,
                            wh.reconciled_at,
                            wh.updated_at,
                            sc.draining,
                            sc.host_boot_id AS control_host_boot_id,
                            sc.reconcile_epoch AS control_reconcile_epoch,
                            sc.reconciled_at AS control_reconciled_at
                        FROM worker_heartbeats AS wh
                        CROSS JOIN system_control AS sc
                        WHERE wh.worker_id = :worker_id
                          AND sc.singleton_id = 1
                        """
                    ).columns(
                        reconcile_epoch=Uuid(as_uuid=True),
                        control_reconcile_epoch=Uuid(as_uuid=True),
                        reconciled_at=DateTime(timezone=True),
                        control_reconciled_at=DateTime(timezone=True),
                        updated_at=DateTime(timezone=True),
                    ),
                    {"worker_id": self._worker_id},
                ).mappings().one_or_none()
            except SQLAlchemyError:
                row = None
            if row is None:
                self._runtime_attestation_unavailable()
            updated_at = ensure_aware(row["updated_at"]).astimezone(UTC)
            fresh = (
                utc_now() - updated_at
            ).total_seconds() <= self._worker_stale_seconds
            reconciled = (
                row["host_boot_id"]
                and row["host_boot_id"] == row["control_host_boot_id"]
                and row["reconcile_epoch"] is not None
                and row["reconcile_epoch"] == row["control_reconcile_epoch"]
                and row["reconciled_at"] is not None
                and row["control_reconciled_at"] is not None
                and ensure_aware(row["reconciled_at"])
                == ensure_aware(row["control_reconciled_at"])
                and not row["draining"]
            )
            reader_field = {
                "mysqlreader": "mysqlreader_plugin_sha256",
                "postgresqlreader": "postgresqlreader_plugin_sha256",
            }[spec.source.plugin_name]
            writer_field = {
                "mysqlwriter": "mysqlwriter_plugin_sha256",
                "postgresqlwriter": "postgresqlwriter_plugin_sha256",
            }[spec.target.plugin_name]
            values = (
                row["runtime_sha256"],
                row[reader_field],
                row[writer_field],
            )
            if (
                not fresh
                or not reconciled
                or row["status"] != "READY"
                or row["runtime_code"] != "RUNTIME_OK"
                or row["oracle_code"] != "ORACLE_OK"
                or row["datax_release"] != "datax_v202309"
                or any(
                    not isinstance(value, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", value)
                    for value in values
                )
            ):
                self._runtime_attestation_unavailable()
            return RuntimeValidationMaterial(
                runtime_sha256=values[0],
                reader_plugin_sha256=values[1],
                writer_plugin_sha256=values[2],
            )

    def validation_failure_report(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        code: str,
        message: str,
        audit: AuditContext,
    ) -> ValidationReport:
        now = utc_now()
        with self.sessions.begin() as session:
            job = self._visible_job(session, principal, job_id, lock=True)
            self._require_project_role(
                principal,
                job.project_id,
                {Role.DEVELOPER},
            )
            organization = self._lock_organization(
                session,
                principal.organization_id,
            )
            report = ValidationReport(
                valid=False,
                draft_spec_hash=job.draft_spec_hash,
                source_schema_hash=None,
                target_schema_hash=None,
                errors=[
                    ValidationIssue(
                        code=code,
                        path="draft_spec",
                        message=message[:1000],
                    )
                ],
                warnings=[],
            )
            job.status = "DRAFT"
            job.validated_spec_hash = None
            job.validation_report = report.model_dump(mode="json")
            job.updated_at = now
            job.row_version += 1
            self._append_audit(
                session,
                organization=organization,
                project_id=job.project_id,
                action="JOB_VALIDATED",
                actor_id=principal.user_id,
                target_type="SYNC_JOB",
                target_id=job.id,
                target_name=job.name,
                changed_fields=[
                    "status",
                    "validated_spec_hash",
                    "validation_report",
                ],
                audit=audit,
                metadata={"validation_issue_code": code},
                outcome="FAILED",
                reason_code=code,
            )
            return report

    def preview_job(
        self,
        *,
        principal: Principal,
        job_id: UUID,
    ) -> JobPreview:
        with self.sessions() as session:
            job = self._visible_job(session, principal, job_id)
            self._require_project_role(
                principal,
                job.project_id,
                {Role.DEVELOPER},
            )
            spec = JobSpecV1.model_validate(job.draft_spec_json)
            warnings = [
                ValidationIssue.model_validate(item)
                for item in (job.validation_report or {}).get("warnings", [])
            ]
        source_engine = (
            "MYSQL_8"
            if spec.source.plugin_name == "mysqlreader"
            else "POSTGRESQL_15"
        )
        target_engine = (
            "MYSQL_8"
            if spec.target.plugin_name == "mysqlwriter"
            else "POSTGRESQL_15"
        )
        try:
            redacted_job = build_datax_job(
                spec,
                source=RuntimeConnection(
                    engine=source_engine,
                    host="redacted.invalid",
                    port=3306 if source_engine == "MYSQL_8" else 5432,
                    database_name="REDACTED",
                    username="REDACTED",
                    password=bytearray(b"${SECRET}"),
                    ssl_mode="REQUIRE",
                ),
                target=RuntimeConnection(
                    engine=target_engine,
                    host="redacted.invalid",
                    port=3306 if target_engine == "MYSQL_8" else 5432,
                    database_name="REDACTED",
                    username="REDACTED",
                    password=bytearray(b"${SECRET}"),
                    ssl_mode="REQUIRE",
                ),
            )
        except UnsafeJobSpec as exc:
            raise ProblemException(
                status=422,
                code="JOB_SPEC_INVALID",
                title="任务草稿无法生成安全预览",
                detail=str(exc)[:500],
            ) from exc
        return JobPreview(
            draft_spec_hash=job.draft_spec_hash,
            redacted_datax_json=redacted_job,
            executable=False,
            warnings=warnings,
        )

    def accept_validation_material(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        material: ValidationMaterial,
        audit: AuditContext,
    ) -> JobResponse:
        """Persist facts returned by the real metadata validator.

        This method intentionally does not fabricate schema or network evidence.
        """

        now = utc_now()
        with self.sessions.begin() as session:
            job = self._visible_job(session, principal, job_id, lock=True)
            self._require_project_role(principal, job.project_id, {Role.DEVELOPER})
            organization = self._lock_organization(session, principal.organization_id)
            spec = JobSpecV1.model_validate(job.draft_spec_json)
            self._check_job_spec_resources(session, job.project_id, spec)
            try:
                source_snapshot = validate_schema_snapshot(
                    material.source_schema_snapshot
                )
                target_snapshot = validate_schema_snapshot(
                    material.target_schema_snapshot
                )
            except ValueError as exc:
                raise ProblemException(
                    status=422,
                    code="SCHEMA_SNAPSHOT_INVALID",
                    title="Schema 快照不符合固定契约",
                    detail="请使用受控元数据探针重新生成完整、规范排序的快照。",
                ) from exc
            computed_source_schema_hash = schema_snapshot_hash(source_snapshot)
            computed_target_schema_hash = schema_snapshot_hash(target_snapshot)
            if (
                material.source_schema_hash != computed_source_schema_hash
                or material.target_schema_hash != computed_target_schema_hash
            ):
                raise ProblemException(
                    status=422,
                    code="SCHEMA_SNAPSHOT_HASH_MISMATCH",
                    title="Schema 快照摘要不匹配",
                    detail="服务端重算的域分离摘要与校验材料不一致。",
                )
            source_revision = session.get(
                DatasourceRevision,
                spec.source.datasource_revision_id,
            )
            target_revision = session.get(
                DatasourceRevision,
                spec.target.datasource_revision_id,
            )
            if source_revision is None or target_revision is None:
                self._not_found()
            source_snapshot_payload = source_snapshot.model_dump(mode="json")
            target_snapshot_payload = target_snapshot.model_dump(mode="json")
            policy = session.get(TransferPolicy, material.transfer_policy_id)
            target_namespace = session.get(TargetNamespace, material.target_namespace_id)
            if (
                policy is None
                or policy.project_id != job.project_id
                or policy.status != "ACTIVE"
                or policy.scope_hash != material.transfer_policy_scope_hash
                or target_namespace is None
            ):
                raise ProblemException(
                    status=409,
                    code="TRANSFER_POLICY_NOT_ACTIVE",
                    title="传输授权不再有效",
                    detail="请重新完成数据源授权和任务校验。",
                )
            self._assert_policy_covers_spec(session, policy, spec)
            if (
                source_snapshot.engine != source_revision.engine
                or target_snapshot.engine != target_revision.engine
                or source_snapshot.physical_endpoint_identity_id
                != source_revision.physical_endpoint_identity_id
                or target_snapshot.physical_endpoint_identity_id
                != target_revision.physical_endpoint_identity_id
                or source_snapshot.physical_table_identity_hash
                != material.source_physical_table_identity_hash
                or target_snapshot.physical_table_identity_hash
                != target_namespace.physical_table_identity_hash
                or source_snapshot.catalog_name != source_revision.database_name
                or target_snapshot.catalog_name != target_revision.database_name
                or not _snapshot_schema_binding_matches(
                    engine=source_revision.engine,
                    database_name=source_revision.database_name,
                    spec_schema_name=spec.source.table.schema_name,
                    snapshot_schema_name=source_snapshot.schema_name,
                )
                or not _snapshot_schema_binding_matches(
                    engine=target_revision.engine,
                    database_name=target_revision.database_name,
                    spec_schema_name=spec.target.table.schema_name,
                    snapshot_schema_name=target_snapshot.schema_name,
                )
                or source_snapshot.table_name != spec.source.table.table_name
                or target_snapshot.table_name != spec.target.table.table_name
            ):
                raise ProblemException(
                    status=422,
                    code="SCHEMA_SNAPSHOT_BINDING_MISMATCH",
                    title="Schema 快照与任务资源不匹配",
                    detail="快照必须绑定当前任务的端点身份、引擎、库、Schema 和物理表。",
                )
            self._assert_snapshot_columns_cover_spec(
                spec=spec,
                source_snapshot=source_snapshot_payload,
                target_snapshot=target_snapshot_payload,
            )
            if (
                material.source_physical_table_identity_hash
                == target_namespace.physical_table_identity_hash
            ):
                raise ProblemException(
                    status=422,
                    code="SOURCE_TARGET_SAME_TABLE",
                    title="源表和目标表不能是同一物理表",
                    detail="V1 insert-only 一次性复制禁止自复制。",
                )
            report = {
                "valid": True,
                "draft_spec_hash": job.draft_spec_hash,
                "source_schema_snapshot": source_snapshot_payload,
                "target_schema_snapshot": target_snapshot_payload,
                "source_schema_hash": computed_source_schema_hash,
                "target_schema_hash": computed_target_schema_hash,
                "source_physical_table_identity_hash": (
                    material.source_physical_table_identity_hash
                ),
                "target_namespace_id": str(material.target_namespace_id),
                "transfer_policy_id": str(material.transfer_policy_id),
                "transfer_policy_scope_hash": material.transfer_policy_scope_hash,
                "runtime_sha256": material.runtime_sha256,
                "reader_plugin_sha256": material.reader_plugin_sha256,
                "writer_plugin_sha256": material.writer_plugin_sha256,
                "errors": [],
                "warnings": [],
            }
            for field in (
                "source_schema_hash",
                "target_schema_hash",
                "source_physical_table_identity_hash",
                "transfer_policy_scope_hash",
                "runtime_sha256",
                "reader_plugin_sha256",
                "writer_plugin_sha256",
            ):
                _validate_sha256(str(report[field]), field)
            job.status = "VALID"
            job.validated_spec_hash = job.draft_spec_hash
            job.validation_report = report
            job.updated_at = now
            job.row_version += 1
            self._append_audit(
                session,
                organization=organization,
                project_id=job.project_id,
                action="JOB_VALIDATED",
                actor_id=principal.user_id,
                target_type="SYNC_JOB",
                target_id=job.id,
                target_name=job.name,
                changed_fields=["status", "validated_spec_hash", "validation_report"],
                audit=audit,
                metadata={
                    "draft_spec_hash": job.draft_spec_hash,
                    "transfer_policy_scope_hash": material.transfer_policy_scope_hash,
                },
            )
            return self._job_response(session, job)

    def publish_validated_job(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        expected_draft_spec_hash: str,
        expected_version: int,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[JobVersionResponse]:
        """Publish a VALID draft without re-running external validation.

        The caller is still expected to invoke the real validator immediately
        before this method. The method rechecks every locally authoritative fact
        and refuses missing/stale validation material.
        """

        self._require_project_role_for_job(principal, job_id, {Role.DEVELOPER})
        now = utc_now()
        request_body = {"expected_draft_spec_hash": expected_draft_spec_hash}
        with self.sessions.begin() as session:
            job = self._visible_job(session, principal, job_id, lock=True)
            organization = self._lock_organization(session, principal.organization_id)
            replay = self._claim_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /jobs/{job_id}/versions",
                key=idempotency_key,
                body=request_body,
                now=now,
            )
            if replay is not None:
                return OperationResult(
                    JobVersionResponse.model_validate(replay.response_body),
                    replayed=True,
                )
            if job.row_version != expected_version:
                self._version_conflict()
            if (
                job.status != "VALID"
                or job.validated_spec_hash != job.draft_spec_hash
                or expected_draft_spec_hash != job.draft_spec_hash
                or not job.validation_report
                or not job.validation_report.get("valid")
            ):
                raise ProblemException(
                    status=409,
                    code="JOB_NOT_VALID",
                    title="任务草稿尚未通过当前校验",
                    detail="请重新校验当前草稿后再发布。",
                )
            spec = JobSpecV1.model_validate(job.draft_spec_json)
            self._check_job_spec_resources(session, job.project_id, spec)
            report = job.validation_report
            policy = session.get(TransferPolicy, UUID(report["transfer_policy_id"]))
            target_namespace = session.get(TargetNamespace, UUID(report["target_namespace_id"]))
            if (
                policy is None
                or policy.status != "ACTIVE"
                or policy.scope_hash != report["transfer_policy_scope_hash"]
                or target_namespace is None
            ):
                raise ProblemException(
                    status=409,
                    code="TRANSFER_POLICY_NOT_ACTIVE",
                    title="传输授权不再有效",
                    detail="请重新校验当前草稿。",
                )
            self._assert_policy_covers_spec(session, policy, spec)
            source_revision = session.get(
                DatasourceRevision,
                spec.source.datasource_revision_id,
            )
            target_revision = session.get(
                DatasourceRevision,
                spec.target.datasource_revision_id,
            )
            if source_revision is None or target_revision is None:
                self._not_found()
            version_no = (
                session.scalar(
                    select(func.max(JobVersion.version_no)).where(JobVersion.job_id == job.id)
                )
                or 0
            ) + 1
            artifact = {
                "spec_hash": job.draft_spec_hash,
                "source_datasource_revision_id": str(source_revision.id),
                "target_datasource_revision_id": str(target_revision.id),
                "source_endpoint_policy_revision_id": str(
                    source_revision.endpoint_policy_revision_id
                ),
                "target_endpoint_policy_revision_id": str(
                    target_revision.endpoint_policy_revision_id
                ),
                "source_physical_table_identity_hash": report[
                    "source_physical_table_identity_hash"
                ],
                "target_namespace_id": str(target_namespace.id),
                "transfer_policy_scope_hash": policy.scope_hash,
                "source_schema_hash": report["source_schema_hash"],
                "target_schema_hash": report["target_schema_hash"],
                "runtime_sha256": report["runtime_sha256"],
                "reader_plugin_sha256": report["reader_plugin_sha256"],
                "writer_plugin_sha256": report["writer_plugin_sha256"],
            }
            version_artifact_hash = _domain_hash("DXJOBVERSIONv1", artifact)
            version = JobVersion(
                id=uuid4(),
                job_id=job.id,
                version_no=version_no,
                job_spec_schema_version="1.0",
                spec_json=spec.model_dump(mode="json"),
                spec_hash=job.draft_spec_hash,
                source_datasource_revision_id=source_revision.id,
                target_datasource_revision_id=target_revision.id,
                source_endpoint_policy_revision_id=source_revision.endpoint_policy_revision_id,
                target_endpoint_policy_revision_id=target_revision.endpoint_policy_revision_id,
                source_physical_table_identity_hash=report[
                    "source_physical_table_identity_hash"
                ],
                target_namespace_id=target_namespace.id,
                transfer_policy_id=policy.id,
                transfer_policy_scope_hash=policy.scope_hash,
                source_schema_snapshot=report["source_schema_snapshot"],
                target_schema_snapshot=report["target_schema_snapshot"],
                source_schema_hash=report["source_schema_hash"],
                target_schema_hash=report["target_schema_hash"],
                reader_plugin_name=spec.source.plugin_name,
                reader_plugin_sha256=report["reader_plugin_sha256"],
                writer_plugin_name=spec.target.plugin_name,
                writer_plugin_sha256=report["writer_plugin_sha256"],
                datax_release="datax_v202309",
                runtime_sha256=report["runtime_sha256"],
                version_artifact_hash=version_artifact_hash,
                published_by=principal.user_id,
                published_at=now,
            )
            session.add(version)
            session.flush()
            job.status = "PUBLISHED"
            job.latest_published_version_id = version.id
            job.updated_at = now
            job.row_version += 1
            self._append_audit(
                session,
                organization=organization,
                project_id=job.project_id,
                action="JOB_VERSION_PUBLISHED",
                actor_id=principal.user_id,
                target_type="JOB_VERSION",
                target_id=version.id,
                target_name=job.name,
                changed_fields=[
                    "job_version",
                    "latest_published_version_id",
                    "status",
                ],
                audit=audit,
                metadata={
                    "version_no": version_no,
                    "version_artifact_hash": version_artifact_hash,
                },
            )
            self._complete_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /jobs/{job_id}/versions",
                key=idempotency_key,
                status=201,
                body=self._job_version_response(version).model_dump(mode="json"),
                resource_type="JOB_VERSION",
                resource_id=version.id,
            )
            return OperationResult(self._job_version_response(version))

    def list_job_versions(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        limit: int,
        cursor: str | None,
    ) -> JobVersionPage:
        with self.sessions() as session:
            self._visible_job(session, principal, job_id)
            statement = select(JobVersion).where(JobVersion.job_id == job_id)
            if cursor:
                published_at, version_id = self._decode_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    scope=f"GET /jobs/{job_id}/versions",
                )
                statement = statement.where(
                    or_(
                        JobVersion.published_at < published_at,
                        and_(
                            JobVersion.published_at == published_at,
                            JobVersion.id < version_id,
                        ),
                    )
                )
            rows = list(
                session.scalars(
                    statement.order_by(
                        JobVersion.published_at.desc(),
                        JobVersion.id.desc(),
                    ).limit(limit + 1)
                )
            )
            has_more = len(rows) > limit
            rows = rows[:limit]
            next_cursor = None
            if has_more and rows:
                next_cursor = self._encode_cursor(
                    actor_id=principal.user_id,
                    scope=f"GET /jobs/{job_id}/versions",
                    created_at=ensure_aware(rows[-1].published_at),
                    resource_id=rows[-1].id,
                )
            return JobVersionPage(
                items=[self._job_version_response(row) for row in rows],
                next_cursor=next_cursor,
                has_more=has_more,
            )

    def get_job_version(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        version_id: UUID,
    ) -> JobVersionResponse:
        with self.sessions() as session:
            self._visible_job(session, principal, job_id)
            version = session.scalar(
                select(JobVersion).where(
                    JobVersion.id == version_id,
                    JobVersion.job_id == job_id,
                )
            )
            if version is None:
                self._not_found()
            return self._job_version_response(version)

    # ------------------------------------------------------------------
    # Execution request facts: API writes only QUEUED + RESERVED.
    # ------------------------------------------------------------------
    def create_execution(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        request: ExecutionCreate,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[ExecutionResponse]:
        now = utc_now()
        try:
            with self.sessions.begin() as session:
                job = self._visible_job(session, principal, job_id, lock=True)
                self._require_project_role(principal, job.project_id, {Role.OPERATOR})
                organization = self._lock_organization(session, principal.organization_id)
                replay = self._claim_idempotency(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /jobs/{job_id}/executions",
                    key=idempotency_key,
                    body=request.model_dump(mode="json"),
                    now=now,
                )
                if replay is not None:
                    return OperationResult(
                        ExecutionResponse.model_validate(replay.response_body),
                        replayed=True,
                    )
                self._require_accepting_new_executions(session)
                version = session.get(JobVersion, request.job_version_id)
                if (
                    version is None
                    or version.job_id != job.id
                    or job.status != "PUBLISHED"
                ):
                    raise ProblemException(
                        status=409,
                        code="JOB_NOT_PUBLISHED",
                        title="任务版本不可执行",
                        detail="请选择当前任务的已发布不可变版本。",
                    )
                self.require_job_version_plugin_certification(
                    version=version,
                    now=now,
                )
                spec = JobSpecV1.model_validate(version.spec_json)
                self._check_job_spec_resources(
                    session,
                    job.project_id,
                    spec,
                    lock_datasources=True,
                )
                policy = session.get(TransferPolicy, version.transfer_policy_id)
                if (
                    policy is None
                    or policy.status != "ACTIVE"
                    or policy.scope_hash != version.transfer_policy_scope_hash
                ):
                    raise ProblemException(
                        status=409,
                        code="TRANSFER_POLICY_NOT_ACTIVE",
                        title="传输授权不再有效",
                        detail="当前版本绑定的传输策略已失效。",
                    )
                self._assert_policy_covers_spec(session, policy, spec)
                self._require_datasource_grants(
                    session,
                    principal=principal,
                    source_revision_id=version.source_datasource_revision_id,
                    target_revision_id=version.target_datasource_revision_id,
                )
                self._validate_execution_confirmations(request, now)
                target_namespace = session.get(TargetNamespace, version.target_namespace_id)
                if target_namespace is None:
                    raise RuntimeError("JobVersion target namespace is missing")
                existing_lock = session.scalar(
                    select(TargetCopyLock.id)
                    .where(
                        TargetCopyLock.target_namespace_id == target_namespace.id,
                        TargetCopyLock.state.in_(_ACTIVE_LOCK_STATES),
                    )
                    .with_for_update()
                )
                if existing_lock is not None:
                    raise ProblemException(
                        status=409,
                        code="TARGET_ACTIVE_EXECUTION",
                        title="目标表已有未完成工作",
                        detail="同一物理目标表只能存在一个排队、活动或恢复中工作。",
                    )
                queued_count = session.scalar(
                    select(func.count(Execution.id)).where(
                        Execution.process_state == "QUEUED"
                    )
                )
                if (queued_count or 0) >= 200:
                    raise ProblemException(
                        status=503,
                        code="CAPACITY_ADMISSION_BLOCKED",
                        title="当前队列已达到安全上限",
                        detail="请等待现有工作完成后重试。",
                        retryable=True,
                        details={"reason": "QUEUE_LIMIT"},
                    )
                execution = Execution(
                    id=uuid4(),
                    project_id=job.project_id,
                    job_id=job.id,
                    job_version_id=version.id,
                    rerun_of_execution_id=None,
                    trigger_type="MANUAL",
                    requested_by=principal.user_id,
                    process_state="QUEUED",
                    data_effect="NONE",
                    verification_state="NOT_STARTED",
                    state_version=1,
                    fence_epoch=0,
                    active_attempt_id=None,
                    queue_priority=0,
                    capacity_profile="LARGE",
                    service_reservation_seconds=3600,
                    log_reservation_bytes=0,
                    workspace_reservation_bytes=0,
                    queue_eligibility_state="ELIGIBLE",
                    queue_block_reason=None,
                    queue_state_changed_at=now,
                    eligible_wait_milliseconds=0,
                    queued_at=now,
                    timeout_seconds=spec.execution_policy.timeout_seconds,
                    source_datasource_revision_id=version.source_datasource_revision_id,
                    target_datasource_revision_id=version.target_datasource_revision_id,
                    source_endpoint_policy_revision_id=(
                        version.source_endpoint_policy_revision_id
                    ),
                    target_endpoint_policy_revision_id=(
                        version.target_endpoint_policy_revision_id
                    ),
                    target_namespace_id=version.target_namespace_id,
                    source_quiescence_confirmation=(
                        request.source_quiescence_confirmation.model_dump(mode="json")
                    ),
                    target_exclusivity_confirmation=(
                        request.target_exclusivity_confirmation.model_dump(mode="json")
                    ),
                    target_exclusivity_status="ACTIVE",
                    attempt_count=0,
                    summary_parse_status="PENDING",
                    log_truncated=False,
                    log_incomplete=False,
                    log_raw_received_bytes=0,
                    log_redacted_received_bytes=0,
                    log_stored_bytes=0,
                    log_dropped_bytes=0,
                    created_at=now,
                )
                session.add(execution)
                session.flush()
                target_lock = TargetCopyLock(
                    id=uuid4(),
                    target_namespace_id=target_namespace.id,
                    physical_table_identity_hash=(
                        target_namespace.physical_table_identity_hash
                    ),
                    execution_id=execution.id,
                    state="RESERVED",
                    reserved_at=now,
                )
                session.add(target_lock)
                session.add(
                    ExecutionEvent(
                        id=uuid4(),
                        execution_id=execution.id,
                        sequence_no=1,
                        event_type="EXECUTION_QUEUED",
                        from_state=None,
                        to_state="QUEUED",
                        payload={
                            "target_namespace_id": str(target_namespace.id),
                            "target_lock_state": "RESERVED",
                        },
                        occurred_at=now,
                    )
                )
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=job.project_id,
                    action="TARGET_EXCLUSIVITY_CONFIRMED",
                    actor_id=principal.user_id,
                    target_type="EXECUTION",
                    target_id=execution.id,
                    target_name=None,
                    changed_fields=[
                        "target_exclusivity_confirmation",
                        "target_exclusivity_status",
                    ],
                    audit=audit,
                    metadata={
                        "statement_version": "1.0",
                        "responsible_party": (
                            request.target_exclusivity_confirmation.responsible_party
                        ),
                        "confirmed_at": _rfc3339(
                            request.target_exclusivity_confirmation.confirmed_at
                        ),
                        "accepted_at": _rfc3339(now),
                        "valid_until": _rfc3339(
                            request.target_exclusivity_confirmation.valid_until
                        ),
                        "target_namespace_id": str(target_namespace.id),
                        "confirmation_sha256": _domain_hash(
                            "DXTARGETEXCLUSIVITYv1",
                            request.target_exclusivity_confirmation.model_dump(mode="json"),
                        ),
                    },
                )
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=job.project_id,
                    action="EXECUTION_CREATED",
                    actor_id=principal.user_id,
                    target_type="EXECUTION",
                    target_id=execution.id,
                    target_name=None,
                    changed_fields=[
                        "execution",
                        "target_copy_lock",
                        "source_quiescence_confirmation",
                    ],
                    audit=audit,
                    metadata={
                        "job_version_id": str(version.id),
                        "target_namespace_id": str(target_namespace.id),
                        "target_lock_state": "RESERVED",
                    },
                )
                response = self._execution_response(execution, target_lock, version)
                self._complete_idempotency(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /jobs/{job_id}/executions",
                    key=idempotency_key,
                    status=202,
                    body=response.model_dump(mode="json"),
                    resource_type="EXECUTION",
                    resource_id=execution.id,
                )
                return OperationResult(response)
        except IntegrityError as exc:
            raise ProblemException(
                status=409,
                code="TARGET_ACTIVE_EXECUTION",
                title="目标表已有未完成工作",
                detail="同一物理目标表只能存在一个排队、活动或恢复中工作。",
            ) from exc

    def get_execution(
        self,
        *,
        principal: Principal,
        execution_id: UUID,
    ) -> ExecutionResponse:
        with self.sessions() as session:
            execution = self._visible_execution(session, principal, execution_id)
            version = session.get(JobVersion, execution.job_version_id)
            if version is None:
                raise RuntimeError("Execution JobVersion is missing")
            return self._execution_response(
                execution,
                self._execution_lock(session, execution.id),
                version,
            )

    def list_executions(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        limit: int,
        cursor: str | None,
        process_states: list[str] | None = None,
        data_effects: list[str] | None = None,
        verification_states: list[str] | None = None,
        target_exclusivity_statuses: list[str] | None = None,
        query: str | None = None,
        job_id: UUID | None = None,
        job_version_id: UUID | None = None,
        requested_by: UUID | None = None,
        queued_from: datetime | None = None,
        queued_to: datetime | None = None,
        is_rerun: bool | None = None,
        unresolved_failure: bool | None = None,
    ) -> ExecutionPage:
        with self.sessions() as session:
            self._visible_project(session, principal, project_id)
            statement = select(Execution).where(Execution.project_id == project_id)
            normalized_query = query.strip().casefold() if query is not None else None
            if normalized_query:
                pattern = _contains_pattern(normalized_query)
                statement = statement.join(
                    SyncJob,
                    SyncJob.id == Execution.job_id,
                ).where(
                    or_(
                        func.lower(SyncJob.name).like(pattern, escape="\\"),
                        func.lower(cast(Execution.id, String)).like(
                            pattern,
                            escape="\\",
                        ),
                    )
                )
            if process_states:
                statement = statement.where(Execution.process_state.in_(process_states))
            if data_effects:
                statement = statement.where(Execution.data_effect.in_(data_effects))
            if verification_states:
                statement = statement.where(
                    Execution.verification_state.in_(verification_states)
                )
            if target_exclusivity_statuses:
                statement = statement.where(
                    Execution.target_exclusivity_status.in_(
                        target_exclusivity_statuses
                    )
                )
            if job_id is not None:
                statement = statement.where(Execution.job_id == job_id)
            if job_version_id is not None:
                statement = statement.where(
                    Execution.job_version_id == job_version_id
                )
            if requested_by is not None:
                statement = statement.where(Execution.requested_by == requested_by)
            if queued_from is not None:
                statement = statement.where(
                    Execution.queued_at >= ensure_aware(queued_from)
                )
            if queued_to is not None:
                statement = statement.where(
                    Execution.queued_at < ensure_aware(queued_to)
                )
            if is_rerun is True:
                statement = statement.where(
                    Execution.rerun_of_execution_id.is_not(None)
                )
            elif is_rerun is False:
                statement = statement.where(
                    Execution.rerun_of_execution_id.is_(None)
                )
            if unresolved_failure is not None:
                unresolved = select(TargetCopyLock.execution_id).where(
                    TargetCopyLock.state == "RECOVERY_REQUIRED"
                )
                if unresolved_failure:
                    statement = statement.where(Execution.id.in_(unresolved))
                else:
                    statement = statement.where(Execution.id.not_in(unresolved))
            scope = _filtered_cursor_scope(
                f"GET /projects/{project_id}/executions",
                {
                    "q": normalized_query,
                    "process_state": sorted(process_states or []),
                    "data_effect": sorted(data_effects or []),
                    "verification_state": sorted(verification_states or []),
                    "target_exclusivity_status": sorted(
                        target_exclusivity_statuses or []
                    ),
                    "job_id": str(job_id) if job_id is not None else None,
                    "job_version_id": (
                        str(job_version_id)
                        if job_version_id is not None
                        else None
                    ),
                    "requested_by": (
                        str(requested_by) if requested_by is not None else None
                    ),
                    "from": (
                        _rfc3339(ensure_aware(queued_from))
                        if queued_from is not None
                        else None
                    ),
                    "to": (
                        _rfc3339(ensure_aware(queued_to))
                        if queued_to is not None
                        else None
                    ),
                    "is_rerun": is_rerun,
                    "unresolved_failure": unresolved_failure,
                },
            )
            if cursor:
                queued_at, execution_id = self._decode_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    scope=scope,
                )
                statement = statement.where(
                    or_(
                        Execution.queued_at < queued_at,
                        and_(
                            Execution.queued_at == queued_at,
                            Execution.id < execution_id,
                        ),
                    )
                )
            rows = list(
                session.scalars(
                    statement.order_by(Execution.queued_at.desc(), Execution.id.desc()).limit(
                        limit + 1
                    )
                )
            )
            has_more = len(rows) > limit
            rows = rows[:limit]
            items = [
                self._execution_response(
                    row,
                    self._execution_lock(session, row.id),
                    self._required_job_version(session, row.job_version_id),
                )
                for row in rows
            ]
            next_cursor = None
            if has_more and rows:
                next_cursor = self._encode_cursor(
                    actor_id=principal.user_id,
                    scope=scope,
                    created_at=ensure_aware(rows[-1].queued_at),
                    resource_id=rows[-1].id,
                )
            return ExecutionPage(items=items, next_cursor=next_cursor, has_more=has_more)

    def request_cancel(
        self,
        *,
        principal: Principal,
        execution_id: UUID,
        reason: str | None,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[CancelRequestResponse]:
        now = utc_now()
        with self.sessions.begin() as session:
            execution = self._visible_execution(session, principal, execution_id, lock=True)
            self._require_project_role(principal, execution.project_id, {Role.OPERATOR})
            organization = self._lock_organization(session, principal.organization_id)
            replay = self._claim_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /executions/{execution_id}/cancel",
                key=idempotency_key,
                body={"reason": reason},
                now=now,
            )
            if replay is not None:
                return OperationResult(
                    CancelRequestResponse.model_validate(replay.response_body),
                    replayed=True,
                )
            if execution.process_state in _TERMINAL_STATES:
                raise ProblemException(
                    status=409,
                    code="EXECUTION_NOT_CANCELABLE",
                    title="当前执行不能取消",
                    detail="终态执行不会被改写。",
                )
            existing = session.scalar(
                select(ExecutionCancelRequest).where(
                    ExecutionCancelRequest.execution_id == execution.id,
                    ExecutionCancelRequest.status.in_(("PENDING", "ACKNOWLEDGED")),
                )
            )
            if existing is not None:
                raise ProblemException(
                    status=409,
                    code="EXECUTION_CANCEL_ALREADY_REQUESTED",
                    title="取消请求已存在",
                    detail="请等待 Worker 或 reconciler 处理现有请求。",
                )
            cancel = ExecutionCancelRequest(
                id=uuid4(),
                execution_id=execution.id,
                requested_by=principal.user_id,
                reason=_clean_optional(reason),
                status="PENDING",
                requested_at=now,
            )
            session.add(cancel)
            response = CancelRequestResponse(
                id=cancel.id,
                execution_id=execution.id,
                status="PENDING",
                requested_at=now,
            )
            self._append_audit(
                session,
                organization=organization,
                project_id=execution.project_id,
                action="EXECUTION_CANCEL_REQUESTED",
                actor_id=principal.user_id,
                target_type="EXECUTION",
                target_id=execution.id,
                target_name=None,
                changed_fields=["execution_cancel_request"],
                audit=audit,
            )
            self._complete_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /executions/{execution_id}/cancel",
                key=idempotency_key,
                status=202,
                body=response.model_dump(mode="json"),
                resource_type="EXECUTION_CANCEL_REQUEST",
                resource_id=cancel.id,
            )
            return OperationResult(response)

    def revoke_target_exclusivity(
        self,
        *,
        principal: Principal,
        execution_id: UUID,
        request: TargetExclusivityRevocationRequest,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[ExecutionResponse]:
        now = utc_now()
        with self.sessions.begin() as session:
            execution = self._visible_execution(session, principal, execution_id, lock=True)
            self._require_project_role(principal, execution.project_id, {Role.OPERATOR})
            organization = self._lock_organization(session, principal.organization_id)
            replay = self._claim_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /executions/{execution_id}/target-exclusivity/revoke",
                key=idempotency_key,
                body=request.model_dump(mode="json"),
                now=now,
            )
            if replay is not None:
                return OperationResult(
                    ExecutionResponse.model_validate(replay.response_body),
                    replayed=True,
                )
            if execution.process_state in _TERMINAL_STATES:
                raise ProblemException(
                    status=409,
                    code="EXECUTION_TERMINAL",
                    title="终态执行不能撤回声明",
                    detail="历史结论不会被墙上时钟或后续请求改写。",
                )
            confirmation = execution.target_exclusivity_confirmation
            if (
                request.responsible_party != confirmation.get("responsible_party")
                or request.statement_version != confirmation.get("statement_version")
            ):
                raise ProblemException(
                    status=422,
                    code="TARGET_EXCLUSIVITY_CONFIRMATION_MISMATCH",
                    title="撤回请求与原声明不匹配",
                    detail="责任方和声明版本必须与 Execution 固化事实一致。",
                )
            if execution.target_exclusivity_status != "ACTIVE":
                raise ProblemException(
                    status=409,
                    code="TARGET_EXCLUSIVITY_NOT_ACTIVE",
                    title="目标独占声明已失效",
                    detail="只有 ACTIVE 声明可以被撤回。",
                )
            execution.target_exclusivity_status = "REVOKED"
            execution.target_exclusivity_revoked_at = now
            execution.target_exclusivity_revocation_reason = request.reason
            execution.state_version += 1
            termination = self._ensure_target_exclusivity_termination(
                session,
                execution=execution,
                now=now,
                attempt_id=execution.active_attempt_id,
            )
            if termination is None:
                raise RuntimeError("revoked target exclusivity must create a termination request")
            self._append_execution_event(
                session,
                execution,
                event_type="TARGET_EXCLUSIVITY_REVOKED",
                payload={
                    "reason": request.reason,
                    "responsible_party": request.responsible_party,
                    "reported_at": _rfc3339(request.reported_at),
                    "termination_request_id": str(termination.id),
                },
                now=now,
            )
            self._append_audit(
                session,
                organization=organization,
                project_id=execution.project_id,
                action="TARGET_EXCLUSIVITY_REVOKED",
                actor_id=principal.user_id,
                target_type="EXECUTION",
                target_id=execution.id,
                target_name=None,
                changed_fields=[
                    "target_exclusivity_status",
                    "target_exclusivity_revoked_at",
                    "target_exclusivity_revocation_reason",
                ],
                audit=audit,
                metadata={
                    "statement_version": request.statement_version,
                    "reason": request.reason,
                    "responsible_party": request.responsible_party,
                    "reported_at": _rfc3339(request.reported_at),
                    "revoked_at": _rfc3339(now),
                    "target_namespace_id": str(execution.target_namespace_id),
                    "confirmation_sha256": _domain_hash(
                        "DXTARGETEXCLUSIVITYv1",
                        confirmation,
                    ),
                },
            )
            lock = self._execution_lock(session, execution.id)
            response = self._execution_response(
                execution,
                lock,
                self._required_job_version(session, execution.job_version_id),
            )
            self._complete_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /executions/{execution_id}/target-exclusivity/revoke",
                key=idempotency_key,
                status=202,
                body=response.model_dump(mode="json"),
                resource_type="EXECUTION",
                resource_id=execution.id,
            )
            return OperationResult(response)

    # ------------------------------------------------------------------
    # Worker-only fact queue and fencing operations. No HTTP route exposes
    # lease tokens or allows the API process to advance execution states.
    # ------------------------------------------------------------------
    def claim_next_execution(
        self,
        *,
        worker_id: str,
        host_boot_id: str,
        cgroup_identity: str,
        credential_selector: CredentialBindingSelector,
        lease_seconds: int = 30,
    ) -> ClaimedExecution | None:
        """Fairly select and claim the next eligible Execution in one transaction.

        The credential selector receives this transaction's Session so current
        Datasource, CredentialSecret, Envelope and KEK facts can be locked and
        validated before any claim fact or fairness cursor is committed.
        """

        if not 5 <= lease_seconds <= 300:
            raise ValueError("lease_seconds must be between 5 and 300")
        if not worker_id or len(worker_id) > 128:
            raise ValueError("worker_id is invalid")
        if not host_boot_id or len(host_boot_id) > 128:
            raise ValueError("host_boot_id is invalid")
        if not cgroup_identity or len(cgroup_identity) > 256:
            raise ValueError("cgroup_identity is invalid")
        with self.sessions.begin() as session:
            # Serialize admission with the Launcher stop request.  PostgreSQL
            # grants the fixed local-stop function the same row lock, so a
            # claim cannot pass a stale `draining=false` observation and then
            # commit after stop preflight has checked for active work.
            control = session.scalar(
                select(SystemControl)
                .where(SystemControl.singleton_id == 1)
                .with_for_update()
            )
            if control is None or control.draining:
                raise ProblemException(
                    status=503,
                    code="SERVICE_DRAINING",
                    title="服务正在对账或停止",
                    detail="完成 Worker 对账前不会领取新的 Execution。",
                    retryable=True,
                )
            now = self._database_now(session)
            pending_cancel = (
                select(ExecutionCancelRequest.id)
                .where(
                    ExecutionCancelRequest.execution_id == Execution.id,
                    ExecutionCancelRequest.status == "PENDING",
                )
                .exists()
            )
            pending_termination = (
                select(WorkTerminationRequest.id)
                .where(
                    WorkTerminationRequest.work_kind == "EXECUTION",
                    WorkTerminationRequest.work_id == Execution.id,
                    WorkTerminationRequest.status.in_(_ACTIVE_WORK_TERMINATION_STATUSES),
                )
                .exists()
            )
            claimable = (
                Execution.process_state == "QUEUED",
                Execution.active_attempt_id.is_(None),
                Execution.queue_eligibility_state == "ELIGIBLE",
                Execution.target_exclusivity_status == "ACTIVE",
                ~pending_cancel,
                ~pending_termination,
            )
            project_has_claimable = (
                select(Execution.id)
                .where(
                    Execution.project_id == ProjectQueueServiceCursor.project_id,
                    *claimable,
                )
                .exists()
            )
            oldest_eligible = (
                select(func.min(Execution.queued_at))
                .where(
                    Execution.project_id == ProjectQueueServiceCursor.project_id,
                    *claimable,
                )
                .scalar_subquery()
            )
            project_cursor = session.scalar(
                select(ProjectQueueServiceCursor)
                .where(project_has_claimable)
                .order_by(
                    ProjectQueueServiceCursor.last_service_sequence.asc(),
                    oldest_eligible.asc(),
                    ProjectQueueServiceCursor.project_id.asc(),
                )
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if project_cursor is None:
                return None
            execution = session.scalar(
                select(Execution)
                .where(
                    Execution.project_id == project_cursor.project_id,
                    *claimable,
                )
                .order_by(
                    Execution.queue_priority.desc(),
                    Execution.queued_at.asc(),
                    Execution.id.asc(),
                )
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if execution is None:
                return None
            confirmation = execution.target_exclusivity_confirmation
            valid_until = _parse_timestamp(confirmation["valid_until"])
            if (
                execution.target_exclusivity_status != "ACTIVE"
                or execution.target_exclusivity_revoked_at is not None
                or execution.target_exclusivity_revocation_reason is not None
                or valid_until <= now
            ):
                if (
                    execution.target_exclusivity_status == "ACTIVE"
                    and valid_until <= now
                ):
                    self._ensure_target_exclusivity_termination(
                        session,
                        execution=execution,
                        now=now,
                        attempt_id=None,
                    )
                    execution.queue_eligibility_state = "BLOCKED"
                    execution.queue_block_reason = "TARGET_EXCLUSIVITY_EXPIRED"
                    execution.queue_state_changed_at = now
                return None
            target_lock = session.scalar(
                select(TargetCopyLock)
                .where(
                    TargetCopyLock.execution_id == execution.id,
                    TargetCopyLock.state == "RESERVED",
                )
                .with_for_update()
            )
            if target_lock is None:
                raise ProblemException(
                    status=409,
                    code="TARGET_RESERVATION_MISSING",
                    title="目标预留事实缺失",
                    detail="Worker 不会在没有匹配 RESERVED 锁时启动外部连接。",
                )
            version = session.get(JobVersion, execution.job_version_id)
            policy = (
                session.scalar(
                    select(TransferPolicy)
                    .where(TransferPolicy.id == version.transfer_policy_id)
                    .with_for_update()
                )
                if version
                else None
            )
            if (
                version is None
                or policy is None
                or policy.status != "ACTIVE"
                or policy.scope_hash != version.transfer_policy_scope_hash
            ):
                execution.queue_eligibility_state = "BLOCKED"
                execution.queue_block_reason = "TRANSFER_POLICY_NOT_ACTIVE"
                execution.queue_state_changed_at = now
                execution.state_version += 1
                return None
            try:
                self.require_job_version_plugin_certification(
                    version=version,
                    now=now,
                )
            except ProblemException as exc:
                if exc.code != "PLUGIN_WINDOWS_E4_CERTIFICATION_REQUIRED":
                    raise
                execution.queue_eligibility_state = "BLOCKED"
                execution.queue_block_reason = "PLUGIN_E4_CERTIFICATION_BLOCKED"
                execution.queue_state_changed_at = now
                execution.state_version += 1
                return None
            source_revision = session.get(
                DatasourceRevision,
                execution.source_datasource_revision_id,
            )
            target_revision = session.get(
                DatasourceRevision,
                execution.target_datasource_revision_id,
            )
            source_policy_revision = session.get(
                EndpointPolicyRevision,
                execution.source_endpoint_policy_revision_id,
            )
            target_policy_revision = session.get(
                EndpointPolicyRevision,
                execution.target_endpoint_policy_revision_id,
            )
            if (
                source_revision is None
                or target_revision is None
                or source_policy_revision is None
                or target_policy_revision is None
            ):
                execution.queue_eligibility_state = "BLOCKED"
                execution.queue_block_reason = "IMMUTABLE_BINDING_MISSING"
                execution.queue_state_changed_at = now
                execution.state_version += 1
                return None
            endpoint_policy_ids = {
                source_policy_revision.endpoint_policy_id,
                target_policy_revision.endpoint_policy_id,
            }
            endpoint_policies = {
                item.id: item
                for item in session.scalars(
                    select(EndpointPolicy)
                    .where(EndpointPolicy.id.in_(endpoint_policy_ids))
                    .order_by(EndpointPolicy.id)
                    .with_for_update()
                )
            }
            source_endpoint_policy = endpoint_policies.get(
                source_policy_revision.endpoint_policy_id
            )
            target_endpoint_policy = endpoint_policies.get(
                target_policy_revision.endpoint_policy_id
            )
            if (
                source_endpoint_policy is None
                or target_endpoint_policy is None
                or source_endpoint_policy.status != "ACTIVE"
                or target_endpoint_policy.status != "ACTIVE"
                or source_endpoint_policy.current_revision_id
                != source_policy_revision.id
                or target_endpoint_policy.current_revision_id
                != target_policy_revision.id
            ):
                execution.queue_eligibility_state = "BLOCKED"
                execution.queue_block_reason = "ENDPOINT_POLICY_NOT_ACTIVE"
                execution.queue_state_changed_at = now
                execution.state_version += 1
                return None
            datasource_ids = {
                source_revision.datasource_id,
                target_revision.datasource_id,
            }
            datasources = {
                item.id: item
                for item in session.scalars(
                    select(Datasource)
                    .where(Datasource.id.in_(datasource_ids))
                    .order_by(Datasource.id)
                    .with_for_update()
                )
            }
            source_datasource = datasources.get(source_revision.datasource_id)
            target_datasource = datasources.get(target_revision.datasource_id)
            # The SQL eligibility predicate was evaluated before this
            # transaction acquired datasource/credential gates.  An emergency
            # current-secret transition may have held the datasource row,
            # durably recorded a WorkTerminationRequest for this queued item,
            # and then committed while we waited.  Do not mark the queue item
            # generically BLOCKED in that case: leave the durable request for
            # the reconciler so it can release TargetCopyLock with its exact
            # safety reason.
            if self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=False,
            ):
                return None
            if source_datasource is None or target_datasource is None:
                execution.queue_eligibility_state = "BLOCKED"
                execution.queue_block_reason = "CREDENTIAL_BINDING_NOT_ACTIVE"
                execution.queue_state_changed_at = now
                execution.state_version += 1
                return None
            try:
                credential_binding = credential_selector(
                    session,
                    source_datasource_id=source_datasource.id,
                    target_datasource_id=target_datasource.id,
                )
            except ProblemException as exc:
                if exc.code != "CREDENTIAL_BINDING_NOT_ACTIVE":
                    raise
                if self._active_work_termination_requests(
                    session,
                    work_kind="EXECUTION",
                    work_id=execution.id,
                    lock=False,
                ):
                    return None
                execution.queue_eligibility_state = "BLOCKED"
                execution.queue_block_reason = exc.code
                execution.queue_state_changed_at = now
                execution.state_version += 1
                return None
            if self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=False,
            ):
                return None
            if (
                source_datasource.status != "ACTIVE"
                or target_datasource.status != "ACTIVE"
                or source_datasource.current_secret_id
                != credential_binding.source_secret_id
                or target_datasource.current_secret_id
                != credential_binding.target_secret_id
            ):
                execution.queue_eligibility_state = "BLOCKED"
                execution.queue_block_reason = "CREDENTIAL_BINDING_NOT_ACTIVE"
                execution.queue_state_changed_at = now
                execution.state_version += 1
                return None
            scheduler = session.scalar(
                select(QueueSchedulerState)
                .where(QueueSchedulerState.singleton_id == 1)
                .with_for_update()
            )
            if scheduler is None:
                raise RuntimeError("queue scheduler state is missing")
            lease_token = secrets.token_urlsafe(32)
            lease_token_hash = hashlib.sha256(lease_token.encode("ascii")).hexdigest()
            next_fence = execution.fence_epoch + 1
            attempt_no = execution.attempt_count + 1
            attempt = ExecutionAttempt(
                id=uuid4(),
                execution_id=execution.id,
                attempt_no=attempt_no,
                worker_id=worker_id,
                lease_token_hash=lease_token_hash,
                fence_epoch=next_fence,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                heartbeat_at=now,
                host_boot_id=host_boot_id,
                cgroup_identity=cgroup_identity,
            )
            session.add(attempt)
            session.flush()
            execution.process_state = "STARTING"
            execution.state_version += 1
            execution.fence_epoch = next_fence
            execution.active_attempt_id = attempt.id
            execution.attempt_count = attempt_no
            execution.source_secret_id = credential_binding.source_secret_id
            execution.target_secret_id = credential_binding.target_secret_id
            execution.source_secret_envelope_id = (
                credential_binding.source_secret_envelope_id
            )
            execution.target_secret_envelope_id = (
                credential_binding.target_secret_envelope_id
            )
            execution.source_secret_version = credential_binding.source_secret_version
            execution.target_secret_version = credential_binding.target_secret_version
            eligible_since = ensure_aware(execution.queue_state_changed_at)
            execution.eligible_wait_milliseconds += max(
                0,
                int((now - eligible_since).total_seconds() * 1000),
            )
            target_lock.state = "ACTIVE"
            target_lock.attempt_id = attempt.id
            target_lock.fence_epoch = next_fence
            target_lock.acquired_at = now
            self._append_execution_event(
                session,
                execution,
                event_type="EXECUTION_CLAIMED",
                from_state="QUEUED",
                to_state="STARTING",
                attempt_id=attempt.id,
                payload={
                    "worker_id": worker_id,
                    "fence_epoch": next_fence,
                    "target_lock_state": "ACTIVE",
                },
                now=now,
            )
            project_cursor.last_service_sequence = scheduler.next_service_sequence
            project_cursor.last_served_at = now
            project_cursor.served_execution_count += 1
            project_cursor.row_version += 1
            project_cursor.updated_at = now
            scheduler.next_service_sequence += 1
            scheduler.updated_at = now
            claimed = ClaimedExecution(
                execution_id=execution.id,
                attempt_id=attempt.id,
                fence_epoch=next_fence,
                lease_token=lease_token,
            )
            return claimed

    def record_claimed_preflight(
        self,
        *,
        claim: ClaimedExecution,
        runtime_preflight: RuntimePreflight | dict[str, Any],
        evidence_validator: PreflightEvidenceValidator,
    ) -> ExecutionRuntimeSnapshot:
        result = self._record_claimed_preflight_transaction(
            claim=claim,
            runtime_preflight=runtime_preflight,
            evidence_validator=evidence_validator,
        )
        if isinstance(result, str):
            if result == "WORK_TERMINATION_PENDING":
                title = "Execution 已收到安全终止请求"
                detail = "Worker 不得继续写入运行前检查事实。"
            else:
                title = "目标独占声明已失效"
                detail = "Worker 必须终止当前 Attempt 并进入恢复门禁。"
            raise ProblemException(
                status=409,
                code=result,
                title=title,
                detail=detail,
            )
        return result

    def _record_claimed_preflight_transaction(
        self,
        *,
        claim: ClaimedExecution,
        runtime_preflight: RuntimePreflight | dict[str, Any],
        evidence_validator: PreflightEvidenceValidator,
    ) -> ExecutionRuntimeSnapshot | str:
        """Persist real post-claim connection and empty-target evidence.

        The Worker must call this only after claim_execution commits and before
        advancing STARTING to RUNNING. No API route exposes this fenced method.
        """

        raw_preflight = (
            runtime_preflight.model_dump(mode="json")
            if isinstance(runtime_preflight, RuntimePreflight)
            else runtime_preflight
        )
        _reject_secret_material(raw_preflight)
        preflight = RuntimePreflight.model_validate(runtime_preflight)
        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution, attempt = self._current_fenced_attempt(
                session,
                claim=claim,
                now=now,
                lock=True,
            )
            if execution.process_state != "STARTING":
                raise ProblemException(
                    status=409,
                    code="PREFLIGHT_STATE_CONFLICT",
                    title="Execution 已不在运行前检查阶段",
                    detail="只有当前 fenced STARTING Attempt 可以写入 preflight 证据。",
                )
            active_terminations = self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=True,
            )
            if active_terminations:
                return "WORK_TERMINATION_PENDING"
            termination = self._ensure_target_exclusivity_termination(
                session,
                execution=execution,
                now=now,
                attempt_id=attempt.id,
            )
            if termination is not None:
                return "TARGET_EXCLUSIVITY_NOT_ACTIVE"
            if execution.runtime_snapshot is not None:
                raise ProblemException(
                    status=409,
                    code="PREFLIGHT_ALREADY_RECORDED",
                    title="运行前检查证据已固化",
                    detail="同一 Attempt 的运行快照不可覆盖。",
                )
            target_lock = self._execution_lock(session, execution.id, lock=True)
            if (
                target_lock.state != "ACTIVE"
                or target_lock.attempt_id != attempt.id
                or target_lock.fence_epoch != claim.fence_epoch
            ):
                self._fence_lost()
            version = session.get(JobVersion, execution.job_version_id)
            source_revision = session.get(
                DatasourceRevision,
                execution.source_datasource_revision_id,
            )
            target_revision = session.get(
                DatasourceRevision,
                execution.target_datasource_revision_id,
            )
            target_namespace = session.get(
                TargetNamespace,
                execution.target_namespace_id,
            )
            if (
                version is None
                or source_revision is None
                or target_revision is None
                or target_namespace is None
                or execution.source_secret_id is None
                or execution.target_secret_id is None
                or execution.source_secret_envelope_id is None
                or execution.target_secret_envelope_id is None
                or execution.source_secret_version is None
                or execution.target_secret_version is None
            ):
                raise RuntimeError("claimed execution bindings are incomplete")
            credential_binding = CredentialBinding(
                source_secret_id=execution.source_secret_id,
                target_secret_id=execution.target_secret_id,
                source_secret_envelope_id=execution.source_secret_envelope_id,
                target_secret_envelope_id=execution.target_secret_envelope_id,
                source_secret_version=execution.source_secret_version,
                target_secret_version=execution.target_secret_version,
            )
            evidence_validator(
                session,
                claim=claim,
                source_evidence_id=preflight.source_connection_evidence_id,
                target_evidence_id=preflight.target_connection_evidence_id,
                source_revision_id=source_revision.id,
                target_revision_id=target_revision.id,
                source_policy_revision_id=(
                    execution.source_endpoint_policy_revision_id
                ),
                target_policy_revision_id=(
                    execution.target_endpoint_policy_revision_id
                ),
            )
            (
                snapshot,
                source_connection_evidence_id,
                target_connection_evidence_id,
                target_empty_evidence,
                resolved_config_hash,
            ) = self._build_runtime_snapshot(
                execution=execution,
                version=version,
                source_revision=source_revision,
                target_revision=target_revision,
                target_namespace=target_namespace,
                target_lock=target_lock,
                credential_binding=credential_binding,
                runtime_preflight=preflight,
                fence_epoch=claim.fence_epoch,
                accepted_at=ensure_aware(execution.created_at),
                observed_at=now,
            )
            execution.source_connection_evidence_id = source_connection_evidence_id
            execution.target_connection_evidence_id = target_connection_evidence_id
            execution.target_empty_evidence = target_empty_evidence.model_dump(mode="json")
            execution.resolved_config_hash = resolved_config_hash
            execution.runtime_snapshot = snapshot.model_dump(mode="json")
            execution.state_version += 1
            self._append_execution_event(
                session,
                execution,
                event_type="EXECUTION_PREFLIGHT_ACCEPTED",
                from_state="STARTING",
                to_state="STARTING",
                attempt_id=attempt.id,
                payload={
                    "target_empty_evidence_hash": target_empty_evidence.evidence_hash,
                    "resolved_config_hash": resolved_config_hash,
                },
                now=now,
            )
            return snapshot

    def heartbeat_execution(
        self,
        *,
        claim: ClaimedExecution,
        lease_seconds: int = 30,
    ) -> datetime:
        if not 5 <= lease_seconds <= 300:
            raise ValueError("lease_seconds must be between 5 and 300")
        termination_pending = False
        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution, attempt = self._current_fenced_attempt(
                session,
                claim=claim,
                now=now,
                lock=True,
            )
            self._ensure_target_exclusivity_termination(
                session,
                execution=execution,
                now=now,
                attempt_id=attempt.id,
            )
            requests = self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=True,
            )
            if requests:
                termination_pending = True
                for request in requests:
                    if request.status == "PENDING":
                        request.status = "ACKNOWLEDGED"
                        request.acknowledged_at = now
                self._append_execution_event(
                    session,
                    execution,
                    event_type="EXECUTION_SYSTEM_TERMINATION_ACKNOWLEDGED",
                    from_state=execution.process_state,
                    to_state=execution.process_state,
                    attempt_id=attempt.id,
                    payload={
                        "termination_request_ids": [str(item.id) for item in requests],
                        "reason_codes": [item.reason_code for item in requests],
                        "acknowledged_via": "HEARTBEAT",
                    },
                    now=now,
                )
            else:
                attempt.heartbeat_at = now
                attempt.lease_expires_at = now + timedelta(seconds=lease_seconds)
                # Touch the execution CAS version so stale state writers cannot ignore
                # a concurrent lifecycle mutation.
                execution.state_version += 1
                lease_expires_at = ensure_aware(attempt.lease_expires_at)
        if termination_pending:
            raise ProblemException(
                status=409,
                code="WORK_TERMINATION_PENDING",
                title="Execution 已收到安全终止请求",
                detail="Worker 不得继续续租，必须停止当前工作并收敛安全终态。",
            )
        return lease_expires_at

    def acknowledge_claimed_execution_termination(
        self,
        *,
        claim: ClaimedExecution,
    ) -> bool:
        """Acknowledge a durable safety stop without advancing business state.

        A managed process may still be alive when this returns.  The caller
        must terminate it and then call :meth:`complete_claimed_execution_termination`
        under the same fence.  Keeping acknowledgement separate makes a
        crash between those steps visible to the reconciler instead of silently
        converting it to a successful or operator-cancelled execution.
        """

        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution, attempt = self._current_fenced_attempt(
                session,
                claim=claim,
                now=now,
                lock=True,
            )
            self._ensure_target_exclusivity_termination(
                session,
                execution=execution,
                now=now,
                attempt_id=attempt.id,
            )
            requests = self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=True,
            )
            if not requests:
                return False
            for request in requests:
                if request.status == "PENDING":
                    request.status = "ACKNOWLEDGED"
                    request.acknowledged_at = now
            self._append_execution_event(
                session,
                execution,
                event_type="EXECUTION_SYSTEM_TERMINATION_ACKNOWLEDGED",
                from_state=execution.process_state,
                to_state=execution.process_state,
                attempt_id=attempt.id,
                payload={
                    "termination_request_ids": [str(item.id) for item in requests],
                    "reason_codes": [item.reason_code for item in requests],
                },
                now=now,
            )
            return True

    def complete_claimed_execution_termination(
        self,
        *,
        claim: ClaimedExecution,
        oracle_started: bool,
    ) -> bool:
        """Finish a safety stop as FAILED and atomically open recovery.

        System termination intentionally outranks a user cancellation request:
        it records a security/precondition failure rather than misclassifying
        the incident as an operator initiated cancellation.
        """

        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution, attempt = self._current_fenced_attempt(
                session,
                claim=claim,
                now=now,
                lock=True,
            )
            requests = self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=True,
            )
            if not requests:
                return False
            if execution.process_state not in {
                "STARTING",
                "RUNNING",
                "VERIFYING",
                "CANCEL_REQUESTED",
            }:
                self._fence_lost()
            target_lock = self._execution_lock(session, execution.id, lock=True)
            if (
                target_lock.state != "ACTIVE"
                or target_lock.attempt_id != attempt.id
                or target_lock.fence_epoch != claim.fence_epoch
            ):
                self._fence_lost()
            for request in requests:
                if request.status == "PENDING":
                    request.status = "ACKNOWLEDGED"
                    request.acknowledged_at = now
            primary = min(
                requests,
                key=lambda item: _TERMINATION_REASON_PRIORITY[item.reason_code],
            )
            failure_code = _TERMINATION_FAILURE_CODES[primary.reason_code]
            from_state = execution.process_state
            verification_inconclusive = (
                oracle_started
                or from_state == "VERIFYING"
                or execution.verification_state == "VERIFYING"
            )
            active_cancel = session.scalar(
                select(ExecutionCancelRequest)
                .where(
                    ExecutionCancelRequest.execution_id == execution.id,
                    ExecutionCancelRequest.status.in_(("PENDING", "ACKNOWLEDGED")),
                )
                .with_for_update()
            )
            if active_cancel is not None:
                active_cancel.status = "REJECTED"
                active_cancel.completed_at = now
            execution.process_state = "FAILED"
            execution.data_effect = "NONE" if from_state == "STARTING" else "UNKNOWN"
            execution.verification_state = (
                "INCONCLUSIVE" if verification_inconclusive else "NOT_STARTED"
            )
            execution.exit_code = (
                attempt.exit_code
                if attempt.exit_code is not None
                else execution.exit_code
            )
            execution.failure_code = failure_code
            execution.failure_message = (
                "A safety termination request stopped this execution; "
                "manual recovery is required."
            )
            if from_state != "STARTING":
                execution.summary_parse_status = "FAILED"
                execution.run_summary = None
            execution.finished_at = now
            execution.active_attempt_id = None
            execution.state_version += 1
            attempt.finished_at = now
            attempt.termination_reason = primary.reason_code
            target_lock.state = "RECOVERY_REQUIRED"
            for request in requests:
                request.status = "COMPLETED"
                request.acknowledged_at = request.acknowledged_at or now
                request.completed_at = now
            self._append_execution_event(
                session,
                execution,
                event_type="EXECUTION_SYSTEM_TERMINATED",
                from_state=from_state,
                to_state="FAILED",
                attempt_id=attempt.id,
                payload={
                    "data_effect": execution.data_effect,
                    "verification_state": execution.verification_state,
                    "failure_code": failure_code,
                    "primary_reason_code": primary.reason_code,
                    "termination_request_ids": [str(item.id) for item in requests],
                    "rejected_cancel_request_id": (
                        str(active_cancel.id) if active_cancel is not None else None
                    ),
                },
                now=now,
            )
            gate = ensure_recovery_gate(
                session,
                execution=execution,
                now=now,
            )
            if gate is None:
                raise RuntimeError("system terminated execution must create a recovery gate")
            return True

    def transition_claimed_execution(
        self,
        *,
        claim: ClaimedExecution,
        expected_state: str,
        new_state: str,
        data_effect: str,
        verification_state: str,
        exit_code: int | None = None,
        verification_report: dict[str, Any] | None = None,
        verification_evidence_hash: str | None = None,
        failure_code: str | None = None,
        failure_message: str | None = None,
        summary_parse_status: str | None = None,
        run_summary: dict[str, Any] | None = None,
    ) -> None:
        outcome = self._transition_claimed_execution_transaction(
            claim=claim,
            expected_state=expected_state,
            new_state=new_state,
            data_effect=data_effect,
            verification_state=verification_state,
            exit_code=exit_code,
            verification_report=verification_report,
            verification_evidence_hash=verification_evidence_hash,
            failure_code=failure_code,
            failure_message=failure_message,
            summary_parse_status=summary_parse_status,
            run_summary=run_summary,
        )
        if outcome == "TERMINATION_PENDING":
            raise ProblemException(
                status=409,
                code="TARGET_EXCLUSIVITY_NOT_ACTIVE",
                title="目标独占声明已失效",
                detail="Worker 必须终止当前 Attempt 并进入恢复门禁。",
            )
        # TERMINATION_CONVERGED means the final terminal transaction itself
        # safely changed a would-be success into FAILED and opened the gate.
        # It is intentionally not retried through the now-cleared fence.

    def _transition_claimed_execution_transaction(
        self,
        *,
        claim: ClaimedExecution,
        expected_state: str,
        new_state: str,
        data_effect: str,
        verification_state: str,
        exit_code: int | None = None,
        verification_report: dict[str, Any] | None = None,
        verification_evidence_hash: str | None = None,
        failure_code: str | None = None,
        failure_message: str | None = None,
        summary_parse_status: str | None = None,
        run_summary: dict[str, Any] | None = None,
    ) -> str | None:
        allowed = {
            "STARTING": {"RUNNING", "FAILED", "CANCEL_REQUESTED"},
            "RUNNING": {"VERIFYING", "FAILED", "TIMED_OUT", "CANCEL_REQUESTED"},
            "VERIFYING": {"SUCCEEDED", "FAILED", "CANCEL_REQUESTED"},
            "CANCEL_REQUESTED": {"CANCELED", "LOST"},
        }
        if new_state not in allowed.get(expected_state, set()):
            raise ValueError("illegal execution transition")
        target_exclusivity_broken = False
        termination_primary_reason: str | None = None
        termination_request_ids: list[str] = []
        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution, attempt = self._current_fenced_attempt(
                session,
                claim=claim,
                now=now,
                lock=True,
            )
            if execution.process_state != expected_state:
                raise ProblemException(
                    status=409,
                    code="FENCE_STATE_CONFLICT",
                    title="Execution 状态已变化",
                    detail="旧 Worker 不得覆盖当前状态。",
                )
            active_terminations = self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=True,
            )
            if active_terminations and not (
                new_state == "SUCCEEDED"
                and all(
                    item.reason_code
                    in {"TARGET_EXCLUSIVITY_REVOKED", "TARGET_EXCLUSIVITY_EXPIRED"}
                    for item in active_terminations
                )
            ):
                raise ProblemException(
                    status=409,
                    code="WORK_TERMINATION_PENDING",
                    title="Execution 已收到安全终止请求",
                    detail="Worker 必须先收敛安全终止，不能推进状态。",
                )
            target_lock = self._execution_lock(session, execution.id, lock=True)
            if (
                target_lock.state != "ACTIVE"
                or target_lock.attempt_id != attempt.id
                or target_lock.fence_epoch != claim.fence_epoch
            ):
                self._fence_lost()
            confirmation_valid_until = _parse_timestamp(
                execution.target_exclusivity_confirmation["valid_until"]
            )
            # This is the final wall-clock check for every non-success state
            # transition.  Returning from inside the transaction commits the
            # newly durable stop; the public wrapper raises only after that
            # commit so the Worker can converge it under the same fence.
            expiration_termination = self._ensure_target_exclusivity_termination(
                session,
                execution=execution,
                now=now,
                attempt_id=attempt.id,
            )
            if expiration_termination is not None and new_state != "SUCCEEDED":
                return "TERMINATION_PENDING"
            parsed_run_summary = (
                RunSummary.model_validate(run_summary)
                if run_summary is not None
                else None
            )
            active_cancel = None
            if new_state in _TERMINAL_STATES:
                active_cancel = session.scalar(
                    select(ExecutionCancelRequest)
                    .where(
                        ExecutionCancelRequest.execution_id == execution.id,
                        ExecutionCancelRequest.status.in_(
                            ("PENDING", "ACKNOWLEDGED")
                        ),
                    )
                    .with_for_update()
                )
                if active_cancel is not None and new_state not in {
                    "CANCELED",
                    "LOST",
                }:
                    # request_cancel locks the same Execution row before it
                    # persists the request. Worker-authored terminal outcomes
                    # therefore have one database ordering with cancellation:
                    # either the terminal state commits first and the API
                    # rejects cancellation, or the accepted cancel is visible
                    # here and the Worker must converge through CANCELED.
                    raise ProblemException(
                        status=409,
                        code="EXECUTION_CANCEL_PENDING",
                        title="Execution 已有待处理取消请求",
                        detail="Worker 必须先完成取消，不能提交其他终态。",
                    )
            if summary_parse_status is not None:
                if summary_parse_status not in {"PENDING", "SUCCEEDED", "FAILED"}:
                    raise ValueError("invalid summary_parse_status")
                if summary_parse_status == "SUCCEEDED" and parsed_run_summary is None:
                    raise ValueError("parsed run summary is required")
                if summary_parse_status != "SUCCEEDED" and parsed_run_summary is not None:
                    raise ValueError("run summary requires successful parsing")
                if (
                    parsed_run_summary is not None
                    and parsed_run_summary.records_failed != 0
                ):
                    raise ValueError("V1 dirty-data tolerance is zero")
                execution.summary_parse_status = summary_parse_status
                execution.run_summary = (
                    parsed_run_summary.model_dump(mode="json")
                    if parsed_run_summary is not None
                    else None
                )
            if new_state == "RUNNING":
                if (
                    data_effect != "NONE"
                    or verification_state != "NOT_STARTED"
                    or execution.target_exclusivity_status != "ACTIVE"
                    or execution.target_exclusivity_revoked_at is not None
                    or execution.target_exclusivity_revocation_reason is not None
                    or confirmation_valid_until <= now
                    or execution.runtime_snapshot is None
                    or execution.target_empty_evidence is None
                    or execution.source_connection_evidence_id is None
                    or execution.target_connection_evidence_id is None
                ):
                    raise ValueError(
                        "RUNNING requires completed fenced preflight with NONE/NOT_STARTED"
                    )
                execution.started_at = execution.started_at or now
                attempt.started_at = attempt.started_at or now
            elif new_state == "VERIFYING":
                if exit_code != 0 or verification_state not in {
                    "NOT_STARTED",
                    "VERIFYING",
                }:
                    raise ValueError("VERIFYING requires DataX exit 0")
                execution.datax_finished_at = now
            elif new_state == "SUCCEEDED":
                if (
                    execution.target_exclusivity_status != "ACTIVE"
                    or execution.target_exclusivity_revoked_at is not None
                    or execution.target_exclusivity_revocation_reason is not None
                    or confirmation_valid_until <= now
                ):
                    target_exclusivity_broken = True
                    self._ensure_target_exclusivity_termination(
                        session,
                        execution=execution,
                        now=now,
                        attempt_id=attempt.id,
                    )
                    # The terminal row lock is the final ordering point with a
                    # concurrent revoke or wall-clock expiry. Persist the safe
                    # terminal result in this transaction, then raise the
                    # stable code after commit so the Worker opens the gate.
                    new_state = "FAILED"
                    data_effect = "UNKNOWN"
                    verification_state = "INCONCLUSIVE"
                    verification_report = None
                    verification_evidence_hash = None
                    failure_code = "TARGET_EXCLUSIVITY_BROKEN"
                    failure_message = (
                        "Target exclusivity was revoked or expired during verification."
                    )
                    target_lock.state = "RECOVERY_REQUIRED"
                else:
                    if (
                        data_effect != "CONFIRMED"
                        or verification_state != "PASSED"
                        or exit_code != 0
                        or not verification_report
                        or verification_evidence_hash is None
                        or execution.summary_parse_status
                        not in {"SUCCEEDED", "FAILED"}
                    ):
                        raise ValueError(
                            "SUCCEEDED requires confirmed independent verification"
                        )
                    summary = self._validate_successful_verification(
                        execution=execution,
                        target_lock=target_lock,
                        version=self._required_job_version(
                            session,
                            execution.job_version_id,
                        ),
                        report=verification_report,
                        verification_evidence_hash=verification_evidence_hash,
                    )
                    if (
                        summary.target_snapshot_finished_at is None
                        or summary.target_snapshot_finished_at
                        > confirmation_valid_until
                    ):
                        raise ValueError(
                            "target snapshot must finish within exclusivity window"
                        )
                    target_lock.state = "RELEASED"
                    target_lock.released_at = now
            elif new_state in _TERMINAL_STATES:
                if expected_state == "RUNNING" and data_effect == "NONE":
                    raise ValueError("a started DataX process cannot finish with NONE")
                if new_state in {"FAILED", "TIMED_OUT", "CANCELED", "LOST"}:
                    target_lock.state = "RECOVERY_REQUIRED"
                if new_state == "CANCELED" and active_cancel is None:
                    raise ValueError("CANCELED requires an accepted cancel request")
                if active_cancel is not None and new_state in {"CANCELED", "LOST"}:
                    # CANCELED consumes its request in this same transaction;
                    # LOST is the reconciler safety outcome and also closes an
                    # accepted request so no active request can be orphaned.
                    active_cancel.status = "COMPLETED"
                    active_cancel.acknowledged_at = active_cancel.acknowledged_at or now
                    active_cancel.completed_at = now
            execution.process_state = new_state
            execution.data_effect = data_effect
            execution.verification_state = verification_state
            execution.exit_code = exit_code
            execution.verification_report = verification_report
            execution.verification_evidence_hash = verification_evidence_hash
            execution.failure_code = failure_code
            execution.failure_message = (
                failure_message[:2000] if failure_message else None
            )
            execution.state_version += 1
            if new_state in _TERMINAL_STATES:
                execution.finished_at = now
                attempt.finished_at = now
                attempt.exit_code = exit_code
                execution.active_attempt_id = None
                if target_exclusivity_broken:
                    terminations = self._active_work_termination_requests(
                        session,
                        work_kind="EXECUTION",
                        work_id=execution.id,
                        lock=True,
                    )
                    if not terminations:
                        raise RuntimeError(
                            "target exclusivity failure must retain a termination request"
                        )
                    primary = min(
                        terminations,
                        key=lambda item: _TERMINATION_REASON_PRIORITY[item.reason_code],
                    )
                    termination_primary_reason = primary.reason_code
                    termination_request_ids = [str(item.id) for item in terminations]
                    for termination in terminations:
                        termination.status = "COMPLETED"
                        termination.acknowledged_at = termination.acknowledged_at or now
                        termination.completed_at = now
                attempt.termination_reason = termination_primary_reason or new_state
            self._append_execution_event(
                session,
                execution,
                event_type=(
                    "EXECUTION_SYSTEM_TERMINATED"
                    if target_exclusivity_broken
                    else f"EXECUTION_{new_state}"
                ),
                from_state=expected_state,
                to_state=new_state,
                attempt_id=attempt.id,
                payload={
                    "data_effect": data_effect,
                    "verification_state": verification_state,
                    "failure_code": failure_code,
                    "primary_reason_code": termination_primary_reason,
                    "termination_request_ids": termination_request_ids,
                },
                now=now,
            )
            if new_state in {"FAILED", "TIMED_OUT", "CANCELED", "LOST"}:
                gate = ensure_recovery_gate(
                    session,
                    execution=execution,
                    now=now,
                )
                if gate is None:
                    raise RuntimeError(
                        "claimed recovery-required terminal state must create a gate"
                    )
        if target_exclusivity_broken:
            return "TERMINATION_CONVERGED"
        return None

    def assert_claimed_verification_exclusivity(
        self,
        *,
        claim: ClaimedExecution,
    ) -> None:
        """Check the external target exclusivity promise at an oracle boundary.

        The oracle invokes this after every bounded database or digest-spool
        batch. Expiry is persisted using database time before the stable error
        is raised, so the Worker can converge the active Attempt through the
        normal FAILED/UNKNOWN/INCONCLUSIVE recovery-gated path.
        """

        broken = False
        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution, attempt = self._current_fenced_attempt(
                session,
                claim=claim,
                now=now,
                lock=True,
            )
            if execution.process_state != "VERIFYING":
                raise ProblemException(
                    status=409,
                    code="FENCE_STATE_CONFLICT",
                    title="Execution 状态已变化",
                    detail="旧 Worker 不得继续当前核验。",
                )
            if self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=True,
            ):
                raise ProblemException(
                    status=409,
                    code="WORK_TERMINATION_PENDING",
                    title="Execution 已收到安全终止请求",
                    detail="Oracle 不得在安全终止待处理时启动。",
                )
            target_lock = self._execution_lock(session, execution.id, lock=True)
            if (
                target_lock.state != "ACTIVE"
                or target_lock.attempt_id != attempt.id
                or target_lock.fence_epoch != claim.fence_epoch
            ):
                self._fence_lost()
            termination = self._ensure_target_exclusivity_termination(
                session,
                execution=execution,
                now=now,
                attempt_id=attempt.id,
            )
            broken = termination is not None
        if broken:
            raise ProblemException(
                status=409,
                code="TARGET_EXCLUSIVITY_BROKEN",
                title="目标独占声明已失效",
                detail="Oracle 已中断；当前 Execution 必须进入恢复门禁。",
            )

    def mark_claimed_oracle_started(
        self,
        *,
        claim: ClaimedExecution,
    ) -> None:
        if self._mark_claimed_oracle_started_transaction(claim=claim):
            raise ProblemException(
                status=409,
                code="WORK_TERMINATION_PENDING",
                title="Execution 已收到安全终止请求",
                detail="Oracle 不得在安全终止待处理时启动。",
            )

    def _mark_claimed_oracle_started_transaction(
        self,
        *,
        claim: ClaimedExecution,
    ) -> bool:
        """Record the exact boundary where independent database reads may begin."""

        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution, attempt = self._current_fenced_attempt(
                session,
                claim=claim,
                now=now,
                lock=True,
            )
            if (
                execution.process_state != "VERIFYING"
                or execution.verification_state != "NOT_STARTED"
                or execution.exit_code != 0
            ):
                raise ProblemException(
                    status=409,
                    code="ORACLE_START_STATE_CONFLICT",
                    title="Oracle 启动状态冲突",
                    detail="只有 DataX 正常退出且尚未启动核验的 Execution 才能启动 Oracle。",
                )
            if self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=True,
            ):
                return True
            target_lock = self._execution_lock(session, execution.id, lock=True)
            if (
                target_lock.state != "ACTIVE"
                or target_lock.attempt_id != attempt.id
                or target_lock.fence_epoch != claim.fence_epoch
            ):
                self._fence_lost()
            if self._ensure_target_exclusivity_termination(
                session,
                execution=execution,
                now=now,
                attempt_id=attempt.id,
            ) is not None:
                return True
            execution.verification_state = "VERIFYING"
            execution.state_version += 1
            self._append_execution_event(
                session,
                execution,
                event_type="EXECUTION_ORACLE_STARTED",
                from_state="VERIFYING",
                to_state="VERIFYING",
                attempt_id=attempt.id,
                payload={
                    "data_effect": execution.data_effect,
                    "verification_state": "VERIFYING",
                },
                now=now,
            )
        return False

    def reconcile_unclaimed_cancel(self, *, execution_id: UUID) -> bool:
        """Reconciler-only path for QUEUED cancellation.

        It deliberately creates no Attempt/fence/recovery gate.
        """

        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution = session.scalar(
                select(Execution).where(Execution.id == execution_id).with_for_update()
            )
            if (
                execution is None
                or execution.process_state != "QUEUED"
                or execution.active_attempt_id is not None
            ):
                return False
            if self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=True,
            ):
                # A durable safety stop wins over a user cancel.  The
                # reconciler will preserve its exact cause and release the
                # reservation through reconcile_unclaimed_work_termination.
                return False
            cancel = session.scalar(
                select(ExecutionCancelRequest)
                .where(
                    ExecutionCancelRequest.execution_id == execution.id,
                    ExecutionCancelRequest.status == "PENDING",
                )
                .with_for_update()
            )
            if cancel is None:
                return False
            target_lock = self._execution_lock(session, execution.id, lock=True)
            if target_lock.state != "RESERVED" or target_lock.attempt_id is not None:
                return False
            self._append_execution_event(
                session,
                execution,
                event_type="EXECUTION_CANCEL_REQUEST_ACKNOWLEDGED",
                from_state="QUEUED",
                to_state="CANCEL_REQUESTED",
                payload={},
                now=now,
            )
            self._append_execution_event(
                session,
                execution,
                event_type="EXECUTION_CANCELED_UNCLAIMED",
                from_state="CANCEL_REQUESTED",
                to_state="CANCELED",
                payload={"target_lock_state": "RELEASED"},
                now=now,
            )
            execution.process_state = "CANCELED"
            execution.data_effect = "NONE"
            execution.verification_state = "NOT_STARTED"
            execution.finished_at = now
            execution.state_version += 2
            target_lock.state = "RELEASED"
            target_lock.released_at = now
            cancel.status = "COMPLETED"
            cancel.acknowledged_at = now
            cancel.completed_at = now
            return True

    def reconcile_unclaimed_target_exclusivity(
        self,
        *,
        execution_id: UUID,
    ) -> bool:
        """Release a never-activated reservation after revoke or expiry."""

        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution = session.scalar(
                select(Execution).where(Execution.id == execution_id).with_for_update()
            )
            if (
                execution is None
                or execution.process_state != "QUEUED"
                or execution.active_attempt_id is not None
            ):
                return False
            target_lock = self._execution_lock(session, execution.id, lock=True)
            if target_lock.state != "RESERVED" or target_lock.attempt_id is not None:
                return False
            termination = self._ensure_target_exclusivity_termination(
                session,
                execution=execution,
                now=now,
                attempt_id=None,
            )
            if termination is None:
                return False
            self._append_execution_event(
                session,
                execution,
                event_type="EXECUTION_CANCELED_UNCLAIMED_PRECONDITION",
                from_state="QUEUED",
                to_state="CANCELED",
                payload={
                    "target_exclusivity_status": (
                        execution.target_exclusivity_status
                    ),
                    "target_lock_state": "RELEASED",
                },
                now=now,
            )
            execution.process_state = "CANCELED"
            execution.data_effect = "NONE"
            execution.verification_state = "NOT_STARTED"
            execution.queue_eligibility_state = "BLOCKED"
            execution.queue_block_reason = (
                f"TARGET_EXCLUSIVITY_{execution.target_exclusivity_status}"
            )
            execution.queue_state_changed_at = now
            execution.failure_code = execution.queue_block_reason
            execution.finished_at = now
            execution.state_version += 1
            target_lock.state = "RELEASED"
            target_lock.released_at = now
            requests = self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=True,
            )
            for request in requests:
                request.status = "COMPLETED"
                request.acknowledged_at = request.acknowledged_at or now
                request.completed_at = now
            return True

    def reconcile_target_exclusivity_expiry(self, *, execution_id: UUID) -> bool:
        """Persist an elapsed target window even when no claim is attempted.

        Expiry is wall-clock state, not a side effect of queue selection.  The
        Worker heartbeat scanner calls this so an idle queue cannot continue
        displaying an expired declaration as ACTIVE indefinitely.
        """

        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution = session.scalar(
                select(Execution).where(Execution.id == execution_id).with_for_update()
            )
            if execution is None or execution.process_state in _TERMINAL_STATES:
                return False
            return (
                self._ensure_target_exclusivity_termination(
                    session,
                    execution=execution,
                    now=now,
                    attempt_id=execution.active_attempt_id,
                )
                is not None
            )

    def reconcile_unclaimed_work_termination(self, *, execution_id: UUID) -> bool:
        """Worker-only convergence for a queued safety termination request.

        No Attempt has existed, so this releases the reservation without
        manufacturing a recovery gate.  The authoritative reason is retained
        in both the Execution failure code and the completed request rows.
        """

        with self.sessions.begin() as session:
            now = self._database_now(session)
            execution = session.scalar(
                select(Execution).where(Execution.id == execution_id).with_for_update()
            )
            if (
                execution is None
                or execution.process_state != "QUEUED"
                or execution.active_attempt_id is not None
            ):
                return False
            requests = self._active_work_termination_requests(
                session,
                work_kind="EXECUTION",
                work_id=execution.id,
                lock=True,
            )
            if not requests:
                return False
            target_lock = self._execution_lock(session, execution.id, lock=True)
            if target_lock.state != "RESERVED" or target_lock.attempt_id is not None:
                return False
            primary = min(
                requests,
                key=lambda item: _TERMINATION_REASON_PRIORITY[item.reason_code],
            )
            active_cancel = session.scalar(
                select(ExecutionCancelRequest)
                .where(
                    ExecutionCancelRequest.execution_id == execution.id,
                    ExecutionCancelRequest.status.in_(("PENDING", "ACKNOWLEDGED")),
                )
                .with_for_update()
            )
            if active_cancel is not None:
                active_cancel.status = "REJECTED"
                active_cancel.completed_at = now
            execution.process_state = "CANCELED"
            execution.data_effect = "NONE"
            execution.verification_state = "NOT_STARTED"
            execution.queue_eligibility_state = "BLOCKED"
            execution.queue_block_reason = _TERMINATION_FAILURE_CODES[primary.reason_code]
            execution.queue_state_changed_at = now
            execution.failure_code = _TERMINATION_FAILURE_CODES[primary.reason_code]
            execution.failure_message = "A safety termination request prevented execution."
            execution.finished_at = now
            execution.state_version += 1
            target_lock.state = "RELEASED"
            target_lock.released_at = now
            for request in requests:
                request.status = "COMPLETED"
                request.acknowledged_at = request.acknowledged_at or now
                request.completed_at = now
            self._append_execution_event(
                session,
                execution,
                event_type="EXECUTION_SYSTEM_TERMINATED_UNCLAIMED",
                from_state="QUEUED",
                to_state="CANCELED",
                payload={
                    "failure_code": execution.failure_code,
                    "primary_reason_code": primary.reason_code,
                    "termination_request_ids": [str(item.id) for item in requests],
                    "target_lock_state": "RELEASED",
                    "rejected_cancel_request_id": (
                        str(active_cancel.id) if active_cancel is not None else None
                    ),
                },
                now=now,
            )
            return True

    # ------------------------------------------------------------------
    # Trusted internal registration helpers for the future credential and
    # network-probe slices. They never accept or persist a password.
    # ------------------------------------------------------------------
    def register_verified_physical_identity(
        self,
        *,
        principal: Principal,
        engine: str,
        normalized_engine_identity: str,
        verification_evidence: dict[str, Any],
        audit: AuditContext,
    ) -> PhysicalEndpointIdentity:
        self._require_admin(principal)
        if engine not in {"MYSQL_8", "POSTGRESQL_15"}:
            raise ValueError("unsupported engine")
        if not normalized_engine_identity or len(normalized_engine_identity) > 512:
            raise ValueError("engine identity is invalid")
        _reject_secret_material(
            verification_evidence,
            path="verification_evidence",
        )
        identity_scheme = (
            "MYSQL_SERVER_UUID"
            if engine == "MYSQL_8"
            else "POSTGRES_SYSTEM_IDENTIFIER"
        )
        server_identity_hash = hashlib.sha256(
            (
                "DXPHYSICALENDPOINTv1\n"
                f"{str(principal.organization_id).lower()}\n"
                f"{engine}\n"
                f"{identity_scheme}\n"
                f"{normalized_engine_identity}"
            ).encode()
        ).hexdigest()
        evidence_hash = _domain_hash(
            "DXPHYSICALENDPOINTEVIDENCEv1",
            verification_evidence,
        )
        now = utc_now()
        with self.sessions.begin() as session:
            organization = self._lock_organization(session, principal.organization_id)
            existing = session.scalar(
                select(PhysicalEndpointIdentity).where(
                    PhysicalEndpointIdentity.organization_id
                    == principal.organization_id,
                    PhysicalEndpointIdentity.engine == engine,
                    PhysicalEndpointIdentity.identity_scheme == identity_scheme,
                    PhysicalEndpointIdentity.server_identity_hash
                    == server_identity_hash,
                )
            )
            if existing is not None:
                return existing
            identity = PhysicalEndpointIdentity(
                id=uuid4(),
                organization_id=principal.organization_id,
                engine=engine,
                identity_scheme=identity_scheme,
                server_identity_hash=server_identity_hash,
                verification_evidence=verification_evidence,
                verification_evidence_hash=evidence_hash,
                created_by=principal.user_id,
                created_at=now,
            )
            session.add(identity)
            self._append_audit(
                session,
                organization=organization,
                project_id=None,
                action="PHYSICAL_ENDPOINT_IDENTITY_BOUND",
                actor_id=principal.user_id,
                target_type="PHYSICAL_ENDPOINT_IDENTITY",
                target_id=identity.id,
                target_name=None,
                changed_fields=[
                    "engine",
                    "identity_scheme",
                    "server_identity_hash",
                    "verification_evidence_hash",
                ],
                audit=audit,
            )
            return identity

    def register_nonsecret_datasource(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        name: str,
        description: str | None,
        endpoint_policy_revision_id: UUID,
        physical_endpoint_identity_id: UUID,
        engine: str,
        host: str,
        port: int,
        database_name: str,
        default_schema: str,
        username: str,
        ssl_mode: str,
        connection_options: dict[str, Any] | None,
        audit: AuditContext,
    ) -> Datasource:
        """Persist only a verified non-secret connection revision.

        The returned Datasource remains DISABLED until the credential service
        atomically installs an ACTIVE CredentialSecret reference.
        """

        self._require_admin(principal)
        if not name.strip() or len(name.strip()) > 128:
            raise ValueError("datasource name is invalid")
        if engine not in {"MYSQL_8", "POSTGRESQL_15"}:
            raise ValueError("unsupported engine")
        if not 1 <= port <= 65535:
            raise ValueError("port is invalid")
        if ssl_mode not in {"DISABLE", "REQUIRE", "VERIFY_CA", "VERIFY_FULL"}:
            raise ValueError("ssl_mode is invalid")
        _validate_connection_identifier(database_name, "database_name")
        _validate_connection_identifier(default_schema, "default_schema")
        _validate_connection_identifier(username, "username")
        if engine == "MYSQL_8" and default_schema != database_name:
            raise ValueError("MySQL default_schema must equal database_name")
        options = connection_options or {}
        _reject_connection_option_secrets(options)
        now = utc_now()
        with self.sessions.begin() as session:
            project = self._visible_project(session, principal, project_id, lock=True)
            if project.status != "ACTIVE":
                raise ProblemException(
                    status=409,
                    code="PROJECT_ARCHIVED",
                    title="项目已归档",
                    detail="归档项目不能新增数据源。",
                )
            organization = self._lock_organization(session, principal.organization_id)
            policy_revision = session.get(
                EndpointPolicyRevision,
                endpoint_policy_revision_id,
            )
            identity = session.get(
                PhysicalEndpointIdentity,
                physical_endpoint_identity_id,
            )
            if (
                policy_revision is None
                or identity is None
                or identity.organization_id != principal.organization_id
                or policy_revision.engine != engine
                or identity.engine != engine
            ):
                raise ProblemException(
                    status=422,
                    code="ENDPOINT_IDENTITY_MISMATCH",
                    title="端点策略与物理身份不匹配",
                    detail="必须先由受控探针验证同一引擎的不可变端点身份。",
                )
            policy = session.get(EndpointPolicy, policy_revision.endpoint_policy_id)
            if (
                policy is None
                or policy.status != "ACTIVE"
                or policy.current_revision_id != policy_revision.id
            ):
                raise ProblemException(
                    status=409,
                    code="ENDPOINT_POLICY_NOT_ACTIVE",
                    title="端点策略不再有效",
                    detail="只能使用当前 ACTIVE EndpointPolicyRevision。",
                )
            if not _host_matches_policy(host, policy_revision):
                raise ProblemException(
                    status=422,
                    code="ENDPOINT_POLICY_DENIED",
                    title="连接端点不在允许范围",
                    detail="host 必须精确匹配 EndpointPolicyRevision。",
                )
            if port not in policy_revision.allowed_ports:
                raise ProblemException(
                    status=422,
                    code="ENDPOINT_POLICY_DENIED",
                    title="连接端口不在允许范围",
                    detail="port 必须包含在 EndpointPolicyRevision.allowed_ports。",
                )
            if policy_revision.tls_required and ssl_mode == "DISABLE":
                raise ProblemException(
                    status=422,
                    code="ENDPOINT_POLICY_DENIED",
                    title="端点策略要求 TLS",
                    detail="不能禁用数据库 TLS。",
                )
            existing = session.scalar(
                select(Datasource.id).where(
                    Datasource.project_id == project_id,
                    func.lower(Datasource.name) == name.strip().casefold(),
                    Datasource.status != "DELETED",
                )
            )
            if existing is not None:
                raise ProblemException(
                    status=409,
                    code="DATASOURCE_NAME_CONFLICT",
                    title="数据源名称已存在",
                    detail="请使用新的数据源名称。",
                )
            config = {
                "endpoint_policy_revision_id": str(policy_revision.id),
                "physical_endpoint_identity_id": str(identity.id),
                "engine": engine,
                "host": host,
                "port": port,
                "database_name": database_name,
                "default_schema": default_schema,
                "username": username,
                "ssl_mode": ssl_mode,
                "connection_options": options,
            }
            datasource = Datasource(
                id=uuid4(),
                project_id=project_id,
                name=name.strip(),
                description=_clean_optional(description),
                current_revision_id=None,
                current_secret_id=None,
                status="DISABLED",
                created_by=principal.user_id,
                created_at=now,
                updated_at=now,
                row_version=1,
            )
            session.add(datasource)
            session.flush()
            revision = DatasourceRevision(
                id=uuid4(),
                datasource_id=datasource.id,
                revision_no=1,
                endpoint_policy_revision_id=policy_revision.id,
                physical_endpoint_identity_id=identity.id,
                engine=engine,
                host=host,
                port=port,
                database_name=database_name,
                default_schema=default_schema,
                username=username,
                ssl_mode=ssl_mode,
                connection_options=options,
                config_hash=_domain_hash("DXDATASOURCEREVISIONv1", config),
                created_by=principal.user_id,
                created_at=now,
            )
            session.add(revision)
            session.flush()
            datasource.current_revision_id = revision.id
            self._append_audit(
                session,
                organization=organization,
                project_id=project_id,
                action="DATASOURCE_CREATED",
                actor_id=principal.user_id,
                target_type="DATASOURCE",
                target_id=datasource.id,
                target_name=datasource.name,
                changed_fields=[
                    "name",
                    "description",
                    "current_revision_id",
                    "status",
                ],
                audit=audit,
                metadata={
                    "revision_id": str(revision.id),
                    "config_hash": revision.config_hash,
                    "credential_configured": False,
                },
            )
            return datasource

    # ------------------------------------------------------------------
    # Append-only audit reads.
    # ------------------------------------------------------------------
    def list_project_audit_events(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        limit: int,
        cursor: str | None,
        action: str | None,
        outcome: str | None,
        actor_id: UUID | None,
        window_from: datetime | None,
        window_to: datetime | None,
    ) -> AuditPage:
        with self.sessions() as session:
            self._visible_project(session, principal, project_id)
            return self._list_audit_events(
                session,
                principal=principal,
                project_id=project_id,
                limit=limit,
                cursor=cursor,
                action=action,
                outcome=outcome,
                actor_id=actor_id,
                window_from=window_from,
                window_to=window_to,
                scope_prefix=f"GET /projects/{project_id}/audit-events",
            )

    def list_organization_audit_events(
        self,
        *,
        principal: Principal,
        project_id: UUID | None,
        limit: int,
        cursor: str | None,
        action: str | None,
        outcome: str | None,
        actor_id: UUID | None,
        window_from: datetime | None,
        window_to: datetime | None,
    ) -> AuditPage:
        self._require_admin(principal)
        with self.sessions() as session:
            if project_id is not None:
                self._visible_project(session, principal, project_id)
            return self._list_audit_events(
                session,
                principal=principal,
                project_id=project_id,
                limit=limit,
                cursor=cursor,
                action=action,
                outcome=outcome,
                actor_id=actor_id,
                window_from=window_from,
                window_to=window_to,
                scope_prefix="GET /audit-events",
            )

    def _list_audit_events(
        self,
        session: Session,
        *,
        principal: Principal,
        project_id: UUID | None,
        limit: int,
        cursor: str | None,
        action: str | None,
        outcome: str | None,
        actor_id: UUID | None,
        window_from: datetime | None,
        window_to: datetime | None,
        scope_prefix: str,
    ) -> AuditPage:
        normalized_from = (
            ensure_aware(window_from) if window_from is not None else None
        )
        normalized_to = (
            ensure_aware(window_to) if window_to is not None else None
        )
        if (
            normalized_from is not None
            and normalized_to is not None
            and normalized_from >= normalized_to
        ):
            raise ProblemException(
                status=422,
                code="VALIDATION_ERROR",
                title="审计时间范围无效",
                detail="from 必须早于 to。",
            )
        filter_document = {
            "project_id": str(project_id) if project_id else None,
            "action": action,
            "outcome": outcome,
            "actor_id": str(actor_id) if actor_id else None,
            "from": _rfc3339(normalized_from) if normalized_from else None,
            "to": _rfc3339(normalized_to) if normalized_to else None,
        }
        cursor_scope = (
            f"{scope_prefix}:"
            f"{_domain_hash('DXAUDITFILTERv1', filter_document)}"
        )
        statement = select(AuditEvent).where(
            AuditEvent.organization_id == principal.organization_id
        )
        if project_id is not None:
            statement = statement.where(AuditEvent.project_id == project_id)
        if action is not None:
            statement = statement.where(
                AuditEvent.event_json["action"].as_string() == action
            )
        if outcome is not None:
            statement = statement.where(
                AuditEvent.event_json["outcome"].as_string() == outcome
            )
        if actor_id is not None:
            statement = statement.where(
                AuditEvent.event_json["actor"]["user_id"].as_string()
                == str(actor_id)
            )
        if normalized_from is not None:
            statement = statement.where(
                AuditEvent.occurred_at >= normalized_from
            )
        if normalized_to is not None:
            statement = statement.where(
                AuditEvent.occurred_at < normalized_to
            )
        if cursor is not None:
            occurred_at, event_id = self._decode_cursor(
                cursor,
                actor_id=principal.user_id,
                scope=cursor_scope,
            )
            statement = statement.where(
                or_(
                    AuditEvent.occurred_at < occurred_at,
                    and_(
                        AuditEvent.occurred_at == occurred_at,
                        AuditEvent.id < event_id,
                    ),
                )
            )
        rows = list(
            session.scalars(
                statement.order_by(
                    AuditEvent.occurred_at.desc(),
                    AuditEvent.id.desc(),
                ).limit(limit + 1)
            )
        )
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = self._encode_cursor(
                actor_id=principal.user_id,
                scope=cursor_scope,
                created_at=ensure_aware(rows[-1].occurred_at),
                resource_id=rows[-1].id,
            )
        return AuditPage(
            items=[dict(row.event_json) for row in rows],
            next_cursor=next_cursor,
            has_more=has_more,
        )

    # ------------------------------------------------------------------
    # Shared authorization, consistency and serialization helpers.
    # ------------------------------------------------------------------
    def _visible_project(
        self,
        session: Session,
        principal: Principal,
        project_id: UUID,
        *,
        lock: bool = False,
    ) -> Project:
        statement = select(Project).where(
            Project.id == project_id,
            Project.organization_id == principal.organization_id,
        )
        if (
            not principal.is_admin
            and project_id not in self._visible_project_ids(principal)
        ):
            self._not_found()
        if lock:
            statement = statement.with_for_update()
        project = session.scalar(statement)
        if project is None:
            self._not_found()
        return project

    def _visible_job(
        self,
        session: Session,
        principal: Principal,
        job_id: UUID,
        *,
        lock: bool = False,
    ) -> SyncJob:
        statement = select(SyncJob).where(SyncJob.id == job_id)
        if lock:
            statement = statement.with_for_update()
        job = session.scalar(statement)
        if job is None:
            self._not_found()
        self._visible_project(session, principal, job.project_id)
        return job

    def _visible_execution(
        self,
        session: Session,
        principal: Principal,
        execution_id: UUID,
        *,
        lock: bool = False,
    ) -> Execution:
        statement = select(Execution).where(Execution.id == execution_id)
        if lock:
            statement = statement.with_for_update()
        execution = session.scalar(statement)
        if execution is None:
            self._not_found()
        self._visible_project(session, principal, execution.project_id)
        return execution

    def _visible_project_ids(self, principal: Principal) -> set[UUID]:
        return {
            assignment.scope_id
            for assignment in principal.role_assignments
            if assignment.scope_type == ScopeType.PROJECT
            and any(
                role in {Role.DEVELOPER, Role.OPERATOR, Role.VIEWER}
                for role in assignment.roles
            )
        }

    def _require_admin(self, principal: Principal) -> None:
        if not principal.is_admin or principal.must_change_password:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限执行此操作",
                detail="需要有效的组织级 Admin 权限并完成首次改密。",
            )

    def _require_project_role(
        self,
        principal: Principal,
        project_id: UUID,
        roles: set[Role],
    ) -> None:
        if principal.must_change_password:
            raise ProblemException(
                status=403,
                code="PASSWORD_CHANGE_REQUIRED",
                title="必须先修改临时密码",
                detail="完成本人密码修改后才能访问业务接口。",
            )
        if principal.is_admin:
            return
        if any(
            assignment.scope_type == ScopeType.PROJECT
            and assignment.scope_id == project_id
            and any(role in roles for role in assignment.roles)
            for assignment in principal.role_assignments
        ):
            return
        raise ProblemException(
            status=403,
            code="FORBIDDEN",
            title="无权限执行此操作",
            detail="当前项目角色不允许该操作。",
        )

    def _require_project_role_for_job(
        self,
        principal: Principal,
        job_id: UUID,
        roles: set[Role],
    ) -> None:
        with self.sessions() as session:
            job = self._visible_job(session, principal, job_id)
            self._require_project_role(principal, job.project_id, roles)

    def _lock_organization(
        self,
        session: Session,
        organization_id: UUID,
    ) -> Organization:
        organization = session.scalar(
            select(Organization)
            .where(Organization.id == organization_id)
            .with_for_update()
        )
        if organization is None or organization.status != "ACTIVE":
            self._not_found()
        return organization

    def _require_accepting_new_executions(self, session: Session) -> None:
        control = session.scalar(
            select(SystemControl).where(SystemControl.singleton_id == 1).with_for_update()
        )
        if control is None or control.draining:
            raise ProblemException(
                status=503,
                code="SERVICE_DRAINING",
                title="服务正在对账或停止",
                detail="Worker 完成启动对账前不接受新的 Execution。",
                retryable=True,
            )

    def _check_job_spec_resources(
        self,
        session: Session,
        project_id: UUID,
        spec: JobSpecV1,
        *,
        lock_datasources: bool = False,
    ) -> None:
        source_revision = session.get(
            DatasourceRevision,
            spec.source.datasource_revision_id,
        )
        target_revision = session.get(
            DatasourceRevision,
            spec.target.datasource_revision_id,
        )
        if source_revision is None or target_revision is None:
            self._not_found()
        if lock_datasources:
            datasource_ids = {
                source_revision.datasource_id,
                target_revision.datasource_id,
            }
            datasources = {
                datasource.id: datasource
                for datasource in session.scalars(
                    select(Datasource)
                    .where(Datasource.id.in_(datasource_ids))
                    .order_by(Datasource.id)
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
            }
            source = datasources.get(source_revision.datasource_id)
            target = datasources.get(target_revision.datasource_id)
        else:
            source = session.get(Datasource, source_revision.datasource_id)
            target = session.get(Datasource, target_revision.datasource_id)
        if (
            source is None
            or target is None
            or source.id != spec.source.datasource_id
            or target.id != spec.target.datasource_id
            or source.project_id != project_id
            or target.project_id != project_id
        ):
            self._not_found()
        if source.status != "ACTIVE" or target.status != "ACTIVE":
            raise ProblemException(
                status=409,
                code="DATASOURCE_DISABLED",
                title="数据源当前不可用",
                detail="源和目标数据源都必须为 ACTIVE。",
            )
        expected_source_plugin = {
            "MYSQL_8": "mysqlreader",
            "POSTGRESQL_15": "postgresqlreader",
        }[source_revision.engine]
        expected_target_plugin = {
            "MYSQL_8": "mysqlwriter",
            "POSTGRESQL_15": "postgresqlwriter",
        }[target_revision.engine]
        if (
            spec.source.plugin_name != expected_source_plugin
            or spec.target.plugin_name != expected_target_plugin
        ):
            raise ProblemException(
                status=422,
                code="JOB_SPEC_INVALID",
                title="插件与数据源引擎不匹配",
                detail="V1 只允许四个认证 Reader/Writer。",
            )

    def _assert_snapshot_columns_cover_spec(
        self,
        *,
        spec: JobSpecV1,
        source_snapshot: dict[str, Any],
        target_snapshot: dict[str, Any],
    ) -> None:
        source_columns = {
            item["name"]: item for item in source_snapshot["columns"]
        }
        target_columns = {
            item["name"]: item for item in target_snapshot["columns"]
        }
        for mapping in spec.mappings:
            source = source_columns.get(mapping.source_column)
            target = target_columns.get(mapping.target_column)
            if (
                source is None
                or target is None
                or source["ordinal_position"] != mapping.source_ordinal
                or target["ordinal_position"] != mapping.target_ordinal
                or str(source["native_type"]).casefold()
                != mapping.source_type.casefold()
                or str(target["native_type"]).casefold()
                != mapping.target_type.casefold()
                or source["nullable"] != mapping.source_nullable
                or target["nullable"] != mapping.target_nullable
                or source["logical_type"] != mapping.oracle_logical_type
                or target["logical_type"] != mapping.oracle_logical_type
            ):
                raise ProblemException(
                    status=422,
                    code="SCHEMA_SNAPSHOT_MAPPING_MISMATCH",
                    title="Schema 快照与列映射不匹配",
                    detail="列名、顺序、原生类型、可空性和 oracle 类型必须与草稿一致。",
                )
        if spec.selection_mode == "ALL_COLUMNS" and [
            item.source_column for item in spec.mappings
        ] != [item["name"] for item in source_snapshot["columns"]]:
            raise ProblemException(
                status=422,
                code="SCHEMA_SNAPSHOT_MAPPING_MISMATCH",
                title="全列复制未覆盖源表全部列",
                detail="ALL_COLUMNS 必须按快照顺序显式固定每个源列。",
            )

    def _require_datasource_grants(
        self,
        session: Session,
        *,
        principal: Principal,
        source_revision_id: UUID,
        target_revision_id: UUID,
    ) -> None:
        membership = session.scalar(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == principal.organization_id,
                OrganizationMember.user_id == principal.user_id,
                OrganizationMember.status == MembershipStatus.ACTIVE,
            )
        )
        source_revision = session.get(DatasourceRevision, source_revision_id)
        target_revision = session.get(DatasourceRevision, target_revision_id)
        if membership is None or source_revision is None or target_revision is None:
            raise ProblemException(
                status=403,
                code="DATASOURCE_USAGE_NOT_GRANTED",
                title="缺少数据源用途授权",
                detail="执行者必须分别获得 SOURCE_USE 和 TARGET_USE。",
            )
        grants = set(
            session.execute(
                select(DatasourceUsageGrant.datasource_id, DatasourceUsageGrant.usage).where(
                    DatasourceUsageGrant.organization_member_id == membership.id,
                    DatasourceUsageGrant.status == "ACTIVE",
                )
            ).all()
        )
        required = {
            (source_revision.datasource_id, "SOURCE_USE"),
            (target_revision.datasource_id, "TARGET_USE"),
        }
        if not required.issubset(grants):
            raise ProblemException(
                status=403,
                code="DATASOURCE_USAGE_NOT_GRANTED",
                title="缺少数据源用途授权",
                detail="执行者必须分别获得 SOURCE_USE 和 TARGET_USE。",
            )

    def _assert_policy_covers_spec(
        self,
        session: Session,
        policy: TransferPolicy,
        spec: JobSpecV1,
    ) -> None:
        if (
            policy.source_datasource_revision_id
            != spec.source.datasource_revision_id
            or policy.target_datasource_revision_id
            != spec.target.datasource_revision_id
        ):
            raise ProblemException(
                status=409,
                code="TRANSFER_POLICY_NOT_ACTIVE",
                title="传输授权不覆盖当前数据源修订",
                detail="必须重新审批精确 revision 对。",
            )
        source_revision = session.get(
            DatasourceRevision,
            spec.source.datasource_revision_id,
        )
        target_revision = session.get(
            DatasourceRevision,
            spec.target.datasource_revision_id,
        )
        if source_revision is None or target_revision is None:
            self._not_found()
        scope = policy.scope_json
        source_scope = scope.get("source", {})
        target_scope = scope.get("target", {})
        source_columns = {mapping.source_column for mapping in spec.mappings}
        target_columns = {mapping.target_column for mapping in spec.mappings}
        if (
            scope.get("schema_version") != "1.0"
            or source_scope.get("catalog") != source_revision.database_name
            or source_scope.get("schema") != spec.source.table.schema_name
            or source_scope.get("table") != spec.source.table.table_name
            or target_scope.get("catalog") != target_revision.database_name
            or target_scope.get("schema") != spec.target.table.schema_name
            or target_scope.get("table") != spec.target.table.table_name
            or not source_columns.issubset(set(source_scope.get("allowed_columns", [])))
            or not target_columns.issubset(set(target_scope.get("allowed_columns", [])))
        ):
            raise ProblemException(
                status=409,
                code="TRANSFER_POLICY_NOT_ACTIVE",
                title="字段映射超出传输授权范围",
                detail="当前任务的表或列不属于 ACTIVE TransferPolicy 精确 scope。",
            )

    def _validate_execution_confirmations(
        self,
        request: ExecutionCreate,
        now: datetime,
    ) -> None:
        source_confirmed_at = request.source_quiescence_confirmation.confirmed_at.astimezone(UTC)
        target_confirmed_at = (
            request.target_exclusivity_confirmation.confirmed_at.astimezone(UTC)
        )
        valid_until = request.target_exclusivity_confirmation.valid_until.astimezone(UTC)
        future_tolerance = now + timedelta(minutes=5)
        if source_confirmed_at > future_tolerance or target_confirmed_at > future_tolerance:
            raise ProblemException(
                status=422,
                code="VALIDATION_ERROR",
                title="确认时间无效",
                detail="确认时间不能显著晚于服务端当前时间。",
            )
        if valid_until <= now:
            raise ProblemException(
                status=422,
                code="TARGET_EXCLUSIVITY_CONFIRMATION_REQUIRED",
                title="目标独占声明已过期",
                detail="valid_until 必须晚于服务端当前时间。",
            )

    def _build_runtime_snapshot(
        self,
        *,
        execution: Execution,
        version: JobVersion,
        source_revision: DatasourceRevision,
        target_revision: DatasourceRevision,
        target_namespace: TargetNamespace,
        target_lock: TargetCopyLock,
        credential_binding: CredentialBinding,
        runtime_preflight: RuntimePreflight,
        fence_epoch: int,
        accepted_at: datetime,
        observed_at: datetime,
    ) -> tuple[
        ExecutionRuntimeSnapshot,
        UUID,
        UUID,
        TargetEmptyEvidence,
        str,
    ]:
        if (
            runtime_preflight.datax_release != version.datax_release
            or runtime_preflight.runtime_sha256 != version.runtime_sha256
            or runtime_preflight.reader_plugin_sha256
            != version.reader_plugin_sha256
            or runtime_preflight.writer_plugin_sha256
            != version.writer_plugin_sha256
        ):
            raise ProblemException(
                status=409,
                code="RUNTIME_BINDING_MISMATCH",
                title="固定 Runtime 与已发布版本不匹配",
                detail="Worker 不得使用未经 JobVersion 固定的 Runtime 或插件。",
            )
        source_connection_evidence_id = runtime_preflight.source_connection_evidence_id
        target_connection_evidence_id = runtime_preflight.target_connection_evidence_id
        target_empty = runtime_preflight.target_empty_evidence
        target_empty_document = target_empty.model_dump(mode="json")
        claimed_target_empty_hash = target_empty_document.pop("evidence_hash")
        if claimed_target_empty_hash != _domain_hash(
            "DXTARGETEMPTYv1",
            target_empty_document,
        ):
            raise ProblemException(
                status=409,
                code="TARGET_EMPTY_EVIDENCE_HASH_MISMATCH",
                title="目标空表证据摘要不匹配",
                detail="Worker 提交的证据内容与域分离摘要不一致。",
            )
        checked_at = target_empty.checked_at.astimezone(UTC)
        confirmation = execution.target_exclusivity_confirmation
        confirmed_at = _parse_timestamp(confirmation["confirmed_at"])
        valid_until = _parse_timestamp(confirmation["valid_until"])
        if (
            target_empty.target_datasource_revision_id != target_revision.id
            or target_empty.target_endpoint_policy_revision_id
            != execution.target_endpoint_policy_revision_id
            or target_empty.target_namespace_id != target_namespace.id
            or target_empty.physical_table_identity_hash
            != target_namespace.physical_table_identity_hash
            or target_empty.connection_evidence_id
            != target_connection_evidence_id
            or checked_at < confirmed_at
            or checked_at > observed_at + timedelta(seconds=5)
            or checked_at > valid_until
        ):
            raise ProblemException(
                status=409,
                code="TARGET_EMPTY_EVIDENCE_INVALID",
                title="目标空表证据与当前执行不匹配",
                detail="Worker 不得在目标身份、连接证据或时间边界不一致时启动 DataX。",
            )
        spec = JobSpecV1.model_validate(version.spec_json)
        snapshot = ExecutionRuntimeSnapshot(
            job_spec_hash=version.spec_hash,
            source_schema_hash=version.source_schema_hash,
            target_schema_hash=version.target_schema_hash,
            source_datasource_revision_id=source_revision.id,
            target_datasource_revision_id=target_revision.id,
            source_endpoint_policy_revision_id=(
                execution.source_endpoint_policy_revision_id
            ),
            target_endpoint_policy_revision_id=(
                execution.target_endpoint_policy_revision_id
            ),
            source_physical_endpoint_identity_id=(
                source_revision.physical_endpoint_identity_id
            ),
            target_namespace=TargetNamespaceSnapshot(
                target_namespace_id=target_namespace.id,
                physical_endpoint_identity_id=(
                    target_namespace.physical_endpoint_identity_id
                ),
                engine=target_namespace.engine,
                normalized_catalog_name=target_namespace.normalized_catalog_name,
                normalized_schema_name=target_namespace.normalized_schema_name,
                normalized_table_name=target_namespace.normalized_table_name,
                normalization_version=target_namespace.normalization_version,
                physical_table_identity_hash=(
                    target_namespace.physical_table_identity_hash
                ),
            ),
            transfer_policy_scope_hash=version.transfer_policy_scope_hash,
            source_secret_version=credential_binding.source_secret_version,
            target_secret_version=credential_binding.target_secret_version,
            source_secret_envelope_id=credential_binding.source_secret_envelope_id,
            target_secret_envelope_id=credential_binding.target_secret_envelope_id,
            datax_release=version.datax_release,
            runtime_sha256=version.runtime_sha256,
            reader_plugin=version.reader_plugin_name,
            reader_plugin_sha256=version.reader_plugin_sha256,
            writer_plugin=version.writer_plugin_name,
            writer_plugin_sha256=version.writer_plugin_sha256,
            source_consistency_mode=spec.source_consistency_mode,
            target_precondition=spec.target_precondition,
            write_semantics=spec.write_semantics,
            duplicate_policy=spec.duplicate_policy,
            partial_write_policy=spec.partial_write_policy,
            source_quiescence_confirmed_by=execution.requested_by,
            source_quiescence_accepted_at=accepted_at,
            target_exclusivity_confirmed_by=execution.requested_by,
            target_exclusivity_responsible_party=confirmation[
                "responsible_party"
            ],
            target_exclusivity_accepted_at=accepted_at,
            target_exclusivity_statement_version=confirmation[
                "statement_version"
            ],
            target_exclusivity_valid_until=valid_until,
            target_exclusivity_confirmation_sha256=_domain_hash(
                "DXTARGETEXCLUSIVITYv1",
                confirmation,
            ),
            target_empty_evidence=target_empty,
            target_lock_key_hash=target_lock.physical_table_identity_hash,
            target_fence_epoch=fence_epoch,
            verification_oracle_schema_version="1.0",
        )
        return (
            snapshot,
            source_connection_evidence_id,
            target_connection_evidence_id,
            target_empty,
            runtime_preflight.resolved_config_hash,
        )

    def _validate_successful_verification(
        self,
        *,
        execution: Execution,
        target_lock: TargetCopyLock,
        version: JobVersion,
        report: dict[str, Any],
        verification_evidence_hash: str,
    ) -> VerificationSummary:
        _reject_secret_material(report, path="verification_report")
        required = {
            "schema_version",
            "oracle_version",
            "execution_id",
            "job_version_id",
            "started_at",
            "finished_at",
            "source_quiescence",
            "target_lock",
            "target_exclusivity",
            "normalization",
            "mapping_order",
            "source_result",
            "target_result",
            "difference",
            "result",
            "artifact_sha256",
        }
        report_keys = frozenset(report)
        if report_keys not in {
            frozenset(required),
            frozenset(required | {"inconclusive_reason"}),
        }:
            raise ValueError("verification report fields do not match oracle v1")
        if (
            report["schema_version"] != "1.0"
            or not re.fullmatch(r"oracle-v1\.[0-9]+", str(report["oracle_version"]))
            or report["result"] != "PASSED"
            or report.get("inconclusive_reason") is not None
            or UUID(str(report["execution_id"])) != execution.id
            or UUID(str(report["job_version_id"])) != execution.job_version_id
        ):
            raise ValueError("verification report identity or result is invalid")
        claimed_artifact_hash = str(report["artifact_sha256"])
        _validate_sha256(claimed_artifact_hash, "artifact_sha256")
        _validate_sha256(
            verification_evidence_hash,
            "verification_evidence_hash",
        )
        artifact_payload = dict(report)
        artifact_payload.pop("artifact_sha256")
        computed_artifact_hash = hashlib.sha256(
            rfc8785.dumps(artifact_payload)
        ).hexdigest()
        if (
            claimed_artifact_hash != computed_artifact_hash
            or verification_evidence_hash != computed_artifact_hash
        ):
            raise ValueError("verification artifact hash does not match its content")

        source_quiescence = _exact_mapping(
            report["source_quiescence"],
            {
                "mode",
                "operator_confirmed_at",
                "preflight_fingerprint",
                "post_verification_fingerprint",
                "unchanged",
            },
            "source_quiescence",
        )
        oracle_target_lock = _exact_mapping(
            report["target_lock"],
            {"lock_key_hash", "fence_epoch", "held_through_verification"},
            "target_lock",
        )
        target_exclusivity = _exact_mapping(
            report["target_exclusivity"],
            {
                "mode",
                "statement_version",
                "responsible_party",
                "confirmed_at",
                "valid_until",
                "status",
                "revoked_at",
                "revocation_reason",
                "target_empty_checked_at",
                "target_snapshot_id",
                "valid_through_target_snapshot",
                "confirmation_evidence_sha256",
            },
            "target_exclusivity",
        )
        source_result = _exact_mapping(
            report["source_result"],
            {
                "row_count",
                "distinct_row_digest_count",
                "multiset_sha256",
                "read_started_at",
                "read_finished_at",
            },
            "source_result",
        )
        target_result = _exact_mapping(
            report["target_result"],
            {
                "row_count",
                "distinct_row_digest_count",
                "multiset_sha256",
                "read_started_at",
                "read_finished_at",
                "snapshot_mode",
                "snapshot_id",
                "snapshot_started_at",
                "snapshot_finished_at",
            },
            "target_result",
        )
        difference = _exact_mapping(
            report["difference"],
            {
                "missing_row_count",
                "unexpected_row_count",
                "row_count_equal",
                "multiset_sha256_equal",
                "sample_digest_pairs",
            },
            "difference",
        )
        runtime = ExecutionRuntimeSnapshot.model_validate(execution.runtime_snapshot)
        target_empty = runtime.target_empty_evidence
        confirmation = execution.target_exclusivity_confirmation
        source_confirmation = execution.source_quiescence_confirmation
        source_preflight_hash = str(source_quiescence["preflight_fingerprint"])
        source_post_hash = str(source_quiescence["post_verification_fingerprint"])
        source_multiset_hash = str(source_result["multiset_sha256"])
        target_multiset_hash = str(target_result["multiset_sha256"])
        for field, value in (
            ("preflight_fingerprint", source_preflight_hash),
            ("post_verification_fingerprint", source_post_hash),
            ("source_multiset_sha256", source_multiset_hash),
            ("target_multiset_sha256", target_multiset_hash),
        ):
            _validate_sha256(value, field)
        if (
            source_quiescence["mode"] != "OPERATOR_QUIESCED"
            or _parse_timestamp(source_quiescence["operator_confirmed_at"])
            != _parse_timestamp(source_confirmation["confirmed_at"])
            or source_quiescence["unchanged"] is not True
            or source_preflight_hash != source_post_hash
            or oracle_target_lock["lock_key_hash"]
            != target_lock.physical_table_identity_hash
            or oracle_target_lock["fence_epoch"] != execution.fence_epoch
            or oracle_target_lock["held_through_verification"] is not True
            or target_exclusivity["mode"] != "OPERATOR_OR_DBA_CONFIRMED"
            or target_exclusivity["statement_version"]
            != confirmation["statement_version"]
            or target_exclusivity["responsible_party"]
            != confirmation["responsible_party"]
            or target_exclusivity["status"] != "ACTIVE"
            or target_exclusivity["revoked_at"] is not None
            or target_exclusivity["revocation_reason"] is not None
            or target_exclusivity["valid_through_target_snapshot"] is not True
            or target_exclusivity["confirmation_evidence_sha256"]
            != runtime.target_exclusivity_confirmation_sha256
            or target_result["snapshot_mode"]
            != "SINGLE_CONSISTENT_READ_TRANSACTION"
            or target_exclusivity["target_snapshot_id"]
            != target_result["snapshot_id"]
        ):
            raise ValueError("verification preconditions are not preserved")
        if (
            not isinstance(source_result["row_count"], int)
            or not isinstance(target_result["row_count"], int)
            or source_result["row_count"] < 0
            or target_result["row_count"] < 0
            or source_result["row_count"] != target_result["row_count"]
            or source_multiset_hash != target_multiset_hash
            or difference["missing_row_count"] != 0
            or difference["unexpected_row_count"] != 0
            or difference["row_count_equal"] is not True
            or difference["multiset_sha256_equal"] is not True
            or difference["sample_digest_pairs"] != []
        ):
            raise ValueError("PASSED requires equal row multisets with zero difference")
        normalization = _exact_mapping(
            report["normalization"],
            set(_ORACLE_NORMALIZATION_V1),
            "normalization",
        )
        if normalization != _ORACLE_NORMALIZATION_V1:
            raise ValueError("oracle normalization profile is not V1")
        mappings = report["mapping_order"]
        if (
            not isinstance(mappings, list)
            or not mappings
            or any(
                not isinstance(mapping, dict)
                or mapping.get("ordinal") != index
                or set(mapping)
                != {"ordinal", "source_column", "target_column", "logical_type"}
                for index, mapping in enumerate(mappings, start=1)
            )
        ):
            raise ValueError("oracle mapping order is invalid")
        expected_mappings = [
            {
                "ordinal": index,
                "source_column": mapping.source_column,
                "target_column": mapping.target_column,
                "logical_type": mapping.oracle_logical_type,
            }
            for index, mapping in enumerate(
                JobSpecV1.model_validate(version.spec_json).mappings,
                start=1,
            )
        ]
        if mappings != expected_mappings:
            raise ValueError("oracle mapping order does not match the JobVersion")

        report_started_at = _parse_timestamp(report["started_at"])
        report_finished_at = _parse_timestamp(report["finished_at"])
        target_confirmed_at = _parse_timestamp(target_exclusivity["confirmed_at"])
        target_valid_until = _parse_timestamp(target_exclusivity["valid_until"])
        target_empty_checked_at = _parse_timestamp(
            target_exclusivity["target_empty_checked_at"]
        )
        target_snapshot_started_at = _parse_timestamp(
            target_result["snapshot_started_at"]
        )
        target_snapshot_finished_at = _parse_timestamp(
            target_result["snapshot_finished_at"]
        )
        target_read_started_at = _parse_timestamp(target_result["read_started_at"])
        target_read_finished_at = _parse_timestamp(target_result["read_finished_at"])
        if (
            target_confirmed_at != _parse_timestamp(confirmation["confirmed_at"])
            or target_valid_until != _parse_timestamp(confirmation["valid_until"])
            or target_empty_checked_at != target_empty.checked_at.astimezone(UTC)
            or not (
                report_started_at
                <= target_empty_checked_at
                <= target_snapshot_started_at
                <= target_read_started_at
                <= target_read_finished_at
                <= target_snapshot_finished_at
                <= report_finished_at
                <= target_valid_until
            )
        ):
            raise ValueError("oracle timestamps do not preserve the V1 evidence window")
        return VerificationSummary(
            oracle_version=report["oracle_version"],
            result="PASSED",
            inconclusive_reason=None,
            source_row_count=source_result["row_count"],
            target_row_count=target_result["row_count"],
            missing_row_count=0,
            unexpected_row_count=0,
            row_count_equal=True,
            multiset_sha256_equal=True,
            target_exclusivity_valid=True,
            target_snapshot_id=target_result["snapshot_id"],
            target_snapshot_started_at=target_snapshot_started_at,
            target_snapshot_finished_at=target_snapshot_finished_at,
            source_multiset_sha256=source_multiset_hash,
            target_multiset_sha256=target_multiset_hash,
            artifact_sha256=computed_artifact_hash,
            finished_at=report_finished_at,
        )

    def _active_work_termination_requests(
        self,
        session: Session,
        *,
        work_kind: str,
        work_id: UUID,
        lock: bool,
    ) -> list[WorkTerminationRequest]:
        statement = (
            select(WorkTerminationRequest)
            .where(
                WorkTerminationRequest.work_kind == work_kind,
                WorkTerminationRequest.work_id == work_id,
                WorkTerminationRequest.status.in_(_ACTIVE_WORK_TERMINATION_STATUSES),
            )
            .order_by(WorkTerminationRequest.requested_at, WorkTerminationRequest.id)
        )
        if lock:
            statement = statement.with_for_update()
        return list(session.scalars(statement))

    @staticmethod
    def _ensure_work_termination_request(
        session: Session,
        *,
        work_kind: str,
        work_id: UUID,
        reason_code: str,
        credential_secret_id: UUID | None,
        now: datetime,
    ) -> WorkTerminationRequest:
        if work_kind not in {"EXECUTION", "RECOVERY_PROBE"}:
            raise ValueError("invalid work termination kind")
        if reason_code not in _TERMINATION_REASON_PRIORITY:
            raise ValueError("invalid work termination reason")
        is_secret_reason = reason_code in {"SECRET_REVOKED", "SECRET_COMPROMISED"}
        if is_secret_reason != (credential_secret_id is not None):
            raise ValueError("termination credential reference does not match reason")
        secret_match = (
            WorkTerminationRequest.credential_secret_id.is_(None)
            if credential_secret_id is None
            else WorkTerminationRequest.credential_secret_id == credential_secret_id
        )
        existing = session.scalar(
            select(WorkTerminationRequest)
            .where(
                WorkTerminationRequest.work_kind == work_kind,
                WorkTerminationRequest.work_id == work_id,
                WorkTerminationRequest.reason_code == reason_code,
                secret_match,
                WorkTerminationRequest.status.in_(_ACTIVE_WORK_TERMINATION_STATUSES),
            )
            .order_by(WorkTerminationRequest.requested_at, WorkTerminationRequest.id)
            .with_for_update()
        )
        if existing is not None:
            return existing
        request = WorkTerminationRequest(
            id=uuid4(),
            work_kind=work_kind,
            work_id=work_id,
            credential_secret_id=credential_secret_id,
            reason_code=reason_code,
            status="PENDING",
            requested_at=now,
        )
        session.add(request)
        return request

    def _ensure_target_exclusivity_termination(
        self,
        session: Session,
        *,
        execution: Execution,
        now: datetime,
        attempt_id: UUID | None,
    ) -> WorkTerminationRequest | None:
        """Persist expiry/revocation before a Worker acts on the safety stop."""

        valid_until = _parse_timestamp(
            execution.target_exclusivity_confirmation["valid_until"]
        )
        if (
            execution.target_exclusivity_status == "ACTIVE"
            and execution.target_exclusivity_revoked_at is None
            and execution.target_exclusivity_revocation_reason is None
            and valid_until <= now
        ):
            execution.target_exclusivity_status = "EXPIRED"
            execution.target_exclusivity_revocation_reason = "VALIDITY_WINDOW_EXPIRED"
            execution.state_version += 1
            self._append_execution_event(
                session,
                execution,
                event_type="TARGET_EXCLUSIVITY_EXPIRED",
                from_state=execution.process_state,
                to_state=execution.process_state,
                attempt_id=attempt_id,
                payload={"valid_until": _rfc3339(valid_until)},
                now=now,
            )
        if execution.target_exclusivity_status == "REVOKED":
            reason_code = "TARGET_EXCLUSIVITY_REVOKED"
        elif execution.target_exclusivity_status == "EXPIRED":
            reason_code = "TARGET_EXCLUSIVITY_EXPIRED"
        else:
            return None
        return self._ensure_work_termination_request(
            session,
            work_kind="EXECUTION",
            work_id=execution.id,
            reason_code=reason_code,
            credential_secret_id=None,
            now=now,
        )

    def _execution_lock(
        self,
        session: Session,
        execution_id: UUID,
        *,
        lock: bool = False,
    ) -> TargetCopyLock:
        statement = select(TargetCopyLock).where(
            TargetCopyLock.execution_id == execution_id
        )
        if lock:
            statement = statement.with_for_update()
        target_lock = session.scalar(statement)
        if target_lock is None:
            raise RuntimeError("Execution target lock is missing")
        return target_lock

    def _required_job_version(
        self,
        session: Session,
        job_version_id: UUID,
    ) -> JobVersion:
        version = session.get(JobVersion, job_version_id)
        if version is None:
            raise RuntimeError("Execution JobVersion is missing")
        return version

    def _current_endpoint_policy_revision(
        self,
        session: Session,
        policy: EndpointPolicy,
    ) -> EndpointPolicyRevision:
        if policy.current_revision_id is None:
            raise RuntimeError("EndpointPolicy current revision is missing")
        revision = session.get(
            EndpointPolicyRevision,
            policy.current_revision_id,
        )
        if revision is None or revision.endpoint_policy_id != policy.id:
            raise RuntimeError("EndpointPolicy current revision is invalid")
        return revision

    def _current_fenced_attempt(
        self,
        session: Session,
        *,
        claim: ClaimedExecution,
        now: datetime,
        lock: bool,
    ) -> tuple[Execution, ExecutionAttempt]:
        statement = select(Execution).where(Execution.id == claim.execution_id)
        if lock:
            statement = statement.with_for_update()
        execution = session.scalar(statement)
        attempt_statement = select(ExecutionAttempt).where(
            ExecutionAttempt.id == claim.attempt_id
        )
        if lock:
            attempt_statement = attempt_statement.with_for_update()
        attempt = session.scalar(attempt_statement)
        token_hash = hashlib.sha256(claim.lease_token.encode("ascii")).hexdigest()
        if (
            execution is None
            or attempt is None
            or execution.active_attempt_id != attempt.id
            or execution.fence_epoch != claim.fence_epoch
            or attempt.fence_epoch != claim.fence_epoch
            or not hmac.compare_digest(attempt.lease_token_hash, token_hash)
            or ensure_aware(attempt.lease_expires_at) <= now
        ):
            self._fence_lost()
        return execution, attempt

    def _fence_lost(self) -> None:
        raise ProblemException(
            status=409,
            code="EXECUTION_FENCE_LOST",
            title="Worker 已失去 Execution 围栏",
            detail="旧 Worker 必须停止外部工作且不得再写状态。",
        )

    def _append_execution_event(
        self,
        session: Session,
        execution: Execution,
        *,
        event_type: str,
        payload: dict[str, Any],
        now: datetime,
        from_state: str | None = None,
        to_state: str | None = None,
        attempt_id: UUID | None = None,
    ) -> None:
        sequence = (
            session.scalar(
                select(func.max(ExecutionEvent.sequence_no)).where(
                    ExecutionEvent.execution_id == execution.id
                )
            )
            or 0
        ) + 1
        session.add(
            ExecutionEvent(
                id=uuid4(),
                execution_id=execution.id,
                sequence_no=sequence,
                event_type=event_type,
                from_state=from_state,
                to_state=to_state,
                attempt_id=attempt_id,
                payload=payload,
                occurred_at=now,
            )
        )

    def _normalize_endpoint_policy(
        self,
        request: EndpointPolicyCreate,
    ) -> dict[str, Any]:
        host = request.host_value.rstrip(".").casefold()
        try:
            parsed_ip = ipaddress.ip_address(host)
        except ValueError:
            parsed_ip = None
        if request.host_kind == "EXACT_IP":
            if parsed_ip is None:
                self._validation_problem("host_value", "EXACT_IP 必须是规范化 IP。")
            host = parsed_ip.compressed
        else:
            if parsed_ip is not None or not _HOSTNAME_PATTERN.fullmatch(host):
                self._validation_problem("host_value", "EXACT_FQDN 必须是精确主机名。")
        try:
            cidrs = sorted(
                {
                    ipaddress.ip_network(value, strict=False).with_prefixlen
                    for value in request.allowed_cidrs
                }
            )
        except ValueError:
            self._validation_problem("allowed_cidrs", "CIDR 格式无效。")
        ports = sorted(set(request.allowed_ports))
        if any(port < 1 or port > 65535 for port in ports):
            self._validation_problem("allowed_ports", "端口必须位于 1..65535。")
        policy_document = {
            "engine": request.engine.value,
            "host_kind": request.host_kind.value,
            "host_value": host,
            "allowed_cidrs": cidrs,
            "allowed_ports": ports,
            "tls_required": request.tls_required,
            "dns_ttl_ceiling_seconds": request.dns_ttl_ceiling_seconds,
            "resolver_policy_version": self._resolver_policy_version,
            "egress_policy_version": self._egress_policy_version,
        }
        return {
            **policy_document,
            "policy_hash": _domain_hash("DXENDPOINTPOLICYv1", policy_document),
        }

    def _project_response(self, project: Project) -> ProjectResponse:
        return ProjectResponse(
            id=project.id,
            organization_id=project.organization_id,
            name=project.name,
            slug=project.slug,
            description=project.description,
            status=project.status,
            row_version=project.row_version,
            created_at=ensure_aware(project.created_at),
            updated_at=ensure_aware(project.updated_at),
        )

    def _endpoint_policy_response(
        self,
        policy: EndpointPolicy,
        revision: EndpointPolicyRevision,
    ) -> EndpointPolicyResponse:
        if policy.current_revision_id is None:
            raise RuntimeError("EndpointPolicy current revision is missing")
        return EndpointPolicyResponse(
            id=policy.id,
            organization_id=policy.organization_id,
            name=policy.name,
            current_revision_id=policy.current_revision_id,
            current_revision_no=revision.revision_no,
            current_revision=EndpointPolicyRevisionResponse(
                id=revision.id,
                endpoint_policy_id=revision.endpoint_policy_id,
                revision_no=revision.revision_no,
                engine=revision.engine,
                host_kind=revision.host_kind,
                host_value=revision.host_value,
                allowed_cidrs=revision.allowed_cidrs,
                allowed_ports=revision.allowed_ports,
                tls_required=revision.tls_required,
                dns_ttl_ceiling_seconds=revision.dns_ttl_ceiling_seconds,
                resolver_policy_version=revision.resolver_policy_version,
                egress_policy_version=revision.egress_policy_version,
                policy_hash=revision.policy_hash,
                created_by=revision.created_by,
                created_at=ensure_aware(revision.created_at),
            ),
            status=policy.status,
            row_version=policy.row_version,
        )

    def _job_response(self, session: Session, job: SyncJob) -> JobResponse:
        latest_version = (
            session.execute(
                select(
                    JobVersion.version_no,
                    JobVersion.reader_plugin_name,
                    JobVersion.writer_plugin_name,
                ).where(
                    JobVersion.id == job.latest_published_version_id,
                    JobVersion.job_id == job.id,
                )
            ).first()
            if job.latest_published_version_id is not None
            else None
        )
        latest_execution = session.execute(
            select(Execution.process_state, Execution.queued_at)
            .where(Execution.job_id == job.id)
            .order_by(Execution.queued_at.desc(), Execution.id.desc())
            .limit(1)
        ).first()
        return JobResponse(
            id=job.id,
            project_id=job.project_id,
            name=job.name,
            description=job.description,
            status=job.status,
            draft_spec=JobSpecV1.model_validate(job.draft_spec_json),
            draft_spec_hash=job.draft_spec_hash,
            validated_spec_hash=job.validated_spec_hash,
            latest_published_version_id=job.latest_published_version_id,
            latest_published_version_no=(
                latest_version.version_no if latest_version is not None else None
            ),
            latest_published_reader_plugin=(
                latest_version.reader_plugin_name
                if latest_version is not None
                else None
            ),
            latest_published_writer_plugin=(
                latest_version.writer_plugin_name
                if latest_version is not None
                else None
            ),
            latest_execution_process_state=(
                latest_execution.process_state
                if latest_execution is not None
                else None
            ),
            latest_execution_at=(
                ensure_aware(latest_execution.queued_at)
                if latest_execution is not None
                else None
            ),
            row_version=job.row_version,
            created_at=ensure_aware(job.created_at),
            updated_at=ensure_aware(job.updated_at),
        )

    def _job_version_response(self, version: JobVersion) -> JobVersionResponse:
        return JobVersionResponse(
            id=version.id,
            job_id=version.job_id,
            version_no=version.version_no,
            spec=JobSpecV1.model_validate(version.spec_json),
            spec_hash=version.spec_hash,
            version_artifact_hash=version.version_artifact_hash,
            source_datasource_revision_id=version.source_datasource_revision_id,
            target_datasource_revision_id=version.target_datasource_revision_id,
            source_endpoint_policy_revision_id=(
                version.source_endpoint_policy_revision_id
            ),
            target_endpoint_policy_revision_id=(
                version.target_endpoint_policy_revision_id
            ),
            source_physical_table_identity_hash=(
                version.source_physical_table_identity_hash
            ),
            target_namespace_id=version.target_namespace_id,
            transfer_policy_id=version.transfer_policy_id,
            transfer_policy_scope_hash=version.transfer_policy_scope_hash,
            source_schema_hash=version.source_schema_hash,
            target_schema_hash=version.target_schema_hash,
            datax_release=version.datax_release,
            runtime_sha256=version.runtime_sha256,
            reader_plugin=version.reader_plugin_name,
            reader_plugin_sha256=version.reader_plugin_sha256,
            writer_plugin=version.writer_plugin_name,
            writer_plugin_sha256=version.writer_plugin_sha256,
            published_by=version.published_by,
            published_at=ensure_aware(version.published_at),
        )

    def _execution_response(
        self,
        execution: Execution,
        target_lock: TargetCopyLock,
        version: JobVersion,
    ) -> ExecutionResponse:
        return ExecutionResponse(
            id=execution.id,
            project_id=execution.project_id,
            job_id=execution.job_id,
            job_version_id=execution.job_version_id,
            rerun_of_execution_id=execution.rerun_of_execution_id,
            trigger_type="MANUAL",
            requested_by=execution.requested_by,
            process_state=execution.process_state,
            data_effect=execution.data_effect,
            verification_state=execution.verification_state,
            target_exclusivity_confirmation=execution.target_exclusivity_confirmation,
            target_exclusivity_status=execution.target_exclusivity_status,
            target_exclusivity_revoked_at=(
                ensure_aware(execution.target_exclusivity_revoked_at)
                if execution.target_exclusivity_revoked_at
                else None
            ),
            target_exclusivity_revocation_reason=(
                execution.target_exclusivity_revocation_reason
            ),
            source_datasource_revision_id=execution.source_datasource_revision_id,
            target_datasource_revision_id=execution.target_datasource_revision_id,
            source_endpoint_policy_revision_id=(
                execution.source_endpoint_policy_revision_id
            ),
            target_endpoint_policy_revision_id=(
                execution.target_endpoint_policy_revision_id
            ),
            target_namespace_id=execution.target_namespace_id,
            target_copy_lock=TargetCopyLockSummary(
                target_namespace_id=target_lock.target_namespace_id,
                state=target_lock.state,
                reserved_at=ensure_aware(target_lock.reserved_at),
                activated_at=(
                    ensure_aware(target_lock.acquired_at)
                    if target_lock.acquired_at
                    else None
                ),
                released_at=(
                    ensure_aware(target_lock.released_at)
                    if target_lock.released_at
                    else None
                ),
                fence_epoch=target_lock.fence_epoch,
            ),
            source_secret_version=execution.source_secret_version,
            target_secret_version=execution.target_secret_version,
            source_secret_envelope_id=execution.source_secret_envelope_id,
            target_secret_envelope_id=execution.target_secret_envelope_id,
            source_connection_evidence_id=execution.source_connection_evidence_id,
            target_connection_evidence_id=execution.target_connection_evidence_id,
            capacity_profile=execution.capacity_profile,
            service_reservation_seconds=execution.service_reservation_seconds,
            queue_eligibility_state=execution.queue_eligibility_state,
            queue_block_reason=execution.queue_block_reason,
            queue_state_changed_at=ensure_aware(execution.queue_state_changed_at),
            eligible_wait_milliseconds=execution.eligible_wait_milliseconds,
            log_incomplete=execution.log_incomplete,
            log_raw_received_bytes=execution.log_raw_received_bytes,
            log_redacted_received_bytes=execution.log_redacted_received_bytes,
            log_stored_bytes=execution.log_stored_bytes,
            log_dropped_bytes=execution.log_dropped_bytes,
            resolved_config_hash=execution.resolved_config_hash,
            runtime_snapshot=execution.runtime_snapshot,
            verification_summary=self._stored_verification_summary(
                execution,
                target_lock,
                version,
            ),
            queued_at=ensure_aware(execution.queued_at),
            started_at=(
                ensure_aware(execution.started_at) if execution.started_at else None
            ),
            finished_at=(
                ensure_aware(execution.finished_at) if execution.finished_at else None
            ),
            exit_code=execution.exit_code,
            failure_code=execution.failure_code,
            failure_message=execution.failure_message,
            summary_parse_status=execution.summary_parse_status,
            run_summary=execution.run_summary,
        )

    def _stored_verification_summary(
        self,
        execution: Execution,
        target_lock: TargetCopyLock,
        version: JobVersion,
    ) -> VerificationSummary | None:
        if execution.verification_report is None:
            return None
        if (
            execution.verification_state == "PASSED"
            and execution.verification_evidence_hash is not None
        ):
            return self._validate_successful_verification(
                execution=execution,
                target_lock=target_lock,
                version=version,
                report=execution.verification_report,
                verification_evidence_hash=execution.verification_evidence_hash,
            )
        return None

    @staticmethod
    def _require_scheduler_state(session: Session) -> None:
        if session.get(QueueSchedulerState, 1) is None:
            raise ProblemException(
                status=503,
                code="SERVICE_UNAVAILABLE",
                title="服务控制状态不可用",
                detail="调度控制事实缺失；请完成数据库迁移和恢复后重试。",
                retryable=True,
            )

    def _claim_idempotency(
        self,
        session: Session,
        *,
        actor_id: UUID,
        scope: str,
        key: str,
        body: dict[str, Any],
        now: datetime,
    ) -> IdempotencyRecord | None:
        request_hash = self._idempotency_request_hash(
            actor_id=actor_id,
            scope=scope,
            body=body,
        )
        existing = session.scalar(
            select(IdempotencyRecord)
            .where(
                IdempotencyRecord.actor_id == actor_id,
                IdempotencyRecord.scope == scope,
                IdempotencyRecord.idempotency_key == key,
            )
            .with_for_update()
        )
        if existing is not None and ensure_aware(existing.expires_at) <= now:
            session.delete(existing)
            session.flush()
            existing = None
        if existing is not None:
            if (
                existing.request_hash_scheme != IDEMPOTENCY_HASH_SCHEME
                or not hmac.compare_digest(existing.request_hash, request_hash)
            ):
                raise ProblemException(
                    status=409,
                    code="IDEMPOTENCY_CONFLICT",
                    title="Idempotency-Key 已用于不同请求",
                    detail="请为新的业务意图使用新的 Idempotency-Key。",
                )
            if existing.response_status is None or existing.response_body is None:
                raise ProblemException(
                    status=409,
                    code="IDEMPOTENCY_IN_PROGRESS",
                    title="相同请求仍在处理中",
                    detail="请稍后使用相同 Idempotency-Key 重试。",
                    retryable=True,
                    headers={"Retry-After": "1"},
                )
            return existing
        session.add(
            IdempotencyRecord(
                id=uuid4(),
                actor_id=actor_id,
                scope=scope,
                idempotency_key=key,
                request_hash=request_hash,
                request_hash_scheme=IDEMPOTENCY_HASH_SCHEME,
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )
        session.flush()
        return None

    def _idempotency_request_hash(
        self,
        *,
        actor_id: UUID,
        scope: str,
        body: dict[str, Any],
    ) -> str:
        scope_bytes = scope.encode("utf-8")
        canonical_body = rfc8785.dumps(body)
        message = b"".join(
            (
                _IDEMPOTENCY_HASH_DOMAIN,
                actor_id.bytes,
                len(scope_bytes).to_bytes(4, "big"),
                scope_bytes,
                len(canonical_body).to_bytes(8, "big"),
                canonical_body,
            )
        )
        return hmac.new(
            self._integrity_hmac_key,
            message,
            hashlib.sha256,
        ).hexdigest()

    def _complete_idempotency(
        self,
        session: Session,
        *,
        actor_id: UUID,
        scope: str,
        key: str,
        status: int,
        body: dict[str, Any],
        resource_type: str,
        resource_id: UUID,
    ) -> None:
        record = session.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.actor_id == actor_id,
                IdempotencyRecord.scope == scope,
                IdempotencyRecord.idempotency_key == key,
            )
        )
        if record is None:
            raise RuntimeError("idempotency record disappeared")
        record.response_status = status
        record.response_body = body
        record.resource_type = resource_type
        record.resource_id = resource_id

    def _append_audit(
        self,
        session: Session,
        *,
        organization: Organization,
        project_id: UUID | None,
        action: str,
        actor_id: UUID | None,
        target_type: str,
        target_id: UUID | None,
        target_name: str | None,
        changed_fields: list[str],
        audit: AuditContext,
        metadata: dict[str, Any] | None = None,
        outcome: str = "SUCCEEDED",
        reason_code: str | None = None,
    ) -> None:
        if outcome not in {"SUCCEEDED", "DENIED", "FAILED"}:
            raise ValueError("audit outcome is invalid")
        if reason_code is not None and (
            len(reason_code) > 64
            or re.fullmatch(r"[A-Z0-9_]+", reason_code) is None
        ):
            raise ValueError("audit reason code is invalid")
        # The organization row is the single serialization point shared with the
        # authentication service's audit writer.
        session.execute(
            select(Organization.id)
            .where(Organization.id == organization.id)
            .with_for_update()
        ).scalar_one()
        previous = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization.id)
            .order_by(AuditEvent.organization_sequence.desc())
            .limit(1)
        )
        sequence = (previous.organization_sequence + 1) if previous else 1
        previous_hash = previous.event_hash if previous else None
        occurred_at = utc_now()
        event_id = uuid4()
        actor = session.get(User, actor_id) if actor_id else None
        event: dict[str, Any] = {
            "schema_version": "1.0",
            "event_id": str(event_id),
            "organization_id": str(organization.id),
            "sequence": sequence,
            "project_id": str(project_id) if project_id else None,
            "occurred_at": _rfc3339(occurred_at),
            "action": action,
            "actor": {
                "kind": "USER" if actor is not None else "SYSTEM",
                "user_id": str(actor.id) if actor is not None else None,
                "display_name": actor.display_name if actor is not None else None,
            },
            "target": {
                "type": target_type,
                "id": str(target_id) if target_id is not None else None,
                "name": target_name,
            },
            "request": {
                "request_id": str(audit.request_id),
                "source_ip": audit.source_ip[:45] if audit.source_ip else None,
                "user_agent": self._safe_audit_user_agent(audit.user_agent),
            },
            "outcome": outcome,
            "reason_code": reason_code,
            "changes": {
                "before_hash": None,
                "after_hash": None,
                "changed_fields": sorted(set(changed_fields)),
            },
            "metadata": metadata or {},
            "integrity": {
                "algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "chain_scope": "ORGANIZATION_SEQUENCE",
                "previous_hash": previous_hash,
            },
        }
        prefix = (
            "DXAUDITv1\n"
            f"{str(organization.id).lower()}\n"
            f"{sequence}\n"
            f"{previous_hash or ('0' * 64)}\n"
        ).encode()
        event_hash = hashlib.sha256(prefix + rfc8785.dumps(event)).hexdigest()
        event["integrity"]["event_hash"] = event_hash
        advance_audit_chain_watermark(
            session,
            organization_id=organization.id,
            previous_sequence=sequence - 1,
            previous_hash=previous_hash,
            sequence=sequence,
            event_hash=event_hash,
            updated_at=occurred_at,
        )
        session.add(
            AuditEvent(
                id=event_id,
                organization_id=organization.id,
                organization_sequence=sequence,
                project_id=project_id,
                event_json=event,
                canonicalization_version="RFC8785-v1",
                previous_hash=previous_hash,
                event_hash=event_hash,
                occurred_at=occurred_at,
                expires_at=occurred_at + timedelta(days=730),
            )
        )
        session.flush()

    def _safe_audit_user_agent(self, user_agent: str | None) -> str | None:
        if user_agent is None:
            return None
        digest = hmac.new(
            self._integrity_hmac_key,
            _AUDIT_USER_AGENT_HASH_DOMAIN
            + user_agent.encode("utf-8", errors="replace"),
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256-v1:{digest}"

    def _encode_cursor(
        self,
        *,
        actor_id: UUID,
        scope: str,
        created_at: datetime,
        resource_id: UUID,
    ) -> str:
        payload = {
            "v": 1,
            "actor_id": str(actor_id),
            "scope": scope,
            "timestamp": _rfc3339(created_at),
            "resource_id": str(resource_id),
        }
        body = rfc8785.dumps(payload)
        signature = hmac.new(
            self._integrity_hmac_key,
            _CURSOR_DOMAIN + body,
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(body + signature).rstrip(b"=").decode("ascii")

    def _decode_cursor(
        self,
        cursor: str,
        *,
        actor_id: UUID,
        scope: str,
    ) -> tuple[datetime, UUID]:
        try:
            padding = "=" * (-len(cursor) % 4)
            decoded = base64.urlsafe_b64decode(cursor + padding)
            body, signature = decoded[:-32], decoded[-32:]
            expected = hmac.new(
                self._integrity_hmac_key,
                _CURSOR_DOMAIN + body,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            payload = json.loads(body)
            if (
                payload.get("v") != 1
                or payload.get("actor_id") != str(actor_id)
                or payload.get("scope") != scope
            ):
                raise ValueError
            return (
                _parse_timestamp(payload["timestamp"]),
                UUID(payload["resource_id"]),
            )
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            raise ProblemException(
                status=400,
                code="CURSOR_INVALID",
                title="分页游标无效",
                detail="请从第一页重新加载。",
            ) from None

    def _database_now(self, session: Session) -> datetime:
        value = session.scalar(select(func.current_timestamp()))
        if value is None:
            raise RuntimeError("database did not return current timestamp")
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def _validation_problem(self, path: str, message: str) -> None:
        raise ProblemException(
            status=422,
            code="VALIDATION_ERROR",
            title="请求字段无效",
            detail="请修正请求后重试。",
            field_errors=[
                {
                    "path": path,
                    "code": "VALIDATION_ERROR",
                    "message": message,
                }
            ],
        )

    def _runtime_attestation_unavailable(self) -> None:
        raise ProblemException(
            status=503,
            code="RUNTIME_ATTESTATION_UNAVAILABLE",
            title="Worker Runtime 尚未通过本次启动对账与证明",
            detail="请等待 Worker、固定 DataX Runtime、Oracle 和启动对账全部就绪后重试。",
            retryable=True,
        )

    def _not_found(self) -> None:
        raise ProblemException(
            status=404,
            code="NOT_FOUND",
            title="资源不存在",
            detail="资源不存在或当前用户无权访问。",
        )

    def _version_conflict(self) -> None:
        raise ProblemException(
            status=409,
            code="VERSION_CONFLICT",
            title="资源已被其他人修改",
            detail="请刷新后重新应用修改。",
        )


def _dashboard_group_counts(
    session: Session,
    column: Any,
    conditions: tuple[Any, ...],
    allowed_values: tuple[str, ...],
) -> dict[str, int]:
    counts = {value: 0 for value in allowed_values}
    for value, count in session.execute(
        select(column, func.count()).where(*conditions).group_by(column)
    ):
        if value not in counts:
            raise RuntimeError("database contains a value outside the V1 contract")
        counts[value] = int(count)
    return counts


def _contains_pattern(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )
    return f"%{escaped}%"


def _filtered_cursor_scope(route: str, filters: dict[str, object]) -> str:
    digest = hashlib.sha256(rfc8785.dumps(filters)).hexdigest()
    return f"{route}#{digest}"


def _dashboard_verified_record_count(
    reports: list[dict[str, Any] | None],
) -> tuple[int, int]:
    total = 0
    missing = 0
    for report in reports:
        target_result = report.get("target_result") if isinstance(report, dict) else None
        row_count = (
            target_result.get("row_count")
            if isinstance(target_result, dict)
            else None
        )
        if (
            not isinstance(row_count, int)
            or isinstance(row_count, bool)
            or row_count < 0
        ):
            missing += 1
            continue
        total += row_count
    return total, missing


def _dashboard_execution_item(
    execution: Execution,
    job_name: str,
) -> DashboardExecutionItem:
    return DashboardExecutionItem(
        execution_id=execution.id,
        job_id=execution.job_id,
        job_version_id=execution.job_version_id,
        job_name=job_name,
        process_state=execution.process_state,
        data_effect=execution.data_effect,
        verification_state=execution.verification_state,
        queued_at=ensure_aware(execution.queued_at),
        started_at=(
            ensure_aware(execution.started_at)
            if execution.started_at is not None
            else None
        ),
        finished_at=(
            ensure_aware(execution.finished_at)
            if execution.finished_at is not None
            else None
        ),
        failure_code=execution.failure_code,
    )


def _dashboard_drilldowns(
    *,
    project_id: UUID,
    window_from: datetime,
    window_to: datetime,
) -> list[DashboardDrilldown]:
    base_path = f"/api/v1/projects/{project_id}"

    def filters(
        *,
        process_states: list[str] | None = None,
        unresolved_failure: bool | None = None,
        jobs: bool = False,
    ) -> DashboardDrilldownFilters:
        return DashboardDrilldownFilters(
            from_=None if jobs else window_from,
            to=None if jobs else window_to,
            process_states=process_states or [],
            verification_states=[],
            data_effects=[],
            exclude_job_status="ARCHIVED" if jobs else None,
            has_published_version=True if jobs else None,
            unresolved_failure=unresolved_failure,
        )

    definitions: tuple[
        tuple[str, str, str, list[str] | None, bool | None, bool],
        ...,
    ] = (
        ("executable_jobs", "JOBS", "jobs", None, None, True),
        ("all_executions", "EXECUTIONS", "executions", None, None, False),
        ("queued", "EXECUTIONS", "executions", ["QUEUED"], None, False),
        (
            "running",
            "EXECUTIONS",
            "executions",
            ["STARTING", "RUNNING", "VERIFYING", "CANCEL_REQUESTED"],
            None,
            False,
        ),
        ("succeeded", "EXECUTIONS", "executions", ["SUCCEEDED"], None, False),
        ("failed", "EXECUTIONS", "executions", ["FAILED"], None, False),
        ("timed_out", "EXECUTIONS", "executions", ["TIMED_OUT"], None, False),
        ("lost", "EXECUTIONS", "executions", ["LOST"], None, False),
        ("canceled", "EXECUTIONS", "executions", ["CANCELED"], None, False),
        (
            "unresolved_failures",
            "EXECUTIONS",
            "executions",
            ["FAILED", "TIMED_OUT", "LOST"],
            True,
            False,
        ),
    )
    return [
        DashboardDrilldown(
            metric_key=metric_key,
            resource=resource,
            path=f"{base_path}/{path}",
            filters=filters(
                process_states=process_states,
                unresolved_failure=unresolved_failure,
                jobs=jobs,
            ),
        )
        for (
            metric_key,
            resource,
            path,
            process_states,
            unresolved_failure,
            jobs,
        ) in definitions
    ]


def _clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _domain_hash(domain: str, value: Any) -> str:
    return hashlib.sha256(domain.encode() + b"\n" + rfc8785.dumps(value)).hexdigest()


def _snapshot_schema_binding_matches(
    *,
    engine: str,
    database_name: str,
    spec_schema_name: str,
    snapshot_schema_name: str,
) -> bool:
    if engine == "MYSQL_8":
        return (
            spec_schema_name == database_name
            and snapshot_schema_name == ""
        )
    if engine == "POSTGRESQL_15":
        return snapshot_schema_name == spec_schema_name
    return False


def _validate_sha256(value: str, field: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError(f"{field} must be a lowercase SHA-256")


def _exact_mapping(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{field} does not match the V1 contract")
    return value


def _rfc3339(value: datetime) -> str:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)


def _host_matches_policy(host: str, revision: EndpointPolicyRevision) -> bool:
    normalized = host.rstrip(".").casefold()
    if revision.host_kind == "EXACT_FQDN":
        return normalized == revision.host_value.rstrip(".").casefold()
    try:
        return (
            ipaddress.ip_address(normalized).compressed
            == ipaddress.ip_address(revision.host_value).compressed
        )
    except ValueError:
        return False


def _reject_connection_option_secrets(options: dict[str, Any]) -> None:
    # The V1 manifest defines no optional driver properties. Accepting arbitrary
    # keys here would silently reintroduce SQL, file paths, JDBC URLs or JVM
    # switches through a field described as non-secret.
    if options:
        raise ValueError("V1 connection_options must be empty")


def _validate_connection_identifier(value: str, field: str) -> None:
    if (
        not value
        or len(value) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or "/" in value
        or "\\" in value
        or "://" in value
    ):
        raise ValueError(f"{field} contains a forbidden value")


def _reject_secret_material(value: Any, path: str = "runtime_snapshot") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.casefold().replace("-", "_")
            if normalized in {
                "password",
                "token",
                "credential",
                "connection_string",
                "jdbc_url",
                "private_key",
            }:
                raise ValueError(f"{path}.{key} contains forbidden secret material")
            _reject_secret_material(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_material(child, f"{path}[{index}]")
