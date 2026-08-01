from __future__ import annotations

import re
from datetime import datetime
from threading import Lock
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response

from datax_studio.api.problems import ProblemException
from datax_studio.auth.routes import (
    IdempotencyKey,
    audit_context,
    business_principal,
)
from datax_studio.auth.service import Principal
from datax_studio.core.schemas import (
    AuditPage,
    CancelExecutionRequest,
    CancelRequestResponse,
    DashboardResponse,
    EndpointPolicyCreate,
    EndpointPolicyPage,
    EndpointPolicyResponse,
    ExecutionCreate,
    ExecutionPage,
    ExecutionResponse,
    JobCreate,
    JobPage,
    JobPatch,
    JobPreview,
    JobResponse,
    JobVersionPage,
    JobVersionResponse,
    PhysicalEndpointIdentityResponse,
    PluginPage,
    ProjectCreate,
    ProjectPage,
    ProjectPatch,
    ProjectResponse,
    PublishRequest,
    TargetExclusivityRevocationRequest,
    TargetNamespaceSnapshot,
    ValidationReport,
)
from datax_studio.core.service import (
    ControlService,
    ValidationMaterial,
    build_control_service,
)
from datax_studio.credentials.routes import get_credential_service
from datax_studio.credentials.service import CredentialService

router = APIRouter()
_service_lock = Lock()
_if_match_pattern = re.compile(r'^W/"([1-9][0-9]*)"$')


def get_control_service(request: Request) -> ControlService:
    service = getattr(request.app.state, "control_service", None)
    if service is not None:
        return service
    with _service_lock:
        service = getattr(request.app.state, "control_service", None)
        if service is None:
            service = build_control_service(request.app.state.settings)
            request.app.state.control_service = service
    return service


@router.get(
    "/plugins",
    response_model=PluginPage,
)
def list_plugin_capabilities(
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> PluginPage:
    return service.list_plugin_capabilities(principal=principal)


@router.get("/projects", response_model=ProjectPage)
def list_projects(
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ProjectPage:
    return service.list_projects(
        principal=principal,
        limit=limit,
        cursor=cursor,
    )


@router.post("/projects", response_model=ProjectResponse, status_code=201)
def create_project(
    request_body: ProjectCreate,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> ProjectResponse:
    result = service.create_project(
        principal=principal,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(result.value.row_version)
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.get("/projects/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: UUID,
    response: Response,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> ProjectResponse:
    project = service.get_project(principal=principal, project_id=project_id)
    response.headers["ETag"] = _etag(project.row_version)
    return project


@router.get(
    "/projects/{project_id}/dashboard",
    response_model=DashboardResponse,
)
def get_project_dashboard(
    project_id: UUID,
    window_from: Annotated[datetime, Query(alias="from")],
    window_to: Annotated[datetime, Query(alias="to")],
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> DashboardResponse:
    return service.get_project_dashboard(
        principal=principal,
        project_id=project_id,
        window_from=window_from,
        window_to=window_to,
    )


@router.get(
    "/projects/{project_id}/audit-events",
    response_model=AuditPage,
)
def list_project_audit_events(
    project_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    action: Annotated[str | None, Query(max_length=64)] = None,
    outcome: Annotated[
        Literal["SUCCEEDED", "DENIED", "FAILED"] | None,
        Query(),
    ] = None,
    actor_id: UUID | None = None,
    window_from: Annotated[datetime | None, Query(alias="from")] = None,
    window_to: Annotated[datetime | None, Query(alias="to")] = None,
) -> AuditPage:
    return service.list_project_audit_events(
        principal=principal,
        project_id=project_id,
        limit=limit,
        cursor=cursor,
        action=action,
        outcome=outcome,
        actor_id=actor_id,
        window_from=window_from,
        window_to=window_to,
    )


@router.get("/audit-events", response_model=AuditPage)
def list_organization_audit_events(
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    project_id: UUID | None = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    outcome: Annotated[
        Literal["SUCCEEDED", "DENIED", "FAILED"] | None,
        Query(),
    ] = None,
    actor_id: UUID | None = None,
    window_from: Annotated[datetime | None, Query(alias="from")] = None,
    window_to: Annotated[datetime | None, Query(alias="to")] = None,
) -> AuditPage:
    return service.list_organization_audit_events(
        principal=principal,
        project_id=project_id,
        limit=limit,
        cursor=cursor,
        action=action,
        outcome=outcome,
        actor_id=actor_id,
        window_from=window_from,
        window_to=window_to,
    )


@router.patch("/projects/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: UUID,
    request_body: ProjectPatch,
    request: Request,
    response: Response,
    if_match: Annotated[str, Header(alias="If-Match")],
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> ProjectResponse:
    project = service.update_project(
        principal=principal,
        project_id=project_id,
        request=request_body,
        expected_version=_parse_if_match(if_match),
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(project.row_version)
    return project


@router.post(
    "/endpoint-policies",
    response_model=EndpointPolicyResponse,
    status_code=201,
)
def create_endpoint_policy(
    request_body: EndpointPolicyCreate,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> EndpointPolicyResponse:
    result = service.create_endpoint_policy(
        principal=principal,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(result.value.row_version)
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.get("/endpoint-policies", response_model=EndpointPolicyPage)
def list_endpoint_policies(
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> EndpointPolicyPage:
    return service.list_endpoint_policies(
        principal=principal,
        limit=limit,
        cursor=cursor,
    )


@router.get(
    "/endpoint-policies/{endpoint_policy_id}",
    response_model=EndpointPolicyResponse,
)
def get_endpoint_policy(
    endpoint_policy_id: UUID,
    response: Response,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> EndpointPolicyResponse:
    policy = service.get_endpoint_policy(
        principal=principal,
        endpoint_policy_id=endpoint_policy_id,
    )
    response.headers["ETag"] = _etag(policy.row_version)
    return policy


@router.get(
    "/physical-endpoint-identities/{physical_endpoint_identity_id}",
    response_model=PhysicalEndpointIdentityResponse,
)
def get_physical_endpoint_identity(
    physical_endpoint_identity_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> PhysicalEndpointIdentityResponse:
    return service.get_physical_endpoint_identity(
        principal=principal,
        physical_endpoint_identity_id=physical_endpoint_identity_id,
    )


@router.get(
    "/target-namespaces/{target_namespace_id}",
    response_model=TargetNamespaceSnapshot,
)
def get_target_namespace(
    target_namespace_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> TargetNamespaceSnapshot:
    return service.get_target_namespace(
        principal=principal,
        target_namespace_id=target_namespace_id,
    )


@router.get("/projects/{project_id}/jobs", response_model=JobPage)
def list_jobs(
    project_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    q: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    status: Literal["DRAFT", "VALID", "PUBLISHED", "ARCHIVED"] | None = None,
    exclude_status: Literal["DRAFT", "VALID", "PUBLISHED", "ARCHIVED"]
    | None = None,
    has_published_version: bool | None = None,
    reader_plugin: Literal["mysqlreader", "postgresqlreader"] | None = None,
    writer_plugin: Literal["mysqlwriter", "postgresqlwriter"] | None = None,
    latest_execution_state: Literal[
        "QUEUED",
        "STARTING",
        "RUNNING",
        "VERIFYING",
        "SUCCEEDED",
        "FAILED",
        "TIMED_OUT",
        "CANCEL_REQUESTED",
        "CANCELED",
        "LOST",
    ]
    | None = None,
) -> JobPage:
    return service.list_jobs(
        principal=principal,
        project_id=project_id,
        limit=limit,
        cursor=cursor,
        query=q,
        status=status,
        exclude_status=exclude_status,
        has_published_version=has_published_version,
        reader_plugin=reader_plugin,
        writer_plugin=writer_plugin,
        latest_execution_state=latest_execution_state,
    )


@router.post(
    "/projects/{project_id}/jobs",
    response_model=JobResponse,
    status_code=201,
)
def create_job(
    project_id: UUID,
    request_body: JobCreate,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> JobResponse:
    result = service.create_job(
        principal=principal,
        project_id=project_id,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(result.value.row_version)
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.get("/jobs/{job_id}", response_model=JobResponse)
def get_job(
    job_id: UUID,
    response: Response,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> JobResponse:
    job = service.get_job(principal=principal, job_id=job_id)
    response.headers["ETag"] = _etag(job.row_version)
    return job


@router.patch("/jobs/{job_id}", response_model=JobResponse)
def update_job(
    job_id: UUID,
    request_body: JobPatch,
    request: Request,
    response: Response,
    if_match: Annotated[str, Header(alias="If-Match")],
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> JobResponse:
    job = service.update_job(
        principal=principal,
        job_id=job_id,
        request=request_body,
        expected_version=_parse_if_match(if_match),
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(job.row_version)
    return job


@router.post("/jobs/{job_id}/validate", response_model=ValidationReport)
def validate_job(
    job_id: UUID,
    request: Request,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
    credential_service: Annotated[
        CredentialService,
        Depends(get_credential_service),
    ],
) -> ValidationReport:
    runtime = service.runtime_validation_material(
        principal=principal,
        job_id=job_id,
    )
    try:
        schema = credential_service.collect_job_validation_material(
            principal=principal,
            job_id=job_id,
            audit=audit_context(request),
        )
        validated = service.accept_validation_material(
            principal=principal,
            job_id=job_id,
            material=ValidationMaterial(
                source_schema_snapshot=schema.source_schema_snapshot,
                target_schema_snapshot=schema.target_schema_snapshot,
                source_schema_hash=schema.source_schema_hash,
                target_schema_hash=schema.target_schema_hash,
                source_physical_table_identity_hash=(
                    schema.source_physical_table_identity_hash
                ),
                target_namespace_id=schema.target_namespace_id,
                transfer_policy_id=schema.transfer_policy_id,
                transfer_policy_scope_hash=schema.transfer_policy_scope_hash,
                runtime_sha256=runtime.runtime_sha256,
                reader_plugin_sha256=runtime.reader_plugin_sha256,
                writer_plugin_sha256=runtime.writer_plugin_sha256,
            ),
            audit=audit_context(request),
        )
    except ProblemException as problem:
        issue_code = _validation_issue_code(problem.code)
        if issue_code is None:
            raise
        return service.validation_failure_report(
            principal=principal,
            job_id=job_id,
            code=issue_code,
            message=problem.detail or problem.title,
            audit=audit_context(request),
        )
    return ValidationReport(
        valid=True,
        draft_spec_hash=validated.draft_spec_hash,
        source_schema_hash=schema.source_schema_hash,
        target_schema_hash=schema.target_schema_hash,
        errors=[],
        warnings=[],
    )


@router.post("/jobs/{job_id}/preview", response_model=JobPreview)
def preview_job(
    job_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> JobPreview:
    return service.preview_job(principal=principal, job_id=job_id)


@router.get("/jobs/{job_id}/versions", response_model=JobVersionPage)
def list_job_versions(
    job_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> JobVersionPage:
    return service.list_job_versions(
        principal=principal,
        job_id=job_id,
        limit=limit,
        cursor=cursor,
    )


@router.post(
    "/jobs/{job_id}/versions",
    response_model=JobVersionResponse,
    status_code=201,
)
def publish_job_version(
    job_id: UUID,
    request_body: PublishRequest,
    request: Request,
    response: Response,
    if_match: Annotated[str, Header(alias="If-Match")],
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> JobVersionResponse:
    result = service.publish_validated_job(
        principal=principal,
        job_id=job_id,
        expected_draft_spec_hash=request_body.expected_draft_spec_hash,
        expected_version=_parse_if_match(if_match),
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.get(
    "/jobs/{job_id}/versions/{version_id}",
    response_model=JobVersionResponse,
)
def get_job_version(
    job_id: UUID,
    version_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> JobVersionResponse:
    return service.get_job_version(
        principal=principal,
        job_id=job_id,
        version_id=version_id,
    )


@router.get("/projects/{project_id}/executions", response_model=ExecutionPage)
def list_executions(
    project_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    process_state: Annotated[
        list[
            Literal[
                "QUEUED",
                "STARTING",
                "RUNNING",
                "VERIFYING",
                "SUCCEEDED",
                "FAILED",
                "TIMED_OUT",
                "CANCEL_REQUESTED",
                "CANCELED",
                "LOST",
            ]
        ]
        | None,
        Query(max_length=10),
    ] = None,
    data_effect: Annotated[
        list[Literal["NONE", "POSSIBLE", "CONFIRMED", "UNKNOWN"]] | None,
        Query(max_length=4),
    ] = None,
    verification_state: Annotated[
        list[
            Literal[
                "NOT_STARTED",
                "VERIFYING",
                "PASSED",
                "FAILED",
                "INCONCLUSIVE",
            ]
        ]
        | None,
        Query(max_length=5),
    ] = None,
    target_exclusivity_status: Annotated[
        list[Literal["ACTIVE", "REVOKED", "EXPIRED"]] | None,
        Query(max_length=3),
    ] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    job_id: UUID | None = None,
    job_version_id: UUID | None = None,
    requested_by: UUID | None = None,
    queued_from: Annotated[datetime | None, Query(alias="from")] = None,
    queued_to: Annotated[datetime | None, Query(alias="to")] = None,
    is_rerun: bool | None = None,
    unresolved_failure: bool | None = None,
) -> ExecutionPage:
    _validate_time_window(queued_from, queued_to)
    _require_unique_query_values(process_state, "process_state")
    _require_unique_query_values(data_effect, "data_effect")
    _require_unique_query_values(verification_state, "verification_state")
    _require_unique_query_values(
        target_exclusivity_status,
        "target_exclusivity_status",
    )
    return service.list_executions(
        principal=principal,
        project_id=project_id,
        limit=limit,
        cursor=cursor,
        process_states=process_state,
        data_effects=data_effect,
        verification_states=verification_state,
        target_exclusivity_statuses=target_exclusivity_status,
        query=q,
        job_id=job_id,
        job_version_id=job_version_id,
        requested_by=requested_by,
        queued_from=queued_from,
        queued_to=queued_to,
        is_rerun=is_rerun,
        unresolved_failure=unresolved_failure,
    )


@router.post(
    "/jobs/{job_id}/executions",
    response_model=ExecutionResponse,
    status_code=202,
)
def create_execution(
    job_id: UUID,
    request_body: ExecutionCreate,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> ExecutionResponse:
    result = service.create_execution(
        principal=principal,
        job_id=job_id,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.get("/executions/{execution_id}", response_model=ExecutionResponse)
def get_execution(
    execution_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> ExecutionResponse:
    return service.get_execution(
        principal=principal,
        execution_id=execution_id,
    )


@router.post(
    "/executions/{execution_id}/cancel",
    response_model=CancelRequestResponse,
    status_code=202,
)
def cancel_execution(
    execution_id: UUID,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
    request_body: CancelExecutionRequest | None = None,
) -> CancelRequestResponse:
    result = service.request_cancel(
        principal=principal,
        execution_id=execution_id,
        reason=request_body.reason if request_body else None,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.post(
    "/executions/{execution_id}/target-exclusivity/revoke",
    response_model=ExecutionResponse,
    status_code=202,
)
def revoke_target_exclusivity(
    execution_id: UUID,
    request_body: TargetExclusivityRevocationRequest,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[ControlService, Depends(get_control_service)],
) -> ExecutionResponse:
    result = service.revoke_target_exclusivity(
        principal=principal,
        execution_id=execution_id,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


def _etag(row_version: int) -> str:
    return f'W/"{row_version}"'


def _parse_if_match(value: str) -> int:
    match = _if_match_pattern.fullmatch(value)
    if match is None:
        raise ProblemException(
            status=422,
            code="VALIDATION_ERROR",
            title="If-Match 格式无效",
            detail='请使用 W/"<row_version>"。',
        )
    return int(match.group(1))


def _validate_time_window(
    queued_from: datetime | None,
    queued_to: datetime | None,
) -> None:
    for field, value in (("from", queued_from), ("to", queued_to)):
        if value is not None and (
            value.tzinfo is None or value.utcoffset() is None
        ):
            raise ProblemException(
                status=422,
                code="VALIDATION_ERROR",
                title="时间范围无效",
                detail=f"{field} 必须包含 UTC offset。",
            )
    if queued_from is not None and queued_to is not None and queued_from >= queued_to:
        raise ProblemException(
            status=422,
            code="VALIDATION_ERROR",
            title="时间范围无效",
            detail="from 必须早于 to。",
        )


def _require_unique_query_values(
    values: list[object] | None,
    field: str,
) -> None:
    if values is not None and len(values) != len(set(values)):
        raise ProblemException(
            status=422,
            code="VALIDATION_ERROR",
            title="筛选条件无效",
            detail=f"{field} 不能包含重复值。",
        )


def _validation_issue_code(problem_code: str) -> str | None:
    return {
        "SOURCE_TARGET_SAME_TABLE": "SOURCE_TARGET_SAME_TABLE",
        "DATASOURCE_REVISION_NOT_CURRENT": "DATASOURCE_DISABLED",
        "DATASOURCE_DISABLED": "DATASOURCE_DISABLED",
        "TARGET_NAMESPACE_NOT_REGISTERED": "TARGET_TABLE_NOT_FOUND",
        "SCHEMA_SNAPSHOT_MAPPING_MISMATCH": "SCHEMA_DRIFT_DETECTED",
        "SCHEMA_SNAPSHOT_BINDING_MISMATCH": "SCHEMA_DRIFT_DETECTED",
        "SCHEMA_SNAPSHOT_INVALID": "SCHEMA_DRIFT_DETECTED",
        "SCHEMA_SNAPSHOT_HASH_MISMATCH": "SCHEMA_DRIFT_DETECTED",
        "TRANSFER_POLICY_NOT_ACTIVE": "JOB_SPEC_INVALID",
        "TRANSFER_SCOPE_DENIED": "JOB_SPEC_INVALID",
    }.get(problem_code)
