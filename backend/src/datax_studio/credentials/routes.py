from __future__ import annotations

import re
from threading import Lock
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response

from datax_studio.auth.routes import (
    IdempotencyKey,
    audit_context,
    business_principal,
)
from datax_studio.auth.service import Principal
from datax_studio.core.schemas import (
    EndpointPolicyResponse,
    EndpointPolicyRevisionResponse,
)
from datax_studio.credentials.ingress import DatasourceOperationAdmissionGuard
from datax_studio.credentials.schemas import (
    CredentialSecretPage,
    CredentialSecretStatusChange,
    CredentialSecretSummary,
    DatasourceAdminDetail,
    DatasourceCreate,
    DatasourcePage,
    DatasourcePatch,
    DatasourceRedactedSummary,
    DatasourceRevisionAdminDetail,
    DatasourceTestResult,
    DatasourceUsageGrantPage,
    DatasourceUsageGrantReplace,
    EndpointConnectionEvidenceResponse,
    EndpointPolicyPatch,
    Engine,
    TableSchemaPage,
)
from datax_studio.credentials.service import (
    CredentialService,
    build_credential_service,
)

router = APIRouter()
_service_lock = Lock()
_if_match_pattern = re.compile(r'^W/"([1-9][0-9]*)"$')

# The detailed, machine-readable contract remains in docs/contracts/openapi.yaml.
# These JSON Schema fragments deliberately retain the status/code/retryability
# discriminators and standard headers in FastAPI's generated surface too, so a
# consumer cannot mistake the live route metadata for an untyped JSON error.
_DATASOURCE_OPERATION_PROBLEM_BASE = {
    "type": "object",
    "required": ["status", "code", "retryable"],
    "properties": {
        "status": {"type": "integer"},
        "code": {"type": "string"},
        "retryable": {"type": "boolean"},
    },
}
_DATASOURCE_OPERATION_STALE_PROBLEM = {
    "allOf": [
        _DATASOURCE_OPERATION_PROBLEM_BASE,
        {
            "type": "object",
            "properties": {
                "status": {"const": 409},
                "code": {"const": "DATASOURCE_OPERATION_STALE"},
                "retryable": {"const": True},
            },
        },
    ]
}
_DATASOURCE_OPERATION_OTHER_CONFLICT_PROBLEM = {
    "allOf": [
        _DATASOURCE_OPERATION_PROBLEM_BASE,
        {
            "type": "object",
            "properties": {
                "status": {"const": 409},
                "code": {
                    "type": "string",
                    "not": {"const": "DATASOURCE_OPERATION_STALE"},
                },
            },
        },
    ]
}
_DATASOURCE_OPERATION_ADMISSION_LIMITED_PROBLEM = {
    "allOf": [
        _DATASOURCE_OPERATION_PROBLEM_BASE,
        {
            "type": "object",
            "properties": {
                "status": {"const": 429},
                "code": {"const": "DATASOURCE_OPERATION_ADMISSION_LIMITED"},
                "retryable": {"const": True},
            },
        },
    ]
}
_DATASOURCE_OPERATION_DEADLINE_PROBLEM = {
    "allOf": [
        _DATASOURCE_OPERATION_PROBLEM_BASE,
        {
            "type": "object",
            "properties": {
                "status": {"const": 503},
                "code": {"const": "DATASOURCE_OPERATION_DEADLINE_EXCEEDED"},
                "retryable": {"const": True},
            },
        },
    ]
}
_DATASOURCE_OPERATION_OTHER_UNAVAILABLE_PROBLEM = {
    "allOf": [
        _DATASOURCE_OPERATION_PROBLEM_BASE,
        {
            "type": "object",
            "properties": {
                "status": {"const": 503},
                "code": {
                    "type": "string",
                    "not": {"const": "DATASOURCE_OPERATION_DEADLINE_EXCEEDED"},
                },
            },
        },
    ]
}
_DATASOURCE_OPERATION_COMMON_HEADERS = {
    "X-Request-Id": {
        "description": "Opaque request correlation identifier.",
        "schema": {"type": "string", "format": "uuid"},
    },
    "Cache-Control": {
        "description": "Problem responses are never cacheable.",
        "schema": {"type": "string", "const": "no-store"},
    },
}
_IDEMPOTENCY_REPLAYED_RESPONSE_HEADER = {
    "description": "Present with value true when the idempotent request was replayed.",
    "schema": {"type": "string", "const": "true"},
}


def _problem_content(schema: dict[str, object]) -> dict[str, object]:
    return {"application/problem+json": {"schema": schema}}


DATASOURCE_EXTERNAL_OPERATION_RESPONSES = {
    409: {
        "description": "Security binding changed while the external operation was in flight.",
        "headers": _DATASOURCE_OPERATION_COMMON_HEADERS,
        "content": _problem_content(
            {
                "oneOf": [
                    _DATASOURCE_OPERATION_STALE_PROBLEM,
                    _DATASOURCE_OPERATION_OTHER_CONFLICT_PROBLEM,
                ]
            }
        ),
    },
    429: {
        "description": "The API-process external datasource operation admission is full.",
        "headers": {
            "Retry-After": {
                "description": "Fixed manual retry delay in seconds.",
                "schema": {"type": "integer", "const": 60},
            },
            **_DATASOURCE_OPERATION_COMMON_HEADERS,
        },
        "content": _problem_content(_DATASOURCE_OPERATION_ADMISSION_LIMITED_PROBLEM),
    },
    503: {
        "description": (
            "The operation deadline or a required external security dependency is unavailable."
        ),
        "headers": _DATASOURCE_OPERATION_COMMON_HEADERS,
        "content": _problem_content(
            {
                "oneOf": [
                    _DATASOURCE_OPERATION_DEADLINE_PROBLEM,
                    _DATASOURCE_OPERATION_OTHER_UNAVAILABLE_PROBLEM,
                ]
            }
        ),
    },
}


def get_credential_service(request: Request) -> CredentialService:
    service = getattr(request.app.state, "credential_service", None)
    if service is not None:
        return service
    with _service_lock:
        service = getattr(request.app.state, "credential_service", None)
        if service is None:
            service = build_credential_service(request.app.state.settings)
            request.app.state.credential_service = service
    return service


def get_datasource_operation_admission(
    request: Request,
) -> DatasourceOperationAdmissionGuard:
    """Return the one API-process admission guard owned by the app."""

    return request.app.state.datasource_operation_admission


@router.patch(
    "/endpoint-policies/{endpoint_policy_id}",
    response_model=EndpointPolicyResponse,
)
def update_endpoint_policy(
    endpoint_policy_id: UUID,
    request_body: EndpointPolicyPatch,
    request: Request,
    response: Response,
    if_match: Annotated[str, Header(alias="If-Match")],
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> EndpointPolicyResponse:
    result = service.update_endpoint_policy(
        principal=principal,
        endpoint_policy_id=endpoint_policy_id,
        request=request_body,
        expected_version=_parse_if_match(if_match),
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(result.row_version)
    return result


@router.get(
    "/endpoint-policies/{endpoint_policy_id}/revisions/{revision_id}",
    response_model=EndpointPolicyRevisionResponse,
)
def get_endpoint_policy_revision(
    endpoint_policy_id: UUID,
    revision_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> EndpointPolicyRevisionResponse:
    return service.get_endpoint_policy_revision(
        principal=principal,
        endpoint_policy_id=endpoint_policy_id,
        revision_id=revision_id,
    )


@router.get(
    "/endpoint-connection-evidence/{connection_evidence_id}",
    response_model=EndpointConnectionEvidenceResponse,
)
def get_endpoint_connection_evidence(
    connection_evidence_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> EndpointConnectionEvidenceResponse:
    return service.get_endpoint_connection_evidence(
        principal=principal,
        connection_evidence_id=connection_evidence_id,
    )


@router.get(
    "/projects/{project_id}/datasources",
    response_model=DatasourcePage,
)
def list_datasources(
    project_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
    cursor: Annotated[
        str | None,
        Query(min_length=1, max_length=2048),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    engine: Engine | None = None,
) -> DatasourcePage:
    return service.list_datasources(
        principal=principal,
        project_id=project_id,
        cursor=cursor,
        limit=limit,
        engine=engine.value if engine is not None else None,
    )


@router.post(
    "/projects/{project_id}/datasources",
    response_model=DatasourceAdminDetail,
    status_code=201,
    responses=DATASOURCE_EXTERNAL_OPERATION_RESPONSES,
)
def create_datasource(
    project_id: UUID,
    request_body: DatasourceCreate,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
    admission: Annotated[
        DatasourceOperationAdmissionGuard,
        Depends(get_datasource_operation_admission),
    ],
) -> DatasourceAdminDetail:
    result = service.create_datasource(
        principal=principal,
        project_id=project_id,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
        admission=admission,
    )
    response.headers["ETag"] = _etag(result.value.row_version)
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.get(
    "/datasources/{datasource_id}",
    response_model=DatasourceRedactedSummary,
)
def get_datasource(
    datasource_id: UUID,
    response: Response,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> DatasourceRedactedSummary:
    result = service.get_redacted(
        principal=principal,
        datasource_id=datasource_id,
    )
    response.headers["ETag"] = _etag(result.row_version)
    return result


@router.get(
    "/datasources/{datasource_id}/admin-detail",
    response_model=DatasourceAdminDetail,
)
def get_datasource_admin_detail(
    datasource_id: UUID,
    response: Response,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> DatasourceAdminDetail:
    result = service.get_admin_detail(
        principal=principal,
        datasource_id=datasource_id,
    )
    response.headers["ETag"] = _etag(result.row_version)
    return result


@router.patch(
    "/datasources/{datasource_id}",
    response_model=DatasourceAdminDetail,
    responses=DATASOURCE_EXTERNAL_OPERATION_RESPONSES,
)
def update_datasource(
    datasource_id: UUID,
    request_body: DatasourcePatch,
    request: Request,
    response: Response,
    if_match: Annotated[str, Header(alias="If-Match")],
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
    admission: Annotated[
        DatasourceOperationAdmissionGuard,
        Depends(get_datasource_operation_admission),
    ],
) -> DatasourceAdminDetail:
    result = service.update_datasource(
        principal=principal,
        datasource_id=datasource_id,
        request=request_body,
        expected_version=_parse_if_match(if_match),
        audit=audit_context(request),
        admission=admission,
    )
    response.headers["ETag"] = _etag(result.row_version)
    return result


@router.delete(
    "/datasources/{datasource_id}",
    status_code=204,
    response_class=Response,
)
def delete_datasource(
    datasource_id: UUID,
    request: Request,
    if_match: Annotated[str, Header(alias="If-Match")],
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> Response:
    service.delete_datasource(
        principal=principal,
        datasource_id=datasource_id,
        expected_version=_parse_if_match(if_match),
        audit=audit_context(request),
    )
    return Response(status_code=204)


@router.get(
    "/datasources/{datasource_id}/revisions/{revision_id}",
    response_model=DatasourceRevisionAdminDetail,
)
def get_datasource_revision(
    datasource_id: UUID,
    revision_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> DatasourceRevisionAdminDetail:
    return service.get_datasource_revision(
        principal=principal,
        datasource_id=datasource_id,
        revision_id=revision_id,
    )


@router.get(
    "/datasources/{datasource_id}/grants",
    response_model=DatasourceUsageGrantPage,
)
def list_datasource_usage_grants(
    datasource_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
    cursor: Annotated[
        str | None,
        Query(min_length=1, max_length=2048),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> DatasourceUsageGrantPage:
    return service.list_datasource_usage_grants(
        principal=principal,
        datasource_id=datasource_id,
        cursor=cursor,
        limit=limit,
    )


@router.put(
    "/datasources/{datasource_id}/grants/{member_id}",
    response_model=DatasourceUsageGrantPage,
)
def replace_datasource_usage_grants(
    datasource_id: UUID,
    member_id: UUID,
    request_body: DatasourceUsageGrantReplace,
    request: Request,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> DatasourceUsageGrantPage:
    return service.replace_datasource_usage_grants(
        principal=principal,
        datasource_id=datasource_id,
        member_id=member_id,
        request=request_body,
        audit=audit_context(request),
    )


@router.get(
    "/datasources/{datasource_id}/credential-secrets",
    response_model=CredentialSecretPage,
)
def list_datasource_credential_secrets(
    datasource_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> CredentialSecretPage:
    return service.list_credential_secrets(
        principal=principal,
        datasource_id=datasource_id,
    )


@router.post(
    "/datasources/{datasource_id}/credential-secrets/{secret_version}/status",
    response_model=CredentialSecretSummary,
    responses={200: {"headers": {"Idempotency-Replayed": _IDEMPOTENCY_REPLAYED_RESPONSE_HEADER}}},
)
def change_datasource_credential_status(
    datasource_id: UUID,
    secret_version: int,
    request_body: CredentialSecretStatusChange,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> CredentialSecretSummary:
    result = service.change_secret_status(
        principal=principal,
        datasource_id=datasource_id,
        secret_version=secret_version,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.post(
    "/datasources/{datasource_id}/test",
    response_model=DatasourceTestResult,
    responses=DATASOURCE_EXTERNAL_OPERATION_RESPONSES,
)
def test_datasource(
    datasource_id: UUID,
    request: Request,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
    admission: Annotated[
        DatasourceOperationAdmissionGuard,
        Depends(get_datasource_operation_admission),
    ],
) -> DatasourceTestResult:
    return service.test_datasource(
        principal=principal,
        datasource_id=datasource_id,
        request_id=request.state.request_id,
        audit=audit_context(request),
        admission=admission,
    )


@router.get(
    "/datasources/{datasource_id}/schema/tables",
    response_model=TableSchemaPage,
    responses=DATASOURCE_EXTERNAL_OPERATION_RESPONSES,
)
def list_datasource_tables(
    datasource_id: UUID,
    request: Request,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[CredentialService, Depends(get_credential_service)],
    admission: Annotated[
        DatasourceOperationAdmissionGuard,
        Depends(get_datasource_operation_admission),
    ],
    usage: Annotated[Literal["SOURCE_USE", "TARGET_USE"], Query()],
    schema_name: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    table_name: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    cursor: Annotated[
        str | None,
        Query(min_length=1, max_length=2048),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> TableSchemaPage:
    return service.list_columns(
        principal=principal,
        datasource_id=datasource_id,
        usage=usage,
        schema_name=schema_name,
        table_name=table_name,
        cursor=cursor,
        limit=limit,
        audit=audit_context(request),
        admission=admission,
    )


def _parse_if_match(value: str) -> int:
    match = _if_match_pattern.fullmatch(value)
    if match is None:
        from datax_studio.api.problems import ProblemException

        raise ProblemException(
            status=422,
            code="VALIDATION_ERROR",
            title="If-Match 格式无效",
            detail='If-Match 必须使用 W/"<row_version>"。',
        )
    return int(match.group(1))


def _etag(version: int) -> str:
    return f'W/"{version}"'
