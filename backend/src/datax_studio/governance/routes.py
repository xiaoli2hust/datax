from __future__ import annotations

import re
from threading import Lock
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response

from datax_studio.api.problems import ProblemException
from datax_studio.auth.routes import (
    IdempotencyKey,
    audit_context,
    business_principal,
)
from datax_studio.auth.service import Principal
from datax_studio.credentials.routes import get_credential_service
from datax_studio.credentials.service import CredentialService
from datax_studio.governance.schemas import (
    Member,
    MemberPage,
    RoleReplaceRequest,
    TransferPolicyCreate,
    TransferPolicyDecision,
    TransferPolicyPage,
    TransferPolicyPatch,
    TransferPolicyResponse,
    TransferPolicySubmit,
)
from datax_studio.governance.service import (
    GovernanceService,
    build_governance_service,
)

router = APIRouter()
_service_lock = Lock()
_if_match_pattern = re.compile(r'^W/"([1-9][0-9]*)"$')


def get_governance_service(request: Request) -> GovernanceService:
    service = getattr(request.app.state, "governance_service", None)
    if service is not None:
        return service
    with _service_lock:
        service = getattr(request.app.state, "governance_service", None)
        if service is None:
            service = build_governance_service(request.app.state.settings)
            request.app.state.governance_service = service
    return service


@router.get(
    "/projects/{project_id}/members",
    response_model=MemberPage,
)
def list_project_members(
    project_id: UUID,
    response: Response,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[GovernanceService, Depends(get_governance_service)],
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> MemberPage:
    result = service.list_project_members(
        principal=principal,
        project_id=project_id,
        limit=limit,
        cursor=cursor,
    )
    response.headers["ETag"] = _etag(result.row_version)
    return result.value


@router.put(
    "/projects/{project_id}/members/{user_id}/roles",
    response_model=Member,
)
def replace_project_member_roles(
    project_id: UUID,
    user_id: UUID,
    request_body: RoleReplaceRequest,
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[GovernanceService, Depends(get_governance_service)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> Member:
    result = service.replace_project_member_roles(
        principal=principal,
        project_id=project_id,
        user_id=user_id,
        request=request_body,
        expected_version=_parse_if_match(if_match) if if_match else None,
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(result.row_version)
    return result.value


@router.get(
    "/projects/{project_id}/transfer-policies",
    response_model=TransferPolicyPage,
)
def list_transfer_policies(
    project_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[GovernanceService, Depends(get_governance_service)],
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> TransferPolicyPage:
    return service.list_transfer_policies(
        principal=principal,
        project_id=project_id,
        limit=limit,
        cursor=cursor,
    )


@router.post(
    "/projects/{project_id}/transfer-policies",
    response_model=TransferPolicyResponse,
    status_code=201,
)
def create_transfer_policy(
    project_id: UUID,
    request_body: TransferPolicyCreate,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[GovernanceService, Depends(get_governance_service)],
    metadata_probe: Annotated[
        CredentialService,
        Depends(get_credential_service),
    ],
) -> TransferPolicyResponse:
    result = service.create_transfer_policy(
        principal=principal,
        project_id=project_id,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
        metadata_probe=metadata_probe,
    )
    response.headers["ETag"] = _etag(result.value.row_version)
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.get(
    "/transfer-policies/{transfer_policy_id}",
    response_model=TransferPolicyResponse,
)
def get_transfer_policy(
    transfer_policy_id: UUID,
    response: Response,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[GovernanceService, Depends(get_governance_service)],
) -> TransferPolicyResponse:
    policy = service.get_transfer_policy(
        principal=principal,
        transfer_policy_id=transfer_policy_id,
    )
    response.headers["ETag"] = _etag(policy.row_version)
    return policy


@router.patch(
    "/transfer-policies/{transfer_policy_id}",
    response_model=TransferPolicyResponse,
)
def update_transfer_policy(
    transfer_policy_id: UUID,
    request_body: TransferPolicyPatch,
    request: Request,
    response: Response,
    if_match: Annotated[str, Header(alias="If-Match")],
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[GovernanceService, Depends(get_governance_service)],
    metadata_probe: Annotated[
        CredentialService,
        Depends(get_credential_service),
    ],
) -> TransferPolicyResponse:
    policy = service.update_transfer_policy(
        principal=principal,
        transfer_policy_id=transfer_policy_id,
        request=request_body,
        expected_version=_parse_if_match(if_match),
        audit=audit_context(request),
        metadata_probe=metadata_probe,
    )
    response.headers["ETag"] = _etag(policy.row_version)
    return policy


@router.post(
    "/transfer-policies/{transfer_policy_id}/submit",
    response_model=TransferPolicyResponse,
)
def submit_transfer_policy(
    transfer_policy_id: UUID,
    request_body: TransferPolicySubmit,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[GovernanceService, Depends(get_governance_service)],
) -> TransferPolicyResponse:
    result = service.submit_transfer_policy(
        principal=principal,
        transfer_policy_id=transfer_policy_id,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(result.value.row_version)
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.post(
    "/transfer-policies/{transfer_policy_id}/approvals",
    response_model=TransferPolicyResponse,
)
def decide_transfer_policy(
    transfer_policy_id: UUID,
    request_body: TransferPolicyDecision,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[GovernanceService, Depends(get_governance_service)],
) -> TransferPolicyResponse:
    result = service.decide_transfer_policy(
        principal=principal,
        transfer_policy_id=transfer_policy_id,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(result.value.row_version)
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
