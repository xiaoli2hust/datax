from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from datax_studio.auth.routes import (
    IdempotencyKey,
    audit_context,
    business_principal,
)
from datax_studio.auth.service import Principal
from datax_studio.core.routes import get_control_service
from datax_studio.core.schemas import ExecutionResponse
from datax_studio.core.service import ControlService
from datax_studio.recovery.schemas import (
    ExecutionRerunCreate,
    RecoveryGateResponse,
    RecoveryProbeResponse,
    RecoverySubmissionResponse,
    RemediationConfirmation,
)
from datax_studio.recovery.service import RecoveryService

router = APIRouter()


def get_recovery_service(
    control: Annotated[ControlService, Depends(get_control_service)],
) -> RecoveryService:
    return RecoveryService(control)


@router.get(
    "/executions/{execution_id}/recovery",
    response_model=RecoveryGateResponse,
)
def get_execution_recovery_gate(
    execution_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[RecoveryService, Depends(get_recovery_service)],
) -> RecoveryGateResponse:
    return service.get_gate(
        principal=principal,
        execution_id=execution_id,
    )


@router.post(
    "/executions/{execution_id}/recovery",
    response_model=RecoverySubmissionResponse,
    status_code=202,
)
def submit_execution_remediation(
    execution_id: UUID,
    request_body: RemediationConfirmation,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[RecoveryService, Depends(get_recovery_service)],
) -> RecoverySubmissionResponse:
    result = service.submit_remediation(
        principal=principal,
        execution_id=execution_id,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.get(
    "/recovery-probes/{recovery_probe_id}",
    response_model=RecoveryProbeResponse,
)
def get_recovery_probe(
    recovery_probe_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[RecoveryService, Depends(get_recovery_service)],
) -> RecoveryProbeResponse:
    return service.get_probe(
        principal=principal,
        recovery_probe_id=recovery_probe_id,
    )


@router.post(
    "/executions/{execution_id}/rerun",
    response_model=ExecutionResponse,
    status_code=202,
)
def rerun_execution(
    execution_id: UUID,
    request_body: ExecutionRerunCreate,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[RecoveryService, Depends(get_recovery_service)],
) -> ExecutionResponse:
    result = service.rerun(
        principal=principal,
        execution_id=execution_id,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value
