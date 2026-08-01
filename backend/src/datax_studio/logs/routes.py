from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from datax_studio.auth.routes import audit_context, business_principal
from datax_studio.auth.service import Principal
from datax_studio.core.routes import get_control_service
from datax_studio.core.service import ControlService
from datax_studio.logs.schemas import LogPage
from datax_studio.logs.service import ExecutionLogService

router = APIRouter()


def get_execution_log_service(
    request: Request,
    control: Annotated[ControlService, Depends(get_control_service)],
) -> ExecutionLogService:
    return ExecutionLogService(
        settings=request.app.state.settings,
        control=control,
    )


@router.get(
    "/executions/{execution_id}/logs",
    response_model=LogPage,
)
def get_execution_logs(
    execution_id: UUID,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[
        ExecutionLogService,
        Depends(get_execution_log_service),
    ],
    cursor: Annotated[str | None, Query(min_length=1, max_length=4096)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    stream: Literal["STDOUT", "STDERR", "SYSTEM"] | None = None,
) -> LogPage:
    return service.get_page(
        principal=principal,
        execution_id=execution_id,
        cursor=cursor,
        limit=limit,
        stream=stream,
    )


@router.get("/executions/{execution_id}/logs/download")
def download_execution_logs(
    execution_id: UUID,
    request: Request,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[
        ExecutionLogService,
        Depends(get_execution_log_service),
    ],
) -> Response:
    artifact = service.download(
        principal=principal,
        execution_id=execution_id,
        audit=audit_context(request),
    )
    return Response(
        content=artifact.content,
        media_type="text/plain",
        headers={
            "Content-Disposition": (f'attachment; filename="execution-{execution_id}.log"'),
            "X-Log-Redaction-Version": (artifact.redaction_rules_version),
            "X-Content-SHA256": artifact.content_sha256,
            "X-Log-Truncated": str(artifact.truncated).lower(),
            "X-Log-Incomplete": str(artifact.incomplete).lower(),
            "X-Log-Raw-Received-Bytes": str(artifact.raw_received_bytes),
            "X-Log-Redacted-Received-Bytes": str(artifact.redacted_received_bytes),
            "X-Log-Stored-Bytes": str(artifact.stored_bytes),
            "X-Log-Dropped-Bytes": str(artifact.dropped_bytes),
            "X-Log-Gap-Count": str(artifact.gap_count),
            "X-Log-Truncation-Reason": artifact.truncation_reason,
        },
    )
