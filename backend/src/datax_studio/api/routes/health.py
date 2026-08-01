from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request, Response, status

from datax_studio.api.models import (
    ComponentHealth,
    HealthResponse,
    HealthStatus,
)

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("/live", response_model=HealthResponse)
def liveness(request: Request) -> HealthResponse:
    settings = request.app.state.settings
    return HealthResponse(
        status=HealthStatus.UP,
        version=settings.app_version,
        checked_at=datetime.now(UTC),
        components={
            "api": ComponentHealth(status=HealthStatus.UP, code="API_RESPONSIVE")
        },
    )


@router.get(
    "/ready",
    response_model=HealthResponse,
    responses={503: {"model": HealthResponse}},
)
def readiness(request: Request, response: Response) -> HealthResponse:
    result = request.app.state.readiness.check()
    if result.status == HealthStatus.DOWN:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return result
