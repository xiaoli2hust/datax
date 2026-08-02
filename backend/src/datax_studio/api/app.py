from __future__ import annotations

from collections.abc import Awaitable, Callable
from uuid import UUID, uuid4

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from datax_studio.api.problems import ProblemException, problem_response
from datax_studio.api.readiness import (
    ReadinessProvider,
    SystemReadinessProvider,
)
from datax_studio.api.routes.health import router as health_router
from datax_studio.auth.ingress import LoginAdmissionGuard, LoginAdmissionRejection
from datax_studio.auth.routes import router as auth_router
from datax_studio.auth.service import AuthService
from datax_studio.core.routes import router as core_router
from datax_studio.core.service import ControlService
from datax_studio.credentials.routes import router as credential_router
from datax_studio.credentials.service import CredentialService
from datax_studio.governance.routes import router as governance_router
from datax_studio.logs.routes import router as log_router
from datax_studio.recovery.routes import router as recovery_router
from datax_studio.settings import Settings, get_settings


def create_app(
    *,
    settings: Settings | None = None,
    readiness: ReadinessProvider | None = None,
    auth_service: AuthService | None = None,
    control_service: ControlService | None = None,
    credential_service: CredentialService | None = None,
) -> FastAPI:
    resolved_settings = settings or get_settings()
    app = FastAPI(
        title="DataX Enterprise Studio API",
        version=resolved_settings.app_version,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = resolved_settings
    app.state.readiness = readiness or SystemReadinessProvider(resolved_settings)
    app.state.login_admission = LoginAdmissionGuard(
        burst=resolved_settings.login_admission_burst,
        rate_per_minute=resolved_settings.login_admission_rate_per_minute,
        max_in_flight=resolved_settings.login_admission_max_in_flight,
    )
    app.state.auth_service = auth_service
    app.state.control_service = control_service
    app.state.credential_service = credential_service
    @app.middleware("http")
    async def loopback_origin_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        origin = request.headers.get("Origin")
        if origin is not None and origin != resolved_settings.ui_origin:
            return problem_response(
                request,
                ProblemException(
                    status=403,
                    code="ORIGIN_NOT_ALLOWED",
                    title="请求来源无效",
                    detail="请求来源不在本机允许列表中。",
                ),
            )
        admission = None
        if (
            request.method == "POST"
            and request.url.path == "/api/v1/auth/login"
        ):
            admission = request.app.state.login_admission.try_acquire()
            if isinstance(admission, LoginAdmissionRejection):
                return problem_response(
                    request,
                    ProblemException(
                        status=429,
                        code="AUTH_LOGIN_ADMISSION_LIMITED",
                        title="登录尝试暂时受限",
                        detail="请稍后重试。",
                        retryable=True,
                        headers={"Retry-After": str(admission.retry_after_seconds)},
                    ),
                )
        try:
            return await call_next(request)
        finally:
            if admission is not None:
                admission.release()

    # Middleware is wrapped in reverse registration order.  Register this
    # after admission so hostile Host headers are rejected before they can
    # consume the deliberately small, global login-admission budget.
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[resolved_settings.trusted_host],
    )

    @app.middleware("http")
    async def request_id_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        try:
            request_id = str(UUID(request.headers.get("X-Request-Id", "")))
        except ValueError:
            request_id = str(uuid4())
        request.state.request_id = UUID(request_id)
        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ProblemException)
    async def problem_exception_handler(
        request: Request,
        exc: ProblemException,
    ) -> JSONResponse:
        return problem_response(request, exc)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        field_errors = []
        for error in exc.errors():
            path = ".".join(str(part) for part in error.get("loc", ()) if part != "body")
            field_errors.append(
                {
                    "path": path or "request",
                    "code": str(error.get("type", "VALIDATION_ERROR")).upper().replace(".", "_"),
                    "message": "请求字段无效。",
                }
            )
        return problem_response(
            request,
            ProblemException(
                status=422,
                code="VALIDATION_ERROR",
                title="请求字段无效",
                detail="请修正请求后重试。",
                field_errors=field_errors,
            ),
        )

    app.include_router(health_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(core_router, prefix="/api/v1")
    app.include_router(credential_router, prefix="/api/v1")
    app.include_router(governance_router, prefix="/api/v1")
    app.include_router(recovery_router, prefix="/api/v1")
    app.include_router(log_router, prefix="/api/v1")
    return app


app: ASGIApp = create_app()
