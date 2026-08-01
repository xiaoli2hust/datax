from __future__ import annotations

import re
from threading import Lock
from typing import Annotated, Literal
from uuid import UUID

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    Query,
    Request,
    Response,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from datax_studio.api.problems import ProblemException
from datax_studio.auth.schemas import (
    AuthResponse,
    ChangePasswordRequest,
    LoginRequest,
    MeResponse,
    OrganizationRoleReplaceRequest,
    ResetPasswordRequest,
    UserCreate,
    UserPage,
    UserPatch,
    UserResponse,
)
from datax_studio.auth.service import (
    AuditContext,
    AuthService,
    Principal,
    build_auth_service,
)

router = APIRouter()
bearer = HTTPBearer(auto_error=False)
_service_lock = Lock()
_if_match_pattern = re.compile(r'^W/"([1-9][0-9]*)"$')

IdempotencyKey = Annotated[
    str,
    Header(
        alias="Idempotency-Key",
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
]


def get_auth_service(request: Request) -> AuthService:
    service = getattr(request.app.state, "auth_service", None)
    if service is not None:
        return service
    with _service_lock:
        service = getattr(request.app.state, "auth_service", None)
        if service is None:
            service = build_auth_service(request.app.state.settings)
            request.app.state.auth_service = service
    return service


def audit_context(request: Request) -> AuditContext:
    source_ip = request.client.host if request.client else None
    return AuditContext(
        request_id=request.state.request_id,
        source_ip=source_ip,
        user_agent=request.headers.get("User-Agent"),
    )


def current_principal(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer),
    ],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> Principal:
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise ProblemException(
            status=401,
            code="AUTH_TOKEN_EXPIRED",
            title="登录会话无效",
            detail="请重新登录。",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return service.authenticate_access(credentials.credentials)


def business_principal(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> Principal:
    if principal.must_change_password:
        service.audit_authorization_denied(
            principal=principal,
            audit=audit_context(request),
            operation="BUSINESS_ROUTE",
            reason_code="PASSWORD_CHANGE_REQUIRED",
        )
        raise ProblemException(
            status=403,
            code="PASSWORD_CHANGE_REQUIRED",
            title="必须先修改临时密码",
            detail="完成本人密码修改后才能访问业务接口。",
        )
    return principal


@router.post("/auth/login", response_model=AuthResponse)
def login(
    request_body: LoginRequest,
    request: Request,
    response: Response,
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> AuthResponse:
    result = service.login(
        email=request_body.email,
        password=request_body.password,
        audit=audit_context(request),
    )
    _set_refresh_cookie(response, result.refresh_token, service.refresh_token_days)
    return result.response


@router.post("/auth/refresh", response_model=AuthResponse)
def refresh(
    request: Request,
    response: Response,
    service: Annotated[AuthService, Depends(get_auth_service)],
    refresh_token: Annotated[str | None, Cookie(alias="des_refresh")] = None,
) -> AuthResponse:
    result = service.refresh(
        refresh_token=refresh_token,
        audit=audit_context(request),
    )
    _set_refresh_cookie(response, result.refresh_token, service.refresh_token_days)
    return result.response


@router.post("/auth/logout", status_code=204)
def logout(
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer),
    ],
    refresh_token: Annotated[str | None, Cookie(alias="des_refresh")] = None,
) -> Response:
    access_token = None
    if credentials is not None and credentials.scheme.casefold() == "bearer":
        access_token = credentials.credentials
    service.logout(
        access_token=access_token,
        refresh_token=refresh_token,
        audit=audit_context(request),
    )
    response = Response(status_code=204)
    response.delete_cookie(
        "des_refresh",
        path="/api/v1/auth",
        secure=False,
        httponly=True,
        samesite="strict",
    )
    return response


@router.get("/auth/me", response_model=MeResponse)
def me(
    principal: Annotated[Principal, Depends(current_principal)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> MeResponse:
    return service.me(principal=principal)


@router.post("/auth/change-password", status_code=204)
def change_password(
    request_body: ChangePasswordRequest,
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    service.change_password(
        principal=principal,
        current_password=request_body.current_password,
        new_password=request_body.new_password,
        audit=audit_context(request),
    )
    return Response(status_code=204)


@router.get("/users", response_model=UserPage)
def list_users(
    request: Request,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[AuthService, Depends(get_auth_service)],
    cursor: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    status: Literal["ACTIVE", "LOCKED", "DISABLED"] | None = None,
) -> UserPage:
    return service.list_users(
        principal=principal,
        audit=audit_context(request),
        limit=limit,
        cursor=cursor,
        status=status,
    )


@router.post("/users", response_model=UserResponse, status_code=201)
def create_user(
    request_body: UserCreate,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> UserResponse:
    result = service.create_user(
        principal=principal,
        request=request_body,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(result.value.row_version)
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: UUID,
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> UserResponse:
    user = service.get_user(
        principal=principal,
        user_id=user_id,
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(user.row_version)
    return user


@router.patch("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: UUID,
    request_body: UserPatch,
    request: Request,
    response: Response,
    if_match: Annotated[str, Header(alias="If-Match")],
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> UserResponse:
    expected_version = _parse_if_match(if_match)
    user = service.update_user(
        principal=principal,
        user_id=user_id,
        request=request_body,
        expected_version=expected_version,
        audit=audit_context(request),
    )
    response.headers["ETag"] = _etag(user.row_version)
    return user


@router.put("/users/{user_id}/organization-roles", response_model=UserResponse)
def replace_organization_roles(
    user_id: UUID,
    request_body: OrganizationRoleReplaceRequest,
    request: Request,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> UserResponse:
    return service.replace_organization_roles(
        principal=principal,
        user_id=user_id,
        roles=list(request_body.roles),
        audit=audit_context(request),
    )


@router.post("/users/{user_id}/unlock", response_model=UserResponse)
def unlock_user(
    user_id: UUID,
    request: Request,
    response: Response,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> UserResponse:
    result = service.unlock_user(
        principal=principal,
        user_id=user_id,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    if result.replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return result.value


@router.post("/users/{user_id}/reset-password", status_code=204)
def reset_password(
    user_id: UUID,
    request_body: ResetPasswordRequest,
    request: Request,
    idempotency_key: IdempotencyKey,
    principal: Annotated[Principal, Depends(business_principal)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    replayed = service.reset_password(
        principal=principal,
        user_id=user_id,
        temporary_password=request_body.temporary_password,
        idempotency_key=idempotency_key,
        audit=audit_context(request),
    )
    response = Response(status_code=204)
    if replayed:
        response.headers["Idempotency-Replayed"] = "true"
    return response


def _set_refresh_cookie(
    response: Response,
    refresh_token: str,
    refresh_token_days: int,
) -> None:
    response.set_cookie(
        key="des_refresh",
        value=refresh_token,
        max_age=refresh_token_days * 24 * 60 * 60,
        path="/api/v1/auth",
        secure=False,
        httponly=True,
        samesite="strict",
    )


def _parse_if_match(value: str) -> int:
    matched = _if_match_pattern.fullmatch(value)
    if matched is None:
        raise ProblemException(
            status=422,
            code="VALIDATION_ERROR",
            title="If-Match 无效",
            detail='If-Match 必须使用 W/"<row_version>"。',
            field_errors=[
                {
                    "path": "If-Match",
                    "code": "INVALID_ETAG",
                    "message": '必须使用 W/"<row_version>"。',
                }
            ],
        )
    return int(matched.group(1))


def _etag(row_version: int) -> str:
    return f'W/"{row_version}"'
