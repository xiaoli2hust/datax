from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from datax_studio.auth.db import Role, ScopeType, UserStatus
from datax_studio.auth.security import normalize_email


def _email(value: str) -> str:
    try:
        return normalize_email(value)
    except ValueError as exc:
        raise ValueError("email is invalid") from exc


NormalizedEmail = Annotated[str, AfterValidator(_email)]
Password = Annotated[str, Field(min_length=12, max_length=256)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserSummary(StrictModel):
    id: UUID
    email: str
    display_name: str
    must_change_password: bool


class ScopedRoles(StrictModel):
    scope_type: ScopeType
    scope_id: UUID
    roles: list[Role]


class UserResponse(StrictModel):
    id: UUID
    email: str
    display_name: str
    status: UserStatus
    must_change_password: bool
    role_assignments: list[ScopedRoles]
    row_version: int
    created_at: datetime
    updated_at: datetime


class UserPage(StrictModel):
    items: list[UserResponse]
    next_cursor: str | None
    has_more: bool


class LoginRequest(StrictModel):
    email: NormalizedEmail
    password: Password


class AuthResponse(StrictModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    user: UserSummary


class MeResponse(StrictModel):
    user: UserSummary
    role_assignments: list[ScopedRoles]


class ChangePasswordRequest(StrictModel):
    current_password: Annotated[str, Field(min_length=1, max_length=256)]
    new_password: Password


class UserCreate(StrictModel):
    email: NormalizedEmail
    display_name: Annotated[str, Field(min_length=1, max_length=128)]
    temporary_password: Password

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("display_name must not be blank")
        return stripped


class UserPatch(StrictModel):
    display_name: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    status: Literal["ACTIVE", "DISABLED"] | None = None

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("display_name must not be blank")
        return stripped

    @field_validator("status")
    @classmethod
    def preserve_explicit_status(cls, value: str | None) -> str | None:
        return value

    def require_change(self) -> UserPatch:
        if "display_name" not in self.model_fields_set and "status" not in self.model_fields_set:
            raise ValueError("at least one field is required")
        return self


class ResetPasswordRequest(StrictModel):
    temporary_password: Password


class OrganizationRoleReplaceRequest(StrictModel):
    roles: Annotated[list[Literal["ADMIN"]], Field(max_length=1)]
