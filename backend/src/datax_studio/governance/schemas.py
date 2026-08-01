from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from datax_studio.auth.db import Role
from datax_studio.auth.schemas import UserSummary


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


ProjectRole = Literal["DEVELOPER", "OPERATOR", "VIEWER"]
PolicyClassification = Literal["STANDARD", "SENSITIVE"]
PolicyStatus = Literal[
    "DRAFT",
    "PENDING_APPROVAL",
    "ACTIVE",
    "REJECTED",
    "REVOKED",
]


class Member(StrictModel):
    organization_member_id: UUID
    user: UserSummary
    roles: list[Role]


class MemberPage(StrictModel):
    items: list[Member]
    next_cursor: str | None
    has_more: bool


class RoleReplaceRequest(StrictModel):
    roles: list[ProjectRole] = Field(max_length=3)

    @field_validator("roles")
    @classmethod
    def require_unique_roles(cls, value: list[ProjectRole]) -> list[ProjectRole]:
        if len(value) != len(set(value)):
            raise ValueError("roles must be unique")
        return value


class TransferPolicyApproval(StrictModel):
    id: UUID
    approved_by: UUID
    decision: Literal["APPROVED", "REJECTED"]
    comment: str | None = Field(default=None, max_length=500)
    decided_at: datetime


class TransferPolicyScopeInputSide(StrictModel):
    catalog: str = Field(min_length=1, max_length=128)
    schema: str = Field(max_length=128)
    table: str = Field(min_length=1, max_length=128)
    selection_mode: Literal["ALL_COLUMNS", "SELECTED_COLUMNS"]
    allowed_columns: list[str] = Field(min_length=1, max_length=2048)

    @field_validator("allowed_columns")
    @classmethod
    def validate_allowed_columns(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("allowed_columns must be unique")
        if any(not column or len(column) > 128 for column in value):
            raise ValueError("allowed_columns entries must contain 1 to 128 characters")
        return value


class TransferPolicyScopeInput(StrictModel):
    schema_version: Literal["1.0"]
    source: TransferPolicyScopeInputSide
    target: TransferPolicyScopeInputSide


class TransferPolicyScopeSide(StrictModel):
    physical_endpoint_identity_id: UUID
    catalog: str = Field(min_length=1, max_length=128)
    schema: str = Field(max_length=128)
    table: str = Field(min_length=1, max_length=128)
    allowed_columns: list[str] = Field(min_length=1, max_length=2048)


class TransferPolicyScope(StrictModel):
    schema_version: Literal["1.0"]
    source: TransferPolicyScopeSide
    target: TransferPolicyScopeSide


class TransferPolicyResponse(StrictModel):
    id: UUID
    project_id: UUID
    source_datasource_revision_id: UUID
    target_datasource_revision_id: UUID
    source_physical_endpoint_identity_id: UUID
    target_physical_endpoint_identity_id: UUID
    scope_json: TransferPolicyScope
    scope_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    classification: PolicyClassification
    status: PolicyStatus
    requested_by: UUID
    approvals: list[TransferPolicyApproval] = Field(max_length=16)
    activated_at: datetime | None
    row_version: int = Field(ge=1)


class TransferPolicyCreate(StrictModel):
    source_datasource_revision_id: UUID
    target_datasource_revision_id: UUID
    requested_scope: TransferPolicyScopeInput
    classification: PolicyClassification


class TransferPolicyPatch(StrictModel):
    source_datasource_revision_id: UUID | None = None
    target_datasource_revision_id: UUID | None = None
    requested_scope: TransferPolicyScopeInput | None = None
    classification: PolicyClassification | None = None
    status: Literal["REVOKED"] | None = None

    @model_validator(mode="after")
    def require_change(self) -> TransferPolicyPatch:
        if not self.model_fields_set:
            raise ValueError("at least one field is required")
        for field_name in self.model_fields_set:
            if getattr(self, field_name) is None:
                raise ValueError(f"{field_name} must not be null")
        return self


class TransferPolicySubmit(StrictModel):
    expected_scope_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class TransferPolicyDecision(StrictModel):
    decision: Literal["APPROVED", "REJECTED"]
    expected_scope_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    comment: str | None = Field(default=None, max_length=500)


class TransferPolicyPage(StrictModel):
    items: list[TransferPolicyResponse]
    next_cursor: str | None
    has_more: bool
