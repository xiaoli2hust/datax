from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol
from uuid import UUID, uuid4

import rfc8785
from sqlalchemy import and_, create_engine, delete, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from datax_studio.api.problems import ProblemException
from datax_studio.auth.db import (
    AuditEvent,
    IdempotencyRecord,
    Organization,
    OrganizationMember,
    Role,
    RoleAssignment,
    ScopeType,
    User,
)
from datax_studio.auth.security import ensure_aware, utc_now
from datax_studio.auth.service import (
    IDEMPOTENCY_HASH_SCHEME,
    AuditContext,
    OperationResult,
    Principal,
)
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    PhysicalEndpointIdentity,
    Project,
    TransferPolicy,
)
from datax_studio.core.db import (
    TransferPolicyApproval as TransferPolicyApprovalRow,
)
from datax_studio.credentials.schemas import TableSchema, TableSchemaPage
from datax_studio.governance.schemas import (
    Member,
    MemberPage,
    RoleReplaceRequest,
    TransferPolicyApproval,
    TransferPolicyCreate,
    TransferPolicyDecision,
    TransferPolicyPage,
    TransferPolicyPatch,
    TransferPolicyResponse,
    TransferPolicyScopeInput,
    TransferPolicyScopeInputSide,
    TransferPolicySubmit,
)
from datax_studio.settings import Settings

_IDEMPOTENCY_HASH_DOMAIN = b"DataXEnterpriseStudio\x00IdempotencyRequestHash\x00v1\x00"
_AUDIT_USER_AGENT_HASH_DOMAIN = b"DataXEnterpriseStudio\x00AuditUserAgentHash\x00v1\x00"
_CURSOR_DOMAIN = b"DataXEnterpriseStudio\x00Cursor\x00v1\x00"
_TRANSFER_POLICY_HASH_DOMAIN = b"DXTRANSFERPOLICYv1\n"
_PROJECT_ROLES = (Role.DEVELOPER, Role.OPERATOR, Role.VIEWER)


class MetadataProbe(Protocol):
    def list_columns(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        usage: str,
        schema_name: str | None,
        table_name: str | None,
        limit: int,
        audit: AuditContext,
    ) -> TableSchemaPage: ...


@dataclass(frozen=True)
class VersionedValue[T]:
    value: T
    row_version: int


@dataclass(frozen=True)
class _RevisionContext:
    project: Project
    source_datasource: Datasource
    source_revision: DatasourceRevision
    target_datasource: Datasource
    target_revision: DatasourceRevision


@dataclass(frozen=True)
class _ScopeMaterial:
    scope_json: dict[str, Any]
    scope_hash: str
    source_physical_endpoint_identity_id: UUID
    target_physical_endpoint_identity_id: UUID


def build_governance_service(settings: Settings) -> GovernanceService:
    engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    return GovernanceService(
        sessions=sessions,
        integrity_hmac_key=settings.idempotency_hmac_key_file.read_bytes(),
    )


class GovernanceService:
    def __init__(
        self,
        *,
        sessions: sessionmaker[Session],
        integrity_hmac_key: bytes,
    ) -> None:
        if len(integrity_hmac_key) < 32:
            raise ValueError("governance integrity HMAC key must contain at least 32 bytes")
        self.sessions = sessions
        self._integrity_hmac_key = bytes(integrity_hmac_key)

    # ------------------------------------------------------------------
    # Project membership
    # ------------------------------------------------------------------
    def list_project_members(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        limit: int,
        cursor: str | None,
    ) -> VersionedValue[MemberPage]:
        self._require_admin_principal(principal)
        with self.sessions() as session:
            self._require_current_admin(session, principal)
            project = self._project_for_organization(
                session,
                principal=principal,
                project_id=project_id,
            )
            cursor_value = (
                self._decode_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    scope=f"GET /projects/{project_id}/members",
                )
                if cursor
                else None
            )
            statement = (
                select(User, OrganizationMember)
                .join(
                    OrganizationMember,
                    OrganizationMember.user_id == User.id,
                )
                .join(
                    RoleAssignment,
                    RoleAssignment.organization_member_id == OrganizationMember.id,
                )
                .where(
                    OrganizationMember.organization_id == principal.organization_id,
                    OrganizationMember.status == "ACTIVE",
                    User.status == "ACTIVE",
                    RoleAssignment.scope_type == ScopeType.PROJECT,
                    RoleAssignment.scope_id == project.id,
                    RoleAssignment.role.in_(_PROJECT_ROLES),
                )
                .distinct()
                .order_by(User.created_at.desc(), User.id.desc())
                .limit(limit + 1)
            )
            if cursor_value is not None:
                created_at, user_id = cursor_value
                statement = statement.where(
                    or_(
                        User.created_at < created_at,
                        and_(
                            User.created_at == created_at,
                            User.id < user_id,
                        ),
                    )
                )
            rows = list(session.execute(statement))
            has_more = len(rows) > limit
            rows = rows[:limit]
            items = [
                self._member_response(
                    session,
                    user=user,
                    organization_member_id=member.id,
                    project_id=project.id,
                )
                for user, member in rows
            ]
            next_cursor = None
            if has_more and rows:
                last_user = rows[-1][0]
                next_cursor = self._encode_cursor(
                    actor_id=principal.user_id,
                    scope=f"GET /projects/{project_id}/members",
                    created_at=last_user.created_at,
                    resource_id=last_user.id,
                )
            return VersionedValue(
                value=MemberPage(
                    items=items,
                    next_cursor=next_cursor,
                    has_more=has_more,
                ),
                row_version=project.row_version,
            )

    def replace_project_member_roles(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        user_id: UUID,
        request: RoleReplaceRequest,
        expected_version: int | None,
        audit: AuditContext,
    ) -> VersionedValue[Member]:
        self._require_admin_principal(principal)
        now = utc_now()
        with self.sessions.begin() as session:
            organization = self._require_current_admin(
                session,
                principal,
                lock=True,
            )
            project = self._project_for_organization(
                session,
                principal=principal,
                project_id=project_id,
                lock=True,
            )
            if project.status != "ACTIVE":
                raise ProblemException(
                    status=409,
                    code="PROJECT_ARCHIVED",
                    title="项目已归档",
                    detail="归档项目不能修改成员角色。",
                )
            if expected_version is not None and project.row_version != expected_version:
                raise ProblemException(
                    status=409,
                    code="VERSION_CONFLICT",
                    title="项目成员列表已被修改",
                    detail="请刷新后重试。",
                )
            member_row = session.execute(
                select(OrganizationMember, User)
                .join(User, User.id == OrganizationMember.user_id)
                .where(
                    OrganizationMember.organization_id == principal.organization_id,
                    OrganizationMember.user_id == user_id,
                    OrganizationMember.status == "ACTIVE",
                    User.status == "ACTIVE",
                )
                .with_for_update()
            ).one_or_none()
            if member_row is None:
                self._not_found()
            member, user = member_row
            existing_roles = set(
                session.scalars(
                    select(RoleAssignment.role).where(
                        RoleAssignment.organization_member_id == member.id,
                        RoleAssignment.scope_type == ScopeType.PROJECT,
                        RoleAssignment.scope_id == project.id,
                    )
                )
            )
            requested_roles = set(request.roles)
            if existing_roles == requested_roles:
                return VersionedValue(
                    value=self._member_response(
                        session,
                        user=user,
                        organization_member_id=member.id,
                        project_id=project.id,
                    ),
                    row_version=project.row_version,
                )
            session.execute(
                delete(RoleAssignment).where(
                    RoleAssignment.organization_member_id == member.id,
                    RoleAssignment.scope_type == ScopeType.PROJECT,
                    RoleAssignment.scope_id == project.id,
                )
            )
            for role in sorted(requested_roles):
                session.add(
                    RoleAssignment(
                        id=uuid4(),
                        organization_member_id=member.id,
                        scope_type=ScopeType.PROJECT,
                        scope_id=project.id,
                        role=role,
                        granted_by=principal.user_id,
                        created_at=now,
                    )
                )
            project.row_version += 1
            project.updated_at = now
            for role in sorted(existing_roles - requested_roles):
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=project.id,
                    action="ROLE_REVOKED",
                    actor_id=principal.user_id,
                    target_type="ROLE_ASSIGNMENT",
                    target_id=user.id,
                    target_name=user.display_name,
                    changed_fields=["role_assignments"],
                    audit=audit,
                    metadata={
                        "role": role,
                        "scope_type": "PROJECT",
                        "scope_id": str(project.id),
                    },
                )
            for role in sorted(requested_roles - existing_roles):
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=project.id,
                    action="ROLE_GRANTED",
                    actor_id=principal.user_id,
                    target_type="ROLE_ASSIGNMENT",
                    target_id=user.id,
                    target_name=user.display_name,
                    changed_fields=["role_assignments"],
                    audit=audit,
                    metadata={
                        "role": role,
                        "scope_type": "PROJECT",
                        "scope_id": str(project.id),
                    },
                )
            session.flush()
            return VersionedValue(
                value=self._member_response(
                    session,
                    user=user,
                    organization_member_id=member.id,
                    project_id=project.id,
                ),
                row_version=project.row_version,
            )

    # ------------------------------------------------------------------
    # Transfer policies
    # ------------------------------------------------------------------
    def list_transfer_policies(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        limit: int,
        cursor: str | None,
    ) -> TransferPolicyPage:
        self._require_admin_principal(principal)
        with self.sessions() as session:
            self._require_current_admin(session, principal)
            project = self._project_for_organization(
                session,
                principal=principal,
                project_id=project_id,
            )
            cursor_value = (
                self._decode_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    scope=f"GET /projects/{project_id}/transfer-policies",
                )
                if cursor
                else None
            )
            statement = (
                select(TransferPolicy)
                .where(TransferPolicy.project_id == project.id)
                .order_by(
                    TransferPolicy.created_at.desc(),
                    TransferPolicy.id.desc(),
                )
                .limit(limit + 1)
            )
            if cursor_value is not None:
                created_at, policy_id = cursor_value
                statement = statement.where(
                    or_(
                        TransferPolicy.created_at < created_at,
                        and_(
                            TransferPolicy.created_at == created_at,
                            TransferPolicy.id < policy_id,
                        ),
                    )
                )
            policies = list(session.scalars(statement))
            has_more = len(policies) > limit
            policies = policies[:limit]
            next_cursor = None
            if has_more and policies:
                next_cursor = self._encode_cursor(
                    actor_id=principal.user_id,
                    scope=f"GET /projects/{project_id}/transfer-policies",
                    created_at=policies[-1].created_at,
                    resource_id=policies[-1].id,
                )
            return TransferPolicyPage(
                items=[self._transfer_policy_response(session, policy) for policy in policies],
                next_cursor=next_cursor,
                has_more=has_more,
            )

    def create_transfer_policy(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        request: TransferPolicyCreate,
        idempotency_key: str,
        audit: AuditContext,
        metadata_probe: MetadataProbe,
    ) -> OperationResult[TransferPolicyResponse]:
        self._require_admin_principal(principal)
        body = request.model_dump(mode="json")
        idempotency_scope = f"POST /projects/{project_id}/transfer-policies"
        with self.sessions() as session:
            self._require_current_admin(session, principal)
            replay = self._idempotent_replay(
                session,
                actor_id=principal.user_id,
                scope=idempotency_scope,
                key=idempotency_key,
                body=body,
                response_model=TransferPolicyResponse,
            )
            if replay is not None:
                return OperationResult(value=replay, replayed=True)
            context = self._revision_context(
                session,
                principal=principal,
                project_id=project_id,
                source_revision_id=request.source_datasource_revision_id,
                target_revision_id=request.target_datasource_revision_id,
            )
        material = self._probe_and_normalize_scope(
            principal=principal,
            context=context,
            requested_scope=request.requested_scope,
            metadata_probe=metadata_probe,
            audit=audit,
        )
        now = utc_now()
        with self.sessions.begin() as session:
            organization = self._require_current_admin(
                session,
                principal,
                lock=True,
            )
            replay = self._claim_idempotency(
                session,
                actor_id=principal.user_id,
                scope=idempotency_scope,
                key=idempotency_key,
                body=body,
                now=now,
            )
            if replay is not None:
                return OperationResult(
                    value=TransferPolicyResponse.model_validate(replay.response_body),
                    replayed=True,
                )
            locked_context = self._revision_context(
                session,
                principal=principal,
                project_id=project_id,
                source_revision_id=request.source_datasource_revision_id,
                target_revision_id=request.target_datasource_revision_id,
                lock=True,
            )
            self._assert_material_matches_context(material, locked_context)
            policy = TransferPolicy(
                id=uuid4(),
                project_id=locked_context.project.id,
                source_datasource_revision_id=locked_context.source_revision.id,
                target_datasource_revision_id=locked_context.target_revision.id,
                source_physical_endpoint_identity_id=(
                    material.source_physical_endpoint_identity_id
                ),
                target_physical_endpoint_identity_id=(
                    material.target_physical_endpoint_identity_id
                ),
                scope_json=material.scope_json,
                scope_hash=material.scope_hash,
                classification=request.classification,
                status="DRAFT",
                requested_by=principal.user_id,
                activated_at=None,
                revoked_by=None,
                revoked_at=None,
                created_at=now,
                updated_at=now,
                row_version=1,
            )
            session.add(policy)
            session.flush()
            self._append_audit(
                session,
                organization=organization,
                project_id=policy.project_id,
                action="TRANSFER_POLICY_CREATED",
                actor_id=principal.user_id,
                target_type="TRANSFER_POLICY",
                target_id=policy.id,
                target_name=None,
                changed_fields=[
                    "classification",
                    "scope_hash",
                    "source_datasource_revision_id",
                    "target_datasource_revision_id",
                ],
                audit=audit,
                metadata={
                    "classification": policy.classification,
                    "scope_hash": policy.scope_hash,
                },
            )
            response = self._transfer_policy_response(session, policy)
            self._complete_idempotency(
                session,
                actor_id=principal.user_id,
                scope=idempotency_scope,
                key=idempotency_key,
                status=201,
                body=response.model_dump(mode="json"),
                resource_type="TRANSFER_POLICY",
                resource_id=policy.id,
            )
            return OperationResult(value=response)

    def get_transfer_policy(
        self,
        *,
        principal: Principal,
        transfer_policy_id: UUID,
    ) -> TransferPolicyResponse:
        self._require_admin_principal(principal)
        with self.sessions() as session:
            self._require_current_admin(session, principal)
            policy, _project = self._visible_policy(
                session,
                principal=principal,
                transfer_policy_id=transfer_policy_id,
            )
            return self._transfer_policy_response(session, policy)

    def update_transfer_policy(
        self,
        *,
        principal: Principal,
        transfer_policy_id: UUID,
        request: TransferPolicyPatch,
        expected_version: int,
        audit: AuditContext,
        metadata_probe: MetadataProbe,
    ) -> TransferPolicyResponse:
        self._require_admin_principal(principal)
        fields = set(request.model_fields_set)
        if "status" in fields and fields != {"status"}:
            self._validation_problem(
                "status",
                "撤销策略不能与范围或分类修改同时提交。",
            )

        material: _ScopeMaterial | None = None
        requested_source_revision_id: UUID | None = None
        requested_target_revision_id: UUID | None = None
        with self.sessions() as session:
            self._require_current_admin(session, principal)
            policy, project = self._visible_policy(
                session,
                principal=principal,
                transfer_policy_id=transfer_policy_id,
            )
            if policy.row_version != expected_version:
                self._version_conflict()
            if fields == {"status"}:
                if policy.status != "ACTIVE":
                    raise ProblemException(
                        status=409,
                        code="TRANSFER_POLICY_NOT_ACTIVE",
                        title="只有生效策略可以撤销",
                        detail="请刷新策略状态后重试。",
                    )
            else:
                if policy.status in {"ACTIVE", "REVOKED"}:
                    raise ProblemException(
                        status=409,
                        code="TRANSFER_POLICY_IMMUTABLE",
                        title="当前策略不可修订",
                        detail="ACTIVE 仅允许撤销，REVOKED 不允许再次修改。",
                    )
                requested_source_revision_id = (
                    request.source_datasource_revision_id
                    if "source_datasource_revision_id" in fields
                    else policy.source_datasource_revision_id
                )
                requested_target_revision_id = (
                    request.target_datasource_revision_id
                    if "target_datasource_revision_id" in fields
                    else policy.target_datasource_revision_id
                )
                context = self._revision_context(
                    session,
                    principal=principal,
                    project_id=project.id,
                    source_revision_id=requested_source_revision_id,
                    target_revision_id=requested_target_revision_id,
                )
                if fields & {
                    "source_datasource_revision_id",
                    "target_datasource_revision_id",
                    "requested_scope",
                }:
                    requested_scope = (
                        request.requested_scope
                        if "requested_scope" in fields
                        else self._scope_input_from_stored(policy.scope_json)
                    )
                    if requested_scope is None:
                        raise RuntimeError("requested scope unexpectedly missing")
                    material = self._probe_and_normalize_scope(
                        principal=principal,
                        context=context,
                        requested_scope=requested_scope,
                        metadata_probe=metadata_probe,
                        audit=audit,
                    )

        now = utc_now()
        with self.sessions.begin() as session:
            organization = self._require_current_admin(
                session,
                principal,
                lock=True,
            )
            policy, project = self._visible_policy(
                session,
                principal=principal,
                transfer_policy_id=transfer_policy_id,
                lock=True,
            )
            if policy.row_version != expected_version:
                self._version_conflict()
            if fields == {"status"}:
                if policy.status != "ACTIVE":
                    raise ProblemException(
                        status=409,
                        code="TRANSFER_POLICY_NOT_ACTIVE",
                        title="只有生效策略可以撤销",
                        detail="请刷新策略状态后重试。",
                    )
                policy.status = "REVOKED"
                policy.revoked_by = principal.user_id
                policy.revoked_at = now
                changed_fields = ["status"]
                action = "TRANSFER_POLICY_REVOKED"
            else:
                if policy.status in {"ACTIVE", "REVOKED"}:
                    raise ProblemException(
                        status=409,
                        code="TRANSFER_POLICY_IMMUTABLE",
                        title="当前策略不可修订",
                        detail="ACTIVE 仅允许撤销，REVOKED 不允许再次修改。",
                    )
                if requested_source_revision_id is None or requested_target_revision_id is None:
                    raise RuntimeError("revision ids unexpectedly missing")
                locked_context = self._revision_context(
                    session,
                    principal=principal,
                    project_id=project.id,
                    source_revision_id=requested_source_revision_id,
                    target_revision_id=requested_target_revision_id,
                    lock=True,
                )
                changed_fields = sorted(fields | {"status", "approvals"})
                if material is not None:
                    self._assert_material_matches_context(
                        material,
                        locked_context,
                    )
                    policy.source_datasource_revision_id = locked_context.source_revision.id
                    policy.target_datasource_revision_id = locked_context.target_revision.id
                    policy.source_physical_endpoint_identity_id = (
                        material.source_physical_endpoint_identity_id
                    )
                    policy.target_physical_endpoint_identity_id = (
                        material.target_physical_endpoint_identity_id
                    )
                    policy.scope_json = material.scope_json
                    policy.scope_hash = material.scope_hash
                if "classification" in fields:
                    if request.classification is None:
                        raise RuntimeError("classification unexpectedly missing")
                    policy.classification = request.classification
                session.execute(
                    delete(TransferPolicyApprovalRow).where(
                        TransferPolicyApprovalRow.transfer_policy_id == policy.id
                    )
                )
                policy.status = "DRAFT"
                policy.requested_by = principal.user_id
                policy.activated_at = None
                policy.revoked_by = None
                policy.revoked_at = None
                action = "TRANSFER_POLICY_UPDATED"
            policy.updated_at = now
            policy.row_version += 1
            self._append_audit(
                session,
                organization=organization,
                project_id=project.id,
                action=action,
                actor_id=principal.user_id,
                target_type="TRANSFER_POLICY",
                target_id=policy.id,
                target_name=None,
                changed_fields=changed_fields,
                audit=audit,
                metadata={
                    "scope_hash": policy.scope_hash,
                    "status": policy.status,
                },
            )
            session.flush()
            return self._transfer_policy_response(session, policy)

    def submit_transfer_policy(
        self,
        *,
        principal: Principal,
        transfer_policy_id: UUID,
        request: TransferPolicySubmit,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[TransferPolicyResponse]:
        self._require_admin_principal(principal)
        body = request.model_dump(mode="json")
        scope = f"POST /transfer-policies/{transfer_policy_id}/submit"
        now = utc_now()
        with self.sessions.begin() as session:
            organization = self._require_current_admin(
                session,
                principal,
                lock=True,
            )
            replay = self._claim_idempotency(
                session,
                actor_id=principal.user_id,
                scope=scope,
                key=idempotency_key,
                body=body,
                now=now,
            )
            if replay is not None:
                return OperationResult(
                    value=TransferPolicyResponse.model_validate(replay.response_body),
                    replayed=True,
                )
            policy, project = self._visible_policy(
                session,
                principal=principal,
                transfer_policy_id=transfer_policy_id,
                lock=True,
            )
            if policy.status != "DRAFT":
                raise ProblemException(
                    status=409,
                    code="TRANSFER_POLICY_NOT_DRAFT",
                    title="只有草稿策略可以提交",
                    detail="请刷新策略状态后重试。",
                )
            self._require_expected_scope_hash(
                policy,
                request.expected_scope_hash,
            )
            self._revision_context(
                session,
                principal=principal,
                project_id=project.id,
                source_revision_id=policy.source_datasource_revision_id,
                target_revision_id=policy.target_datasource_revision_id,
                lock=True,
            )
            existing_approval = session.scalar(
                select(TransferPolicyApprovalRow.id).where(
                    TransferPolicyApprovalRow.transfer_policy_id == policy.id
                )
            )
            if existing_approval is not None:
                raise ProblemException(
                    status=409,
                    code="TRANSFER_POLICY_STALE_APPROVALS",
                    title="草稿仍包含旧审批",
                    detail="已拒绝提交不一致的审批状态。",
                )
            policy.status = "PENDING_APPROVAL"
            policy.updated_at = now
            policy.row_version += 1
            self._append_audit(
                session,
                organization=organization,
                project_id=project.id,
                action="TRANSFER_POLICY_SUBMITTED",
                actor_id=principal.user_id,
                target_type="TRANSFER_POLICY",
                target_id=policy.id,
                target_name=None,
                changed_fields=["status"],
                audit=audit,
                metadata={"scope_hash": policy.scope_hash},
            )
            session.flush()
            response = self._transfer_policy_response(session, policy)
            self._complete_idempotency(
                session,
                actor_id=principal.user_id,
                scope=scope,
                key=idempotency_key,
                status=200,
                body=response.model_dump(mode="json"),
                resource_type="TRANSFER_POLICY",
                resource_id=policy.id,
            )
            return OperationResult(value=response)

    def decide_transfer_policy(
        self,
        *,
        principal: Principal,
        transfer_policy_id: UUID,
        request: TransferPolicyDecision,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[TransferPolicyResponse]:
        self._require_admin_principal(principal)
        body = request.model_dump(mode="json")
        scope = f"POST /transfer-policies/{transfer_policy_id}/approvals"
        now = utc_now()
        with self.sessions.begin() as session:
            organization = self._require_current_admin(
                session,
                principal,
                lock=True,
            )
            replay = self._claim_idempotency(
                session,
                actor_id=principal.user_id,
                scope=scope,
                key=idempotency_key,
                body=body,
                now=now,
            )
            if replay is not None:
                return OperationResult(
                    value=TransferPolicyResponse.model_validate(replay.response_body),
                    replayed=True,
                )
            policy, project = self._visible_policy(
                session,
                principal=principal,
                transfer_policy_id=transfer_policy_id,
                lock=True,
            )
            if policy.status != "PENDING_APPROVAL":
                raise ProblemException(
                    status=409,
                    code="TRANSFER_POLICY_NOT_PENDING",
                    title="策略当前不可审批",
                    detail="仅 PENDING_APPROVAL 状态可审批。",
                )
            self._require_expected_scope_hash(
                policy,
                request.expected_scope_hash,
            )
            if policy.requested_by == principal.user_id:
                raise ProblemException(
                    status=403,
                    code="TRANSFER_POLICY_SELF_APPROVAL_FORBIDDEN",
                    title="申请人不能审批自己的策略",
                    detail="请由另一名组织 Admin 独立审批。",
                )
            prior_decision = session.scalar(
                select(TransferPolicyApprovalRow.id).where(
                    TransferPolicyApprovalRow.transfer_policy_id == policy.id,
                    TransferPolicyApprovalRow.approved_by == principal.user_id,
                )
            )
            if prior_decision is not None:
                raise ProblemException(
                    status=409,
                    code="TRANSFER_POLICY_ALREADY_DECIDED",
                    title="当前管理员已经审批",
                    detail="每名 Admin 对同一版本只能提交一次决定。",
                )
            self._revision_context(
                session,
                principal=principal,
                project_id=project.id,
                source_revision_id=policy.source_datasource_revision_id,
                target_revision_id=policy.target_datasource_revision_id,
                lock=True,
            )
            approval = TransferPolicyApprovalRow(
                id=uuid4(),
                transfer_policy_id=policy.id,
                approved_by=principal.user_id,
                decision=request.decision,
                comment=self._clean_optional(request.comment),
                decided_at=now,
            )
            session.add(approval)
            if request.decision == "REJECTED":
                policy.status = "REJECTED"
            else:
                session.flush()
                approved_count = session.scalar(
                    select(func.count())
                    .select_from(TransferPolicyApprovalRow)
                    .where(
                        TransferPolicyApprovalRow.transfer_policy_id == policy.id,
                        TransferPolicyApprovalRow.decision == "APPROVED",
                    )
                )
                threshold = 1 if policy.classification == "STANDARD" else 2
                if approved_count >= threshold:
                    conflict = session.scalar(
                        select(TransferPolicy.id).where(
                            TransferPolicy.project_id == project.id,
                            TransferPolicy.status == "ACTIVE",
                            TransferPolicy.source_datasource_revision_id
                            == policy.source_datasource_revision_id,
                            TransferPolicy.target_datasource_revision_id
                            == policy.target_datasource_revision_id,
                            TransferPolicy.id != policy.id,
                        )
                    )
                    if conflict is not None:
                        raise ProblemException(
                            status=409,
                            code="TRANSFER_POLICY_ACTIVE_CONFLICT",
                            title="相同修订对已有生效策略",
                            detail=(
                                "同一 source/target DatasourceRevision 对只允许一个 ACTIVE 策略。"
                            ),
                        )
                    policy.status = "ACTIVE"
                    policy.activated_at = now
            policy.updated_at = now
            policy.row_version += 1
            self._append_audit(
                session,
                organization=organization,
                project_id=project.id,
                action=(
                    "TRANSFER_POLICY_REJECTED"
                    if request.decision == "REJECTED"
                    else "TRANSFER_POLICY_APPROVED"
                ),
                actor_id=principal.user_id,
                target_type="TRANSFER_POLICY",
                target_id=policy.id,
                target_name=None,
                changed_fields=["approvals", "status"],
                audit=audit,
                metadata={
                    "decision": request.decision,
                    "scope_hash": policy.scope_hash,
                    "resulting_status": policy.status,
                },
            )
            session.flush()
            response = self._transfer_policy_response(session, policy)
            self._complete_idempotency(
                session,
                actor_id=principal.user_id,
                scope=scope,
                key=idempotency_key,
                status=200,
                body=response.model_dump(mode="json"),
                resource_type="TRANSFER_POLICY",
                resource_id=policy.id,
            )
            return OperationResult(value=response)

    # ------------------------------------------------------------------
    # Authorization and persistence helpers
    # ------------------------------------------------------------------
    def _require_admin_principal(self, principal: Principal) -> None:
        if principal.must_change_password:
            raise ProblemException(
                status=403,
                code="PASSWORD_CHANGE_REQUIRED",
                title="必须先修改临时密码",
                detail="完成本人密码修改后才能访问治理接口。",
            )
        if not principal.is_admin:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限执行此操作",
                detail="需要组织级 Admin 权限。",
            )

    def _require_current_admin(
        self,
        session: Session,
        principal: Principal,
        *,
        lock: bool = False,
    ) -> Organization:
        organization_statement = select(Organization).where(
            Organization.id == principal.organization_id,
            Organization.status == "ACTIVE",
        )
        if lock:
            organization_statement = organization_statement.with_for_update()
        organization = session.scalar(organization_statement)
        if organization is None:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="组织当前不可用",
                detail="组织不存在或已被停用。",
            )
        member = session.scalar(
            select(OrganizationMember)
            .join(User, User.id == OrganizationMember.user_id)
            .where(
                OrganizationMember.organization_id == organization.id,
                OrganizationMember.user_id == principal.user_id,
                OrganizationMember.status == "ACTIVE",
                User.status == "ACTIVE",
                User.must_change_password.is_(False),
            )
        )
        if member is None:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="组织成员身份不可用",
                detail="需要有效组织成员身份并完成首次改密。",
            )
        assignment = session.scalar(
            select(RoleAssignment.id).where(
                RoleAssignment.organization_member_id == member.id,
                RoleAssignment.scope_type == ScopeType.ORGANIZATION,
                RoleAssignment.scope_id == organization.id,
                RoleAssignment.role == Role.ADMIN,
            )
        )
        if assignment is None:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="组织 Admin 权限已失效",
                detail="请刷新登录状态后重试。",
            )
        return organization

    def _require_current_project_reader(
        self,
        session: Session,
        *,
        principal: Principal,
        project: Project,
    ) -> None:
        if principal.must_change_password:
            raise ProblemException(
                status=403,
                code="PASSWORD_CHANGE_REQUIRED",
                title="必须先修改临时密码",
                detail="完成本人密码修改后才能访问治理接口。",
            )
        member = session.scalar(
            select(OrganizationMember)
            .join(User, User.id == OrganizationMember.user_id)
            .where(
                OrganizationMember.organization_id == project.organization_id,
                OrganizationMember.user_id == principal.user_id,
                OrganizationMember.status == "ACTIVE",
                User.status == "ACTIVE",
                User.must_change_password.is_(False),
            )
        )
        if member is None:
            self._not_found()
        allowed = session.scalar(
            select(RoleAssignment.id).where(
                RoleAssignment.organization_member_id == member.id,
                or_(
                    and_(
                        RoleAssignment.scope_type == ScopeType.ORGANIZATION,
                        RoleAssignment.scope_id == project.organization_id,
                        RoleAssignment.role == Role.ADMIN,
                    ),
                    and_(
                        RoleAssignment.scope_type == ScopeType.PROJECT,
                        RoleAssignment.scope_id == project.id,
                        RoleAssignment.role.in_(_PROJECT_ROLES),
                    ),
                ),
            )
        )
        if allowed is None:
            self._not_found()

    def _project_for_organization(
        self,
        session: Session,
        *,
        principal: Principal,
        project_id: UUID,
        lock: bool = False,
    ) -> Project:
        statement = select(Project).where(
            Project.id == project_id,
            Project.organization_id == principal.organization_id,
        )
        if lock:
            statement = statement.with_for_update()
        project = session.scalar(statement)
        if project is None:
            self._not_found()
        return project

    def _visible_policy(
        self,
        session: Session,
        *,
        principal: Principal,
        transfer_policy_id: UUID,
        lock: bool = False,
    ) -> tuple[TransferPolicy, Project]:
        statement = (
            select(TransferPolicy, Project)
            .join(Project, Project.id == TransferPolicy.project_id)
            .where(
                TransferPolicy.id == transfer_policy_id,
                Project.organization_id == principal.organization_id,
            )
        )
        if lock:
            statement = statement.with_for_update()
        row = session.execute(statement).one_or_none()
        if row is None:
            self._not_found()
        return row

    def _revision_context(
        self,
        session: Session,
        *,
        principal: Principal,
        project_id: UUID,
        source_revision_id: UUID,
        target_revision_id: UUID,
        lock: bool = False,
    ) -> _RevisionContext:
        project = self._project_for_organization(
            session,
            principal=principal,
            project_id=project_id,
            lock=lock,
        )
        if project.status != "ACTIVE":
            raise ProblemException(
                status=409,
                code="PROJECT_ARCHIVED",
                title="项目已归档",
                detail="归档项目不能创建或推进传输策略。",
            )

        def load_revision(
            revision_id: UUID,
        ) -> tuple[DatasourceRevision, Datasource]:
            statement = (
                select(DatasourceRevision, Datasource)
                .join(
                    Datasource,
                    Datasource.id == DatasourceRevision.datasource_id,
                )
                .where(
                    DatasourceRevision.id == revision_id,
                    Datasource.project_id == project.id,
                )
            )
            if lock:
                statement = statement.with_for_update()
            row = session.execute(statement).one_or_none()
            if row is None:
                self._not_found()
            revision, datasource = row
            if datasource.status != "ACTIVE" or datasource.current_revision_id != revision.id:
                raise ProblemException(
                    status=409,
                    code="DATASOURCE_REVISION_NOT_CURRENT",
                    title="数据源修订当前不可用",
                    detail="策略只能固定项目内处于 ACTIVE 的当前数据源修订。",
                )
            identity = session.scalar(
                select(PhysicalEndpointIdentity.id).where(
                    PhysicalEndpointIdentity.id == revision.physical_endpoint_identity_id,
                    PhysicalEndpointIdentity.organization_id == principal.organization_id,
                    PhysicalEndpointIdentity.engine == revision.engine,
                )
            )
            if identity is None:
                raise ProblemException(
                    status=409,
                    code="PHYSICAL_ENDPOINT_IDENTITY_INVALID",
                    title="物理端点身份不可用",
                    detail="数据源修订与组织物理端点身份不一致。",
                )
            return revision, datasource

        source_revision, source_datasource = load_revision(source_revision_id)
        target_revision, target_datasource = load_revision(target_revision_id)
        return _RevisionContext(
            project=project,
            source_datasource=source_datasource,
            source_revision=source_revision,
            target_datasource=target_datasource,
            target_revision=target_revision,
        )

    # ------------------------------------------------------------------
    # Metadata normalization and policy hashing
    # ------------------------------------------------------------------
    def _probe_and_normalize_scope(
        self,
        *,
        principal: Principal,
        context: _RevisionContext,
        requested_scope: TransferPolicyScopeInput,
        metadata_probe: MetadataProbe,
        audit: AuditContext,
    ) -> _ScopeMaterial:
        self._validate_requested_side_before_probe(
            requested_scope.source,
            context.source_revision,
            field="source",
        )
        self._validate_requested_side_before_probe(
            requested_scope.target,
            context.target_revision,
            field="target",
        )
        try:
            source_page = metadata_probe.list_columns(
                principal=principal,
                datasource_id=context.source_datasource.id,
                usage="SOURCE_USE",
                schema_name=(
                    requested_scope.source.schema
                    if context.source_revision.engine == "POSTGRESQL_15"
                    else None
                ),
                table_name=requested_scope.source.table,
                limit=2,
                audit=audit,
            )
            target_page = metadata_probe.list_columns(
                principal=principal,
                datasource_id=context.target_datasource.id,
                usage="TARGET_USE",
                schema_name=(
                    requested_scope.target.schema
                    if context.target_revision.engine == "POSTGRESQL_15"
                    else None
                ),
                table_name=requested_scope.target.table,
                limit=2,
                audit=audit,
            )
        except Exception as exc:
            raise ProblemException(
                status=503,
                code="DATASOURCE_METADATA_UNAVAILABLE",
                title="无法固定传输范围",
                detail="真实数据库元数据当前不可用；未创建或修改策略。",
                retryable=True,
            ) from exc
        source_table = self._single_table(source_page, field="source")
        target_table = self._single_table(target_page, field="target")
        if hmac.compare_digest(
            source_table.physical_table_identity_hash,
            target_table.physical_table_identity_hash,
        ):
            raise ProblemException(
                status=422,
                code="TRANSFER_POLICY_SELF_COPY_FORBIDDEN",
                title="源表与目标表是同一物理表",
                detail="V1 不允许同表自复制。",
                field_errors=[
                    {
                        "field": "requested_scope.target",
                        "message": "target must not resolve to the source table",
                    }
                ],
            )
        source = self._normalize_side(
            requested_scope.source,
            revision=context.source_revision,
            table=source_table,
            field="source",
            require_target_compatibility=False,
        )
        target = self._normalize_side(
            requested_scope.target,
            revision=context.target_revision,
            table=target_table,
            field="target",
            require_target_compatibility=True,
        )
        if (
            context.source_revision.physical_endpoint_identity_id
            == context.target_revision.physical_endpoint_identity_id
            and source["catalog"] == target["catalog"]
            and source["schema"] == target["schema"]
            and source["table"] == target["table"]
        ):
            raise ProblemException(
                status=422,
                code="TRANSFER_POLICY_SELF_COPY_FORBIDDEN",
                title="源表与目标表是同一物理表",
                detail="V1 不允许同表自复制。",
            )
        scope_json: dict[str, Any] = {
            "schema_version": "1.0",
            "source": source,
            "target": target,
        }
        scope_hash = hashlib.sha256(
            _TRANSFER_POLICY_HASH_DOMAIN + rfc8785.dumps(scope_json)
        ).hexdigest()
        return _ScopeMaterial(
            scope_json=scope_json,
            scope_hash=scope_hash,
            source_physical_endpoint_identity_id=(
                context.source_revision.physical_endpoint_identity_id
            ),
            target_physical_endpoint_identity_id=(
                context.target_revision.physical_endpoint_identity_id
            ),
        )

    def _validate_requested_side_before_probe(
        self,
        requested: TransferPolicyScopeInputSide,
        revision: DatasourceRevision,
        *,
        field: str,
    ) -> None:
        if requested.catalog != revision.database_name:
            self._validation_problem(
                f"requested_scope.{field}.catalog",
                "catalog 必须与所选 DatasourceRevision 的 database_name 完全一致。",
            )
        if revision.engine == "MYSQL_8" and requested.schema != "":
            self._validation_problem(
                f"requested_scope.{field}.schema",
                "MySQL 规范化 schema 必须使用空字符串。",
            )
        if revision.engine == "POSTGRESQL_15" and not requested.schema:
            self._validation_problem(
                f"requested_scope.{field}.schema",
                "PostgreSQL 必须提交明确 schema。",
            )

    def _single_table(
        self,
        page: TableSchemaPage,
        *,
        field: str,
    ) -> TableSchema:
        if page.has_more or len(page.items) != 1:
            raise ProblemException(
                status=422,
                code="TRANSFER_POLICY_TABLE_NOT_EXACT",
                title="无法唯一确定物理表",
                detail="真实元数据必须精确返回一个表。",
                field_errors=[
                    {
                        "field": f"requested_scope.{field}.table",
                        "message": "must resolve to exactly one table",
                    }
                ],
            )
        return page.items[0]

    def _normalize_side(
        self,
        requested: TransferPolicyScopeInputSide,
        *,
        revision: DatasourceRevision,
        table: TableSchema,
        field: str,
        require_target_compatibility: bool,
    ) -> dict[str, Any]:
        if requested.table != table.table_name:
            self._validation_problem(
                f"requested_scope.{field}.table",
                "table 必须与真实元数据返回的标识符完全一致。",
            )
        normalized_schema = ""
        if revision.engine == "POSTGRESQL_15":
            if requested.schema != table.schema_name:
                self._validation_problem(
                    f"requested_scope.{field}.schema",
                    "schema 必须与真实元数据返回的标识符完全一致。",
                )
            normalized_schema = table.schema_name
        if not table.oracle_compatible:
            raise ProblemException(
                status=422,
                code="TRANSFER_POLICY_ORACLE_INCOMPATIBLE",
                title="表结构不支持独立核验",
                detail=f"{field} 表不满足 V1 oracle 兼容性要求。",
                details={"incompatibility_reasons": table.incompatibility_reasons},
            )
        if require_target_compatibility and not table.target_insert_compatible:
            raise ProblemException(
                status=422,
                code="TRANSFER_POLICY_TARGET_INCOMPATIBLE",
                title="目标表不支持 insert-only 写入",
                detail="目标表不满足 V1 目标兼容性要求。",
                details={"incompatibility_reasons": table.incompatibility_reasons},
            )
        actual_columns = {column.name: column for column in table.columns}
        if not actual_columns:
            self._validation_problem(
                f"requested_scope.{field}.allowed_columns",
                "真实表必须至少包含一列。",
            )
        requested_names = set(requested.allowed_columns)
        if requested.selection_mode == "ALL_COLUMNS":
            if requested_names != set(actual_columns):
                self._validation_problem(
                    f"requested_scope.{field}.allowed_columns",
                    "ALL_COLUMNS 必须完整显式展开当前真实元数据中的全部列。",
                )
        elif not requested_names.issubset(actual_columns):
            self._validation_problem(
                f"requested_scope.{field}.allowed_columns",
                "SELECTED_COLUMNS 只能包含真实元数据中的精确列名。",
            )
        selected_columns = [actual_columns[name] for name in requested_names]
        if any(not column.oracle_supported for column in selected_columns):
            self._validation_problem(
                f"requested_scope.{field}.allowed_columns",
                "所选列包含 oracle 不支持的类型或生成列。",
            )
        if require_target_compatibility and any(column.generated for column in selected_columns):
            self._validation_problem(
                f"requested_scope.{field}.allowed_columns",
                "目标允许列不能包含生成列。",
            )
        return {
            "physical_endpoint_identity_id": str(revision.physical_endpoint_identity_id),
            "catalog": revision.database_name,
            "schema": normalized_schema,
            "table": table.table_name,
            "allowed_columns": sorted(
                requested_names,
                key=lambda value: value.encode("utf-8"),
            ),
        }

    def _scope_input_from_stored(
        self,
        scope_json: dict[str, Any],
    ) -> TransferPolicyScopeInput:
        return TransferPolicyScopeInput.model_validate(
            {
                "schema_version": "1.0",
                "source": {
                    "catalog": scope_json["source"]["catalog"],
                    "schema": scope_json["source"]["schema"],
                    "table": scope_json["source"]["table"],
                    "selection_mode": "SELECTED_COLUMNS",
                    "allowed_columns": scope_json["source"]["allowed_columns"],
                },
                "target": {
                    "catalog": scope_json["target"]["catalog"],
                    "schema": scope_json["target"]["schema"],
                    "table": scope_json["target"]["table"],
                    "selection_mode": "SELECTED_COLUMNS",
                    "allowed_columns": scope_json["target"]["allowed_columns"],
                },
            }
        )

    def _assert_material_matches_context(
        self,
        material: _ScopeMaterial,
        context: _RevisionContext,
    ) -> None:
        if (
            material.source_physical_endpoint_identity_id
            != context.source_revision.physical_endpoint_identity_id
            or material.target_physical_endpoint_identity_id
            != context.target_revision.physical_endpoint_identity_id
        ):
            raise ProblemException(
                status=409,
                code="DATASOURCE_REVISION_CHANGED",
                title="数据源修订在元数据探测期间发生变化",
                detail="未保存策略，请刷新后重试。",
            )

    # ------------------------------------------------------------------
    # Response, idempotency, audit, and cursor helpers
    # ------------------------------------------------------------------
    def _member_response(
        self,
        session: Session,
        *,
        user: User,
        organization_member_id: UUID,
        project_id: UUID,
    ) -> Member:
        roles = list(
            session.scalars(
                select(RoleAssignment.role)
                .where(
                    RoleAssignment.organization_member_id == organization_member_id,
                    RoleAssignment.scope_type == ScopeType.PROJECT,
                    RoleAssignment.scope_id == project_id,
                    RoleAssignment.role.in_(_PROJECT_ROLES),
                )
                .order_by(RoleAssignment.role)
            )
        )
        return Member(
            organization_member_id=organization_member_id,
            user={
                "id": user.id,
                "email": user.email,
                "display_name": user.display_name,
                "must_change_password": user.must_change_password,
            },
            roles=roles,
        )

    def _transfer_policy_response(
        self,
        session: Session,
        policy: TransferPolicy,
    ) -> TransferPolicyResponse:
        approvals = list(
            session.scalars(
                select(TransferPolicyApprovalRow)
                .where(TransferPolicyApprovalRow.transfer_policy_id == policy.id)
                .order_by(
                    TransferPolicyApprovalRow.decided_at,
                    TransferPolicyApprovalRow.id,
                )
            )
        )
        return TransferPolicyResponse(
            id=policy.id,
            project_id=policy.project_id,
            source_datasource_revision_id=(policy.source_datasource_revision_id),
            target_datasource_revision_id=(policy.target_datasource_revision_id),
            source_physical_endpoint_identity_id=(policy.source_physical_endpoint_identity_id),
            target_physical_endpoint_identity_id=(policy.target_physical_endpoint_identity_id),
            scope_json=policy.scope_json,
            scope_hash=policy.scope_hash,
            classification=policy.classification,
            status=policy.status,
            requested_by=policy.requested_by,
            approvals=[
                TransferPolicyApproval(
                    id=approval.id,
                    approved_by=approval.approved_by,
                    decision=approval.decision,
                    comment=approval.comment,
                    decided_at=ensure_aware(approval.decided_at),
                )
                for approval in approvals
            ],
            activated_at=(
                ensure_aware(policy.activated_at) if policy.activated_at is not None else None
            ),
            row_version=policy.row_version,
        )

    def _require_expected_scope_hash(
        self,
        policy: TransferPolicy,
        expected_scope_hash: str,
    ) -> None:
        if not hmac.compare_digest(policy.scope_hash, expected_scope_hash):
            raise ProblemException(
                status=409,
                code="TRANSFER_POLICY_SCOPE_HASH_MISMATCH",
                title="策略范围已变化",
                detail="请刷新后使用当前 scope_hash 重试。",
            )

    def _idempotent_replay[T](
        self,
        session: Session,
        *,
        actor_id: UUID,
        scope: str,
        key: str,
        body: dict[str, Any],
        response_model: type[T],
    ) -> T | None:
        record = session.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.actor_id == actor_id,
                IdempotencyRecord.scope == scope,
                IdempotencyRecord.idempotency_key == key,
            )
        )
        if record is None or ensure_aware(record.expires_at) <= utc_now():
            return None
        self._validate_idempotency_record(
            record,
            actor_id=actor_id,
            scope=scope,
            body=body,
        )
        if record.response_body is None:
            raise ProblemException(
                status=409,
                code="IDEMPOTENCY_IN_PROGRESS",
                title="相同请求仍在处理中",
                detail="请稍后使用相同 Idempotency-Key 重试。",
                retryable=True,
                headers={"Retry-After": "1"},
            )
        return response_model.model_validate(record.response_body)  # type: ignore[attr-defined]

    def _claim_idempotency(
        self,
        session: Session,
        *,
        actor_id: UUID,
        scope: str,
        key: str,
        body: dict[str, Any],
        now: datetime,
    ) -> IdempotencyRecord | None:
        record = session.scalar(
            select(IdempotencyRecord)
            .where(
                IdempotencyRecord.actor_id == actor_id,
                IdempotencyRecord.scope == scope,
                IdempotencyRecord.idempotency_key == key,
            )
            .with_for_update()
        )
        if record is not None and ensure_aware(record.expires_at) <= now:
            session.delete(record)
            session.flush()
            record = None
        if record is not None:
            self._validate_idempotency_record(
                record,
                actor_id=actor_id,
                scope=scope,
                body=body,
            )
            if record.response_body is None:
                raise ProblemException(
                    status=409,
                    code="IDEMPOTENCY_IN_PROGRESS",
                    title="相同请求仍在处理中",
                    detail="请稍后使用相同 Idempotency-Key 重试。",
                    retryable=True,
                    headers={"Retry-After": "1"},
                )
            return record
        session.add(
            IdempotencyRecord(
                id=uuid4(),
                actor_id=actor_id,
                scope=scope,
                idempotency_key=key,
                request_hash=self._idempotency_request_hash(
                    actor_id=actor_id,
                    scope=scope,
                    body=body,
                ),
                request_hash_scheme=IDEMPOTENCY_HASH_SCHEME,
                response_status=None,
                response_body=None,
                resource_type=None,
                resource_id=None,
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )
        session.flush()
        return None

    def _validate_idempotency_record(
        self,
        record: IdempotencyRecord,
        *,
        actor_id: UUID,
        scope: str,
        body: dict[str, Any],
    ) -> None:
        expected = self._idempotency_request_hash(
            actor_id=actor_id,
            scope=scope,
            body=body,
        )
        if record.request_hash_scheme != IDEMPOTENCY_HASH_SCHEME or not hmac.compare_digest(
            record.request_hash, expected
        ):
            raise ProblemException(
                status=409,
                code="IDEMPOTENCY_CONFLICT",
                title="Idempotency-Key 已用于不同请求",
                detail="请为新的业务意图使用新的 Idempotency-Key。",
            )

    def _idempotency_request_hash(
        self,
        *,
        actor_id: UUID,
        scope: str,
        body: dict[str, Any],
    ) -> str:
        scope_bytes = scope.encode("utf-8")
        canonical_body = rfc8785.dumps(body)
        message = b"".join(
            (
                _IDEMPOTENCY_HASH_DOMAIN,
                actor_id.bytes,
                len(scope_bytes).to_bytes(4, "big"),
                scope_bytes,
                len(canonical_body).to_bytes(8, "big"),
                canonical_body,
            )
        )
        return hmac.new(
            self._integrity_hmac_key,
            message,
            hashlib.sha256,
        ).hexdigest()

    def _complete_idempotency(
        self,
        session: Session,
        *,
        actor_id: UUID,
        scope: str,
        key: str,
        status: int,
        body: dict[str, Any],
        resource_type: str,
        resource_id: UUID,
    ) -> None:
        record = session.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.actor_id == actor_id,
                IdempotencyRecord.scope == scope,
                IdempotencyRecord.idempotency_key == key,
            )
        )
        if record is None:
            raise RuntimeError("idempotency record disappeared")
        record.response_status = status
        record.response_body = body
        record.resource_type = resource_type
        record.resource_id = resource_id

    def _append_audit(
        self,
        session: Session,
        *,
        organization: Organization,
        project_id: UUID | None,
        action: str,
        actor_id: UUID | None,
        target_type: str,
        target_id: UUID | None,
        target_name: str | None,
        changed_fields: list[str],
        audit: AuditContext,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        session.execute(
            select(Organization.id).where(Organization.id == organization.id).with_for_update()
        ).scalar_one()
        previous = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization.id)
            .order_by(AuditEvent.organization_sequence.desc())
            .limit(1)
        )
        sequence = previous.organization_sequence + 1 if previous else 1
        previous_hash = previous.event_hash if previous else None
        occurred_at = utc_now()
        event_id = uuid4()
        actor = session.get(User, actor_id) if actor_id else None
        event: dict[str, Any] = {
            "schema_version": "1.0",
            "event_id": str(event_id),
            "organization_id": str(organization.id),
            "sequence": sequence,
            "project_id": str(project_id) if project_id else None,
            "occurred_at": self._rfc3339(occurred_at),
            "action": action,
            "actor": {
                "kind": "USER" if actor is not None else "SYSTEM",
                "user_id": str(actor.id) if actor is not None else None,
                "display_name": (actor.display_name if actor is not None else None),
            },
            "target": {
                "type": target_type,
                "id": str(target_id) if target_id is not None else None,
                "name": target_name,
            },
            "request": {
                "request_id": str(audit.request_id),
                "source_ip": audit.source_ip[:45] if audit.source_ip else None,
                "user_agent": self._safe_audit_user_agent(audit.user_agent),
            },
            "outcome": "SUCCEEDED",
            "reason_code": None,
            "changes": {
                "before_hash": None,
                "after_hash": None,
                "changed_fields": sorted(set(changed_fields)),
            },
            "metadata": metadata or {},
            "integrity": {
                "algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "chain_scope": "ORGANIZATION_SEQUENCE",
                "previous_hash": previous_hash,
            },
        }
        prefix = (
            "DXAUDITv1\n"
            f"{str(organization.id).lower()}\n"
            f"{sequence}\n"
            f"{previous_hash or ('0' * 64)}\n"
        ).encode()
        event_hash = hashlib.sha256(prefix + rfc8785.dumps(event)).hexdigest()
        event["integrity"]["event_hash"] = event_hash
        session.add(
            AuditEvent(
                id=event_id,
                organization_id=organization.id,
                organization_sequence=sequence,
                project_id=project_id,
                event_json=event,
                canonicalization_version="RFC8785-v1",
                previous_hash=previous_hash,
                event_hash=event_hash,
                occurred_at=occurred_at,
                expires_at=occurred_at + timedelta(days=730),
            )
        )
        session.flush()

    def _safe_audit_user_agent(self, user_agent: str | None) -> str | None:
        if user_agent is None:
            return None
        digest = hmac.new(
            self._integrity_hmac_key,
            _AUDIT_USER_AGENT_HASH_DOMAIN + user_agent.encode("utf-8", errors="replace"),
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256-v1:{digest}"

    def _encode_cursor(
        self,
        *,
        actor_id: UUID,
        scope: str,
        created_at: datetime,
        resource_id: UUID,
    ) -> str:
        payload = {
            "v": 1,
            "actor_id": str(actor_id),
            "scope": scope,
            "timestamp": self._rfc3339(ensure_aware(created_at)),
            "resource_id": str(resource_id),
        }
        body = rfc8785.dumps(payload)
        signature = hmac.new(
            self._integrity_hmac_key,
            _CURSOR_DOMAIN + body,
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(body + signature).rstrip(b"=").decode()

    def _decode_cursor(
        self,
        cursor: str,
        *,
        actor_id: UUID,
        scope: str,
    ) -> tuple[datetime, UUID]:
        try:
            padding = "=" * (-len(cursor) % 4)
            decoded = base64.urlsafe_b64decode(cursor + padding)
            if len(decoded) <= 32:
                raise ValueError
            body, signature = decoded[:-32], decoded[-32:]
            expected = hmac.new(
                self._integrity_hmac_key,
                _CURSOR_DOMAIN + body,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            payload = json.loads(body)
            if (
                payload.get("v") != 1
                or payload.get("actor_id") != str(actor_id)
                or payload.get("scope") != scope
            ):
                raise ValueError
            created_at = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
            return ensure_aware(created_at), UUID(payload["resource_id"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            raise ProblemException(
                status=400,
                code="INVALID_CURSOR",
                title="分页游标无效",
                detail="请从第一页重新开始。",
            ) from None

    def _version_conflict(self) -> None:
        raise ProblemException(
            status=409,
            code="VERSION_CONFLICT",
            title="传输策略已被修改",
            detail="请刷新后重试。",
        )

    def _validation_problem(self, field: str, message: str) -> None:
        raise ProblemException(
            status=422,
            code="VALIDATION_ERROR",
            title="请求参数无效",
            detail=message,
            field_errors=[{"field": field, "message": message}],
        )

    def _not_found(self) -> None:
        raise ProblemException(
            status=404,
            code="NOT_FOUND",
            title="资源不存在",
            detail="资源不存在或当前主体无权查看。",
        )

    @staticmethod
    def _clean_optional(value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @staticmethod
    def _rfc3339(value: datetime) -> str:
        return ensure_aware(value).isoformat().replace("+00:00", "Z")
