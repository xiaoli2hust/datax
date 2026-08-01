from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class OrganizationStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"


class UserStatus(StrEnum):
    ACTIVE = "ACTIVE"
    LOCKED = "LOCKED"
    DISABLED = "DISABLED"


class MembershipStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"


class ScopeType(StrEnum):
    ORGANIZATION = "ORGANIZATION"
    PROJECT = "PROJECT"


class Role(StrEnum):
    ADMIN = "ADMIN"
    DEVELOPER = "DEVELOPER"
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'SUSPENDED')",
            name="ck_organizations_status",
        ),
        CheckConstraint("row_version >= 1", name="ck_organizations_row_version"),
        Index(
            "uq_organizations_single_active",
            "status",
            unique=True,
            sqlite_where=text("status = 'ACTIVE'"),
            postgresql_where=text("status = 'ACTIVE'"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'LOCKED', 'DISABLED')",
            name="ck_users_status",
        ),
        CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_count"),
        CheckConstraint("row_version >= 1", name="ck_users_row_version"),
        UniqueConstraint("email", name="uq_users_email"),
        Index("ix_users_status_created", "status", "created_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class OrganizationMember(Base):
    __tablename__ = "organization_members"
    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'SUSPENDED')",
            name="ck_organization_members_status",
        ),
        UniqueConstraint(
            "organization_id",
            "user_id",
            name="uq_organization_members_org_user",
        ),
        Index("ix_organization_members_user_status", "user_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RoleAssignment(Base):
    __tablename__ = "role_assignments"
    __table_args__ = (
        CheckConstraint(
            "scope_type IN ('ORGANIZATION', 'PROJECT')",
            name="ck_role_assignments_scope_type",
        ),
        CheckConstraint(
            "role IN ('ADMIN', 'DEVELOPER', 'OPERATOR', 'VIEWER')",
            name="ck_role_assignments_role",
        ),
        CheckConstraint(
            "(scope_type = 'ORGANIZATION' AND role = 'ADMIN') OR "
            "(scope_type = 'PROJECT' AND role IN ('DEVELOPER', 'OPERATOR', 'VIEWER'))",
            name="ck_role_assignments_scope_role",
        ),
        UniqueConstraint(
            "organization_member_id",
            "scope_type",
            "scope_id",
            "role",
            name="uq_role_assignments_member_scope_role",
        ),
        Index(
            "ix_role_assignments_member_scope",
            "organization_member_id",
            "scope_type",
            "scope_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_member_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organization_members.id", ondelete="RESTRICT"),
        nullable=False,
    )
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    granted_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_auth_sessions_token_hash"),
        UniqueConstraint("rotated_from_id", name="uq_auth_sessions_rotated_from"),
        Index("ix_auth_sessions_user_active", "user_id", "revoked_at", "expires_at"),
        Index("ix_auth_sessions_family", "family_id", "issued_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    family_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    rotated_from_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("auth_sessions.id", ondelete="RESTRICT"),
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(64))
    ip_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32))


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint(
            "actor_id",
            "scope",
            "idempotency_key",
            name="uq_idempotency_actor_scope_key",
        ),
        CheckConstraint(
            "request_hash_scheme = 'HMAC-SHA256-v1'",
            name="ck_idempotency_request_hash_scheme",
        ),
        Index("ix_idempotency_expires", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    actor_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    scope: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    request_hash_scheme: Mapped[str] = mapped_column(String(32), nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "organization_sequence",
            name="uq_audit_events_org_sequence",
        ),
        UniqueConstraint("event_hash", name="uq_audit_events_event_hash"),
        Index("ix_audit_events_org_sequence", "organization_id", "organization_sequence"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    organization_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    project_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    event_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    canonicalization_version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="RFC8785-v1",
    )
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
