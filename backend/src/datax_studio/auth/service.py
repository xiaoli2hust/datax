from __future__ import annotations

import hashlib
import hmac
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import Lock
from typing import Any
from uuid import UUID, uuid4

import jwt
import rfc8785
from pydantic import ValidationError
from sqlalchemy import and_, create_engine, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from datax_studio.api.problems import ProblemException
from datax_studio.audit_integrity import advance_audit_chain_watermark
from datax_studio.auth.db import (
    AuditEvent,
    AuthSession,
    IdempotencyRecord,
    MembershipStatus,
    Organization,
    OrganizationMember,
    OrganizationStatus,
    Role,
    RoleAssignment,
    ScopeType,
    User,
    UserStatus,
)
from datax_studio.auth.schemas import (
    AuthResponse,
    MeResponse,
    ScopedRoles,
    UserCreate,
    UserPage,
    UserPatch,
    UserResponse,
    UserSummary,
)
from datax_studio.auth.security import (
    Argon2idPasswordHasher,
    TokenManager,
    ensure_aware,
    normalize_email,
    utc_now,
)
from datax_studio.settings import Settings

IDEMPOTENCY_HASH_SCHEME = "HMAC-SHA256-v1"
_IDEMPOTENCY_HASH_DOMAIN = b"DataXEnterpriseStudio\x00IdempotencyRequestHash\x00v1\x00"
_IDEMPOTENCY_LOCK_DOMAIN = b"DataXEnterpriseStudio\x00IdempotencyAdvisoryLock\x00v1\x00"
_AUDIT_USER_AGENT_HASH_DOMAIN = b"DataXEnterpriseStudio\x00AuditUserAgentHash\x00v1\x00"
_LOGGER = logging.getLogger(__name__)
_SQLITE_IDEMPOTENCY_LOCKS_GUARD = Lock()
_SQLITE_IDEMPOTENCY_LOCKS: dict[bytes, tuple[Lock, int]] = {}


@dataclass(frozen=True)
class AuditContext:
    request_id: UUID
    source_ip: str | None
    user_agent: str | None


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    organization_id: UUID
    session_id: UUID
    email: str
    display_name: str
    must_change_password: bool
    role_assignments: tuple[ScopedRoles, ...]

    @property
    def is_admin(self) -> bool:
        return any(
            assignment.scope_type == ScopeType.ORGANIZATION
            and assignment.scope_id == self.organization_id
            and Role.ADMIN in assignment.roles
            for assignment in self.role_assignments
        )


@dataclass(frozen=True)
class AuthResult:
    response: AuthResponse
    refresh_token: str


@dataclass(frozen=True)
class OperationResult[T]:
    value: T
    replayed: bool = False


def build_auth_service(settings: Settings) -> AuthService:
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        future=True,
    )
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    refresh_hmac_key = settings.refresh_token_hmac_key_file.read_bytes()
    idempotency_hmac_key = settings.idempotency_hmac_key_file.read_bytes()
    if len(idempotency_hmac_key) < 32:
        raise ValueError("idempotency HMAC key must contain at least 32 bytes")
    if hmac.compare_digest(refresh_hmac_key, idempotency_hmac_key):
        raise ValueError("idempotency and refresh HMAC keys must be independent")
    tokens = TokenManager.from_files(
        private_key_file=settings.jwt_private_key_file,
        public_key_file=settings.jwt_public_key_file,
        refresh_hmac_key_file=settings.refresh_token_hmac_key_file,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        access_token_seconds=settings.access_token_seconds,
    )
    return AuthService(
        sessions=sessions,
        password_hasher=Argon2idPasswordHasher(),
        tokens=tokens,
        idempotency_hmac_key=idempotency_hmac_key,
        refresh_token_days=settings.refresh_token_days,
        login_failure_limit=settings.login_failure_limit,
        login_lock_seconds=settings.login_lock_seconds,
    )


def bootstrap_required(settings: Settings) -> bool:
    """Return whether the one-time bootstrap is required without loading auth keys."""
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        future=True,
    )
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        with sessions() as session:
            return session.scalar(select(func.count(User.id))) == 0
    finally:
        engine.dispose()


class AuthService:
    def __init__(
        self,
        *,
        sessions: sessionmaker[Session],
        password_hasher: Argon2idPasswordHasher,
        tokens: TokenManager,
        idempotency_hmac_key: bytes,
        refresh_token_days: int = 30,
        login_failure_limit: int = 5,
        login_lock_seconds: int = 900,
    ) -> None:
        self.sessions = sessions
        self.password_hasher = password_hasher
        self.tokens = tokens
        if len(idempotency_hmac_key) < 32:
            raise ValueError("idempotency HMAC key must contain at least 32 bytes")
        self._idempotency_hmac_key = bytes(idempotency_hmac_key)
        self.refresh_token_days = refresh_token_days
        self.login_failure_limit = login_failure_limit
        self.login_lock_seconds = login_lock_seconds

    def bootstrap_admin(
        self,
        *,
        email: str,
        display_name: str,
        password: str,
        organization_name: str,
        audit: AuditContext,
    ) -> UserResponse:
        normalized_email = normalize_email(email)
        self._validate_password(password)
        normalized_name = display_name.strip()
        if not normalized_name or len(normalized_name) > 128:
            raise ValueError("display name is invalid")
        now = utc_now()
        with self.sessions() as session:
            try:
                with session.begin():
                    if session.bind is not None and session.bind.dialect.name == "postgresql":
                        session.execute(text("LOCK TABLE users IN EXCLUSIVE MODE"))
                    if session.scalar(select(func.count(User.id))) != 0:
                        raise ProblemException(
                            status=409,
                            code="BOOTSTRAP_ALREADY_COMPLETED",
                            title="初始管理员已经存在",
                            detail="一次性初始管理员引导只允许在空用户库执行。",
                        )
                    organization = session.scalar(
                        select(Organization)
                        .where(Organization.status == OrganizationStatus.ACTIVE)
                        .with_for_update()
                    )
                    if organization is None:
                        organization = Organization(
                            id=uuid4(),
                            name=organization_name[:128],
                            status=OrganizationStatus.ACTIVE,
                            created_at=now,
                            updated_at=now,
                            row_version=1,
                        )
                        session.add(organization)
                        session.flush()
                    user = User(
                        id=uuid4(),
                        email=normalized_email,
                        display_name=normalized_name,
                        password_hash=self.password_hasher.hash(password),
                        must_change_password=True,
                        password_changed_at=now,
                        status=UserStatus.ACTIVE,
                        failed_login_count=0,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    )
                    session.add(user)
                    session.flush()
                    member = OrganizationMember(
                        id=uuid4(),
                        organization_id=organization.id,
                        user_id=user.id,
                        status=MembershipStatus.ACTIVE,
                        joined_at=now,
                    )
                    session.add(member)
                    session.flush()
                    session.add(
                        RoleAssignment(
                            id=uuid4(),
                            organization_member_id=member.id,
                            scope_type=ScopeType.ORGANIZATION,
                            scope_id=organization.id,
                            role=Role.ADMIN,
                            granted_by=user.id,
                            created_at=now,
                        )
                    )
                    self._append_audit(
                        session,
                        organization=organization,
                        action="SYSTEM_BOOTSTRAP_ADMIN",
                        actor=None,
                        target_type="USER",
                        target_id=user.id,
                        target_name=None,
                        outcome="SUCCEEDED",
                        reason_code=None,
                        changed_fields=["user", "organization_member", "role_assignment"],
                        audit=audit,
                    )
                    session.flush()
                    return self._user_response(session, user, organization.id)
            except IntegrityError as exc:
                raise ProblemException(
                    status=409,
                    code="BOOTSTRAP_ALREADY_COMPLETED",
                    title="初始管理员已经存在",
                    detail="一次性初始管理员引导只允许在空用户库执行。",
                ) from exc

    def recover_last_admin(
        self,
        *,
        email: str,
        password: str,
        audit: AuditContext,
    ) -> UserResponse:
        """Recover one locked organization Admin only when no active Admin remains."""
        normalized_email = normalize_email(email)
        self._validate_password(password)
        now = utc_now()
        with self.sessions.begin() as session:
            organization = session.scalar(
                select(Organization)
                .where(Organization.status == OrganizationStatus.ACTIVE)
                .with_for_update()
            )
            if organization is None:
                raise ProblemException(
                    status=409,
                    code="ADMIN_RECOVERY_NOT_ALLOWED",
                    title="管理员恢复不可用",
                    detail="当前系统没有可恢复的活动组织。",
                )
            active_admins = session.scalar(
                select(func.count(func.distinct(User.id)))
                .select_from(User)
                .join(OrganizationMember, OrganizationMember.user_id == User.id)
                .join(
                    RoleAssignment,
                    RoleAssignment.organization_member_id == OrganizationMember.id,
                )
                .where(
                    OrganizationMember.organization_id == organization.id,
                    OrganizationMember.status == MembershipStatus.ACTIVE,
                    User.status == UserStatus.ACTIVE,
                    RoleAssignment.scope_type == ScopeType.ORGANIZATION,
                    RoleAssignment.scope_id == organization.id,
                    RoleAssignment.role == Role.ADMIN,
                )
            )
            if active_admins:
                raise ProblemException(
                    status=409,
                    code="ADMIN_RECOVERY_NOT_ALLOWED",
                    title="管理员恢复不可用",
                    detail="仍有有效管理员时禁止使用本机离线恢复。",
                )
            user = session.scalar(
                select(User)
                .join(OrganizationMember, OrganizationMember.user_id == User.id)
                .join(
                    RoleAssignment,
                    RoleAssignment.organization_member_id == OrganizationMember.id,
                )
                .where(
                    func.lower(User.email) == normalized_email,
                    User.status == UserStatus.LOCKED,
                    OrganizationMember.organization_id == organization.id,
                    OrganizationMember.status == MembershipStatus.ACTIVE,
                    RoleAssignment.scope_type == ScopeType.ORGANIZATION,
                    RoleAssignment.scope_id == organization.id,
                    RoleAssignment.role == Role.ADMIN,
                )
                .with_for_update()
            )
            if user is None:
                raise ProblemException(
                    status=409,
                    code="ADMIN_RECOVERY_NOT_ALLOWED",
                    title="管理员恢复不可用",
                    detail="只能恢复当前组织中已锁定的管理员。",
                )
            user.password_hash = self.password_hasher.hash(password)
            user.password_changed_at = now
            user.must_change_password = True
            user.status = UserStatus.ACTIVE
            user.failed_login_count = 0
            user.locked_until = None
            user.updated_at = now
            user.row_version += 1
            self._revoke_locked_user_sessions(
                session,
                user_id=user.id,
                now=now,
                reason="ADMIN_LOCAL_RECOVERY",
            )
            self._append_audit(
                session,
                organization=organization,
                action="SYSTEM_RECOVER_ADMIN",
                actor=None,
                target_type="USER",
                target_id=user.id,
                target_name=None,
                outcome="SUCCEEDED",
                reason_code=None,
                changed_fields=[
                    "password_hash",
                    "must_change_password",
                    "status",
                    "failed_login_count",
                    "locked_until",
                    "auth_sessions",
                ],
                audit=audit,
                metadata={"recovery_method": "LOCAL_STDIN_CLI"},
            )
            return self._user_response(session, user, organization.id)

    def login(
        self,
        *,
        email: str,
        password: str,
        audit: AuditContext,
    ) -> AuthResult:
        normalized_email = normalize_email(email)
        now = utc_now()
        session = self.sessions()
        try:
            organization = session.scalar(
                select(Organization)
                .where(Organization.status == OrganizationStatus.ACTIVE)
                .with_for_update()
            )
            if organization is None:
                self.password_hasher.verify_dummy(password)
                session.rollback()
                raise self._invalid_credentials()
            user = session.scalar(
                select(User).where(func.lower(User.email) == normalized_email).with_for_update()
            )
            if user is None:
                self.password_hasher.verify_dummy(password)
                self._append_audit(
                    session,
                    organization=organization,
                    action="AUTH_LOGIN_FAILED",
                    actor=None,
                    target_type="AUTH_SESSION",
                    target_id=None,
                    target_name=None,
                    outcome="DENIED",
                    reason_code="INVALID_CREDENTIALS",
                    changed_fields=[],
                    audit=audit,
                )
                session.commit()
                raise self._invalid_credentials()

            locked_until = ensure_aware(user.locked_until) if user.locked_until else None
            if user.status == UserStatus.LOCKED and locked_until and locked_until <= now:
                user.status = UserStatus.ACTIVE
                user.failed_login_count = 0
                user.locked_until = None
                user.updated_at = now
                user.row_version += 1

            valid_password = self.password_hasher.verify(user.password_hash, password)
            membership = session.scalar(
                select(OrganizationMember).where(
                    OrganizationMember.organization_id == organization.id,
                    OrganizationMember.user_id == user.id,
                )
            )
            blocked = (
                user.status != UserStatus.ACTIVE
                or membership is None
                or membership.status != MembershipStatus.ACTIVE
            )
            if not valid_password or blocked:
                reason = "INVALID_CREDENTIALS"
                if user.status != UserStatus.DISABLED:
                    user.failed_login_count += 1
                    if user.failed_login_count >= self.login_failure_limit:
                        user.status = UserStatus.LOCKED
                        user.locked_until = now + timedelta(seconds=self.login_lock_seconds)
                        reason = "ACCOUNT_TEMPORARILY_LOCKED"
                    user.updated_at = now
                    user.row_version += 1
                self._append_audit(
                    session,
                    organization=organization,
                    action="AUTH_LOGIN_FAILED",
                    actor=None,
                    target_type="USER",
                    target_id=user.id,
                    target_name=None,
                    outcome="DENIED",
                    reason_code=reason,
                    changed_fields=["failed_login_count", "locked_until"]
                    if user.status != UserStatus.DISABLED
                    else [],
                    audit=audit,
                )
                session.commit()
                raise self._invalid_credentials()

            if self.password_hasher.needs_rehash(user.password_hash):
                user.password_hash = self.password_hasher.hash(password)
            user.failed_login_count = 0
            user.locked_until = None
            user.last_login_at = now
            user.updated_at = now
            user.row_version += 1
            refresh_token, auth_session = self._new_session(
                user=user,
                now=now,
                source_ip=audit.source_ip,
            )
            session.add(auth_session)
            self._append_audit(
                session,
                organization=organization,
                action="AUTH_LOGIN_SUCCEEDED",
                actor=user,
                target_type="AUTH_SESSION",
                target_id=auth_session.id,
                target_name=None,
                outcome="SUCCEEDED",
                reason_code=None,
                changed_fields=["last_login_at", "auth_session"],
                audit=audit,
            )
            session.flush()
            access_token, _ = self.tokens.issue_access(
                user_id=user.id,
                organization_id=organization.id,
                session_id=auth_session.id,
                now=now,
            )
            response = self._auth_response(user, access_token)
            session.commit()
            return AuthResult(response=response, refresh_token=refresh_token)
        except ProblemException:
            if session.in_transaction():
                session.rollback()
            raise
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def refresh(
        self,
        *,
        refresh_token: str | None,
        audit: AuditContext,
    ) -> AuthResult:
        if not self.tokens.is_valid_refresh_token(refresh_token):
            raise self._invalid_credentials()
        now = utc_now()
        token_hash = self.tokens.hash_refresh_token(refresh_token)
        session = self.sessions()
        try:
            candidate = session.scalar(
                select(AuthSession).where(AuthSession.token_hash == token_hash)
            )
            if candidate is None:
                session.rollback()
                raise self._invalid_credentials()
            candidate_membership = session.scalar(
                select(OrganizationMember).where(OrganizationMember.user_id == candidate.user_id)
            )
            if candidate_membership is None:
                session.rollback()
                raise self._invalid_credentials()
            organization = session.scalar(
                select(Organization)
                .where(Organization.id == candidate_membership.organization_id)
                .with_for_update()
            )
            if organization is None:
                session.rollback()
                raise self._invalid_credentials()
            user = self._lock_users(session, {candidate.user_id}).get(candidate.user_id)
            membership = session.scalar(
                select(OrganizationMember)
                .where(
                    OrganizationMember.id == candidate_membership.id,
                    OrganizationMember.organization_id == organization.id,
                    OrganizationMember.user_id == candidate.user_id,
                )
                .with_for_update()
            )
            locked_sessions = self._lock_user_sessions(
                session,
                {candidate.user_id},
            )
            existing = next(
                (
                    item
                    for item in locked_sessions
                    if item.id == candidate.id
                    and item.user_id == candidate.user_id
                    and hmac.compare_digest(item.token_hash, token_hash)
                ),
                None,
            )
            if user is None or membership is None or existing is None:
                session.rollback()
                raise self._invalid_credentials()
            if existing.revoked_at is not None:
                if existing.revoke_reason in {"ROTATED", "REFRESH_TOKEN_REPLAY"}:
                    self._revoke_family(
                        session,
                        family_id=existing.family_id,
                        now=now,
                        reason="REFRESH_TOKEN_REPLAY",
                    )
                    self._append_audit(
                        session,
                        organization=organization,
                        action="AUTH_TOKEN_REFRESHED",
                        actor=user,
                        target_type="AUTH_SESSION",
                        target_id=existing.id,
                        target_name=None,
                        outcome="DENIED",
                        reason_code="REFRESH_TOKEN_REPLAY",
                        changed_fields=["auth_session_family"],
                        audit=audit,
                    )
                    session.commit()
                else:
                    session.rollback()
                raise self._invalid_credentials()
            if (
                ensure_aware(existing.expires_at) <= now
                or user.status != UserStatus.ACTIVE
                or organization.status != OrganizationStatus.ACTIVE
                or membership.status != MembershipStatus.ACTIVE
            ):
                self._revoke_family(
                    session,
                    family_id=existing.family_id,
                    now=now,
                    reason="IDENTITY_UNAVAILABLE",
                )
                session.commit()
                raise self._invalid_credentials()

            existing.last_used_at = now
            existing.revoked_at = now
            existing.revoke_reason = "ROTATED"
            rotated_token, rotated = self._new_session(
                user=user,
                now=now,
                source_ip=audit.source_ip,
                family_id=existing.family_id,
                rotated_from_id=existing.id,
            )
            session.add(rotated)
            self._append_audit(
                session,
                organization=organization,
                action="AUTH_TOKEN_REFRESHED",
                actor=user,
                target_type="AUTH_SESSION",
                target_id=rotated.id,
                target_name=None,
                outcome="SUCCEEDED",
                reason_code=None,
                changed_fields=["auth_session"],
                audit=audit,
            )
            session.flush()
            access_token, _ = self.tokens.issue_access(
                user_id=user.id,
                organization_id=organization.id,
                session_id=rotated.id,
                now=now,
            )
            response = self._auth_response(user, access_token)
            session.commit()
            return AuthResult(response=response, refresh_token=rotated_token)
        except ProblemException:
            if session.in_transaction():
                session.rollback()
            raise
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def authenticate_access(self, token: str) -> Principal:
        try:
            claims = self.tokens.decode_access(token)
        except (jwt.InvalidTokenError, KeyError, TypeError, ValueError) as exc:
            raise self._invalid_access_token() from exc
        now = utc_now()
        with self.sessions() as session:
            auth_session = session.get(AuthSession, claims.session_id)
            if (
                auth_session is None
                or auth_session.user_id != claims.user_id
                or auth_session.revoked_at is not None
                or ensure_aware(auth_session.expires_at) <= now
            ):
                raise self._invalid_access_token()
            organization, user, membership = self._identity_for_session(
                session,
                auth_session,
                lock=False,
            )
            if (
                organization.id != claims.organization_id
                or organization.status != OrganizationStatus.ACTIVE
                or user.status != UserStatus.ACTIVE
                or membership.status != MembershipStatus.ACTIVE
            ):
                raise self._invalid_access_token()
            roles = tuple(self._scoped_roles(session, user.id))
            return Principal(
                user_id=user.id,
                organization_id=organization.id,
                session_id=auth_session.id,
                email=user.email,
                display_name=user.display_name,
                must_change_password=user.must_change_password,
                role_assignments=roles,
            )

    def logout(
        self,
        *,
        access_token: str | None,
        refresh_token: str | None,
        audit: AuditContext,
    ) -> None:
        access_claims = None
        if access_token:
            try:
                access_claims = self.tokens.decode_access_for_logout(access_token)
            except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
                access_claims = None
        refresh_hash = None
        if self.tokens.is_valid_refresh_token(refresh_token):
            refresh_hash = self.tokens.hash_refresh_token(refresh_token)
        if access_claims is None and refresh_hash is None:
            return
        now = utc_now()
        with self.sessions.begin() as session:
            organization = session.scalar(
                select(Organization)
                .where(Organization.status == OrganizationStatus.ACTIVE)
                .with_for_update()
            )
            if organization is None:
                return
            conditions = []
            if access_claims is not None and access_claims.organization_id == organization.id:
                conditions.append(
                    and_(
                        AuthSession.id == access_claims.session_id,
                        AuthSession.user_id == access_claims.user_id,
                    )
                )
            if refresh_hash is not None:
                conditions.append(AuthSession.token_hash == refresh_hash)
            if not conditions:
                return
            candidates = list(
                session.scalars(
                    select(AuthSession).where(or_(*conditions)).order_by(AuthSession.id)
                )
            )
            candidate_user_ids = {item.user_id for item in candidates}
            users = self._lock_users(session, candidate_user_ids)
            memberships = (
                {
                    membership.user_id: membership
                    for membership in session.scalars(
                        select(OrganizationMember)
                        .where(
                            OrganizationMember.organization_id == organization.id,
                            OrganizationMember.user_id.in_(sorted(candidate_user_ids, key=str)),
                        )
                        .order_by(OrganizationMember.user_id)
                        .with_for_update()
                    )
                }
                if candidate_user_ids
                else {}
            )
            locked_sessions = self._lock_user_sessions(
                session,
                candidate_user_ids,
            )
            auth_sessions = []
            for auth_session in locked_sessions:
                access_matches = (
                    access_claims is not None
                    and access_claims.organization_id == organization.id
                    and auth_session.id == access_claims.session_id
                    and auth_session.user_id == access_claims.user_id
                )
                refresh_matches = refresh_hash is not None and hmac.compare_digest(
                    auth_session.token_hash, refresh_hash
                )
                if (
                    (access_matches or refresh_matches)
                    and auth_session.user_id in users
                    and auth_session.user_id in memberships
                ):
                    auth_sessions.append(auth_session)
            mismatch = len({item.id for item in auth_sessions}) > 1
            for auth_session in auth_sessions:
                user = users[auth_session.user_id]
                changed = auth_session.revoked_at is None
                if changed:
                    auth_session.revoked_at = now
                    auth_session.revoke_reason = "LOGOUT"
                self._append_audit(
                    session,
                    organization=organization,
                    action="AUTH_LOGOUT",
                    actor=user,
                    target_type="AUTH_SESSION",
                    target_id=auth_session.id,
                    target_name=None,
                    outcome="SUCCEEDED",
                    reason_code=None if changed else "ALREADY_REVOKED",
                    changed_fields=["auth_session"] if changed else [],
                    audit=audit,
                    metadata={"credential_mismatch": mismatch},
                )

    def change_password(
        self,
        *,
        principal: Principal,
        current_password: str,
        new_password: str,
        audit: AuditContext,
    ) -> None:
        self._validate_password(new_password)
        now = utc_now()
        try:
            with self.sessions() as session, session.begin():
                organization = self._lock_organization(
                    session,
                    principal.organization_id,
                )
                user = session.scalar(
                    select(User).where(User.id == principal.user_id).with_for_update()
                )
                if user is None or not self.password_hasher.verify(
                    user.password_hash,
                    current_password,
                ):
                    raise self._invalid_credentials()
                if self.password_hasher.verify(user.password_hash, new_password):
                    raise ProblemException(
                        status=422,
                        code="VALIDATION_ERROR",
                        title="新密码无效",
                        detail="新密码不能与当前密码相同。",
                        field_errors=[
                            {
                                "path": "new_password",
                                "code": "PASSWORD_REUSED",
                                "message": "新密码不能与当前密码相同。",
                            }
                        ],
                    )
                user.password_hash = self.password_hasher.hash(new_password)
                user.password_changed_at = now
                user.must_change_password = False
                user.failed_login_count = 0
                user.locked_until = None
                user.updated_at = now
                user.row_version += 1
                self._revoke_locked_user_sessions(
                    session,
                    user_id=user.id,
                    now=now,
                    reason="PASSWORD_CHANGED",
                    exclude_session_id=principal.session_id,
                )
                self._append_audit(
                    session,
                    organization=organization,
                    action="USER_PASSWORD_CHANGED",
                    actor=user,
                    target_type="USER",
                    target_id=user.id,
                    target_name=None,
                    outcome="SUCCEEDED",
                    reason_code=None,
                    changed_fields=[
                        "password_hash",
                        "must_change_password",
                        "auth_sessions",
                    ],
                    audit=audit,
                )
        except ProblemException as exc:
            if exc.code == "AUTH_INVALID_CREDENTIALS":
                self._append_failure_audit_safely(
                    organization_id=principal.organization_id,
                    actor_id=principal.user_id,
                    action="USER_PASSWORD_CHANGED",
                    target_type="USER",
                    target_id=principal.user_id,
                    reason_code="CURRENT_PASSWORD_INVALID",
                    audit=audit,
                )
            raise

    def me(self, *, principal: Principal) -> MeResponse:
        return MeResponse(
            user=UserSummary(
                id=principal.user_id,
                email=principal.email,
                display_name=principal.display_name,
                must_change_password=principal.must_change_password,
            ),
            role_assignments=list(principal.role_assignments),
        )

    def audit_authorization_denied(
        self,
        *,
        principal: Principal,
        audit: AuditContext,
        operation: str,
        reason_code: str,
    ) -> None:
        self._append_failure_audit_safely(
            organization_id=principal.organization_id,
            actor_id=principal.user_id,
            action="AUTHORIZATION_DENIED",
            target_type="USER",
            target_id=principal.user_id,
            reason_code=reason_code,
            audit=audit,
            metadata={"operation": operation},
        )

    def list_users(
        self,
        *,
        principal: Principal,
        audit: AuditContext,
        limit: int,
        cursor: str | None,
        status: str | None,
    ) -> UserPage:
        self._require_admin(principal, audit=audit, operation="LIST_USERS")
        cursor_position: tuple[datetime, UUID] | None = None
        if cursor:
            try:
                cursor_position = self.tokens.decode_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    status=status,
                )
            except ValueError as exc:
                raise ProblemException(
                    status=400,
                    code="CURSOR_INVALID",
                    title="分页游标无效",
                    detail="请从第一页重新加载。",
                ) from exc
        with self.sessions() as session:
            statement = (
                select(User)
                .join(OrganizationMember, OrganizationMember.user_id == User.id)
                .where(OrganizationMember.organization_id == principal.organization_id)
            )
            if status is not None:
                statement = statement.where(User.status == status)
            if cursor_position is not None:
                created_at, user_id = cursor_position
                statement = statement.where(
                    or_(
                        User.created_at < created_at,
                        and_(User.created_at == created_at, User.id < user_id),
                    )
                )
            users = list(
                session.scalars(
                    statement.order_by(User.created_at.desc(), User.id.desc()).limit(limit + 1)
                )
            )
            has_more = len(users) > limit
            page_users = users[:limit]
            items = [
                self._user_response(session, user, principal.organization_id) for user in page_users
            ]
            next_cursor = None
            if has_more and page_users:
                last = page_users[-1]
                next_cursor = self.tokens.encode_cursor(
                    created_at=last.created_at,
                    user_id=last.id,
                    actor_id=principal.user_id,
                    status=status,
                )
            return UserPage(items=items, next_cursor=next_cursor, has_more=has_more)

    def get_user(
        self,
        *,
        principal: Principal,
        user_id: UUID,
        audit: AuditContext,
    ) -> UserResponse:
        self._require_admin(principal, audit=audit, operation="GET_USER")
        with self.sessions() as session:
            user = self._visible_user(session, principal.organization_id, user_id)
            return self._user_response(session, user, principal.organization_id)

    def create_user(
        self,
        *,
        principal: Principal,
        request: UserCreate,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[UserResponse]:
        self._require_admin(principal, audit=audit, operation="CREATE_USER")
        now = utc_now()
        request_body = request.model_dump(mode="json")
        with self.sessions() as session:
            try:
                with self._idempotency_transaction(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /users",
                    key=idempotency_key,
                ):
                    replay = self._claim_idempotency(
                        session,
                        actor_id=principal.user_id,
                        scope="POST /users",
                        key=idempotency_key,
                        body=request_body,
                        now=now,
                    )
                    if replay is not None:
                        return OperationResult(
                            self._user_idempotency_replay_response(
                                session,
                                record=replay,
                                organization_id=principal.organization_id,
                                expected_user_id=None,
                                expected_status=201,
                            ),
                            replayed=True,
                        )
                    organization = self._lock_organization(
                        session,
                        principal.organization_id,
                    )
                    if session.scalar(
                        select(User.id).where(func.lower(User.email) == request.email)
                    ):
                        raise ProblemException(
                            status=409,
                            code="USER_EMAIL_CONFLICT",
                            title="邮箱已被使用",
                            detail="请使用其他邮箱。",
                        )
                    user = User(
                        id=uuid4(),
                        email=request.email,
                        display_name=request.display_name,
                        password_hash=self.password_hasher.hash(request.temporary_password),
                        must_change_password=True,
                        password_changed_at=now,
                        status=UserStatus.ACTIVE,
                        failed_login_count=0,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    )
                    session.add(user)
                    session.flush()
                    session.add(
                        OrganizationMember(
                            id=uuid4(),
                            organization_id=organization.id,
                            user_id=user.id,
                            status=MembershipStatus.ACTIVE,
                            joined_at=now,
                        )
                    )
                    self._append_audit(
                        session,
                        organization=organization,
                        action="USER_CREATED",
                        actor=session.get(User, principal.user_id),
                        target_type="USER",
                        target_id=user.id,
                        target_name=None,
                        outcome="SUCCEEDED",
                        reason_code=None,
                        changed_fields=["user", "organization_member"],
                        audit=audit,
                    )
                    response = self._user_response(session, user, organization.id)
                    self._complete_idempotency(
                        session,
                        actor_id=principal.user_id,
                        scope="POST /users",
                        key=idempotency_key,
                        status=201,
                        body=response.model_dump(mode="json"),
                        resource_type="USER",
                        resource_id=user.id,
                    )
                    return OperationResult(response)
            except ProblemException as exc:
                if exc.code == "USER_EMAIL_CONFLICT":
                    self._append_failure_audit_safely(
                        organization_id=principal.organization_id,
                        actor_id=principal.user_id,
                        action="USER_CREATED",
                        target_type="USER",
                        target_id=None,
                        reason_code="USER_EMAIL_CONFLICT",
                        audit=audit,
                    )
                raise
            except IntegrityError as exc:
                if not self._is_integrity_constraint(exc, "uq_users_email"):
                    raise
                self._append_failure_audit_safely(
                    organization_id=principal.organization_id,
                    actor_id=principal.user_id,
                    action="USER_CREATED",
                    target_type="USER",
                    target_id=None,
                    reason_code="USER_EMAIL_CONFLICT",
                    audit=audit,
                )
                raise ProblemException(
                    status=409,
                    code="USER_EMAIL_CONFLICT",
                    title="邮箱已被使用",
                    detail="请使用其他邮箱。",
                ) from exc

    def update_user(
        self,
        *,
        principal: Principal,
        user_id: UUID,
        request: UserPatch,
        expected_version: int,
        audit: AuditContext,
    ) -> UserResponse:
        self._require_admin(principal, audit=audit, operation="UPDATE_USER")
        try:
            request.require_change()
        except ValueError as exc:
            raise ProblemException(
                status=422,
                code="VALIDATION_ERROR",
                title="请求字段无效",
                detail="至少提供一个要修改的字段。",
            ) from exc
        now = utc_now()
        with self.sessions.begin() as session:
            organization = self._lock_organization(session, principal.organization_id)
            user = self._visible_user(
                session,
                principal.organization_id,
                user_id,
                lock=True,
            )
            if (
                self._lock_membership(
                    session,
                    organization_id=organization.id,
                    user_id=user.id,
                )
                is None
            ):
                raise self._not_found()
            if user.row_version != expected_version:
                raise self._version_conflict()
            changed_fields: list[str] = []
            if "display_name" in request.model_fields_set:
                if request.display_name is None:
                    raise self._validation_problem("display_name", "NULL_NOT_ALLOWED")
                user.display_name = request.display_name
                changed_fields.append("display_name")
            if "status" in request.model_fields_set:
                if request.status is None:
                    raise self._validation_problem("status", "NULL_NOT_ALLOWED")
                if request.status == UserStatus.DISABLED:
                    if self._is_last_active_admin(session, organization.id, user.id):
                        raise self._last_admin_problem()
                    user.status = UserStatus.DISABLED
                    self._revoke_locked_user_sessions(
                        session,
                        user_id=user.id,
                        now=now,
                        reason="USER_DISABLED",
                    )
                    changed_fields.extend(["status", "auth_sessions"])
                else:
                    user.status = UserStatus.ACTIVE
                    user.failed_login_count = 0
                    user.locked_until = None
                    changed_fields.extend(["status", "failed_login_count", "locked_until"])
            user.updated_at = now
            user.row_version += 1
            self._append_audit(
                session,
                organization=organization,
                action="USER_STATUS_CHANGED",
                actor=session.get(User, principal.user_id),
                target_type="USER",
                target_id=user.id,
                target_name=None,
                outcome="SUCCEEDED",
                reason_code=None,
                changed_fields=changed_fields,
                audit=audit,
            )
            return self._user_response(session, user, organization.id)

    def replace_organization_roles(
        self,
        *,
        principal: Principal,
        user_id: UUID,
        roles: list[str],
        audit: AuditContext,
    ) -> UserResponse:
        self._require_admin(
            principal,
            audit=audit,
            operation="REPLACE_ORGANIZATION_ROLES",
        )
        now = utc_now()
        with self.sessions.begin() as session:
            organization = self._lock_organization(session, principal.organization_id)
            user = self._visible_user(
                session,
                principal.organization_id,
                user_id,
                lock=True,
            )
            member = session.scalar(
                select(OrganizationMember)
                .where(
                    OrganizationMember.organization_id == organization.id,
                    OrganizationMember.user_id == user.id,
                )
                .with_for_update()
            )
            if member is None:
                raise self._not_found()
            assignment = session.scalar(
                select(RoleAssignment)
                .where(
                    RoleAssignment.organization_member_id == member.id,
                    RoleAssignment.scope_type == ScopeType.ORGANIZATION,
                    RoleAssignment.scope_id == organization.id,
                    RoleAssignment.role == Role.ADMIN,
                )
                .with_for_update()
            )
            should_be_admin = Role.ADMIN in roles
            actor = session.get(User, principal.user_id)
            if should_be_admin and assignment is None:
                session.add(
                    RoleAssignment(
                        id=uuid4(),
                        organization_member_id=member.id,
                        scope_type=ScopeType.ORGANIZATION,
                        scope_id=organization.id,
                        role=Role.ADMIN,
                        granted_by=principal.user_id,
                        created_at=now,
                    )
                )
                self._append_audit(
                    session,
                    organization=organization,
                    action="ROLE_GRANTED",
                    actor=actor,
                    target_type="ROLE_ASSIGNMENT",
                    target_id=user.id,
                    target_name=None,
                    outcome="SUCCEEDED",
                    reason_code=None,
                    changed_fields=["role_assignments"],
                    audit=audit,
                )
            elif not should_be_admin and assignment is not None:
                if self._is_last_active_admin(session, organization.id, user.id):
                    raise self._last_admin_problem()
                session.delete(assignment)
                self._append_audit(
                    session,
                    organization=organization,
                    action="ROLE_REVOKED",
                    actor=actor,
                    target_type="ROLE_ASSIGNMENT",
                    target_id=user.id,
                    target_name=None,
                    outcome="SUCCEEDED",
                    reason_code=None,
                    changed_fields=["role_assignments"],
                    audit=audit,
                )
            return self._user_response(session, user, organization.id)

    def unlock_user(
        self,
        *,
        principal: Principal,
        user_id: UUID,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[UserResponse]:
        self._require_admin(principal, audit=audit, operation="UNLOCK_USER")
        now = utc_now()
        body = {"user_id": str(user_id)}
        with (
            self.sessions() as session,
            self._idempotency_transaction(
                session,
                actor_id=principal.user_id,
                scope="POST /users/{user_id}/unlock",
                key=idempotency_key,
            ),
        ):
            replay = self._claim_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /users/{user_id}/unlock",
                key=idempotency_key,
                body=body,
                now=now,
            )
            if replay is not None:
                return OperationResult(
                    self._user_idempotency_replay_response(
                        session,
                        record=replay,
                        organization_id=principal.organization_id,
                        expected_user_id=user_id,
                        expected_status=200,
                    ),
                    replayed=True,
                )
            organization = self._lock_organization(
                session,
                principal.organization_id,
            )
            user = self._visible_user(
                session,
                principal.organization_id,
                user_id,
                lock=True,
            )
            if user.status == UserStatus.LOCKED:
                user.status = UserStatus.ACTIVE
            user.failed_login_count = 0
            user.locked_until = None
            user.updated_at = now
            user.row_version += 1
            self._append_audit(
                session,
                organization=organization,
                action="USER_UNLOCKED",
                actor=session.get(User, principal.user_id),
                target_type="USER",
                target_id=user.id,
                target_name=None,
                outcome="SUCCEEDED",
                reason_code=None,
                changed_fields=["status", "failed_login_count", "locked_until"],
                audit=audit,
            )
            response = self._user_response(session, user, organization.id)
            self._complete_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /users/{user_id}/unlock",
                key=idempotency_key,
                status=200,
                body=response.model_dump(mode="json"),
                resource_type="USER",
                resource_id=user.id,
            )
            return OperationResult(response)

    def reset_password(
        self,
        *,
        principal: Principal,
        user_id: UUID,
        temporary_password: str,
        idempotency_key: str,
        audit: AuditContext,
    ) -> bool:
        self._require_admin(principal, audit=audit, operation="RESET_PASSWORD")
        self._validate_password(temporary_password)
        now = utc_now()
        body = {
            "user_id": str(user_id),
            "temporary_password": temporary_password,
        }
        with (
            self.sessions() as session,
            self._idempotency_transaction(
                session,
                actor_id=principal.user_id,
                scope="POST /users/{user_id}/reset-password",
                key=idempotency_key,
            ),
        ):
            replay = self._claim_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /users/{user_id}/reset-password",
                key=idempotency_key,
                body=body,
                now=now,
            )
            if replay is not None:
                self._assert_user_idempotency_replay_resource(
                    session,
                    record=replay,
                    organization_id=principal.organization_id,
                    expected_user_id=user_id,
                    expected_status=204,
                )
                if replay.response_body != {}:
                    raise self._idempotency_resource_conflict()
                return True
            organization = self._lock_organization(
                session,
                principal.organization_id,
            )
            user = self._visible_user(
                session,
                principal.organization_id,
                user_id,
                lock=True,
            )
            if (
                self._lock_membership(
                    session,
                    organization_id=organization.id,
                    user_id=user.id,
                )
                is None
            ):
                raise self._not_found()
            user.password_hash = self.password_hasher.hash(temporary_password)
            user.password_changed_at = now
            user.must_change_password = True
            user.failed_login_count = 0
            user.locked_until = None
            if user.status == UserStatus.LOCKED:
                user.status = UserStatus.ACTIVE
            user.updated_at = now
            user.row_version += 1
            self._revoke_locked_user_sessions(
                session,
                user_id=user.id,
                now=now,
                reason="PASSWORD_RESET",
            )
            self._append_audit(
                session,
                organization=organization,
                action="USER_PASSWORD_RESET",
                actor=session.get(User, principal.user_id),
                target_type="USER",
                target_id=user.id,
                target_name=None,
                outcome="SUCCEEDED",
                reason_code=None,
                changed_fields=[
                    "password_hash",
                    "must_change_password",
                    "auth_sessions",
                ],
                audit=audit,
            )
            self._complete_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /users/{user_id}/reset-password",
                key=idempotency_key,
                status=204,
                body={},
                resource_type="USER",
                resource_id=user.id,
            )
            return False

    def _new_session(
        self,
        *,
        user: User,
        now: datetime,
        source_ip: str | None,
        family_id: UUID | None = None,
        rotated_from_id: UUID | None = None,
    ) -> tuple[str, AuthSession]:
        refresh_token = self.tokens.new_refresh_token()
        session_id = uuid4()
        return refresh_token, AuthSession(
            id=session_id,
            user_id=user.id,
            token_hash=self.tokens.hash_refresh_token(refresh_token),
            family_id=family_id or session_id,
            rotated_from_id=rotated_from_id,
            issued_at=now,
            expires_at=now + timedelta(days=self.refresh_token_days),
            ip_hash=self.tokens.hash_ip(source_ip),
        )

    def _lock_users(
        self,
        session: Session,
        user_ids: set[UUID],
    ) -> dict[UUID, User]:
        if not user_ids:
            return {}
        users = list(
            session.scalars(
                select(User)
                .where(User.id.in_(sorted(user_ids, key=str)))
                .order_by(User.id)
                .with_for_update()
            )
        )
        return {user.id: user for user in users}

    def _lock_user_sessions(
        self,
        session: Session,
        user_ids: set[UUID],
    ) -> list[AuthSession]:
        if not user_ids:
            return []
        return list(
            session.scalars(
                select(AuthSession)
                .where(AuthSession.user_id.in_(sorted(user_ids, key=str)))
                .order_by(AuthSession.id)
                .with_for_update()
            )
        )

    def _lock_membership(
        self,
        session: Session,
        *,
        organization_id: UUID,
        user_id: UUID,
    ) -> OrganizationMember | None:
        return session.scalar(
            select(OrganizationMember)
            .where(
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.user_id == user_id,
            )
            .with_for_update()
        )

    def _revoke_locked_user_sessions(
        self,
        session: Session,
        *,
        user_id: UUID,
        now: datetime,
        reason: str,
        exclude_session_id: UUID | None = None,
    ) -> None:
        auth_sessions = self._lock_user_sessions(session, {user_id})
        for auth_session in auth_sessions:
            if auth_session.id != exclude_session_id and auth_session.revoked_at is None:
                auth_session.revoked_at = now
                auth_session.revoke_reason = reason

    def _identity_for_session(
        self,
        session: Session,
        auth_session: AuthSession,
        *,
        lock: bool,
    ) -> tuple[Organization, User, OrganizationMember]:
        user_statement = select(User).where(User.id == auth_session.user_id)
        if lock:
            user_statement = user_statement.with_for_update()
        user = session.scalar(user_statement)
        if user is None:
            raise self._invalid_credentials()
        membership_statement = select(OrganizationMember).where(
            OrganizationMember.user_id == user.id
        )
        if lock:
            membership_statement = membership_statement.with_for_update()
        membership = session.scalar(membership_statement)
        if membership is None:
            raise self._invalid_credentials()
        organization_statement = select(Organization).where(
            Organization.id == membership.organization_id
        )
        if lock:
            organization_statement = organization_statement.with_for_update()
        organization = session.scalar(organization_statement)
        if organization is None:
            raise self._invalid_credentials()
        return organization, user, membership

    def _scoped_roles(self, session: Session, user_id: UUID) -> list[ScopedRoles]:
        rows = session.execute(
            select(
                RoleAssignment.scope_type,
                RoleAssignment.scope_id,
                RoleAssignment.role,
            )
            .join(
                OrganizationMember,
                OrganizationMember.id == RoleAssignment.organization_member_id,
            )
            .where(
                OrganizationMember.user_id == user_id,
                OrganizationMember.status == MembershipStatus.ACTIVE,
            )
            .order_by(
                RoleAssignment.scope_type,
                RoleAssignment.scope_id,
                RoleAssignment.role,
            )
        ).all()
        grouped: dict[tuple[str, UUID], list[Role]] = {}
        for scope_type, scope_id, role in rows:
            grouped.setdefault((scope_type, scope_id), []).append(Role(role))
        return [
            ScopedRoles(
                scope_type=ScopeType(scope_type),
                scope_id=scope_id,
                roles=roles,
            )
            for (scope_type, scope_id), roles in grouped.items()
        ]

    def _user_response(
        self,
        session: Session,
        user: User,
        organization_id: UUID,
    ) -> UserResponse:
        del organization_id
        return UserResponse(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            status=UserStatus(user.status),
            must_change_password=user.must_change_password,
            role_assignments=self._scoped_roles(session, user.id),
            row_version=user.row_version,
            created_at=ensure_aware(user.created_at),
            updated_at=ensure_aware(user.updated_at),
        )

    def _auth_response(self, user: User, access_token: str) -> AuthResponse:
        return AuthResponse(
            access_token=access_token,
            expires_in=self.tokens.access_token_seconds,
            user=UserSummary(
                id=user.id,
                email=user.email,
                display_name=user.display_name,
                must_change_password=user.must_change_password,
            ),
        )

    def _lock_organization(
        self,
        session: Session,
        organization_id: UUID,
    ) -> Organization:
        organization = session.scalar(
            select(Organization).where(Organization.id == organization_id).with_for_update()
        )
        if organization is None or organization.status != OrganizationStatus.ACTIVE:
            raise self._not_found()
        return organization

    def _visible_user(
        self,
        session: Session,
        organization_id: UUID,
        user_id: UUID,
        *,
        lock: bool = False,
    ) -> User:
        statement = (
            select(User)
            .join(OrganizationMember, OrganizationMember.user_id == User.id)
            .where(
                User.id == user_id,
                OrganizationMember.organization_id == organization_id,
            )
        )
        if lock:
            statement = statement.with_for_update(of=User)
        user = session.scalar(statement)
        if user is None:
            raise self._not_found()
        return user

    def _is_last_active_admin(
        self,
        session: Session,
        organization_id: UUID,
        user_id: UUID,
    ) -> bool:
        target_is_admin = session.scalar(
            select(func.count(RoleAssignment.id))
            .join(
                OrganizationMember,
                OrganizationMember.id == RoleAssignment.organization_member_id,
            )
            .where(
                OrganizationMember.user_id == user_id,
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.status == MembershipStatus.ACTIVE,
                RoleAssignment.scope_type == ScopeType.ORGANIZATION,
                RoleAssignment.scope_id == organization_id,
                RoleAssignment.role == Role.ADMIN,
            )
        )
        if not target_is_admin:
            return False
        active_admins = session.scalar(
            select(func.count(func.distinct(User.id)))
            .select_from(User)
            .join(OrganizationMember, OrganizationMember.user_id == User.id)
            .join(
                RoleAssignment,
                RoleAssignment.organization_member_id == OrganizationMember.id,
            )
            .where(
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.status == MembershipStatus.ACTIVE,
                User.status == UserStatus.ACTIVE,
                RoleAssignment.scope_type == ScopeType.ORGANIZATION,
                RoleAssignment.scope_id == organization_id,
                RoleAssignment.role == Role.ADMIN,
            )
        )
        return (active_admins or 0) <= 1

    def _revoke_family(
        self,
        session: Session,
        *,
        family_id: UUID,
        now: datetime,
        reason: str,
    ) -> None:
        session.execute(
            update(AuthSession)
            .where(
                AuthSession.family_id == family_id,
                AuthSession.revoked_at.is_(None),
            )
            .values(revoked_at=now, revoke_reason=reason)
        )

    @contextmanager
    def _idempotency_transaction(
        self,
        session: Session,
        *,
        actor_id: UUID,
        scope: str,
        key: str,
    ) -> Iterator[None]:
        """Serialize one idempotency namespace for the full database transaction."""
        lock_material = b"\x00".join(
            (
                _IDEMPOTENCY_LOCK_DOMAIN,
                actor_id.bytes,
                scope.encode("utf-8"),
                key.encode("utf-8"),
            )
        )
        lock_digest = hashlib.sha256(lock_material).digest()
        dialect = session.get_bind().dialect.name
        sqlite_lock: Lock | None = None
        if dialect == "sqlite":
            with _SQLITE_IDEMPOTENCY_LOCKS_GUARD:
                sqlite_lock, references = _SQLITE_IDEMPOTENCY_LOCKS.get(
                    lock_digest,
                    (Lock(), 0),
                )
                _SQLITE_IDEMPOTENCY_LOCKS[lock_digest] = (
                    sqlite_lock,
                    references + 1,
                )
            if not sqlite_lock.acquire(blocking=False):
                with _SQLITE_IDEMPOTENCY_LOCKS_GUARD:
                    registered_lock, references = _SQLITE_IDEMPOTENCY_LOCKS[lock_digest]
                    if references == 1:
                        del _SQLITE_IDEMPOTENCY_LOCKS[lock_digest]
                    else:
                        _SQLITE_IDEMPOTENCY_LOCKS[lock_digest] = (
                            registered_lock,
                            references - 1,
                        )
                raise self._idempotency_in_progress()
        try:
            with session.begin():
                if dialect == "postgresql":
                    advisory_key = int.from_bytes(
                        lock_digest[:8],
                        byteorder="big",
                        signed=True,
                    )
                    acquired = session.scalar(select(func.pg_try_advisory_xact_lock(advisory_key)))
                    if not acquired:
                        raise self._idempotency_in_progress()
                yield
        finally:
            if sqlite_lock is not None:
                with _SQLITE_IDEMPOTENCY_LOCKS_GUARD:
                    sqlite_lock.release()
                    registered_lock, references = _SQLITE_IDEMPOTENCY_LOCKS[lock_digest]
                    if references == 1:
                        del _SQLITE_IDEMPOTENCY_LOCKS[lock_digest]
                    else:
                        _SQLITE_IDEMPOTENCY_LOCKS[lock_digest] = (
                            registered_lock,
                            references - 1,
                        )

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
        request_hash = self._idempotency_request_hash(
            actor_id=actor_id,
            scope=scope,
            body=body,
        )
        existing = session.scalar(
            select(IdempotencyRecord)
            .where(
                IdempotencyRecord.actor_id == actor_id,
                IdempotencyRecord.scope == scope,
                IdempotencyRecord.idempotency_key == key,
            )
            .with_for_update()
        )
        if existing is not None and ensure_aware(existing.expires_at) <= ensure_aware(now):
            session.delete(existing)
            session.flush()
            existing = None
        if existing is not None:
            if existing.request_hash_scheme != IDEMPOTENCY_HASH_SCHEME or not hmac.compare_digest(
                existing.request_hash, request_hash
            ):
                raise ProblemException(
                    status=409,
                    code="IDEMPOTENCY_CONFLICT",
                    title="幂等键已用于其他请求",
                    detail="请使用新的 Idempotency-Key。",
                )
            if existing.response_status is None:
                raise self._idempotency_in_progress()
            return existing
        session.add(
            IdempotencyRecord(
                id=uuid4(),
                actor_id=actor_id,
                scope=scope,
                idempotency_key=key,
                request_hash=request_hash,
                request_hash_scheme=IDEMPOTENCY_HASH_SCHEME,
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )
        session.flush()
        return None

    def _assert_user_idempotency_replay_resource(
        self,
        session: Session,
        *,
        record: IdempotencyRecord,
        organization_id: UUID,
        expected_user_id: UUID | None,
        expected_status: int,
    ) -> User:
        """Fail closed unless a completed record still names this durable User."""

        resource_id = record.resource_id
        if (
            record.resource_type != "USER"
            or resource_id is None
            or record.response_status != expected_status
            or (expected_user_id is not None and resource_id != expected_user_id)
        ):
            raise self._idempotency_resource_conflict()
        user = session.scalar(
            select(User)
            .join(OrganizationMember, OrganizationMember.user_id == User.id)
            .where(
                User.id == resource_id,
                OrganizationMember.organization_id == organization_id,
            )
        )
        if user is None:
            raise self._idempotency_resource_conflict()
        return user

    def _user_idempotency_replay_response(
        self,
        session: Session,
        *,
        record: IdempotencyRecord,
        organization_id: UUID,
        expected_user_id: UUID | None,
        expected_status: int,
    ) -> UserResponse:
        user = self._assert_user_idempotency_replay_resource(
            session,
            record=record,
            organization_id=organization_id,
            expected_user_id=expected_user_id,
            expected_status=expected_status,
        )
        if record.response_body is None:
            raise self._idempotency_resource_conflict()
        try:
            response = UserResponse.model_validate(record.response_body)
        except ValidationError as exc:
            raise self._idempotency_resource_conflict() from exc
        if response.id != record.resource_id or response.id != user.id:
            raise self._idempotency_resource_conflict()
        return response

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
            self._idempotency_hmac_key,
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
        action: str,
        actor: User | None,
        target_type: str,
        target_id: UUID | None,
        target_name: str | None,
        outcome: str,
        reason_code: str | None,
        changed_fields: list[str],
        audit: AuditContext,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        # Locking the organization row serializes the per-organization chain.
        session.execute(
            select(Organization.id).where(Organization.id == organization.id).with_for_update()
        ).scalar_one()
        previous = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization.id)
            .order_by(AuditEvent.organization_sequence.desc())
            .limit(1)
        )
        sequence = (previous.organization_sequence + 1) if previous else 1
        previous_hash = previous.event_hash if previous else None
        occurred_at = utc_now()
        event_id = uuid4()
        event: dict[str, Any] = {
            "schema_version": "1.0",
            "event_id": str(event_id),
            "organization_id": str(organization.id),
            "sequence": sequence,
            "project_id": None,
            "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
            "action": action,
            "actor": {
                "kind": "USER" if actor is not None else "SYSTEM",
                "user_id": str(actor.id) if actor is not None else None,
                "display_name": actor.display_name if actor is not None else None,
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
            "outcome": outcome,
            "reason_code": reason_code,
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
        advance_audit_chain_watermark(
            session,
            organization_id=organization.id,
            previous_sequence=sequence - 1,
            previous_hash=previous_hash,
            sequence=sequence,
            event_hash=event_hash,
            updated_at=occurred_at,
        )
        session.add(
            AuditEvent(
                id=event_id,
                organization_id=organization.id,
                organization_sequence=sequence,
                project_id=None,
                event_json=event,
                canonicalization_version="RFC8785-v1",
                previous_hash=previous_hash,
                event_hash=event_hash,
                occurred_at=occurred_at,
                expires_at=occurred_at + timedelta(days=730),
            )
        )

    def _safe_audit_user_agent(self, user_agent: str | None) -> str | None:
        if user_agent is None:
            return None
        digest = hmac.new(
            self._idempotency_hmac_key,
            _AUDIT_USER_AGENT_HASH_DOMAIN + user_agent.encode("utf-8", errors="replace"),
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256-v1:{digest}"

    def _append_failure_audit_safely(
        self,
        *,
        organization_id: UUID,
        actor_id: UUID | None,
        action: str,
        target_type: str,
        target_id: UUID | None,
        reason_code: str,
        audit: AuditContext,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Persist a denial independently without changing the original response."""
        try:
            with self.sessions.begin() as session:
                organization = session.scalar(
                    select(Organization).where(Organization.id == organization_id).with_for_update()
                )
                if organization is None:
                    return
                actor = session.get(User, actor_id) if actor_id is not None else None
                self._append_audit(
                    session,
                    organization=organization,
                    action=action,
                    actor=actor,
                    target_type=target_type,
                    target_id=target_id,
                    target_name=None,
                    outcome="DENIED",
                    reason_code=reason_code,
                    changed_fields=[],
                    audit=audit,
                    metadata=metadata,
                )
        except Exception:
            _LOGGER.warning(
                "Failed to persist independent authentication denial audit",
                exc_info=True,
            )

    def _require_admin(
        self,
        principal: Principal,
        *,
        audit: AuditContext,
        operation: str,
    ) -> None:
        if not principal.is_admin or principal.must_change_password:
            self.audit_authorization_denied(
                principal=principal,
                audit=audit,
                operation=operation,
                reason_code="RBAC_FORBIDDEN",
            )
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限执行此操作",
                detail="需要有效的组织级 Admin 权限并完成首次改密。",
            )

    @staticmethod
    def _idempotency_in_progress() -> ProblemException:
        return ProblemException(
            status=409,
            code="IDEMPOTENCY_IN_PROGRESS",
            title="同一请求正在处理中",
            detail="请稍后使用相同 Idempotency-Key 重试。",
            retryable=True,
            headers={"Retry-After": "1"},
        )

    @staticmethod
    def _idempotency_resource_conflict() -> ProblemException:
        return ProblemException(
            status=409,
            code="IDEMPOTENCY_CONFLICT",
            title="Idempotency-Key 已用于不同请求",
            detail="幂等键保存的资源或响应与当前请求不一致。",
        )

    @staticmethod
    def _is_integrity_constraint(
        exc: IntegrityError,
        constraint_name: str,
    ) -> bool:
        original = exc.orig
        diagnostic = getattr(original, "diag", None)
        if (
            getattr(original, "sqlstate", None) == "23505"
            and getattr(diagnostic, "constraint_name", None) == constraint_name
        ):
            return True
        if getattr(original, "sqlite_errorname", None) != "SQLITE_CONSTRAINT_UNIQUE":
            return False
        if constraint_name == "uq_users_email":
            return "UNIQUE constraint failed: users.email" in str(original)
        return False

    def _validate_password(self, password: str) -> None:
        if len(password) < 12 or len(password) > 256:
            raise ValueError("password must contain 12 to 256 characters")

    @staticmethod
    def _invalid_credentials() -> ProblemException:
        return ProblemException(
            status=401,
            code="AUTH_INVALID_CREDENTIALS",
            title="认证失败",
            detail="邮箱或密码无效。",
            headers={"WWW-Authenticate": "Bearer"},
        )

    @staticmethod
    def _invalid_access_token() -> ProblemException:
        return ProblemException(
            status=401,
            code="AUTH_TOKEN_EXPIRED",
            title="登录会话无效",
            detail="请重新登录。",
            headers={"WWW-Authenticate": "Bearer"},
        )

    @staticmethod
    def _not_found() -> ProblemException:
        return ProblemException(
            status=404,
            code="NOT_FOUND",
            title="资源不存在",
            detail="资源不存在或不可见。",
        )

    @staticmethod
    def _version_conflict() -> ProblemException:
        return ProblemException(
            status=409,
            code="VERSION_CONFLICT",
            title="资源已被其他人修改",
            detail="请刷新后重新应用修改。",
        )

    @staticmethod
    def _last_admin_problem() -> ProblemException:
        return ProblemException(
            status=409,
            code="LAST_ADMIN_REQUIRED",
            title="必须保留一名有效管理员",
            detail="不能停用或撤销最后一名有效组织管理员。",
        )

    @staticmethod
    def _validation_problem(path: str, code: str) -> ProblemException:
        return ProblemException(
            status=422,
            code="VALIDATION_ERROR",
            title="请求字段无效",
            detail="请修正请求后重试。",
            field_errors=[
                {
                    "path": path,
                    "code": code,
                    "message": "该字段不允许为 null。",
                }
            ],
        )
