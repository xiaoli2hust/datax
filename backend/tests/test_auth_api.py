from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from uuid import UUID, uuid4

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from datax_studio.api.app import create_app
from datax_studio.api.problems import ProblemException
from datax_studio.auth.db import (
    AuditEvent,
    AuthSession,
    Base,
    IdempotencyRecord,
    Organization,
    OrganizationMember,
    RoleAssignment,
    User,
    UserStatus,
)
from datax_studio.auth.schemas import UserCreate
from datax_studio.auth.security import (
    Argon2idPasswordHasher,
    TokenManager,
    utc_now,
)
from datax_studio.auth.service import AuditContext, AuthService
from datax_studio.settings import Settings

TEMP_PASSWORD = "Temp-password-123!"
ADMIN_PASSWORD = "Admin-password-456!"
USER_PASSWORD = "User-password-789!"


@pytest.fixture
def auth_stack() -> tuple[TestClient, AuthService, sessionmaker, TokenManager]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            OrganizationMember.__table__,
            RoleAssignment.__table__,
            AuthSession.__table__,
            IdempotencyRecord.__table__,
            AuditEvent.__table__,
        ],
    )
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    private_key = Ed25519PrivateKey.generate()
    tokens = TokenManager(
        private_key=private_key,
        public_key=private_key.public_key(),
        refresh_hmac_key=b"r" * 32,
        issuer="test-issuer",
        audience="test-audience",
        access_token_seconds=900,
    )
    service = AuthService(
        sessions=sessions,
        password_hasher=Argon2idPasswordHasher(
            time_cost=1,
            memory_cost=8_192,
            parallelism=1,
        ),
        tokens=tokens,
        idempotency_hmac_key=b"i" * 32,
        refresh_token_days=30,
        login_failure_limit=5,
        login_lock_seconds=900,
    )
    service.bootstrap_admin(
        email="Admin@Example.com",
        display_name="Local Admin",
        password=TEMP_PASSWORD,
        organization_name="Test Organization",
        audit=_audit(),
    )
    app = create_app(
        settings=Settings(app_version="test", trusted_host="testserver"),
        auth_service=service,
    )
    with TestClient(app) as client:
        yield client, service, sessions, tokens


def _audit() -> AuditContext:
    return AuditContext(
        request_id=uuid4(),
        source_ip="127.0.0.1",
        user_agent="pytest",
    )


def _login(client: TestClient, email: str, password: str) -> tuple[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"], client.cookies.get("des_refresh")


def _activate_admin(client: TestClient) -> str:
    access_token, _ = _login(client, "admin@example.com", TEMP_PASSWORD)
    changed = client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "current_password": TEMP_PASSWORD,
            "new_password": ADMIN_PASSWORD,
        },
    )
    assert changed.status_code == 204, changed.text
    return access_token


def _create_user(
    client: TestClient,
    admin_token: str,
    *,
    email: str = "user@example.com",
    key: str = "create-user-001",
) -> dict:
    response = client.post(
        "/api/v1/users",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Idempotency-Key": key,
        },
        json={
            "email": email,
            "display_name": "Test User",
            "temporary_password": TEMP_PASSWORD,
        },
    )
    assert response.status_code == 201, response.text
    assert "temporary_password" not in response.text
    return response.json()


def test_login_uses_argon2id_ed25519_and_strict_loopback_cookie(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, sessions, tokens = auth_stack

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "ADMIN@example.com", "password": TEMP_PASSWORD},
    )

    assert response.status_code == 200
    assert response.json()["user"]["must_change_password"] is True
    cookie = response.headers["set-cookie"]
    assert "des_refresh=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/api/v1/auth" in cookie
    assert "Secure" not in cookie
    assert "Domain=" not in cookie
    claims = tokens.decode_access(response.json()["access_token"])
    assert claims.user_id
    assert claims.organization_id
    assert claims.session_id

    refresh_token = client.cookies.get("des_refresh")
    with sessions() as session:
        user = session.scalar(select(User))
        auth_session = session.scalar(select(AuthSession))
        assert user is not None and user.password_hash.startswith("$argon2id$")
        assert TEMP_PASSWORD not in user.password_hash
        assert auth_session is not None
        assert auth_session.token_hash == tokens.hash_refresh_token(refresh_token)
    assert refresh_token.encode() != auth_session.token_hash


def test_temporary_password_is_visible_and_business_routes_are_blocked(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, _, _ = auth_stack
    access_token, _ = _login(client, "admin@example.com", TEMP_PASSWORD)
    headers = {"Authorization": f"Bearer {access_token}"}

    me = client.get("/api/v1/auth/me", headers=headers)
    blocked = client.get("/api/v1/users", headers=headers)

    assert me.status_code == 200
    assert me.json()["user"]["must_change_password"] is True
    assert blocked.status_code == 403
    assert blocked.json()["code"] == "PASSWORD_CHANGE_REQUIRED"


def test_refresh_rotates_and_replay_revokes_the_whole_family(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, sessions, _ = auth_stack
    _, old_refresh = _login(client, "admin@example.com", TEMP_PASSWORD)

    rotated = client.post("/api/v1/auth/refresh")
    assert rotated.status_code == 200
    new_refresh = client.cookies.get("des_refresh")
    assert new_refresh != old_refresh
    new_access = rotated.json()["access_token"]

    with TestClient(client.app) as replay_client:
        replay_client.cookies.set(
            "des_refresh",
            old_refresh,
            path="/api/v1/auth",
        )
        replay = replay_client.post("/api/v1/auth/refresh")
    assert replay.status_code == 401
    assert replay.json()["code"] == "AUTH_INVALID_CREDENTIALS"

    invalidated = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {new_access}"},
    )
    assert invalidated.status_code == 401
    with sessions() as session:
        assert session.scalar(
            select(func.count(AuthSession.id)).where(
                AuthSession.revoke_reason == "REFRESH_TOKEN_REPLAY"
            )
        )


def test_login_failure_lock_and_local_last_admin_recovery(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, service, sessions, _ = auth_stack
    admin_token = _activate_admin(client)

    with pytest.raises(ProblemException) as active_recovery:
        service.recover_last_admin(
            email="admin@example.com",
            password="Recovery-password-123!",
            audit=_audit(),
        )
    assert active_recovery.value.code == "ADMIN_RECOVERY_NOT_ALLOWED"

    for _ in range(5):
        failed = client.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "Wrong-password-123!"},
        )
        assert failed.status_code == 401
        assert failed.json()["code"] == "AUTH_INVALID_CREDENTIALS"

    with sessions() as session:
        admin = session.scalar(select(User).where(User.email == "admin@example.com"))
        assert admin is not None
        assert admin.status == UserStatus.LOCKED
        assert admin.failed_login_count == 5
        admin_id = admin.id

    assert (
        client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).status_code
        == 401
    )

    recovered = service.recover_last_admin(
        email="admin@example.com",
        password="Recovery-password-123!",
        audit=_audit(),
    )
    assert recovered.id == admin_id
    assert recovered.status == UserStatus.ACTIVE
    assert recovered.must_change_password is True
    recovered_token, _ = _login(
        client,
        "admin@example.com",
        "Recovery-password-123!",
    )
    blocked = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {recovered_token}"},
    )
    assert blocked.status_code == 403
    assert blocked.json()["code"] == "PASSWORD_CHANGE_REQUIRED"
    with sessions() as session:
        event = session.scalar(
            select(AuditEvent).where(
                AuditEvent.event_json["action"].as_string() == "SYSTEM_RECOVER_ADMIN"
            )
        )
        assert event is not None
        assert "Recovery-password-123!" not in json.dumps(event.event_json)


def test_user_idempotency_rbac_disable_and_password_reset_revoke_sessions(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, sessions, _ = auth_stack
    admin_token = _activate_admin(client)
    created = _create_user(client, admin_token)

    replay = client.post(
        "/api/v1/users",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Idempotency-Key": "create-user-001",
        },
        json={
            "email": "user@example.com",
            "display_name": "Test User",
            "temporary_password": TEMP_PASSWORD,
        },
    )
    assert replay.status_code == 201
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json()["id"] == created["id"]

    with sessions() as session:
        record = session.scalar(
            select(IdempotencyRecord).where(IdempotencyRecord.idempotency_key == "create-user-001")
        )
        assert record is not None
        assert record.request_hash_scheme == "HMAC-SHA256-v1"
        unsafe_hash = hashlib.sha256(
            rfc8785.dumps(
                {
                    "email": "user@example.com",
                    "display_name": "Test User",
                    "temporary_password": TEMP_PASSWORD,
                }
            )
        ).hexdigest()
        assert record.request_hash != unsafe_hash
        assert TEMP_PASSWORD not in json.dumps(record.response_body)

    conflict = client.post(
        "/api/v1/users",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Idempotency-Key": "create-user-001",
        },
        json={
            "email": "other@example.com",
            "display_name": "Other",
            "temporary_password": TEMP_PASSWORD,
        },
    )
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"

    with sessions.begin() as session:
        user = session.get(User, UUID(created["id"]))
        assert user is not None
        user.status = UserStatus.LOCKED
        user.failed_login_count = 5
    unlocked = client.post(
        f"/api/v1/users/{created['id']}/unlock",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Idempotency-Key": "unlock-user-001",
        },
    )
    replayed_unlock = client.post(
        f"/api/v1/users/{created['id']}/unlock",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Idempotency-Key": "unlock-user-001",
        },
    )
    assert unlocked.status_code == 200
    assert replayed_unlock.status_code == 200
    assert replayed_unlock.headers["Idempotency-Replayed"] == "true"

    user_token, _ = _login(client, "user@example.com", TEMP_PASSWORD)
    forbidden = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["code"] == "PASSWORD_CHANGE_REQUIRED"

    changed = client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "current_password": TEMP_PASSWORD,
            "new_password": USER_PASSWORD,
        },
    )
    assert changed.status_code == 204

    rbac_denied = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert rbac_denied.status_code == 403
    assert rbac_denied.json()["code"] == "FORBIDDEN"

    reset = client.post(
        f"/api/v1/users/{created['id']}/reset-password",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Idempotency-Key": "reset-user-001",
        },
        json={"temporary_password": "Reset-password-321!"},
    )
    assert reset.status_code == 204
    replayed_reset = client.post(
        f"/api/v1/users/{created['id']}/reset-password",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Idempotency-Key": "reset-user-001",
        },
        json={"temporary_password": "Reset-password-321!"},
    )
    assert replayed_reset.status_code == 204
    assert replayed_reset.headers["Idempotency-Replayed"] == "true"
    revoked = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert revoked.status_code == 401

    detail = client.get(
        f"/api/v1/users/{created['id']}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert detail.status_code == 200
    disabled = client.patch(
        f"/api/v1/users/{created['id']}",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "If-Match": detail.headers["etag"],
        },
        json={"status": "DISABLED"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "DISABLED"
    with sessions() as session:
        user = session.get(User, UUID(created["id"]))
        assert user is not None and user.must_change_password is True
        authorization_denial = session.scalar(
            select(AuditEvent).where(
                AuditEvent.event_json["action"].as_string() == "AUTHORIZATION_DENIED",
                AuditEvent.event_json["reason_code"].as_string() == "RBAC_FORBIDDEN",
            )
        )
        assert authorization_denial is not None


def test_sqlite_idempotency_try_lock_rejects_concurrent_request(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, service, _, _ = auth_stack
    admin_token = _activate_admin(client)
    principal = service.authenticate_access(admin_token)
    entered_hash = Event()
    release_hash = Event()
    original_hash = service.password_hasher.hash

    def slow_hash(password: str) -> str:
        if password == "Concurrent-password-123!":
            entered_hash.set()
            assert release_hash.wait(timeout=5)
        return original_hash(password)

    monkeypatch.setattr(service.password_hasher, "hash", slow_hash)
    request = UserCreate(
        email="concurrent@example.com",
        display_name="Concurrent User",
        temporary_password="Concurrent-password-123!",
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            service.create_user,
            principal=principal,
            request=request,
            idempotency_key="concurrent-create-001",
            audit=_audit(),
        )
        assert entered_hash.wait(timeout=5)
        second = executor.submit(
            service.create_user,
            principal=principal,
            request=request,
            idempotency_key="concurrent-create-001",
            audit=_audit(),
        )
        with pytest.raises(ProblemException) as in_progress:
            second.result(timeout=5)
        assert in_progress.value.code == "IDEMPOTENCY_IN_PROGRESS"
        assert in_progress.value.headers == {
            "Retry-After": "1",
        }
        release_hash.set()
        assert first.result(timeout=5).replayed is False


def test_expired_idempotency_record_is_replaced_inside_lock(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, sessions, _ = auth_stack
    admin_token = _activate_admin(client)
    _create_user(
        client,
        admin_token,
        email="expired-first@example.com",
        key="expired-create-001",
    )
    with sessions.begin() as session:
        record = session.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.idempotency_key == "expired-create-001"
            )
        )
        assert record is not None
        old_record_id = record.id
        record.expires_at = utc_now() - timedelta(seconds=1)

    replaced = client.post(
        "/api/v1/users",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Idempotency-Key": "expired-create-001",
        },
        json={
            "email": "expired-second@example.com",
            "display_name": "Second User",
            "temporary_password": TEMP_PASSWORD,
        },
    )

    assert replaced.status_code == 201, replaced.text
    with sessions() as session:
        records = list(
            session.scalars(
                select(IdempotencyRecord).where(
                    IdempotencyRecord.idempotency_key == "expired-create-001"
                )
            )
        )
        assert len(records) == 1
        assert records[0].id != old_record_id


def test_integrity_error_mapping_requires_exact_unique_constraint() -> None:
    class Diagnostic:
        def __init__(self, constraint_name: str) -> None:
            self.constraint_name = constraint_name

    class PostgresUniqueViolation(Exception):
        sqlstate = "23505"

        def __init__(self, constraint_name: str) -> None:
            self.diag = Diagnostic(constraint_name)

    email_conflict = IntegrityError(
        "INSERT INTO users",
        {},
        PostgresUniqueViolation("uq_users_email"),
    )
    unrelated_unique = IntegrityError(
        "INSERT INTO idempotency_records",
        {},
        PostgresUniqueViolation("uq_idempotency_actor_scope_key"),
    )

    assert AuthService._is_integrity_constraint(
        email_conflict,
        "uq_users_email",
    )
    assert not AuthService._is_integrity_constraint(
        unrelated_unique,
        "uq_users_email",
    )


def test_denials_are_independently_audited_without_raw_request_secrets(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, sessions, _ = auth_stack
    admin_token = _activate_admin(client)
    wrong_password = "Definitely-wrong-123!"
    wrong = client.post(
        "/api/v1/auth/change-password",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "User-Agent": "wrong-password-canary",
        },
        json={
            "current_password": wrong_password,
            "new_password": "Unused-password-123!",
        },
    )
    assert wrong.status_code == 401

    _create_user(client, admin_token, email="duplicate@example.com")
    duplicate = client.post(
        "/api/v1/users",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Idempotency-Key": "duplicate-create-002",
            "User-Agent": "duplicate-email-canary",
        },
        json={
            "email": "duplicate@example.com",
            "display_name": "Duplicate",
            "temporary_password": "Duplicate-password-123!",
        },
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["code"] == "USER_EMAIL_CONFLICT"

    with sessions() as session:
        denied = list(
            session.scalars(
                select(AuditEvent)
                .where(AuditEvent.event_json["outcome"].as_string() == "DENIED")
                .order_by(AuditEvent.organization_sequence)
            )
        )
    serialized = json.dumps([event.event_json for event in denied])
    assert any(
        event.event_json["action"] == "USER_PASSWORD_CHANGED"
        and event.event_json["reason_code"] == "CURRENT_PASSWORD_INVALID"
        for event in denied
    )
    assert any(
        event.event_json["action"] == "USER_CREATED"
        and event.event_json["reason_code"] == "USER_EMAIL_CONFLICT"
        for event in denied
    )
    assert wrong_password not in serialized
    assert "wrong-password-canary" not in serialized
    assert "duplicate-email-canary" not in serialized


def test_failed_denial_audit_does_not_mask_original_rbac_error(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, service, _, _ = auth_stack
    admin_token = _activate_admin(client)
    _create_user(client, admin_token, email="audit-failure@example.com")
    user_token, _ = _login(client, "audit-failure@example.com", TEMP_PASSWORD)
    changed = client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "current_password": TEMP_PASSWORD,
            "new_password": USER_PASSWORD,
        },
    )
    assert changed.status_code == 204

    def fail_audit(*args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated audit storage failure")

    monkeypatch.setattr(service, "_append_audit", fail_audit)
    denied = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {user_token}"},
    )

    assert denied.status_code == 403
    assert denied.json()["code"] == "FORBIDDEN"


def test_last_active_admin_cannot_be_disabled_or_revoked(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, _, _ = auth_stack
    admin_token = _activate_admin(client)
    me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {admin_token}"},
    ).json()
    admin_id = me["user"]["id"]
    detail = client.get(
        f"/api/v1/users/{admin_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    disabled = client.patch(
        f"/api/v1/users/{admin_id}",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "If-Match": detail.headers["etag"],
        },
        json={"status": "DISABLED"},
    )
    assert disabled.status_code == 409
    assert disabled.json()["code"] == "LAST_ADMIN_REQUIRED"

    revoked = client.put(
        f"/api/v1/users/{admin_id}/organization-roles",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"roles": []},
    )
    assert revoked.status_code == 409
    assert revoked.json()["code"] == "LAST_ADMIN_REQUIRED"


def test_bootstrap_is_one_time_and_audit_chain_contains_no_secrets(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, service, sessions, _ = auth_stack
    _login(client, "admin@example.com", TEMP_PASSWORD)
    with pytest.raises(ProblemException) as raised:
        service.bootstrap_admin(
            email="second@example.com",
            display_name="Second",
            password="Second-password-123!",
            organization_name="Other",
            audit=_audit(),
        )
    assert raised.value.code == "BOOTSTRAP_ALREADY_COMPLETED"

    with sessions() as session:
        events = list(
            session.scalars(select(AuditEvent).order_by(AuditEvent.organization_sequence))
        )
    assert events[0].event_json["action"] == "SYSTEM_BOOTSTRAP_ADMIN"
    assert all(event.organization_sequence == index for index, event in enumerate(events, start=1))
    assert all(
        event.previous_hash == (events[index - 1].event_hash if index else None)
        for index, event in enumerate(events)
    )
    serialized = json.dumps([event.event_json for event in events])
    assert TEMP_PASSWORD not in serialized
    assert "des_refresh" not in serialized


def test_audit_user_agent_is_domain_separated_hmac_not_raw_input(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    _, service, sessions, _ = auth_stack
    canary = "Bearer audit-canary-secret\r\ncontrol"
    service.login(
        email="admin@example.com",
        password=TEMP_PASSWORD,
        audit=AuditContext(
            request_id=uuid4(),
            source_ip="127.0.0.1",
            user_agent=canary,
        ),
    )

    with sessions() as session:
        event = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.event_json["action"].as_string() == "AUTH_LOGIN_SUCCEEDED")
            .order_by(AuditEvent.organization_sequence.desc())
        )
        assert event is not None
        stored = event.event_json["request"]["user_agent"]
        assert stored.startswith("hmac-sha256-v1:")
        assert len(stored) == len("hmac-sha256-v1:") + 64
        assert "audit-canary-secret" not in json.dumps(event.event_json)
        assert "\r" not in stored and "\n" not in stored


def test_logout_is_idempotent_and_revokes_bearer_cookie_mismatch(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, sessions, _ = auth_stack
    _activate_admin(client)
    access_a, _ = _login(client, "admin@example.com", ADMIN_PASSWORD)
    access_b, refresh_b = _login(client, "admin@example.com", ADMIN_PASSWORD)

    logged_out = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access_a}"},
    )
    assert logged_out.status_code == 204
    assert client.cookies.get("des_refresh") is None

    with sessions() as session:
        active = session.scalar(
            select(func.count(AuthSession.id)).where(
                AuthSession.token_hash
                == client.app.state.auth_service.tokens.hash_refresh_token(refresh_b),
                AuthSession.revoked_at.is_(None),
            )
        )
        assert active == 0
    assert (
        client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_a}"},
        ).status_code
        == 401
    )
    assert (
        client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_b}"},
        ).status_code
        == 401
    )

    repeated = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access_a}"},
    )
    assert repeated.status_code == 204


def test_logout_without_credentials_is_an_idempotent_noop(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, _, _ = auth_stack
    client.cookies.clear()

    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 204
    assert client.cookies.get("des_refresh") is None


def test_malformed_refresh_cookie_returns_safe_problem(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, _, _ = auth_stack
    client.cookies.set("des_refresh", "not-valid*refresh", path="/api/v1/auth")

    response = client.post("/api/v1/auth/refresh")

    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "AUTH_INVALID_CREDENTIALS"


def test_validation_errors_use_problem_contract(
    auth_stack: tuple[TestClient, AuthService, sessionmaker, TokenManager],
) -> None:
    client, _, _, _ = auth_stack
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "invalid", "password": "short"},
    )
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "VALIDATION_ERROR"
    assert response.json()["request_id"]
