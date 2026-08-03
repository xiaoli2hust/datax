from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from datax_studio.api.problems import ProblemException
from datax_studio.auth.db import (
    AuditChainWatermark,
    AuditEvent,
    AuthSession,
    Base,
    IdempotencyRecord,
    Organization,
    OrganizationMember,
    RoleAssignment,
    User,
)
from datax_studio.auth.schemas import UserCreate
from datax_studio.auth.security import Argon2idPasswordHasher, TokenManager
from datax_studio.auth.service import AuditContext, AuthService, Principal

POSTGRES_TEST_URL_ENV = "DATAX_AUTH_POSTGRES_TEST_URL"
TEMP_PASSWORD = "Postgres-temp-password-123!"
ADMIN_PASSWORD = "Postgres-admin-password-456!"
AUTH_TABLES = [
    Organization.__table__,
    User.__table__,
    OrganizationMember.__table__,
    RoleAssignment.__table__,
    AuthSession.__table__,
    IdempotencyRecord.__table__,
    AuditEvent.__table__,
    AuditChainWatermark.__table__,
]


def _audit() -> AuditContext:
    return AuditContext(
        request_id=uuid4(),
        source_ip="127.0.0.1",
        user_agent="postgres-concurrency-test",
    )


@pytest.fixture
def postgres_auth_stack() -> tuple[AuthService, sessionmaker, Principal]:
    database_url = os.getenv(POSTGRES_TEST_URL_ENV)
    if not database_url:
        pytest.skip(f"{POSTGRES_TEST_URL_ENV} is required")
    schema = f"auth_concurrency_{uuid4().hex}"
    administration_engine = create_engine(database_url, pool_pre_ping=True)
    with administration_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    test_engine: Engine | None = None
    try:
        test_engine = create_engine(
            database_url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=0,
            connect_args={
                "options": (
                    f"-csearch_path={schema} -clock_timeout=3000ms -cstatement_timeout=10000ms"
                )
            },
        )
        Base.metadata.create_all(test_engine, tables=AUTH_TABLES)
        sessions = sessionmaker(bind=test_engine, expire_on_commit=False)
        private_key = Ed25519PrivateKey.generate()
        service = AuthService(
            sessions=sessions,
            password_hasher=Argon2idPasswordHasher(
                time_cost=1,
                memory_cost=8_192,
                parallelism=1,
            ),
            tokens=TokenManager(
                private_key=private_key,
                public_key=private_key.public_key(),
                refresh_hmac_key=b"p" * 32,
                issuer="postgres-test-issuer",
                audience="postgres-test-audience",
                access_token_seconds=900,
            ),
            idempotency_hmac_key=b"q" * 32,
            refresh_token_days=30,
        )
        service.bootstrap_admin(
            email="admin@example.com",
            display_name="Postgres Admin",
            password=TEMP_PASSWORD,
            organization_name="Postgres Test",
            audit=_audit(),
        )
        login = service.login(
            email="admin@example.com",
            password=TEMP_PASSWORD,
            audit=_audit(),
        )
        temporary_principal = service.authenticate_access(login.response.access_token)
        service.change_password(
            principal=temporary_principal,
            current_password=TEMP_PASSWORD,
            new_password=ADMIN_PASSWORD,
            audit=_audit(),
        )
        principal = service.authenticate_access(login.response.access_token)
        yield service, sessions, principal
    finally:
        if test_engine is not None:
            test_engine.dispose()
        with administration_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        administration_engine.dispose()


def test_postgres_advisory_try_lock_rejects_concurrent_idempotency(
    postgres_auth_stack: tuple[AuthService, sessionmaker, Principal],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, principal = postgres_auth_stack
    entered_hash = Event()
    release_hash = Event()
    original_hash = service.password_hasher.hash

    def slow_hash(password: str) -> str:
        if password == "Concurrent-postgres-password-123!":
            entered_hash.set()
            assert release_hash.wait(timeout=5)
        return original_hash(password)

    monkeypatch.setattr(service.password_hasher, "hash", slow_hash)
    request = UserCreate(
        email="advisory-lock@example.com",
        display_name="Advisory Lock",
        temporary_password="Concurrent-postgres-password-123!",
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            service.create_user,
            principal=principal,
            request=request,
            idempotency_key="postgres-advisory-001",
            audit=_audit(),
        )
        assert entered_hash.wait(timeout=5)
        second = executor.submit(
            service.create_user,
            principal=principal,
            request=request,
            idempotency_key="postgres-advisory-001",
            audit=_audit(),
        )
        with pytest.raises(ProblemException) as in_progress:
            second.result(timeout=5)
        assert in_progress.value.code == "IDEMPOTENCY_IN_PROGRESS"
        release_hash.set()
        assert first.result(timeout=5).replayed is False


def test_postgres_refresh_and_reset_finish_without_deadlock(
    postgres_auth_stack: tuple[AuthService, sessionmaker, Principal],
) -> None:
    service, _, admin = postgres_auth_stack
    created = service.create_user(
        principal=admin,
        request=UserCreate(
            email="refresh-reset@example.com",
            display_name="Refresh Reset",
            temporary_password="Refresh-reset-start-123!",
        ),
        idempotency_key="refresh-reset-create-001",
        audit=_audit(),
    ).value
    current_password = "Refresh-reset-start-123!"

    for index in range(8):
        login = service.login(
            email="refresh-reset@example.com",
            password=current_password,
            audit=_audit(),
        )
        next_password = f"Refresh-reset-next-{index:02d}-123!"
        barrier = Barrier(2)

        def refresh(
            current_barrier: Barrier = barrier,
            refresh_token: str = login.refresh_token,
        ) -> str:
            current_barrier.wait(timeout=5)
            try:
                service.refresh(
                    refresh_token=refresh_token,
                    audit=_audit(),
                )
            except ProblemException as exc:
                assert exc.code == "AUTH_INVALID_CREDENTIALS"
                return "REVOKED"
            return "REFRESHED"

        def reset(
            current_barrier: Barrier = barrier,
            password: str = next_password,
            attempt: int = index,
        ) -> bool:
            current_barrier.wait(timeout=5)
            return service.reset_password(
                principal=admin,
                user_id=created.id,
                temporary_password=password,
                idempotency_key=f"refresh-reset-{attempt:02d}",
                audit=_audit(),
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            refresh_future = executor.submit(refresh)
            reset_future = executor.submit(reset)
            assert refresh_future.result(timeout=8) in {"REFRESHED", "REVOKED"}
            assert reset_future.result(timeout=8) is False
        current_password = next_password
