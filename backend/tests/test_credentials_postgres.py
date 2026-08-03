from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from datax_studio.api.problems import ProblemException
from datax_studio.auth.db import (
    AuthSession,
    Base,
    MembershipStatus,
    Organization,
    OrganizationMember,
    Role,
    RoleAssignment,
    ScopeType,
    User,
)
from datax_studio.auth.schemas import ScopedRoles
from datax_studio.auth.service import AuditContext, Principal
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    EndpointPolicy,
    EndpointPolicyRevision,
    PhysicalEndpointIdentity,
    Project,
)
from datax_studio.credentials.connectors import DatabaseConnector, ProbeResult
from datax_studio.credentials.db import (
    CredentialSecret,
    CredentialSecretEnvelope,
)
from datax_studio.credentials.keyring import KekKeyring
from datax_studio.credentials.network import EndpointPolicyGuard, ResolvedEndpoint
from datax_studio.credentials.schemas import DatasourcePatch, EndpointPolicyPatch
from datax_studio.credentials.service import CredentialService
from datax_studio.egress_attestation import EgressVerification

POSTGRES_TEST_URL_ENV = "DATAX_CREDENTIAL_POSTGRES_TEST_URL"


class _FixedEgressVerifier:
    """Controlled attestation for a database-transaction concurrency test.

    This fixture does not run an endpoint probe: its only real external
    dependency is the isolated PostgreSQL database that exercises row locking
    and secret/envelope transactions.  Endpoint/egress behavior has separate
    integration and E3 coverage.
    """

    def verify_runtime(self) -> EgressVerification:
        return self._verification()

    def verify_policy(self, **_kwargs: object) -> EgressVerification:
        return self._verification()

    @staticmethod
    def _verification() -> EgressVerification:
        return EgressVerification(
            policy_engine_version="egress-v1",
            resolver_policy_version="resolver-v1",
            network_namespace_id="net:[1]",
            policy_set_hash="1" * 64,
            ruleset_hash="2" * 64,
            checked_at=datetime.now(UTC),
        )


@pytest.fixture
def postgres_rotation_stack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[CredentialService, sessionmaker, Principal, UUID]:
    database_url = os.getenv(POSTGRES_TEST_URL_ENV)
    if not database_url:
        pytest.skip(f"{POSTGRES_TEST_URL_ENV} is required")
    schema = f"credential_rotation_{uuid4().hex}"
    administration_engine = create_engine(database_url, pool_pre_ping=True)
    with administration_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    test_engine: Engine | None = None
    try:
        test_engine = create_engine(
            database_url,
            pool_pre_ping=True,
            pool_size=8,
            max_overflow=0,
            connect_args={
                "options": (
                    f"-csearch_path={schema} -clock_timeout=5000ms -cstatement_timeout=15000ms"
                )
            },
        )
        Base.metadata.create_all(test_engine)
        sessions = sessionmaker(bind=test_engine, expire_on_commit=False)
        key_path = tmp_path / "credential-kek-v1.key"
        key_path.write_bytes(b"p" * 32)
        key_path.chmod(0o600)
        guard = EndpointPolicyGuard(
            resolver_policy_version="resolver-v1",
            egress_policy_version="egress-v1",
            egress_verifier=_FixedEgressVerifier(),
        )
        service = CredentialService(
            sessions=sessions,
            keyring=KekKeyring(tmp_path),
            active_kek_version="v1",
            integrity_hmac_key=b"h" * 32,
            guard=guard,
            connector=DatabaseConnector(
                guard=guard,
                connect_timeout_seconds=1,
                query_timeout_seconds=1,
            ),
        )

        def controlled_probe(
            _revision: object,
            *,
            password: bytearray,
            resolved: ResolvedEndpoint,
            deadline: object,
        ) -> ProbeResult:
            # The endpoint record intentionally uses a non-routable fixture
            # address.  This test proves PostgreSQL optimistic-lock behavior,
            # so it must not silently turn into a network-probe test.
            del password, deadline
            return ProbeResult(
                server_identity="postgres-credential-concurrency-fixture",
                server_version="fixture",
                peer_ip=resolved.selected_ip,
                latency_ms=1,
            )

        monkeypatch.setattr(service.connector, "probe", controlled_probe)
        service.ensure_active_kek_registered()
        now = datetime.now(UTC)
        organization_id = uuid4()
        user_id = uuid4()
        session_id = uuid4()
        project_id = uuid4()
        policy_id = uuid4()
        policy_revision_id = uuid4()
        identity_id = uuid4()
        datasource_id = uuid4()
        revision_id = uuid4()
        organization_member_id = uuid4()
        with sessions.begin() as session:
            session.add_all(
                [
                    Organization(
                        id=organization_id,
                        name="Credential PG",
                        status="ACTIVE",
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    User(
                        id=user_id,
                        email="admin@example.com",
                        display_name="Admin",
                        password_hash="not-used",
                        must_change_password=False,
                        password_changed_at=now,
                        status="ACTIVE",
                        failed_login_count=0,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                ]
            )
            session.flush()
            # SQLAlchemy has no ORM relationships between these independent
            # facts, so retain the real FK order explicitly for PostgreSQL.
            session.add_all(
                [
                    AuthSession(
                        id=session_id,
                        user_id=user_id,
                        token_hash=b"p" * 32,
                        family_id=session_id,
                        rotated_from_id=None,
                        issued_at=now,
                        expires_at=now + timedelta(days=1),
                        last_used_at=now,
                        revoked_at=None,
                        revoke_reason=None,
                        ip_hash=None,
                    ),
                    OrganizationMember(
                        id=organization_member_id,
                        organization_id=organization_id,
                        user_id=user_id,
                        status=MembershipStatus.ACTIVE,
                        joined_at=now,
                    ),
                ]
            )
            session.flush()
            session.add(
                RoleAssignment(
                    id=uuid4(),
                    organization_member_id=organization_member_id,
                    scope_type=ScopeType.ORGANIZATION,
                    scope_id=organization_id,
                    role=Role.ADMIN,
                    granted_by=user_id,
                    created_at=now,
                )
            )
            session.flush()
            session.add_all(
                [
                    Project(
                        id=project_id,
                        organization_id=organization_id,
                        name="Project",
                        slug="project",
                        status="ACTIVE",
                        created_by=user_id,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    EndpointPolicy(
                        id=policy_id,
                        organization_id=organization_id,
                        name="Policy",
                        current_revision_id=policy_revision_id,
                        status="ACTIVE",
                        created_by=user_id,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    PhysicalEndpointIdentity(
                        id=identity_id,
                        organization_id=organization_id,
                        engine="POSTGRESQL_15",
                        identity_scheme="POSTGRES_SYSTEM_IDENTIFIER",
                        server_identity_hash="b" * 64,
                        verification_evidence={},
                        verification_evidence_hash="c" * 64,
                        created_by=user_id,
                        created_at=now,
                    ),
                ]
            )
            session.flush()
            session.add(
                EndpointPolicyRevision(
                    id=policy_revision_id,
                    endpoint_policy_id=policy_id,
                    revision_no=1,
                    engine="POSTGRESQL_15",
                    host_kind="EXACT_IP",
                    host_value="10.0.0.5",
                    allowed_cidrs=["10.0.0.5/32"],
                    allowed_ports=[5432],
                    tls_required=False,
                    dns_ttl_ceiling_seconds=60,
                    resolver_policy_version="resolver-v1",
                    egress_policy_version="egress-v1",
                    policy_hash="a" * 64,
                    created_by=user_id,
                    created_at=now,
                )
            )
            session.flush()
            datasource = Datasource(
                id=datasource_id,
                project_id=project_id,
                name="Rotated",
                current_revision_id=revision_id,
                status="DISABLED",
                created_by=user_id,
                created_at=now,
                updated_at=now,
                row_version=1,
            )
            session.add(datasource)
            session.add(
                DatasourceRevision(
                    id=revision_id,
                    datasource_id=datasource_id,
                    revision_no=1,
                    endpoint_policy_revision_id=policy_revision_id,
                    physical_endpoint_identity_id=identity_id,
                    engine="POSTGRESQL_15",
                    host="10.0.0.5",
                    port=5432,
                    database_name="warehouse",
                    default_schema="public",
                    username="reader",
                    ssl_mode="DISABLE",
                    connection_options={},
                    config_hash="d" * 64,
                    created_by=user_id,
                    created_at=now,
                )
            )
            session.flush()
            service._install_secret(
                session,
                organization_id=organization_id,
                project_id=project_id,
                datasource=datasource,
                password=bytearray(b"initial-password"),
                actor_id=user_id,
                now=now,
            )
            datasource.status = "ACTIVE"
        principal = Principal(
            user_id=user_id,
            organization_id=organization_id,
            session_id=session_id,
            email="admin@example.com",
            display_name="Admin",
            must_change_password=False,
            role_assignments=(
                ScopedRoles(
                    scope_type=ScopeType.ORGANIZATION,
                    scope_id=organization_id,
                    roles=[Role.ADMIN],
                ),
            ),
        )
        yield service, sessions, principal, datasource_id
    finally:
        if test_engine is not None:
            test_engine.dispose()
        with administration_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        administration_engine.dispose()


def test_postgres_concurrent_rotation_has_one_winner(
    postgres_rotation_stack: tuple[
        CredentialService,
        sessionmaker,
        Principal,
        UUID,
    ],
) -> None:
    service, sessions, principal, datasource_id = postgres_rotation_stack
    barrier = Barrier(2)

    def rotate(password: str) -> str:
        barrier.wait(timeout=5)
        try:
            service.update_datasource(
                principal=principal,
                datasource_id=datasource_id,
                request=DatasourcePatch(password=password),
                expected_version=1,
                audit=AuditContext(
                    request_id=uuid4(),
                    source_ip="127.0.0.1",
                    user_agent="postgres-rotation-test",
                ),
            )
        except ProblemException as exc:
            return exc.code
        return "ROTATED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(rotate, "winner-one")
        second = executor.submit(rotate, "winner-two")
        results = {
            first.result(timeout=10),
            second.result(timeout=10),
        }
    # Depending on which phase-A transaction obtains the row after the
    # winner's C commit, the loser either sees the old ETag immediately or
    # has its detached A/B result rejected as stale.  Both are correct; two
    # successful rotations are not.
    assert results in (
        {"ROTATED", "VERSION_CONFLICT"},
        {"ROTATED", "DATASOURCE_OPERATION_STALE"},
    )

    with sessions() as session:
        secrets = list(
            session.scalars(select(CredentialSecret).order_by(CredentialSecret.secret_version))
        )
        envelopes = list(session.scalars(select(CredentialSecretEnvelope)))
        datasource = session.get(Datasource, datasource_id)
        assert datasource is not None
        assert datasource.row_version == 2
        assert len(secrets) == 2
        assert [secret.status for secret in secrets] == ["RETIRED", "ACTIVE"]
        assert datasource.current_secret_id == secrets[-1].id
        assert len(envelopes) == 2
        assert all(b"winner" not in secret.ciphertext for secret in secrets)


def test_postgres_blocked_probe_holds_no_organization_lock(
    postgres_rotation_stack: tuple[
        CredentialService,
        sessionmaker,
        Principal,
        UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """E2 lock-order evidence for ADR-0014's B phase.

    The connector waits only after phase A and the strict-current credential
    barrier have both committed.  A second PostgreSQL session must be able to
    take the same Organization row lock with NOWAIT while that probe remains
    blocked.  This is deliberately a real PostgreSQL test, not a SQLite/mock
    substitute for lock behavior.
    """

    service, sessions, principal, datasource_id = postgres_rotation_stack
    probe_started = Event()
    release_probe = Event()

    def blocked_probe(
        _revision: object,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
        deadline: object,
    ) -> ProbeResult:
        del password, deadline
        probe_started.set()
        assert release_probe.wait(timeout=5), "test must release the blocked B-phase probe"
        return ProbeResult(
            server_identity="postgres-credential-lock-fixture",
            server_version="fixture",
            peer_ip=resolved.selected_ip,
            latency_ms=1,
        )

    monkeypatch.setattr(service.connector, "probe", blocked_probe)

    def test_datasource() -> str:
        try:
            result = service.test_datasource(
                principal=principal,
                datasource_id=datasource_id,
                request_id=uuid4(),
                audit=AuditContext(
                    request_id=uuid4(),
                    source_ip="127.0.0.1",
                    user_agent="postgres-adr-0014-lock-test",
                ),
            )
        except ProblemException as exc:
            return exc.code
        return result.status

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(test_datasource)
        assert probe_started.wait(timeout=5), "connector probe did not enter B phase"

        # A blocked probe must not retain the Organization row locked by phase
        # A.  NOWAIT makes any accidental product-transaction lock an immediate
        # , deterministic PostgreSQL failure instead of a timing assertion.
        with sessions.begin() as session:
            organization = session.scalar(
                select(Organization)
                .where(Organization.id == principal.organization_id)
                .with_for_update(nowait=True)
            )
            assert organization is not None

        release_probe.set()
        assert future.result(timeout=10) == "SUCCEEDED"


def test_postgres_concurrent_endpoint_policy_patch_has_one_revision_winner(
    postgres_rotation_stack: tuple[
        CredentialService,
        sessionmaker,
        Principal,
        UUID,
    ],
) -> None:
    service, sessions, principal, datasource_id = postgres_rotation_stack
    with sessions() as session:
        datasource = session.get(Datasource, datasource_id)
        assert datasource is not None
        datasource_revision = session.get(
            DatasourceRevision,
            datasource.current_revision_id,
        )
        assert datasource_revision is not None
        original_revision = session.get(
            EndpointPolicyRevision,
            datasource_revision.endpoint_policy_revision_id,
        )
        assert original_revision is not None
        policy_id = original_revision.endpoint_policy_id
        original_revision_id = original_revision.id
    barrier = Barrier(2)

    def update_policy(ttl_seconds: int) -> str:
        barrier.wait(timeout=5)
        try:
            service.update_endpoint_policy(
                principal=principal,
                endpoint_policy_id=policy_id,
                request=EndpointPolicyPatch(
                    dns_ttl_ceiling_seconds=ttl_seconds,
                ),
                expected_version=1,
                audit=AuditContext(
                    request_id=uuid4(),
                    source_ip="127.0.0.1",
                    user_agent="postgres-endpoint-policy-test",
                ),
            )
        except ProblemException as exc:
            return exc.code
        return "UPDATED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(update_policy, 61)
        second = executor.submit(update_policy, 62)
        results = {
            first.result(timeout=10),
            second.result(timeout=10),
        }
    assert results == {"UPDATED", "VERSION_CONFLICT"}

    with sessions() as session:
        policy = session.get(EndpointPolicy, policy_id)
        revisions = list(
            session.scalars(
                select(EndpointPolicyRevision)
                .where(EndpointPolicyRevision.endpoint_policy_id == policy_id)
                .order_by(EndpointPolicyRevision.revision_no)
            )
        )
    assert policy is not None
    assert policy.row_version == 2
    assert len(revisions) == 2
    assert revisions[0].id == original_revision_id
    assert revisions[0].revision_no == 1
    assert revisions[0].dns_ttl_ceiling_seconds == 60
    assert revisions[1].revision_no == 2
    assert revisions[1].dns_ttl_ceiling_seconds in {61, 62}
    assert policy.current_revision_id == revisions[1].id
