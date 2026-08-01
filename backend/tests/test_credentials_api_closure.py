from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from datax_studio.api.app import create_app
from datax_studio.auth.db import (
    AuditEvent,
    Base,
    Organization,
    OrganizationMember,
    Role,
    RoleAssignment,
    ScopeType,
    User,
)
from datax_studio.auth.routes import business_principal
from datax_studio.auth.schemas import ScopedRoles
from datax_studio.auth.service import Principal
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    DatasourceUsageGrant,
    EndpointPolicy,
    EndpointPolicyRevision,
    PhysicalEndpointIdentity,
    Project,
    SyncJob,
)
from datax_studio.core.service import ControlService
from datax_studio.credentials.connectors import DatabaseConnector, ProbeResult
from datax_studio.credentials.db import (
    CredentialSecret,
    EndpointConnectionEvidence,
)
from datax_studio.credentials.keyring import KekKeyring
from datax_studio.credentials.network import (
    EndpointPolicyGuard,
    ResolvedEndpoint,
)
from datax_studio.credentials.service import CredentialService
from datax_studio.schema_snapshot import SchemaSnapshot
from datax_studio.settings import Settings


@dataclass(frozen=True)
class CredentialApiStack:
    client: TestClient
    sessions: sessionmaker
    service: CredentialService
    principal_ref: dict[str, Principal]
    admin_a: Principal
    viewer_a: Principal
    ids: dict[str, UUID]


def _principal(
    *,
    user_id: UUID,
    organization_id: UUID,
    email: str,
    role: Role,
    scope_id: UUID,
) -> Principal:
    scope_type = (
        ScopeType.ORGANIZATION
        if role == Role.ADMIN
        else ScopeType.PROJECT
    )
    return Principal(
        user_id=user_id,
        organization_id=organization_id,
        session_id=uuid4(),
        email=email,
        display_name=email.split("@", maxsplit=1)[0],
        must_change_password=False,
        role_assignments=(
            ScopedRoles(
                scope_type=scope_type,
                scope_id=scope_id,
                roles=[role],
            ),
        ),
    )


@pytest.fixture
def credential_api_stack(tmp_path: Path) -> CredentialApiStack:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    key_path = tmp_path / "credential-kek-v1.key"
    key_path.write_bytes(b"k" * 32)
    key_path.chmod(0o600)
    guard = EndpointPolicyGuard(
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        connect_timeout_seconds=1,
    )
    service = CredentialService(
        sessions=sessions,
        keyring=KekKeyring(tmp_path),
        active_kek_version="v1",
        integrity_hmac_key=b"c" * 32,
        guard=guard,
        connector=DatabaseConnector(
            guard=guard,
            connect_timeout_seconds=1,
            query_timeout_seconds=1,
        ),
    )
    now = datetime.now(UTC)
    ids = {
        name: uuid4()
        for name in (
            "org_a",
            "org_b",
            "admin_a",
            "viewer_a",
            "outsider_a",
            "admin_b",
            "admin_member_a",
            "viewer_member_a",
            "outsider_member_a",
            "admin_member_b",
            "project_a",
            "project_b",
            "policy_a",
            "policy_b",
            "policy_revision_a",
            "policy_revision_b",
            "identity_a",
            "identity_b",
            "datasource_a",
            "datasource_b",
            "datasource_revision_a",
            "datasource_revision_b",
            "evidence_a",
            "evidence_b",
        )
    }
    with sessions.begin() as session:
        session.add_all(
            [
                Organization(
                    id=ids["org_a"],
                    name="Organization A",
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                Organization(
                    id=ids["org_b"],
                    name="Organization B",
                    status="SUSPENDED",
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                User(
                    id=ids["admin_a"],
                    email="admin-a@example.com",
                    display_name="Admin A",
                    password_hash="not-used",
                    must_change_password=False,
                    password_changed_at=now,
                    status="ACTIVE",
                    failed_login_count=0,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                User(
                    id=ids["viewer_a"],
                    email="viewer-a@example.com",
                    display_name="Viewer A",
                    password_hash="not-used",
                    must_change_password=False,
                    password_changed_at=now,
                    status="ACTIVE",
                    failed_login_count=0,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                User(
                    id=ids["outsider_a"],
                    email="outsider-a@example.com",
                    display_name="Outsider A",
                    password_hash="not-used",
                    must_change_password=False,
                    password_changed_at=now,
                    status="ACTIVE",
                    failed_login_count=0,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                User(
                    id=ids["admin_b"],
                    email="admin-b@example.com",
                    display_name="Admin B",
                    password_hash="not-used",
                    must_change_password=False,
                    password_changed_at=now,
                    status="ACTIVE",
                    failed_login_count=0,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                OrganizationMember(
                    id=ids["admin_member_a"],
                    organization_id=ids["org_a"],
                    user_id=ids["admin_a"],
                    status="ACTIVE",
                    joined_at=now,
                ),
                OrganizationMember(
                    id=ids["viewer_member_a"],
                    organization_id=ids["org_a"],
                    user_id=ids["viewer_a"],
                    status="ACTIVE",
                    joined_at=now,
                ),
                OrganizationMember(
                    id=ids["outsider_member_a"],
                    organization_id=ids["org_a"],
                    user_id=ids["outsider_a"],
                    status="ACTIVE",
                    joined_at=now,
                ),
                OrganizationMember(
                    id=ids["admin_member_b"],
                    organization_id=ids["org_b"],
                    user_id=ids["admin_b"],
                    status="ACTIVE",
                    joined_at=now,
                ),
                Project(
                    id=ids["project_a"],
                    organization_id=ids["org_a"],
                    name="Project A",
                    slug="project-a",
                    status="ACTIVE",
                    created_by=ids["admin_a"],
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                Project(
                    id=ids["project_b"],
                    organization_id=ids["org_b"],
                    name="Project B",
                    slug="project-b",
                    status="ACTIVE",
                    created_by=ids["admin_b"],
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                RoleAssignment(
                    id=uuid4(),
                    organization_member_id=ids["viewer_member_a"],
                    scope_type="PROJECT",
                    scope_id=ids["project_a"],
                    role="VIEWER",
                    granted_by=ids["admin_a"],
                    created_at=now,
                ),
                EndpointPolicy(
                    id=ids["policy_a"],
                    organization_id=ids["org_a"],
                    name="Policy A",
                    current_revision_id=ids["policy_revision_a"],
                    status="ACTIVE",
                    created_by=ids["admin_a"],
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                EndpointPolicy(
                    id=ids["policy_b"],
                    organization_id=ids["org_b"],
                    name="Policy B",
                    current_revision_id=ids["policy_revision_b"],
                    status="ACTIVE",
                    created_by=ids["admin_b"],
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                EndpointPolicyRevision(
                    id=ids["policy_revision_a"],
                    endpoint_policy_id=ids["policy_a"],
                    revision_no=1,
                    engine="POSTGRESQL_15",
                    host_kind="EXACT_FQDN",
                    host_value="db-a.example.com",
                    allowed_cidrs=["10.0.0.0/24"],
                    allowed_ports=[5432],
                    tls_required=True,
                    dns_ttl_ceiling_seconds=60,
                    resolver_policy_version="resolver-v1",
                    egress_policy_version="egress-v1",
                    policy_hash="a" * 64,
                    created_by=ids["admin_a"],
                    created_at=now,
                ),
                EndpointPolicyRevision(
                    id=ids["policy_revision_b"],
                    endpoint_policy_id=ids["policy_b"],
                    revision_no=1,
                    engine="MYSQL_8",
                    host_kind="EXACT_IP",
                    host_value="10.10.0.5",
                    allowed_cidrs=["10.10.0.5/32"],
                    allowed_ports=[3306],
                    tls_required=True,
                    dns_ttl_ceiling_seconds=60,
                    resolver_policy_version="resolver-v1",
                    egress_policy_version="egress-v1",
                    policy_hash="b" * 64,
                    created_by=ids["admin_b"],
                    created_at=now,
                ),
                PhysicalEndpointIdentity(
                    id=ids["identity_a"],
                    organization_id=ids["org_a"],
                    engine="POSTGRESQL_15",
                    identity_scheme="POSTGRES_SYSTEM_IDENTIFIER",
                    server_identity_hash="c" * 64,
                    verification_evidence={"source": "test"},
                    verification_evidence_hash="d" * 64,
                    created_by=ids["admin_a"],
                    created_at=now,
                ),
                PhysicalEndpointIdentity(
                    id=ids["identity_b"],
                    organization_id=ids["org_b"],
                    engine="MYSQL_8",
                    identity_scheme="MYSQL_SERVER_UUID",
                    server_identity_hash="e" * 64,
                    verification_evidence={"source": "test"},
                    verification_evidence_hash="f" * 64,
                    created_by=ids["admin_b"],
                    created_at=now,
                ),
                Datasource(
                    id=ids["datasource_a"],
                    project_id=ids["project_a"],
                    name="Datasource A",
                    description="A",
                    current_revision_id=ids["datasource_revision_a"],
                    current_secret_id=None,
                    status="ACTIVE",
                    created_by=ids["admin_a"],
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                Datasource(
                    id=ids["datasource_b"],
                    project_id=ids["project_b"],
                    name="Datasource B",
                    description="B",
                    current_revision_id=ids["datasource_revision_b"],
                    current_secret_id=None,
                    status="ACTIVE",
                    created_by=ids["admin_b"],
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                DatasourceRevision(
                    id=ids["datasource_revision_a"],
                    datasource_id=ids["datasource_a"],
                    revision_no=1,
                    endpoint_policy_revision_id=ids["policy_revision_a"],
                    physical_endpoint_identity_id=ids["identity_a"],
                    engine="POSTGRESQL_15",
                    host="db-a.example.com",
                    port=5432,
                    database_name="database_a",
                    default_schema="public",
                    username="reader_a",
                    ssl_mode="VERIFY_FULL",
                    connection_options={},
                    config_hash="1" * 64,
                    created_by=ids["admin_a"],
                    created_at=now,
                ),
                DatasourceRevision(
                    id=ids["datasource_revision_b"],
                    datasource_id=ids["datasource_b"],
                    revision_no=1,
                    endpoint_policy_revision_id=ids["policy_revision_b"],
                    physical_endpoint_identity_id=ids["identity_b"],
                    engine="MYSQL_8",
                    host="10.10.0.5",
                    port=3306,
                    database_name="database_b",
                    default_schema="database_b",
                    username="reader_b",
                    ssl_mode="REQUIRE",
                    connection_options={},
                    config_hash="2" * 64,
                    created_by=ids["admin_b"],
                    created_at=now,
                ),
                EndpointConnectionEvidence(
                    id=ids["evidence_a"],
                    operation_kind="TEST",
                    datasource_revision_id=ids["datasource_revision_a"],
                    endpoint_policy_revision_id=ids["policy_revision_a"],
                    resolver_policy_version="resolver-v1",
                    cname_chain=["db-a.example.com"],
                    resolved_ips=["10.0.0.5"],
                    selected_ip="10.0.0.5",
                    dns_valid_until=now + timedelta(minutes=1),
                    egress_policy_version="egress-v1",
                    egress_enforcement_status="VERIFIED",
                    egress_evidence_hash="3" * 64,
                    peer_ip="10.0.0.5",
                    tls_peer_spki_sha256="4" * 64,
                    decision="ALLOWED",
                    evidence_hash="5" * 64,
                    observed_at=now,
                ),
                EndpointConnectionEvidence(
                    id=ids["evidence_b"],
                    operation_kind="TEST",
                    datasource_revision_id=ids["datasource_revision_b"],
                    endpoint_policy_revision_id=ids["policy_revision_b"],
                    resolver_policy_version="resolver-v1",
                    cname_chain=[],
                    resolved_ips=["10.10.0.5"],
                    selected_ip="10.10.0.5",
                    dns_valid_until=now + timedelta(minutes=1),
                    egress_policy_version="egress-v1",
                    egress_enforcement_status="VERIFIED",
                    egress_evidence_hash="6" * 64,
                    peer_ip="10.10.0.5",
                    tls_peer_spki_sha256="7" * 64,
                    decision="ALLOWED",
                    evidence_hash="8" * 64,
                    observed_at=now,
                ),
            ]
        )

    admin_a = _principal(
        user_id=ids["admin_a"],
        organization_id=ids["org_a"],
        email="admin-a@example.com",
        role=Role.ADMIN,
        scope_id=ids["org_a"],
    )
    viewer_a = _principal(
        user_id=ids["viewer_a"],
        organization_id=ids["org_a"],
        email="viewer-a@example.com",
        role=Role.VIEWER,
        scope_id=ids["project_a"],
    )
    principal_ref = {"value": admin_a}
    app = create_app(
        settings=Settings(app_version="test", trusted_host="testserver"),
        control_service=ControlService(
            sessions=sessions,
            integrity_hmac_key=b"c" * 32,
        ),
        credential_service=service,
    )
    app.dependency_overrides[business_principal] = (
        lambda: principal_ref["value"]
    )
    with TestClient(app) as client:
        yield CredentialApiStack(
            client=client,
            sessions=sessions,
            service=service,
            principal_ref=principal_ref,
            admin_a=admin_a,
            viewer_a=viewer_a,
            ids=ids,
        )


def test_endpoint_policy_patch_creates_immutable_revision_and_honors_etag(
    credential_api_stack: CredentialApiStack,
) -> None:
    stack = credential_api_stack
    policy_id = stack.ids["policy_a"]
    revision_1_id = stack.ids["policy_revision_a"]

    duplicate = stack.client.patch(
        f"/api/v1/endpoint-policies/{policy_id}",
        headers={"If-Match": 'W/"1"'},
        json={"allowed_cidrs": ["10.0.0.0/24", "10.0.0.0/24"]},
    )
    invalid_host = stack.client.patch(
        f"/api/v1/endpoint-policies/{policy_id}",
        headers={"If-Match": 'W/"1"'},
        json={"host_kind": "EXACT_IP", "host_value": "db.example.com"},
    )
    explicit_null = stack.client.patch(
        f"/api/v1/endpoint-policies/{policy_id}",
        headers={"If-Match": 'W/"1"'},
        json={"name": None},
    )
    assert duplicate.status_code == 422
    assert invalid_host.status_code == 422
    assert explicit_null.status_code == 422

    updated = stack.client.patch(
        f"/api/v1/endpoint-policies/{policy_id}",
        headers={"If-Match": 'W/"1"'},
        json={"host_value": "DB2-A.Example.COM."},
    )
    assert updated.status_code == 200, updated.text
    assert updated.headers["etag"] == 'W/"2"'
    updated_body = updated.json()
    revision_2_id = updated_body["current_revision_id"]
    assert updated_body["row_version"] == 2
    assert updated_body["current_revision_no"] == 2
    assert updated_body["current_revision"]["host_value"] == "db2-a.example.com"

    revision_1 = stack.client.get(
        f"/api/v1/endpoint-policies/{policy_id}/revisions/{revision_1_id}"
    )
    revision_2 = stack.client.get(
        f"/api/v1/endpoint-policies/{policy_id}/revisions/{revision_2_id}"
    )
    assert revision_1.status_code == 200
    assert revision_2.status_code == 200
    assert revision_1.json()["host_value"] == "db-a.example.com"
    assert revision_1.json()["revision_no"] == 1
    assert revision_2.json()["host_value"] == "db2-a.example.com"
    assert revision_2.json()["revision_no"] == 2

    stale = stack.client.patch(
        f"/api/v1/endpoint-policies/{policy_id}",
        headers={"If-Match": 'W/"1"'},
        json={"status": "DISABLED"},
    )
    disabled = stack.client.patch(
        f"/api/v1/endpoint-policies/{policy_id}",
        headers={"If-Match": 'W/"2"'},
        json={"status": "DISABLED"},
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "VERSION_CONFLICT"
    assert disabled.status_code == 200
    assert disabled.headers["etag"] == 'W/"3"'
    assert disabled.json()["current_revision_id"] == revision_2_id
    assert disabled.json()["current_revision_no"] == 2
    assert disabled.json()["status"] == "DISABLED"

    stack.principal_ref["value"] = stack.viewer_a
    forbidden = stack.client.patch(
        f"/api/v1/endpoint-policies/{policy_id}",
        headers={"If-Match": 'W/"3"'},
        json={"status": "ACTIVE"},
    )
    stack.principal_ref["value"] = stack.admin_a
    cross_tenant_patch = stack.client.patch(
        f"/api/v1/endpoint-policies/{stack.ids['policy_b']}",
        headers={"If-Match": 'W/"1"'},
        json={"status": "DISABLED"},
    )
    cross_tenant_revision = stack.client.get(
        "/api/v1/endpoint-policies/"
        f"{stack.ids['policy_b']}/revisions/"
        f"{stack.ids['policy_revision_b']}"
    )
    assert forbidden.status_code == 403
    assert cross_tenant_patch.status_code == 404
    assert cross_tenant_revision.status_code == 404

    with stack.sessions() as session:
        revisions = list(
            session.scalars(
                select(EndpointPolicyRevision)
                .where(EndpointPolicyRevision.endpoint_policy_id == policy_id)
                .order_by(EndpointPolicyRevision.revision_no)
            )
        )
        actions = [
            event.event_json["action"]
            for event in session.scalars(
                select(AuditEvent)
                .where(AuditEvent.organization_id == stack.ids["org_a"])
                .order_by(AuditEvent.organization_sequence)
            )
        ]
    assert [item.host_value for item in revisions] == [
        "db-a.example.com",
        "db2-a.example.com",
    ]
    assert actions == [
        "ENDPOINT_POLICY_REVISION_CREATED",
        "ENDPOINT_POLICY_DISABLED",
    ]


def test_admin_only_revision_and_connection_evidence_are_redacted(
    credential_api_stack: CredentialApiStack,
) -> None:
    stack = credential_api_stack
    revision = stack.client.get(
        "/api/v1/datasources/"
        f"{stack.ids['datasource_a']}/revisions/"
        f"{stack.ids['datasource_revision_a']}"
    )
    evidence = stack.client.get(
        f"/api/v1/endpoint-connection-evidence/{stack.ids['evidence_a']}"
    )
    assert revision.status_code == 200
    assert evidence.status_code == 200
    assert set(revision.json()) == {
        "id",
        "datasource_id",
        "revision_no",
        "endpoint_policy_revision_id",
        "physical_endpoint_identity_id",
        "engine",
        "host",
        "port",
        "database_name",
        "default_schema",
        "username",
        "ssl_mode",
        "connection_options",
        "config_hash",
        "created_by",
        "created_at",
    }
    assert set(evidence.json()) == {
        "id",
        "operation_kind",
        "datasource_revision_id",
        "endpoint_policy_revision_id",
        "resolver_policy_version",
        "resolved_ips",
        "selected_ip",
        "peer_observation_status",
        "peer_ip",
        "egress_policy_version",
        "egress_evidence_hash",
        "decision",
        "evidence_hash",
        "observed_at",
    }
    serialized = json.dumps(
        {"revision": revision.json(), "evidence": evidence.json()}
    ).casefold()
    for forbidden_fragment in (
        "password",
        "secret_id",
        "ciphertext",
        "nonce",
        "dsn",
        "jdbc:",
        "tls_peer_spki",
        "fence_epoch",
        "execution_id",
        "recovery_probe_id",
    ):
        assert forbidden_fragment not in serialized

    stack.principal_ref["value"] = stack.viewer_a
    forbidden_revision = stack.client.get(
        "/api/v1/datasources/"
        f"{stack.ids['datasource_a']}/revisions/"
        f"{stack.ids['datasource_revision_a']}"
    )
    forbidden_evidence = stack.client.get(
        f"/api/v1/endpoint-connection-evidence/{stack.ids['evidence_a']}"
    )
    stack.principal_ref["value"] = stack.admin_a
    cross_tenant_revision = stack.client.get(
        "/api/v1/datasources/"
        f"{stack.ids['datasource_b']}/revisions/"
        f"{stack.ids['datasource_revision_b']}"
    )
    cross_tenant_evidence = stack.client.get(
        f"/api/v1/endpoint-connection-evidence/{stack.ids['evidence_b']}"
    )
    assert forbidden_revision.status_code == 403
    assert forbidden_evidence.status_code == 403
    assert cross_tenant_revision.status_code == 404
    assert cross_tenant_evidence.status_code == 404


def test_usage_grants_require_same_project_and_replace_atomically(
    credential_api_stack: CredentialApiStack,
) -> None:
    stack = credential_api_stack
    datasource_id = stack.ids["datasource_a"]
    member_id = stack.ids["viewer_member_a"]
    grant_url = f"/api/v1/datasources/{datasource_id}/grants/{member_id}"

    granted = stack.client.put(
        grant_url,
        json={"usages": ["SOURCE_USE", "TARGET_USE"]},
    )
    assert granted.status_code == 200, granted.text
    assert {item["usage"] for item in granted.json()["items"]} == {
        "SOURCE_USE",
        "TARGET_USE",
    }
    assert {item["status"] for item in granted.json()["items"]} == {"ACTIVE"}
    no_change = stack.client.put(
        grant_url,
        json={"usages": ["SOURCE_USE", "TARGET_USE"]},
    )
    assert no_change.status_code == 200
    assert {item["usage"] for item in no_change.json()["items"]} == {
        "SOURCE_USE",
        "TARGET_USE",
    }

    first_page = stack.client.get(
        f"/api/v1/datasources/{datasource_id}/grants",
        params={"limit": 1},
    )
    assert first_page.status_code == 200
    assert len(first_page.json()["items"]) == 1
    assert first_page.json()["has_more"] is True
    assert first_page.json()["next_cursor"]
    second_page = stack.client.get(
        f"/api/v1/datasources/{datasource_id}/grants",
        params={"limit": 1, "cursor": first_page.json()["next_cursor"]},
    )
    assert second_page.status_code == 200
    assert len(second_page.json()["items"]) == 1
    assert (
        second_page.json()["items"][0]["id"]
        != first_page.json()["items"][0]["id"]
    )
    tampered_cursor = (
        first_page.json()["next_cursor"][:-1]
        + (
            "A"
            if first_page.json()["next_cursor"][-1] != "A"
            else "B"
        )
    )
    invalid_cursor = stack.client.get(
        f"/api/v1/datasources/{datasource_id}/grants",
        params={"cursor": tampered_cursor},
    )
    assert invalid_cursor.status_code == 400
    assert invalid_cursor.json()["code"] == "CURSOR_INVALID"

    no_project_membership = stack.client.put(
        "/api/v1/datasources/"
        f"{datasource_id}/grants/{stack.ids['outsider_member_a']}",
        json={"usages": ["SOURCE_USE"]},
    )
    cross_tenant_member = stack.client.put(
        "/api/v1/datasources/"
        f"{datasource_id}/grants/{stack.ids['admin_member_b']}",
        json={"usages": ["SOURCE_USE"]},
    )
    cross_tenant_list = stack.client.get(
        f"/api/v1/datasources/{stack.ids['datasource_b']}/grants"
    )
    assert no_project_membership.status_code == 422
    assert (
        no_project_membership.json()["code"]
        == "PROJECT_MEMBERSHIP_REQUIRED"
    )
    assert cross_tenant_member.status_code == 404
    assert cross_tenant_list.status_code == 404

    revoked = stack.client.put(grant_url, json={"usages": []})
    assert revoked.status_code == 200
    assert revoked.json() == {
        "items": [],
        "next_cursor": None,
        "has_more": False,
    }
    with stack.sessions() as session:
        rows = list(
            session.scalars(
                select(DatasourceUsageGrant)
                .where(
                    DatasourceUsageGrant.datasource_id == datasource_id,
                    DatasourceUsageGrant.organization_member_id == member_id,
                )
                .order_by(DatasourceUsageGrant.usage)
            )
        )
        actions = [
            event.event_json["action"]
            for event in session.scalars(
                select(AuditEvent)
                .where(AuditEvent.organization_id == stack.ids["org_a"])
                .order_by(AuditEvent.organization_sequence)
            )
        ]
    assert len(rows) == 2
    assert {row.status for row in rows} == {"REVOKED"}
    assert all(row.revoked_by == stack.ids["admin_a"] for row in rows)
    assert all(row.revoked_at is not None for row in rows)
    assert actions == [
        "DATASOURCE_USAGE_GRANTED",
        "DATASOURCE_UPDATED",
        "DATASOURCE_USAGE_REVOKED",
    ]

    stack.principal_ref["value"] = stack.viewer_a
    forbidden_get = stack.client.get(
        f"/api/v1/datasources/{datasource_id}/grants"
    )
    forbidden_put = stack.client.put(
        grant_url,
        json={"usages": ["SOURCE_USE"]},
    )
    assert forbidden_get.status_code == 403
    assert forbidden_put.status_code == 403


def test_datasource_delete_is_soft_blocked_by_active_references_and_audited(
    credential_api_stack: CredentialApiStack,
) -> None:
    stack = credential_api_stack
    datasource_id = stack.ids["datasource_a"]
    member_id = stack.ids["viewer_member_a"]
    datasource_url = f"/api/v1/datasources/{datasource_id}"

    stack.principal_ref["value"] = stack.viewer_a
    forbidden = stack.client.delete(
        datasource_url,
        headers={"If-Match": 'W/"1"'},
    )
    stack.principal_ref["value"] = stack.admin_a
    cross_tenant = stack.client.delete(
        f"/api/v1/datasources/{stack.ids['datasource_b']}",
        headers={"If-Match": 'W/"1"'},
    )
    malformed_etag = stack.client.delete(
        datasource_url,
        headers={"If-Match": '"1"'},
    )
    missing_etag = stack.client.delete(datasource_url)
    assert forbidden.status_code == 403
    assert cross_tenant.status_code == 404
    assert malformed_etag.status_code == 422
    assert missing_etag.status_code == 422

    granted = stack.client.put(
        f"{datasource_url}/grants/{member_id}",
        json={"usages": ["SOURCE_USE"]},
    )
    assert granted.status_code == 200
    now = datetime.now(UTC)
    job_id = uuid4()
    with stack.sessions.begin() as session:
        session.add(
            SyncJob(
                id=job_id,
                project_id=stack.ids["project_a"],
                name="Active draft",
                status="DRAFT",
                draft_spec_json={
                    "source": {"datasource_id": str(datasource_id)},
                    "target": {"datasource_id": str(uuid4())},
                },
                draft_spec_hash="9" * 64,
                created_by=stack.ids["admin_a"],
                created_at=now,
                updated_at=now,
                row_version=1,
            )
        )

    blocked = stack.client.delete(
        datasource_url,
        headers={"If-Match": 'W/"1"'},
    )
    assert blocked.status_code == 409
    assert blocked.json()["code"] == "DATASOURCE_HAS_ACTIVE_REFERENCES"
    assert (
        blocked.json()["details"]["reference_type"]
        == "NON_ARCHIVED_JOB_DRAFT"
    )

    with stack.sessions.begin() as session:
        job = session.get(SyncJob, job_id)
        assert job is not None
        job.status = "ARCHIVED"
        job.archived_by = stack.ids["admin_a"]
        job.archived_at = now
        job.updated_at = now
        job.row_version += 1

    stale = stack.client.delete(
        datasource_url,
        headers={"If-Match": 'W/"2"'},
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "VERSION_CONFLICT"
    deleted = stack.client.delete(
        datasource_url,
        headers={"If-Match": 'W/"1"'},
    )
    assert deleted.status_code == 204
    assert deleted.content == b""
    historical_revision = stack.client.get(
        f"{datasource_url}/revisions/"
        f"{stack.ids['datasource_revision_a']}"
    )
    assert historical_revision.status_code == 200
    assert historical_revision.json()["id"] == str(
        stack.ids["datasource_revision_a"]
    )

    with stack.sessions() as session:
        datasource = session.get(Datasource, datasource_id)
        grant = session.scalar(
            select(DatasourceUsageGrant).where(
                DatasourceUsageGrant.datasource_id == datasource_id,
                DatasourceUsageGrant.organization_member_id == member_id,
                DatasourceUsageGrant.usage == "SOURCE_USE",
            )
        )
        actions = [
            event.event_json["action"]
            for event in session.scalars(
                select(AuditEvent)
                .where(AuditEvent.organization_id == stack.ids["org_a"])
                .order_by(AuditEvent.organization_sequence)
            )
        ]
    assert datasource is not None
    assert datasource.status == "DELETED"
    assert datasource.deleted_at is not None
    assert datasource.row_version == 2
    assert grant is not None
    assert grant.status == "REVOKED"
    assert grant.revoked_by == stack.ids["admin_a"]
    assert grant.revoked_at is not None
    assert actions == [
        "DATASOURCE_USAGE_GRANTED",
        "DATASOURCE_DELETED",
    ]


def _install_test_credential(stack: CredentialApiStack) -> UUID:
    stack.service.ensure_active_kek_registered()
    now = datetime.now(UTC)
    with stack.sessions.begin() as session:
        datasource = session.get(Datasource, stack.ids["datasource_a"])
        assert datasource is not None
        secret = stack.service._install_secret(
            session,
            organization_id=stack.ids["org_a"],
            project_id=stack.ids["project_a"],
            datasource=datasource,
            password=bytearray(b"old-test-password"),
            actor_id=stack.ids["admin_a"],
            now=now,
        )
        return secret.id


def _resolved(
    policy_revision: EndpointPolicyRevision,
    *,
    host: str,
    port: int,
) -> ResolvedEndpoint:
    selected_ip = (
        "10.10.0.5"
        if policy_revision.engine == "MYSQL_8"
        else "10.0.0.5"
    )
    return ResolvedEndpoint(
        endpoint_policy_revision_id=policy_revision.id,
        endpoint_policy_hash=policy_revision.policy_hash,
        hostname=host,
        port=port,
        cname_chain=(),
        resolved_ips=(selected_ip,),
        selected_ip=selected_ip,
        dns_valid_until=datetime.now(UTC) + timedelta(seconds=30),
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        egress_enforcement_status="VERIFIED",
        egress_attestation_hash="a" * 64,
    )


def test_datasource_patch_creates_revision_reuses_or_rotates_secret_and_fails_closed(
    credential_api_stack: CredentialApiStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack = credential_api_stack
    datasource_id = stack.ids["datasource_a"]
    original_revision_id = stack.ids["datasource_revision_a"]
    original_secret_id = _install_test_credential(stack)
    now = datetime.now(UTC)
    mysql_policy_id = uuid4()
    mysql_policy_revision_id = uuid4()
    with stack.sessions.begin() as session:
        session.add_all(
            [
                EndpointPolicy(
                    id=mysql_policy_id,
                    organization_id=stack.ids["org_a"],
                    name="MySQL policy",
                    current_revision_id=mysql_policy_revision_id,
                    status="ACTIVE",
                    created_by=stack.ids["admin_a"],
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                EndpointPolicyRevision(
                    id=mysql_policy_revision_id,
                    endpoint_policy_id=mysql_policy_id,
                    revision_no=1,
                    engine="MYSQL_8",
                    host_kind="EXACT_IP",
                    host_value="10.10.0.5",
                    allowed_cidrs=["10.10.0.5/32"],
                    allowed_ports=[3306],
                    tls_required=True,
                    dns_ttl_ceiling_seconds=60,
                    resolver_policy_version="resolver-v1",
                    egress_policy_version="egress-v1",
                    policy_hash="b" * 64,
                    created_by=stack.ids["admin_a"],
                    created_at=now,
                ),
            ]
        )

    probed_passwords: list[bytes] = []

    def resolve(
        policy_revision: EndpointPolicyRevision,
        *,
        host: str,
        port: int,
        now: datetime | None = None,
    ) -> ResolvedEndpoint:
        del now
        return _resolved(policy_revision, host=host, port=port)

    def probe(
        revision: DatasourceRevision,
        *,
        password: bytearray,
        resolved: ResolvedEndpoint,
    ) -> ProbeResult:
        probed_passwords.append(bytes(password))
        engine = revision.engine
        return ProbeResult(
            server_identity=(
                "mysql-server-uuid"
                if engine == "MYSQL_8"
                else "postgres-system-id"
            ),
            server_version="test-server",
            peer_ip=resolved.selected_ip,
            latency_ms=1,
        )

    monkeypatch.setattr(stack.service.guard, "resolve", resolve)
    monkeypatch.setattr(
        stack.service.guard,
        "verify_rebinding",
        lambda _policy, _resolved_endpoint: None,
    )
    monkeypatch.setattr(stack.service.connector, "probe", probe)

    switched = stack.client.patch(
        f"/api/v1/datasources/{datasource_id}",
        headers={"If-Match": 'W/"1"'},
        json={
            "endpoint_policy_id": str(mysql_policy_id),
            "engine": "MYSQL_8",
            "host": "10.10.0.5",
            "port": 3306,
            "database_name": "sales",
            "default_schema": "sales",
            "username": "reader",
            "ssl_mode": "REQUIRE",
        },
    )
    assert switched.status_code == 200, switched.text
    revision_2_id = UUID(switched.json()["current_revision"]["id"])
    assert revision_2_id != original_revision_id
    assert switched.json()["current_revision"]["revision_no"] == 2
    assert switched.json()["engine"] == "MYSQL_8"
    assert switched.headers["etag"] == 'W/"2"'
    with stack.sessions() as session:
        datasource = session.get(Datasource, datasource_id)
        revisions = list(
            session.scalars(
                select(DatasourceRevision)
                .where(DatasourceRevision.datasource_id == datasource_id)
                .order_by(DatasourceRevision.revision_no)
            )
        )
    assert datasource is not None
    assert datasource.current_secret_id == original_secret_id
    assert [item.revision_no for item in revisions] == [1, 2]
    assert revisions[0].host == "db-a.example.com"
    assert revisions[1].host == "10.10.0.5"

    rotated = stack.client.patch(
        f"/api/v1/datasources/{datasource_id}",
        headers={"If-Match": 'W/"2"'},
        json={"password": "new-test-password"},
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.headers["etag"] == 'W/"3"'
    assert UUID(rotated.json()["current_revision"]["id"]) == revision_2_id
    assert rotated.json()["current_secret"]["secret_version"] == 2
    with stack.sessions() as session:
        datasource = session.get(Datasource, datasource_id)
        secrets = list(
            session.scalars(
                select(CredentialSecret)
                .where(CredentialSecret.datasource_id == datasource_id)
                .order_by(CredentialSecret.secret_version)
            )
        )
    assert datasource is not None
    assert datasource.current_secret_id == secrets[1].id
    assert [item.status for item in secrets] == ["RETIRED", "ACTIVE"]
    assert probed_passwords == [
        b"old-test-password",
        b"new-test-password",
    ]

    disabled = stack.client.patch(
        f"/api/v1/datasources/{datasource_id}",
        headers={"If-Match": 'W/"3"'},
        json={"status": "DISABLED"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "DISABLED"
    assert len(probed_passwords) == 2
    restored = stack.client.patch(
        f"/api/v1/datasources/{datasource_id}",
        headers={"If-Match": 'W/"4"'},
        json={"status": "ACTIVE"},
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["status"] == "ACTIVE"
    assert len(probed_passwords) == 3

    def failed_probe(**_kwargs: object) -> ProbeResult:
        raise ValueError("DATABASE_CONNECTION_FAILED")

    monkeypatch.setattr(stack.service.connector, "probe", failed_probe)
    failed = stack.client.patch(
        f"/api/v1/datasources/{datasource_id}",
        headers={"If-Match": 'W/"5"'},
        json={
            "database_name": "must_not_persist",
            "default_schema": "must_not_persist",
            "password": "must-not-persist",
        },
    )
    assert failed.status_code == 422
    assert failed.json()["code"] == "DATABASE_CONNECTION_FAILED"
    with stack.sessions() as session:
        datasource = session.get(Datasource, datasource_id)
        revision_count = session.scalar(
            select(func.count(DatasourceRevision.id)).where(
                DatasourceRevision.datasource_id == datasource_id
            )
        )
        secret_count = session.scalar(
            select(func.count(CredentialSecret.id)).where(
                CredentialSecret.datasource_id == datasource_id
            )
        )
    assert datasource is not None
    assert datasource.row_version == 5
    assert datasource.current_revision_id == revision_2_id
    assert revision_count == 2
    assert secret_count == 2


def test_datasource_list_cursor_is_signed_and_bound_to_actor_project_and_filter(
    credential_api_stack: CredentialApiStack,
) -> None:
    stack = credential_api_stack
    now = datetime.now(UTC)
    added_ids = [uuid4(), uuid4()]
    revision_ids = [uuid4(), uuid4()]
    with stack.sessions.begin() as session:
        for offset, (datasource_id, revision_id) in enumerate(
            zip(added_ids, revision_ids, strict=True),
            start=1,
        ):
            created_at = now + timedelta(seconds=offset)
            session.add(
                Datasource(
                    id=datasource_id,
                    project_id=stack.ids["project_a"],
                    name=f"Paged {offset}",
                    current_revision_id=revision_id,
                    status="ACTIVE",
                    created_by=stack.ids["admin_a"],
                    created_at=created_at,
                    updated_at=created_at,
                    row_version=1,
                )
            )
            session.add(
                DatasourceRevision(
                    id=revision_id,
                    datasource_id=datasource_id,
                    revision_no=1,
                    endpoint_policy_revision_id=stack.ids[
                        "policy_revision_a"
                    ],
                    physical_endpoint_identity_id=stack.ids["identity_a"],
                    engine="POSTGRESQL_15",
                    host="db-a.example.com",
                    port=5432,
                    database_name="database_a",
                    default_schema="public",
                    username="reader_a",
                    ssl_mode="VERIFY_FULL",
                    connection_options={},
                    config_hash=hashlib.sha256(
                        str(datasource_id).encode()
                    ).hexdigest(),
                    created_by=stack.ids["admin_a"],
                    created_at=created_at,
                )
            )

    first = stack.client.get(
        f"/api/v1/projects/{stack.ids['project_a']}/datasources",
        params={"limit": 1},
    )
    assert first.status_code == 200
    assert first.json()["has_more"] is True
    cursor = first.json()["next_cursor"]
    assert cursor
    second = stack.client.get(
        f"/api/v1/projects/{stack.ids['project_a']}/datasources",
        params={"limit": 1, "cursor": cursor},
    )
    assert second.status_code == 200
    assert (
        second.json()["items"][0]["id"]
        != first.json()["items"][0]["id"]
    )

    stack.principal_ref["value"] = stack.viewer_a
    wrong_actor = stack.client.get(
        f"/api/v1/projects/{stack.ids['project_a']}/datasources",
        params={"limit": 1, "cursor": cursor},
    )
    assert wrong_actor.status_code == 400
    assert wrong_actor.json()["code"] == "CURSOR_INVALID"
    stack.principal_ref["value"] = stack.admin_a
    changed_filter = stack.client.get(
        f"/api/v1/projects/{stack.ids['project_a']}/datasources",
        params={
            "limit": 1,
            "cursor": cursor,
            "engine": "POSTGRESQL_15",
        },
    )
    assert changed_filter.status_code == 400
    assert changed_filter.json()["code"] == "CURSOR_INVALID"
    mysql_only = stack.client.get(
        f"/api/v1/projects/{stack.ids['project_a']}/datasources",
        params={"engine": "MYSQL_8"},
    )
    assert mysql_only.status_code == 200
    assert mysql_only.json()["items"] == []


def test_datasource_can_be_disabled_when_its_policy_revision_is_stale(
    credential_api_stack: CredentialApiStack,
) -> None:
    stack = credential_api_stack
    _install_test_credential(stack)
    policy_updated = stack.client.patch(
        f"/api/v1/endpoint-policies/{stack.ids['policy_a']}",
        headers={"If-Match": 'W/"1"'},
        json={"dns_ttl_ceiling_seconds": 30},
    )
    assert policy_updated.status_code == 200
    disabled = stack.client.patch(
        f"/api/v1/datasources/{stack.ids['datasource_a']}",
        headers={"If-Match": 'W/"1"'},
        json={"status": "DISABLED"},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["status"] == "DISABLED"


def _metadata_snapshot(
    *,
    identity_id: UUID,
    table_name: str,
) -> SchemaSnapshot:
    return SchemaSnapshot.model_validate(
        {
            "schema_version": "1.0",
            "normalization_version": "1.0",
            "engine": "POSTGRESQL_15",
            "physical_endpoint_identity_id": str(identity_id),
            "physical_table_identity_hash": hashlib.sha256(
                table_name.encode()
            ).hexdigest(),
            "identifier_case_mode": "POSTGRESQL_FOLDED_OR_QUOTED",
            "catalog_name": "database_a",
            "schema_name": "public",
            "table_name": table_name,
            "table_kind": "BASE_TABLE",
            "columns": [
                {
                    "ordinal_position": 1,
                    "name": "id",
                    "native_type": "bigint",
                    "logical_type": "INTEGER",
                    "nullable": False,
                    "unsigned": False,
                    "generated": False,
                    "identity": False,
                    "character_maximum_length": None,
                    "numeric_precision": 64,
                    "numeric_scale": 0,
                    "datetime_precision": None,
                    "character_set_name": None,
                    "collation_name": None,
                    "default_present": False,
                    "default_expression_sha256": None,
                }
            ],
            "constraints": [],
            "triggers": [],
            "table_options": {
                "partitioned": False,
                "row_security_enabled": False,
            },
        }
    )


def test_metadata_cursor_pages_without_repeating_and_rejects_scope_changes(
    credential_api_stack: CredentialApiStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack = credential_api_stack
    _install_test_credential(stack)
    other_datasource_id = uuid4()
    other_revision_id = uuid4()
    now = datetime.now(UTC)
    with stack.sessions.begin() as session:
        session.add(
            Datasource(
                id=other_datasource_id,
                project_id=stack.ids["project_a"],
                name="Other datasource",
                current_revision_id=other_revision_id,
                status="ACTIVE",
                created_by=stack.ids["admin_a"],
                created_at=now,
                updated_at=now,
                row_version=1,
            )
        )
        session.add(
            DatasourceRevision(
                id=other_revision_id,
                datasource_id=other_datasource_id,
                revision_no=1,
                endpoint_policy_revision_id=stack.ids["policy_revision_a"],
                physical_endpoint_identity_id=stack.ids["identity_a"],
                engine="POSTGRESQL_15",
                host="db-a.example.com",
                port=5432,
                database_name="database_a",
                default_schema="public",
                username="reader_a",
                ssl_mode="VERIFY_FULL",
                connection_options={},
                config_hash="f" * 64,
                created_by=stack.ids["admin_a"],
                created_at=now,
            )
        )
    snapshots = [
        _metadata_snapshot(
            identity_id=stack.ids["identity_a"],
            table_name=name,
        )
        for name in ("alpha", "beta", "gamma")
    ]
    connector_calls: list[tuple[str, str] | None] = []

    def resolve(
        policy_revision: EndpointPolicyRevision,
        *,
        host: str,
        port: int,
        now: datetime | None = None,
    ) -> ResolvedEndpoint:
        del now
        return _resolved(policy_revision, host=host, port=port)

    def schema_snapshots(
        _revision: DatasourceRevision,
        *,
        physical_endpoint_identity_id: UUID,
        password: bytearray,
        resolved: ResolvedEndpoint,
        schema_name: str | None,
        table_name: str | None,
        limit: int,
        after: tuple[str, str] | None = None,
    ) -> tuple[list[SchemaSnapshot], str, bool]:
        assert physical_endpoint_identity_id == stack.ids["identity_a"]
        assert bytes(password) == b"old-test-password"
        assert schema_name is None
        connector_calls.append(after)
        candidates = [
            item
            for item in snapshots
            if (table_name is None or item.table_name == table_name)
            and (after is None or item.table_name > after[1])
        ]
        return (
            candidates[:limit],
            resolved.selected_ip,
            len(candidates) > limit,
        )

    monkeypatch.setattr(stack.service.guard, "resolve", resolve)
    monkeypatch.setattr(
        stack.service.guard,
        "verify_rebinding",
        lambda _policy, _resolved_endpoint: None,
    )
    monkeypatch.setattr(
        stack.service.connector,
        "schema_snapshots",
        schema_snapshots,
    )
    url = (
        f"/api/v1/datasources/{stack.ids['datasource_a']}/schema/tables"
    )
    first = stack.client.get(url, params={"limit": 1})
    assert first.status_code == 200, first.text
    assert [item["table_name"] for item in first.json()["items"]] == ["alpha"]
    cursor = first.json()["next_cursor"]
    assert cursor
    second = stack.client.get(
        url,
        params={"limit": 1, "cursor": cursor},
    )
    assert second.status_code == 200, second.text
    assert [item["table_name"] for item in second.json()["items"]] == ["beta"]
    assert connector_calls == [None, ("public", "alpha")]

    other_admin = _principal(
        user_id=stack.ids["outsider_a"],
        organization_id=stack.ids["org_a"],
        email="other-admin@example.com",
        role=Role.ADMIN,
        scope_id=stack.ids["org_a"],
    )
    stack.principal_ref["value"] = other_admin
    wrong_actor = stack.client.get(
        url,
        params={"limit": 1, "cursor": cursor},
    )
    assert wrong_actor.status_code == 400
    assert wrong_actor.json()["code"] == "CURSOR_INVALID"
    stack.principal_ref["value"] = stack.admin_a
    wrong_datasource = stack.client.get(
        f"/api/v1/datasources/{other_datasource_id}/schema/tables",
        params={"limit": 1, "cursor": cursor},
    )
    assert wrong_datasource.status_code == 400
    assert wrong_datasource.json()["code"] == "CURSOR_INVALID"
    changed_filter = stack.client.get(
        url,
        params={
            "limit": 1,
            "cursor": cursor,
            "schema_name": "public",
        },
    )
    assert changed_filter.status_code == 400
    assert changed_filter.json()["code"] == "CURSOR_INVALID"
    assert connector_calls == [None, ("public", "alpha")]

    def metadata_failure(*_args: object, **_kwargs: object) -> None:
        raise TimeoutError("database did not respond")

    monkeypatch.setattr(
        stack.service.connector,
        "schema_snapshots",
        metadata_failure,
    )
    unavailable = stack.client.get(url, params={"limit": 1})
    assert unavailable.status_code == 503
    assert unavailable.json()["code"] == "DATASOURCE_METADATA_UNAVAILABLE"
    assert unavailable.json()["retryable"] is True
