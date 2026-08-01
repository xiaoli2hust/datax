from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import rfc8785
from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from datax_studio.api.problems import ProblemException
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
from datax_studio.auth.schemas import ScopedRoles
from datax_studio.auth.service import AuditContext, Principal
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    EndpointPolicy,
    EndpointPolicyRevision,
    PhysicalEndpointIdentity,
    Project,
    TransferPolicy,
    TransferPolicyApproval,
)
from datax_studio.credentials.schemas import (
    ColumnSchema,
    TableSchema,
    TableSchemaPage,
)
from datax_studio.governance.schemas import (
    RoleReplaceRequest,
    TransferPolicyCreate,
    TransferPolicyDecision,
    TransferPolicyPatch,
    TransferPolicyScopeInput,
    TransferPolicySubmit,
)
from datax_studio.governance.service import GovernanceService


@dataclass
class FakeMetadataProbe:
    pages: dict[UUID, TableSchemaPage]
    fail: bool = False
    calls: list[tuple[UUID, str, str | None, str | None]] = field(
        default_factory=list
    )

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
    ) -> TableSchemaPage:
        del principal, limit, audit
        self.calls.append((datasource_id, usage, schema_name, table_name))
        if self.fail:
            raise RuntimeError("database is offline")
        return self.pages[datasource_id]


@dataclass(frozen=True)
class GovernanceStack:
    sessions: sessionmaker
    service: GovernanceService
    probe: FakeMetadataProbe
    audit: AuditContext
    project_id: UUID
    source_revision_id: UUID
    target_revision_id: UUID
    source_datasource_id: UUID
    target_datasource_id: UUID
    source_identity_id: UUID
    target_identity_id: UUID
    member_user_id: UUID
    requester: Principal
    approver_one: Principal
    approver_two: Principal


@pytest.fixture
def governance_stack() -> GovernanceStack:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(UTC)
    organization_id = uuid4()
    project_id = uuid4()
    source_datasource_id = uuid4()
    target_datasource_id = uuid4()
    source_revision_id = uuid4()
    target_revision_id = uuid4()
    source_identity_id = uuid4()
    target_identity_id = uuid4()
    endpoint_policy_id = uuid4()
    endpoint_revision_id = uuid4()
    requester_id = uuid4()
    approver_one_id = uuid4()
    approver_two_id = uuid4()
    member_user_id = uuid4()
    users = [
        (requester_id, "requester@example.com", "Requester"),
        (approver_one_id, "approver-one@example.com", "Approver One"),
        (approver_two_id, "approver-two@example.com", "Approver Two"),
        (member_user_id, "member@example.com", "Member"),
    ]
    member_ids = {user_id: uuid4() for user_id, _, _ in users}
    with sessions.begin() as session:
        session.add(
            Organization(
                id=organization_id,
                name="Governance Test Organization",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
                row_version=1,
            )
        )
        for user_id, email, display_name in users:
            session.add(
                User(
                    id=user_id,
                    email=email,
                    display_name=display_name,
                    password_hash="not-used-by-governance-tests",
                    must_change_password=False,
                    password_changed_at=now,
                    status="ACTIVE",
                    failed_login_count=0,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                )
            )
            session.add(
                OrganizationMember(
                    id=member_ids[user_id],
                    organization_id=organization_id,
                    user_id=user_id,
                    status="ACTIVE",
                    joined_at=now,
                )
            )
        for admin_id in (
            requester_id,
            approver_one_id,
            approver_two_id,
        ):
            session.add(
                RoleAssignment(
                    id=uuid4(),
                    organization_member_id=member_ids[admin_id],
                    scope_type=ScopeType.ORGANIZATION,
                    scope_id=organization_id,
                    role=Role.ADMIN,
                    granted_by=requester_id,
                    created_at=now,
                )
            )
        session.add(
            Project(
                id=project_id,
                organization_id=organization_id,
                name="Offline Copy",
                slug="offline-copy",
                description=None,
                status="ACTIVE",
                created_by=requester_id,
                archived_by=None,
                archived_at=None,
                created_at=now,
                updated_at=now,
                row_version=1,
            )
        )
        session.add(
            EndpointPolicy(
                id=endpoint_policy_id,
                organization_id=organization_id,
                name="PostgreSQL local test",
                current_revision_id=endpoint_revision_id,
                status="ACTIVE",
                created_by=requester_id,
                created_at=now,
                updated_at=now,
                row_version=1,
            )
        )
        session.add(
            EndpointPolicyRevision(
                id=endpoint_revision_id,
                endpoint_policy_id=endpoint_policy_id,
                revision_no=1,
                engine="POSTGRESQL_15",
                host_kind="EXACT_IP",
                host_value="127.0.0.1",
                allowed_cidrs=["127.0.0.1/32"],
                allowed_ports=[5432],
                tls_required=False,
                dns_ttl_ceiling_seconds=60,
                resolver_policy_version="resolver-test",
                egress_policy_version="egress-test",
                policy_hash="1" * 64,
                created_by=requester_id,
                created_at=now,
            )
        )
        session.add_all(
            [
                PhysicalEndpointIdentity(
                    id=source_identity_id,
                    organization_id=organization_id,
                    engine="POSTGRESQL_15",
                    identity_scheme="POSTGRES_SYSTEM_IDENTIFIER",
                    server_identity_hash="2" * 64,
                    verification_evidence={"test": "source"},
                    verification_evidence_hash="3" * 64,
                    created_by=requester_id,
                    created_at=now,
                ),
                PhysicalEndpointIdentity(
                    id=target_identity_id,
                    organization_id=organization_id,
                    engine="POSTGRESQL_15",
                    identity_scheme="POSTGRES_SYSTEM_IDENTIFIER",
                    server_identity_hash="4" * 64,
                    verification_evidence={"test": "target"},
                    verification_evidence_hash="5" * 64,
                    created_by=requester_id,
                    created_at=now,
                ),
            ]
        )
        session.add_all(
            [
                Datasource(
                    id=source_datasource_id,
                    project_id=project_id,
                    name="Source",
                    description=None,
                    current_revision_id=source_revision_id,
                    current_secret_id=None,
                    status="ACTIVE",
                    last_test_status="SUCCEEDED",
                    last_tested_at=now,
                    last_test_error_code=None,
                    created_by=requester_id,
                    deleted_at=None,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
                Datasource(
                    id=target_datasource_id,
                    project_id=project_id,
                    name="Target",
                    description=None,
                    current_revision_id=target_revision_id,
                    current_secret_id=None,
                    status="ACTIVE",
                    last_test_status="SUCCEEDED",
                    last_tested_at=now,
                    last_test_error_code=None,
                    created_by=requester_id,
                    deleted_at=None,
                    created_at=now,
                    updated_at=now,
                    row_version=1,
                ),
            ]
        )
        session.add_all(
            [
                DatasourceRevision(
                    id=source_revision_id,
                    datasource_id=source_datasource_id,
                    revision_no=1,
                    endpoint_policy_revision_id=endpoint_revision_id,
                    physical_endpoint_identity_id=source_identity_id,
                    engine="POSTGRESQL_15",
                    host="127.0.0.1",
                    port=5432,
                    database_name="sales",
                    default_schema="public",
                    username="source_reader",
                    ssl_mode="DISABLE",
                    connection_options={},
                    config_hash="6" * 64,
                    created_by=requester_id,
                    created_at=now,
                ),
                DatasourceRevision(
                    id=target_revision_id,
                    datasource_id=target_datasource_id,
                    revision_no=1,
                    endpoint_policy_revision_id=endpoint_revision_id,
                    physical_endpoint_identity_id=target_identity_id,
                    engine="POSTGRESQL_15",
                    host="127.0.0.1",
                    port=5432,
                    database_name="warehouse",
                    default_schema="public",
                    username="target_writer",
                    ssl_mode="DISABLE",
                    connection_options={},
                    config_hash="7" * 64,
                    created_by=requester_id,
                    created_at=now,
                ),
            ]
        )

    source_page = _table_page(
        table_name="orders",
        physical_table_hash="8" * 64,
        captured_at=now,
    )
    target_page = _table_page(
        table_name="orders_copy",
        physical_table_hash="9" * 64,
        captured_at=now,
    )
    probe = FakeMetadataProbe(
        pages={
            source_datasource_id: source_page,
            target_datasource_id: target_page,
        }
    )

    def principal(user_id: UUID, email: str, display_name: str) -> Principal:
        return Principal(
            user_id=user_id,
            organization_id=organization_id,
            session_id=uuid4(),
            email=email,
            display_name=display_name,
            must_change_password=False,
            role_assignments=(
                ScopedRoles(
                    scope_type=ScopeType.ORGANIZATION,
                    scope_id=organization_id,
                    roles=[Role.ADMIN],
                ),
            ),
        )

    return GovernanceStack(
        sessions=sessions,
        service=GovernanceService(
            sessions=sessions,
            integrity_hmac_key=b"governance-test-integrity-key-0001",
        ),
        probe=probe,
        audit=AuditContext(
            request_id=uuid4(),
            source_ip="127.0.0.1",
            user_agent="pytest-governance",
        ),
        project_id=project_id,
        source_revision_id=source_revision_id,
        target_revision_id=target_revision_id,
        source_datasource_id=source_datasource_id,
        target_datasource_id=target_datasource_id,
        source_identity_id=source_identity_id,
        target_identity_id=target_identity_id,
        member_user_id=member_user_id,
        requester=principal(
            requester_id,
            "requester@example.com",
            "Requester",
        ),
        approver_one=principal(
            approver_one_id,
            "approver-one@example.com",
            "Approver One",
        ),
        approver_two=principal(
            approver_two_id,
            "approver-two@example.com",
            "Approver Two",
        ),
    )


def test_member_role_replace_and_empty_atomic_revoke(
    governance_stack: GovernanceStack,
) -> None:
    assigned = governance_stack.service.replace_project_member_roles(
        principal=governance_stack.requester,
        project_id=governance_stack.project_id,
        user_id=governance_stack.member_user_id,
        request=RoleReplaceRequest(roles=["VIEWER", "DEVELOPER"]),
        expected_version=1,
        audit=governance_stack.audit,
    )
    assert assigned.row_version == 2
    assert assigned.value.organization_member_id is not None
    assert set(assigned.value.roles) == {Role.DEVELOPER, Role.VIEWER}

    listed = governance_stack.service.list_project_members(
        principal=governance_stack.requester,
        project_id=governance_stack.project_id,
        limit=50,
        cursor=None,
    )
    assert [item.user.id for item in listed.value.items] == [governance_stack.member_user_id]

    revoked = governance_stack.service.replace_project_member_roles(
        principal=governance_stack.requester,
        project_id=governance_stack.project_id,
        user_id=governance_stack.member_user_id,
        request=RoleReplaceRequest(roles=[]),
        expected_version=2,
        audit=governance_stack.audit,
    )
    assert revoked.row_version == 3
    assert revoked.value.roles == []
    with governance_stack.sessions() as session:
        project_role_count = session.scalar(
            select(func.count())
            .select_from(RoleAssignment)
            .join(
                OrganizationMember,
                OrganizationMember.id == RoleAssignment.organization_member_id,
            )
            .where(
                OrganizationMember.user_id == governance_stack.member_user_id,
                RoleAssignment.scope_type == ScopeType.PROJECT,
                RoleAssignment.scope_id == governance_stack.project_id,
            )
        )
        events = list(
            session.scalars(
                select(AuditEvent).order_by(AuditEvent.organization_sequence)
            )
        )
    assert project_role_count == 0
    assert [event.event_json["action"] for event in events] == [
        "ROLE_GRANTED",
        "ROLE_GRANTED",
        "ROLE_REVOKED",
        "ROLE_REVOKED",
    ]
    schema = json.loads(
        (
            Path(__file__).parents[2]
            / "docs"
            / "contracts"
            / "audit-event.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for event in events:
        validator.validate(event.event_json)


def test_server_fixes_scope_from_real_metadata_and_hashes_canonical_json(
    governance_stack: GovernanceStack,
) -> None:
    created = _create_policy(
        governance_stack,
        classification="STANDARD",
        key="create-policy-scope-001",
    ).value

    assert created.scope_json.source.physical_endpoint_identity_id == (
        governance_stack.source_identity_id
    )
    assert created.scope_json.target.physical_endpoint_identity_id == (
        governance_stack.target_identity_id
    )
    assert created.scope_json.source.allowed_columns == ["id", "name"]
    assert created.scope_json.target.allowed_columns == ["id", "name"]
    canonical_scope = created.scope_json.model_dump(mode="json")
    assert (
        created.scope_hash
        == hashlib.sha256(b"DXTRANSFERPOLICYv1\n" + rfc8785.dumps(canonical_scope)).hexdigest()
    )
    assert governance_stack.probe.calls == [
        (
            governance_stack.source_datasource_id,
            "SOURCE_USE",
            "public",
            "orders",
        ),
        (
            governance_stack.target_datasource_id,
            "TARGET_USE",
            "public",
            "orders_copy",
        ),
    ]


def test_transfer_policy_scope_is_admin_only(
    governance_stack: GovernanceStack,
) -> None:
    policy = _create_policy(
        governance_stack,
        classification="STANDARD",
        key="create-policy-admin-read-001",
    ).value
    developer = Principal(
        user_id=governance_stack.member_user_id,
        organization_id=governance_stack.requester.organization_id,
        session_id=uuid4(),
        email="member@example.com",
        display_name="Member",
        must_change_password=False,
        role_assignments=(
            ScopedRoles(
                scope_type=ScopeType.PROJECT,
                scope_id=governance_stack.project_id,
                roles=[Role.DEVELOPER],
            ),
        ),
    )

    with pytest.raises(ProblemException) as list_failure:
        governance_stack.service.list_transfer_policies(
            principal=developer,
            project_id=governance_stack.project_id,
            limit=50,
            cursor=None,
        )
    assert list_failure.value.code == "FORBIDDEN"
    with pytest.raises(ProblemException) as detail_failure:
        governance_stack.service.get_transfer_policy(
            principal=developer,
            transfer_policy_id=policy.id,
        )
    assert detail_failure.value.code == "FORBIDDEN"


def test_metadata_unavailable_is_503_and_does_not_create_policy(
    governance_stack: GovernanceStack,
) -> None:
    governance_stack.probe.fail = True
    with pytest.raises(ProblemException) as caught:
        _create_policy(
            governance_stack,
            classification="STANDARD",
            key="create-policy-offline-001",
        )
    assert caught.value.status == 503
    assert caught.value.code == "DATASOURCE_METADATA_UNAVAILABLE"
    with governance_stack.sessions() as session:
        assert session.scalar(select(func.count()).select_from(TransferPolicy)) == 0


def test_requester_cannot_approve_own_policy(
    governance_stack: GovernanceStack,
) -> None:
    policy = _create_policy(
        governance_stack,
        classification="STANDARD",
        key="create-policy-self-001",
    ).value
    submitted = governance_stack.service.submit_transfer_policy(
        principal=governance_stack.requester,
        transfer_policy_id=policy.id,
        request=TransferPolicySubmit(expected_scope_hash=policy.scope_hash),
        idempotency_key="submit-policy-self-001",
        audit=governance_stack.audit,
    ).value
    with pytest.raises(ProblemException) as caught:
        governance_stack.service.decide_transfer_policy(
            principal=governance_stack.requester,
            transfer_policy_id=policy.id,
            request=TransferPolicyDecision(
                decision="APPROVED",
                expected_scope_hash=submitted.scope_hash,
                comment=None,
            ),
            idempotency_key="approve-policy-self-001",
            audit=governance_stack.audit,
        )
    assert caught.value.status == 403
    assert caught.value.code == "TRANSFER_POLICY_SELF_APPROVAL_FORBIDDEN"
    with governance_stack.sessions() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(TransferPolicyApproval)
                .where(TransferPolicyApproval.transfer_policy_id == policy.id)
            )
            == 0
        )


def test_sensitive_policy_needs_two_distinct_non_requester_admins(
    governance_stack: GovernanceStack,
) -> None:
    policy = _create_policy(
        governance_stack,
        classification="SENSITIVE",
        key="create-policy-sensitive-001",
    ).value
    pending = governance_stack.service.submit_transfer_policy(
        principal=governance_stack.requester,
        transfer_policy_id=policy.id,
        request=TransferPolicySubmit(expected_scope_hash=policy.scope_hash),
        idempotency_key="submit-policy-sensitive-001",
        audit=governance_stack.audit,
    ).value
    first = governance_stack.service.decide_transfer_policy(
        principal=governance_stack.approver_one,
        transfer_policy_id=policy.id,
        request=TransferPolicyDecision(
            decision="APPROVED",
            expected_scope_hash=pending.scope_hash,
            comment="first independent review",
        ),
        idempotency_key="approve-policy-sensitive-001",
        audit=governance_stack.audit,
    ).value
    assert first.status == "PENDING_APPROVAL"
    assert len(first.approvals) == 1

    second = governance_stack.service.decide_transfer_policy(
        principal=governance_stack.approver_two,
        transfer_policy_id=policy.id,
        request=TransferPolicyDecision(
            decision="APPROVED",
            expected_scope_hash=pending.scope_hash,
            comment="second independent review",
        ),
        idempotency_key="approve-policy-sensitive-002",
        audit=governance_stack.audit,
    ).value
    assert second.status == "ACTIVE"
    assert len(second.approvals) == 2
    assert {approval.approved_by for approval in second.approvals} == {
        governance_stack.approver_one.user_id,
        governance_stack.approver_two.user_id,
    }


def test_stale_scope_hash_is_rejected(
    governance_stack: GovernanceStack,
) -> None:
    policy = _create_policy(
        governance_stack,
        classification="STANDARD",
        key="create-policy-stale-001",
    ).value
    with pytest.raises(ProblemException) as caught:
        governance_stack.service.submit_transfer_policy(
            principal=governance_stack.requester,
            transfer_policy_id=policy.id,
            request=TransferPolicySubmit(expected_scope_hash="0" * 64),
            idempotency_key="submit-policy-stale-001",
            audit=governance_stack.audit,
        )
    assert caught.value.status == 409
    assert caught.value.code == "TRANSFER_POLICY_SCOPE_HASH_MISMATCH"


def test_scope_revision_clears_approvals_and_returns_to_draft(
    governance_stack: GovernanceStack,
) -> None:
    policy = _create_policy(
        governance_stack,
        classification="SENSITIVE",
        key="create-policy-revise-001",
    ).value
    pending = governance_stack.service.submit_transfer_policy(
        principal=governance_stack.requester,
        transfer_policy_id=policy.id,
        request=TransferPolicySubmit(expected_scope_hash=policy.scope_hash),
        idempotency_key="submit-policy-revise-001",
        audit=governance_stack.audit,
    ).value
    approved = governance_stack.service.decide_transfer_policy(
        principal=governance_stack.approver_one,
        transfer_policy_id=policy.id,
        request=TransferPolicyDecision(
            decision="APPROVED",
            expected_scope_hash=pending.scope_hash,
            comment=None,
        ),
        idempotency_key="approve-policy-revise-001",
        audit=governance_stack.audit,
    ).value
    revised = governance_stack.service.update_transfer_policy(
        principal=governance_stack.requester,
        transfer_policy_id=policy.id,
        request=TransferPolicyPatch(
            requested_scope=_requested_scope(
                source_columns=["id"],
                target_columns=["id"],
                selection_mode="SELECTED_COLUMNS",
            )
        ),
        expected_version=approved.row_version,
        audit=governance_stack.audit,
        metadata_probe=governance_stack.probe,
    )
    assert revised.status == "DRAFT"
    assert revised.approvals == []
    assert revised.scope_json.source.allowed_columns == ["id"]


def test_activation_rejects_another_active_policy_for_revision_pair(
    governance_stack: GovernanceStack,
) -> None:
    first_policy = _create_policy(
        governance_stack,
        classification="STANDARD",
        key="create-policy-conflict-001",
    ).value
    first_pending = governance_stack.service.submit_transfer_policy(
        principal=governance_stack.requester,
        transfer_policy_id=first_policy.id,
        request=TransferPolicySubmit(expected_scope_hash=first_policy.scope_hash),
        idempotency_key="submit-policy-conflict-001",
        audit=governance_stack.audit,
    ).value
    active = governance_stack.service.decide_transfer_policy(
        principal=governance_stack.approver_one,
        transfer_policy_id=first_policy.id,
        request=TransferPolicyDecision(
            decision="APPROVED",
            expected_scope_hash=first_pending.scope_hash,
            comment=None,
        ),
        idempotency_key="approve-policy-conflict-001",
        audit=governance_stack.audit,
    ).value
    assert active.status == "ACTIVE"

    second_policy = _create_policy(
        governance_stack,
        classification="STANDARD",
        key="create-policy-conflict-002",
    ).value
    second_pending = governance_stack.service.submit_transfer_policy(
        principal=governance_stack.requester,
        transfer_policy_id=second_policy.id,
        request=TransferPolicySubmit(expected_scope_hash=second_policy.scope_hash),
        idempotency_key="submit-policy-conflict-002",
        audit=governance_stack.audit,
    ).value
    with pytest.raises(ProblemException) as caught:
        governance_stack.service.decide_transfer_policy(
            principal=governance_stack.approver_two,
            transfer_policy_id=second_policy.id,
            request=TransferPolicyDecision(
                decision="APPROVED",
                expected_scope_hash=second_pending.scope_hash,
                comment=None,
            ),
            idempotency_key="approve-policy-conflict-002",
            audit=governance_stack.audit,
        )
    assert caught.value.status == 409
    assert caught.value.code == "TRANSFER_POLICY_ACTIVE_CONFLICT"
    fetched = governance_stack.service.get_transfer_policy(
        principal=governance_stack.requester,
        transfer_policy_id=second_policy.id,
    )
    assert fetched.status == "PENDING_APPROVAL"
    assert fetched.approvals == []


def _create_policy(
    stack: GovernanceStack,
    *,
    classification: str,
    key: str,
):
    return stack.service.create_transfer_policy(
        principal=stack.requester,
        project_id=stack.project_id,
        request=TransferPolicyCreate(
            source_datasource_revision_id=stack.source_revision_id,
            target_datasource_revision_id=stack.target_revision_id,
            requested_scope=_requested_scope(
                source_columns=["name", "id"],
                target_columns=["name", "id"],
                selection_mode="ALL_COLUMNS",
            ),
            classification=classification,
        ),
        idempotency_key=key,
        audit=stack.audit,
        metadata_probe=stack.probe,
    )


def _requested_scope(
    *,
    source_columns: list[str],
    target_columns: list[str],
    selection_mode: str,
) -> TransferPolicyScopeInput:
    return TransferPolicyScopeInput.model_validate(
        {
            "schema_version": "1.0",
            "source": {
                "catalog": "sales",
                "schema": "public",
                "table": "orders",
                "selection_mode": selection_mode,
                "allowed_columns": source_columns,
            },
            "target": {
                "catalog": "warehouse",
                "schema": "public",
                "table": "orders_copy",
                "selection_mode": selection_mode,
                "allowed_columns": target_columns,
            },
        }
    )


def _table_page(
    *,
    table_name: str,
    physical_table_hash: str,
    captured_at: datetime,
) -> TableSchemaPage:
    return TableSchemaPage(
        items=[
            TableSchema(
                schema_name="public",
                table_name=table_name,
                physical_table_identity_hash=physical_table_hash,
                columns=[
                    _column("id", 1, logical_type="INTEGER"),
                    _column("name", 2, logical_type="TEXT"),
                ],
                schema_hash=hashlib.sha256(table_name.encode()).hexdigest(),
                oracle_compatible=True,
                target_insert_compatible=True,
                incompatibility_reasons=[],
                captured_at=captured_at,
            )
        ],
        next_cursor=None,
        has_more=False,
    )


def _column(
    name: str,
    ordinal: int,
    *,
    logical_type: str,
) -> ColumnSchema:
    return ColumnSchema.model_validate(
        {
            "name": name,
            "ordinal": ordinal,
            "native_type": "text" if logical_type == "TEXT" else "bigint",
            "logical_type": logical_type,
            "nullable": False,
            "primary_key": name == "id",
            "generated": False,
            "identity": False,
            "character_maximum_length": None,
            "numeric_precision": None,
            "numeric_scale": None,
            "datetime_precision": None,
            "oracle_supported": True,
            "unsupported_reason": None,
        }
    )
