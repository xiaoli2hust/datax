from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from datax_studio.auth.db import Organization, User
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    EndpointPolicy,
    EndpointPolicyRevision,
    Execution,
    JobVersion,
    PhysicalEndpointIdentity,
    Project,
    SyncJob,
    TargetNamespace,
    TransferPolicy,
)

POSTGRES_URL = os.getenv("DATAX_MIGRATION_POSTGRES_TEST_URL")
API_POSTGRES_URL = os.getenv("DATAX_API_POSTGRES_TEST_URL")
WORKER_POSTGRES_URL = os.getenv("DATAX_WORKER_POSTGRES_TEST_URL")
ISSUER_POSTGRES_URL = os.getenv("DATAX_PHASE_A_ISSUER_POSTGRES_TEST_URL")
CONSUMER_POSTGRES_URL = os.getenv("DATAX_PHASE_A_CONSUMER_POSTGRES_TEST_URL")
RUNNER_POSTGRES_URL = os.getenv("DATAX_PHASE_A_RUNNER_POSTGRES_TEST_URL")

_SCHEMA = "des_phase_a_qualification"
_AUTHORIZATION_TABLE = f"{_SCHEMA}.phase_a_execution_authorizations"
_AUTHORIZE_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_authorize_phase_a_execution(
        :authorization_id,
        :grant_id,
        :execution_id
    ) AS authorization_id
    """
)
_READ_SQL = text(
    f"""
    SELECT *
    FROM {_SCHEMA}.des_read_active_phase_a_execution_authorization(:execution_id)
    """
)
_ISSUE_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_issue_phase_a_qualification_grant(
        :grant_id, :nonce_id, :nonce_sha256, :payload_binding_sha256,
        :payload_root_sha256, :candidate_commit, :worker_image_digest,
        :runtime_sha256, 'mysqlreader', :reader_plugin_sha256,
        'postgresqlwriter', :writer_plugin_sha256, 'phase-a-e2-harness',
        'phase-a-e2-environment', :harness_environment_manifest_sha256,
        '1.0.0+e2', :qh_document_sha256, :qh_qualification_id,
        :qh_issuer_key_id, clock_timestamp() - INTERVAL '2 minutes',
        clock_timestamp() - INTERVAL '1 minute', clock_timestamp() + INTERVAL '15 minutes'
    ) AS grant_id
    """
)
_REVOKE_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_revoke_phase_a_qualification_grant(
        :grant_id,
        'TEST_REVOKED'
    ) AS revoked
    """
)
_RESERVE_LOCK_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_reserve_phase_a_execution_lock(
        :lock_id,
        :execution_id
    ) AS lock_id
    """
)
_CLAIM_LOCK_SQL = text(
    f"""
    SELECT *
    FROM {_SCHEMA}.des_claim_phase_a_execution_lock(
        :execution_id,
        :attempt_id,
        :worker_id,
        :lease_token_hash,
        :host_boot_id,
        :cgroup_identity,
        :lease_seconds
    )
    """
)
_HEARTBEAT_LOCK_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_heartbeat_phase_a_execution_lock(
        :execution_id,
        :attempt_id,
        :fence_epoch,
        :lease_token_hash,
        :lease_seconds
    ) AS lease_expires_at
    """
)
_RECOVERY_LOCK_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_require_phase_a_execution_recovery(
        :execution_id,
        :attempt_id,
        :fence_epoch,
        :lease_token_hash,
        :reason
    ) AS transitioned
    """
)
_RELEASE_LOCK_SQL = text(
    f"""
    SELECT {_SCHEMA}.des_release_phase_a_execution_lock(
        :execution_id,
        :attempt_id,
        :fence_epoch,
        :lease_token_hash,
        :reason
    ) AS released
    """
)

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="DATAX_MIGRATION_POSTGRES_TEST_URL is not configured",
)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _assert_sqlstate(error: DBAPIError, expected: str) -> None:
    assert getattr(error.orig, "sqlstate", None) == expected


def _seed_pending_private_execution(
    engine_url: str,
    *,
    authorization_mode: str = "PHASE_A_HARNESS",
) -> tuple[UUID, dict[str, str]]:
    """Create the smallest valid public binding the private function accepts.

    The setup deliberately uses product ORM facts rather than temporary fake
    tables.  It does not call an API or Worker and therefore remains E2 proof
    of the PostgreSQL boundary, not an E3 product execution.
    """

    if authorization_mode not in {"PHASE_A_HARNESS", "STANDARD"}:
        raise ValueError("unsupported synthetic execution authorization mode")
    engine = create_engine(engine_url, pool_pre_ping=True)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(UTC)
    label = uuid4().hex
    organization_id = uuid4()
    user_id = uuid4()
    project_id = uuid4()
    source_identity_id = uuid4()
    target_identity_id = uuid4()
    source_policy_id = uuid4()
    target_policy_id = uuid4()
    source_policy_revision_id = uuid4()
    target_policy_revision_id = uuid4()
    source_datasource_id = uuid4()
    target_datasource_id = uuid4()
    source_revision_id = uuid4()
    target_revision_id = uuid4()
    target_namespace_id = uuid4()
    transfer_policy_id = uuid4()
    job_id = uuid4()
    job_version_id = uuid4()
    execution_id = uuid4()
    source_identity_hash = _hash(f"{label}:source-server")
    target_identity_hash = _hash(f"{label}:target-server")
    source_table_hash = _hash(f"{label}:source-table")
    target_table_hash = _hash(f"{label}:target-table")
    source_config_hash = _hash(f"{label}:source-config")
    target_config_hash = _hash(f"{label}:target-config")
    source_policy_hash = _hash(f"{label}:source-policy")
    target_policy_hash = _hash(f"{label}:target-policy")
    spec_hash = _hash(f"{label}:spec")
    artifact_hash = _hash(f"{label}:artifact")
    scope_hash = _hash(f"{label}:scope")
    runtime_sha256 = _hash(f"{label}:runtime")
    reader_plugin_sha256 = _hash(f"{label}:mysqlreader")
    writer_plugin_sha256 = _hash(f"{label}:postgresqlwriter")
    try:
        with sessions.begin() as session:
            session.add_all(
                [
                    Organization(
                        id=organization_id,
                        name=f"Phase-A authorization {label}",
                        # This fixture exercises only the private SQL
                        # boundary. Keeping its synthetic organization
                        # SUSPENDED avoids consuming V1's one-ACTIVE-org test
                        # invariant or appearing in later egress-view tests.
                        status="SUSPENDED",
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    User(
                        id=user_id,
                        email=f"phase-a-{label}@example.test",
                        display_name="Phase-A E2",
                        password_hash="not-used-by-phase-a-e2",
                        must_change_password=False,
                        password_changed_at=now,
                        status="ACTIVE",
                        failed_login_count=0,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    Project(
                        id=project_id,
                        organization_id=organization_id,
                        name=f"Phase-A project {label}",
                        slug=f"phase-a-{label}",
                        status="ACTIVE",
                        created_by=user_id,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    PhysicalEndpointIdentity(
                        id=source_identity_id,
                        organization_id=organization_id,
                        engine="MYSQL_8",
                        identity_scheme="MYSQL_SERVER_UUID",
                        server_identity_hash=source_identity_hash,
                        verification_evidence={"kind": "E2"},
                        verification_evidence_hash=_hash(f"{label}:source-evidence"),
                        created_by=user_id,
                        created_at=now,
                    ),
                    PhysicalEndpointIdentity(
                        id=target_identity_id,
                        organization_id=organization_id,
                        engine="POSTGRESQL_15",
                        identity_scheme="POSTGRES_SYSTEM_IDENTIFIER",
                        server_identity_hash=target_identity_hash,
                        verification_evidence={"kind": "E2"},
                        verification_evidence_hash=_hash(f"{label}:target-evidence"),
                        created_by=user_id,
                        created_at=now,
                    ),
                    EndpointPolicy(
                        id=source_policy_id,
                        organization_id=organization_id,
                        name=f"source policy {label}",
                        current_revision_id=source_policy_revision_id,
                        status="ACTIVE",
                        created_by=user_id,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    EndpointPolicy(
                        id=target_policy_id,
                        organization_id=organization_id,
                        name=f"target policy {label}",
                        current_revision_id=target_policy_revision_id,
                        status="ACTIVE",
                        created_by=user_id,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    EndpointPolicyRevision(
                        id=source_policy_revision_id,
                        endpoint_policy_id=source_policy_id,
                        revision_no=1,
                        engine="MYSQL_8",
                        host_kind="EXACT_FQDN",
                        host_value=f"mysql-{label}.example.test",
                        allowed_cidrs=["10.10.0.0/24"],
                        allowed_ports=[3306],
                        tls_required=True,
                        dns_ttl_ceiling_seconds=60,
                        resolver_policy_version="resolver-v1",
                        egress_policy_version="egress-v1",
                        policy_hash=source_policy_hash,
                        created_by=user_id,
                        created_at=now,
                    ),
                    EndpointPolicyRevision(
                        id=target_policy_revision_id,
                        endpoint_policy_id=target_policy_id,
                        revision_no=1,
                        engine="POSTGRESQL_15",
                        host_kind="EXACT_FQDN",
                        host_value=f"postgres-{label}.example.test",
                        allowed_cidrs=["10.20.0.0/24"],
                        allowed_ports=[5432],
                        tls_required=True,
                        dns_ttl_ceiling_seconds=60,
                        resolver_policy_version="resolver-v1",
                        egress_policy_version="egress-v1",
                        policy_hash=target_policy_hash,
                        created_by=user_id,
                        created_at=now,
                    ),
                    Datasource(
                        id=source_datasource_id,
                        project_id=project_id,
                        name=f"source {label}",
                        current_revision_id=source_revision_id,
                        current_secret_id=None,
                        status="ACTIVE",
                        created_by=user_id,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    Datasource(
                        id=target_datasource_id,
                        project_id=project_id,
                        name=f"target {label}",
                        current_revision_id=target_revision_id,
                        current_secret_id=None,
                        status="ACTIVE",
                        created_by=user_id,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    DatasourceRevision(
                        id=source_revision_id,
                        datasource_id=source_datasource_id,
                        revision_no=1,
                        endpoint_policy_revision_id=source_policy_revision_id,
                        physical_endpoint_identity_id=source_identity_id,
                        engine="MYSQL_8",
                        host=f"mysql-{label}.example.test",
                        port=3306,
                        database_name=f"source_{label}",
                        default_schema=f"source_{label}",
                        username="reader",
                        ssl_mode="VERIFY_FULL",
                        connection_options={},
                        config_hash=source_config_hash,
                        created_by=user_id,
                        created_at=now,
                    ),
                    DatasourceRevision(
                        id=target_revision_id,
                        datasource_id=target_datasource_id,
                        revision_no=1,
                        endpoint_policy_revision_id=target_policy_revision_id,
                        physical_endpoint_identity_id=target_identity_id,
                        engine="POSTGRESQL_15",
                        host=f"postgres-{label}.example.test",
                        port=5432,
                        database_name=f"target_{label}",
                        default_schema="public",
                        username="writer",
                        ssl_mode="VERIFY_FULL",
                        connection_options={},
                        config_hash=target_config_hash,
                        created_by=user_id,
                        created_at=now,
                    ),
                    TargetNamespace(
                        id=target_namespace_id,
                        physical_endpoint_identity_id=target_identity_id,
                        engine="POSTGRESQL_15",
                        normalized_catalog_name=f"target_{label}",
                        normalized_schema_name="public",
                        normalized_table_name=f"target_table_{label}",
                        normalization_version="1.0",
                        physical_table_identity_hash=target_table_hash,
                        created_at=now,
                    ),
                    TransferPolicy(
                        id=transfer_policy_id,
                        project_id=project_id,
                        source_datasource_revision_id=source_revision_id,
                        target_datasource_revision_id=target_revision_id,
                        source_physical_endpoint_identity_id=source_identity_id,
                        target_physical_endpoint_identity_id=target_identity_id,
                        scope_json={"schema_version": "1.0", "label": label},
                        scope_hash=scope_hash,
                        classification="STANDARD",
                        status="ACTIVE",
                        requested_by=user_id,
                        activated_at=now,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    SyncJob(
                        id=job_id,
                        project_id=project_id,
                        name=f"copy {label}",
                        status="PUBLISHED",
                        draft_spec_json={"schema_version": "1.0", "label": label},
                        draft_spec_hash=spec_hash,
                        validated_spec_hash=spec_hash,
                        validation_report={"valid": True},
                        latest_published_version_id=job_version_id,
                        created_by=user_id,
                        created_at=now,
                        updated_at=now,
                        row_version=1,
                    ),
                    JobVersion(
                        id=job_version_id,
                        job_id=job_id,
                        version_no=1,
                        job_spec_schema_version="1.0",
                        spec_json={"schema_version": "1.0", "label": label},
                        spec_hash=spec_hash,
                        source_datasource_revision_id=source_revision_id,
                        target_datasource_revision_id=target_revision_id,
                        source_endpoint_policy_revision_id=source_policy_revision_id,
                        target_endpoint_policy_revision_id=target_policy_revision_id,
                        source_physical_table_identity_hash=source_table_hash,
                        target_namespace_id=target_namespace_id,
                        transfer_policy_id=transfer_policy_id,
                        transfer_policy_scope_hash=scope_hash,
                        source_schema_snapshot={"schema_version": "1.0"},
                        target_schema_snapshot={"schema_version": "1.0"},
                        source_schema_hash=_hash(f"{label}:source-schema"),
                        target_schema_hash=_hash(f"{label}:target-schema"),
                        reader_plugin_name="mysqlreader",
                        reader_plugin_sha256=reader_plugin_sha256,
                        writer_plugin_name="postgresqlwriter",
                        writer_plugin_sha256=writer_plugin_sha256,
                        datax_release="datax_v202309",
                        runtime_sha256=runtime_sha256,
                        version_artifact_hash=artifact_hash,
                        published_by=user_id,
                        published_at=now,
                    ),
                    Execution(
                        id=execution_id,
                        project_id=project_id,
                        job_id=job_id,
                        job_version_id=job_version_id,
                        rerun_of_execution_id=None,
                        trigger_type="MANUAL",
                        authorization_mode=authorization_mode,
                        requested_by=user_id,
                        process_state="QUEUED",
                        data_effect="NONE",
                        verification_state="NOT_STARTED",
                        state_version=1,
                        fence_epoch=0,
                        active_attempt_id=None,
                        queue_priority=0,
                        capacity_profile="LARGE",
                        service_reservation_seconds=3600,
                        log_reservation_bytes=0,
                        workspace_reservation_bytes=0,
                        queue_eligibility_state=(
                            "BLOCKED"
                            if authorization_mode == "PHASE_A_HARNESS"
                            else "ELIGIBLE"
                        ),
                        queue_block_reason=(
                            "PHASE_A_AUTHORIZATION_PENDING"
                            if authorization_mode == "PHASE_A_HARNESS"
                            else None
                        ),
                        queue_state_changed_at=now,
                        eligible_wait_milliseconds=0,
                        queued_at=now,
                        timeout_seconds=3600,
                        source_datasource_revision_id=source_revision_id,
                        target_datasource_revision_id=target_revision_id,
                        source_endpoint_policy_revision_id=source_policy_revision_id,
                        target_endpoint_policy_revision_id=target_policy_revision_id,
                        target_namespace_id=target_namespace_id,
                        source_secret_id=None,
                        target_secret_id=None,
                        source_secret_envelope_id=None,
                        target_secret_envelope_id=None,
                        source_secret_version=None,
                        target_secret_version=None,
                        source_connection_evidence_id=None,
                        target_connection_evidence_id=None,
                        source_quiescence_confirmation={"statement_version": "1.0"},
                        target_exclusivity_confirmation={"statement_version": "1.0"},
                        target_exclusivity_status="ACTIVE",
                        target_exclusivity_revoked_at=None,
                        target_exclusivity_revocation_reason=None,
                        target_empty_evidence=None,
                        runtime_snapshot=None,
                        resolved_config_hash=None,
                        attempt_count=0,
                        exit_code=None,
                        failure_code=None,
                        failure_message=None,
                        summary_parse_status="PENDING",
                        run_summary=None,
                        verification_report=None,
                        verification_evidence_hash=None,
                        log_truncated=False,
                        log_incomplete=False,
                        log_raw_received_bytes=0,
                        log_redacted_received_bytes=0,
                        log_stored_bytes=0,
                        log_dropped_bytes=0,
                        first_truncated_sequence=None,
                        created_at=now,
                    ),
                ]
            )
            # The ORM classes intentionally model ids rather than relationship
            # collections, so PostgreSQL cannot infer every insert order from
            # this isolated E2 fixture.  Flush bounded dependency layers to
            # keep the fixture faithful to the real foreign-key graph.
            session.flush(
                [
                    record
                    for record in session.new
                    if isinstance(record, (Organization, User))
                ]
            )
            session.flush(
                [
                    record
                    for record in session.new
                    if isinstance(
                        record,
                        (Project, PhysicalEndpointIdentity, EndpointPolicy),
                    )
                ]
            )
            session.flush(
                [
                    record
                    for record in session.new
                    if isinstance(record, (EndpointPolicyRevision, Datasource))
                ]
            )
            session.flush(
                [
                    record
                    for record in session.new
                    if isinstance(record, (DatasourceRevision, TargetNamespace))
                ]
            )
            session.flush(
                [
                    record
                    for record in session.new
                    if isinstance(record, (TransferPolicy, SyncJob))
                ]
            )
            session.flush(
                [record for record in session.new if isinstance(record, JobVersion)]
            )
            session.flush(
                [record for record in session.new if isinstance(record, Execution)]
            )
        return execution_id, {
            "project_id": str(project_id),
            "user_id": str(user_id),
            "source_datasource_id": str(source_datasource_id),
            "source_policy_id": str(source_policy_id),
            "source_identity_id": str(source_identity_id),
            "target_namespace_id": str(target_namespace_id),
            "transfer_policy_id": str(transfer_policy_id),
            "runtime_sha256": runtime_sha256,
            "reader_plugin_sha256": reader_plugin_sha256,
            "writer_plugin_sha256": writer_plugin_sha256,
            "artifact_hash": artifact_hash,
            "spec_hash": spec_hash,
            "source_config_hash": source_config_hash,
            "target_config_hash": target_config_hash,
            "source_policy_hash": source_policy_hash,
            "target_policy_hash": target_policy_hash,
            "source_identity_hash": source_identity_hash,
            "target_identity_hash": target_identity_hash,
            "source_table_hash": source_table_hash,
            "target_table_hash": target_table_hash,
            "scope_hash": scope_hash,
        }
    finally:
        engine.dispose()


def _issue_parameters(
    *,
    grant_id: UUID,
    nonce_id: UUID,
    facts: dict[str, str],
) -> dict[str, object]:
    return {
        "grant_id": grant_id,
        "nonce_id": nonce_id,
        "nonce_sha256": _hash(f"{nonce_id}:nonce"),
        "payload_binding_sha256": _hash(f"{grant_id}:payload-binding"),
        "payload_root_sha256": _hash(f"{grant_id}:payload-root"),
        "candidate_commit": "a" * 40,
        "worker_image_digest": f"sha256:{'b' * 64}",
        "runtime_sha256": facts["runtime_sha256"],
        "reader_plugin_sha256": facts["reader_plugin_sha256"],
        "writer_plugin_sha256": facts["writer_plugin_sha256"],
        "harness_environment_manifest_sha256": _hash(f"{grant_id}:harness"),
        "qh_document_sha256": _hash(f"{grant_id}:qh"),
        "qh_qualification_id": f"qh-e2-{grant_id.hex}",
        "qh_issuer_key_id": f"hqa-e2-{grant_id.hex}",
    }


@pytest.mark.skipif(
    not all(
        (API_POSTGRES_URL, WORKER_POSTGRES_URL, ISSUER_POSTGRES_URL, CONSUMER_POSTGRES_URL)
    ),
    reason="runtime and private Phase-A PostgreSQL role URLs are not configured",
)
def test_phase_a_authorization_is_private_immutable_and_excludes_standard_worker() -> None:
    assert POSTGRES_URL is not None
    assert API_POSTGRES_URL is not None
    assert WORKER_POSTGRES_URL is not None
    assert ISSUER_POSTGRES_URL is not None
    assert CONSUMER_POSTGRES_URL is not None
    execution_id, facts = _seed_pending_private_execution(POSTGRES_URL)
    grant_id = uuid4()
    authorization_id = uuid4()
    owner = create_engine(POSTGRES_URL, pool_pre_ping=True)
    issuer = create_engine(ISSUER_POSTGRES_URL, pool_pre_ping=True, poolclass=NullPool)
    consumer = create_engine(CONSUMER_POSTGRES_URL, pool_pre_ping=True, poolclass=NullPool)
    try:
        with owner.connect() as connection:
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == "20260802_0023"
            for role in ("datax_api", "datax_worker", "datax_egress_guard"):
                assert connection.execute(
                    text(
                        "SELECT has_table_privilege(:role, :table_name, 'SELECT')"
                    ),
                    {"role": role, "table_name": _AUTHORIZATION_TABLE},
                ).scalar_one() is False
                assert connection.execute(
                    text(
                        "SELECT has_function_privilege("
                        ":role, "
                        "to_regprocedure('des_phase_a_qualification."
                        "des_authorize_phase_a_execution(uuid,uuid,uuid)'), "
                        "'EXECUTE')"
                    ),
                    {"role": role},
                ).scalar_one() is False

        with issuer.begin() as connection:
            issued = connection.execute(
                _ISSUE_SQL,
                _issue_parameters(
                    grant_id=grant_id,
                    nonce_id=uuid4(),
                    facts=facts,
                ),
            ).scalar_one()
            assert issued == grant_id
            authorized = connection.execute(
                _AUTHORIZE_SQL,
                {
                    "authorization_id": authorization_id,
                    "grant_id": grant_id,
                    "execution_id": execution_id,
                },
            ).scalar_one()
            assert authorized == authorization_id

        with owner.connect() as connection:
            execution = connection.execute(
                text(
                    "SELECT authorization_mode, queue_eligibility_state, "
                    "queue_block_reason, state_version "
                    "FROM public.executions WHERE id = :execution_id"
                ),
                {"execution_id": execution_id},
            ).mappings().one()
            assert execution["authorization_mode"] == "PHASE_A_HARNESS"
            assert execution["queue_eligibility_state"] == "BLOCKED"
            assert execution["queue_block_reason"] == (
                "PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED"
            )
            assert execution["state_version"] == 2

        with consumer.begin() as connection:
            row = connection.execute(
                _READ_SQL,
                {"execution_id": execution_id},
            ).mappings().one()
            assert row["authorization_id"] == authorization_id
            assert row["grant_id"] == grant_id
            assert row["execution_id"] == execution_id
            assert row["runtime_sha256"] == facts["runtime_sha256"]
            assert row["job_version_artifact_hash"] == facts["artifact_hash"]
            assert row["transfer_policy_scope_hash"] == facts["scope_hash"]

        for url, statement in (
            (
                API_POSTGRES_URL,
                "SELECT * FROM des_phase_a_qualification."
                "des_read_active_phase_a_execution_authorization(NULL::uuid)",
            ),
            (
                WORKER_POSTGRES_URL,
                "SELECT des_phase_a_qualification.des_authorize_phase_a_execution("
                "NULL::uuid, NULL::uuid, NULL::uuid)",
            ),
            (
                ISSUER_POSTGRES_URL,
                "SELECT * FROM des_phase_a_qualification."
                "des_read_active_phase_a_execution_authorization(NULL::uuid)",
            ),
            (
                CONSUMER_POSTGRES_URL,
                "SELECT des_phase_a_qualification.des_authorize_phase_a_execution("
                "NULL::uuid, NULL::uuid, NULL::uuid)",
            ),
        ):
            role_engine = create_engine(url, pool_pre_ping=True, poolclass=NullPool)
            try:
                with pytest.raises(DBAPIError) as failure, role_engine.connect() as connection:
                    connection.execute(text(statement))
                _assert_sqlstate(failure.value, "42501")
            finally:
                role_engine.dispose()

        # The application filters are not the whole boundary.  Even a direct
        # API/Worker database connection receives no Phase-A execution row;
        # an attempted write to an execution descendant fails the RLS check.
        for url in (API_POSTGRES_URL, WORKER_POSTGRES_URL):
            role_engine = create_engine(url, pool_pre_ping=True, poolclass=NullPool)
            try:
                with role_engine.connect() as connection:
                    assert connection.execute(
                        text(
                            "SELECT count(*) FROM public.executions "
                            "WHERE id = :execution_id"
                        ),
                        {"execution_id": execution_id},
                    ).scalar_one() == 0

                with role_engine.begin() as connection:
                    updated = connection.execute(
                        text(
                            "UPDATE public.executions "
                            "SET queue_block_reason = 'standard-role-attempt' "
                            "WHERE id = :execution_id"
                        ),
                        {"execution_id": execution_id},
                    )
                    assert updated.rowcount == 0

                with pytest.raises(DBAPIError) as failure, role_engine.begin() as connection:
                    connection.execute(
                        text(
                            "INSERT INTO public.execution_cancel_requests "
                            "(id, execution_id, requested_by, reason, status, requested_at) "
                            "VALUES (:id, :execution_id, :requested_by, "
                            "'standard-role-attempt', 'PENDING', clock_timestamp())"
                        ),
                        {
                            "id": uuid4(),
                            "execution_id": execution_id,
                            "requested_by": UUID(facts["user_id"]),
                        },
                    )
                _assert_sqlstate(failure.value, "42501")
            finally:
                role_engine.dispose()

        with pytest.raises(DBAPIError) as failure, owner.begin() as connection:
            connection.execute(
                text(
                    "UPDATE public.executions "
                    "SET authorization_mode = 'STANDARD' "
                    "WHERE id = :execution_id"
                ),
                {"execution_id": execution_id},
            )
        _assert_sqlstate(failure.value, "55000")

        with pytest.raises(DBAPIError) as failure, owner.begin() as connection:
            connection.execute(
                text(
                    f"UPDATE {_AUTHORIZATION_TABLE} "
                    "SET payload_root_sha256 = payload_root_sha256 "
                    "WHERE id = :authorization_id"
                ),
                {"authorization_id": authorization_id},
            )
        _assert_sqlstate(failure.value, "55000")

        with issuer.begin() as connection:
            assert connection.execute(_REVOKE_SQL, {"grant_id": grant_id}).scalar_one() is True
        with consumer.begin() as connection:
            assert connection.execute(
                _READ_SQL,
                {"execution_id": execution_id},
            ).mappings().one_or_none() is None
    finally:
        consumer.dispose()
        issuer.dispose()
        owner.dispose()


@pytest.mark.skipif(
    not all(
        (
            API_POSTGRES_URL,
            WORKER_POSTGRES_URL,
            ISSUER_POSTGRES_URL,
            RUNNER_POSTGRES_URL,
        )
    ),
    reason="runtime, issuer, and private Phase-A runner PostgreSQL role URLs are not configured",
)
def test_phase_a_lock_is_global_fenced_and_hidden_from_standard_runtime() -> None:
    """Exercise the protected lock primitive against real PostgreSQL only.

    This is E2 evidence for the database boundary.  It deliberately does not
    create a product runner, invoke DataX, or turn a Phase-A execution into a
    supported execution path.
    """

    assert POSTGRES_URL is not None
    assert API_POSTGRES_URL is not None
    assert WORKER_POSTGRES_URL is not None
    assert ISSUER_POSTGRES_URL is not None
    assert RUNNER_POSTGRES_URL is not None
    execution_id, facts = _seed_pending_private_execution(POSTGRES_URL)
    standard_execution_id, _standard_facts = _seed_pending_private_execution(
        POSTGRES_URL,
        authorization_mode="STANDARD",
    )
    grant_id = uuid4()
    authorization_id = uuid4()
    lock_id = uuid4()
    attempt_id = uuid4()
    lease_token_hash = _hash(f"phase-a-lock-e2:{execution_id}:lease")
    owner = create_engine(POSTGRES_URL, pool_pre_ping=True, poolclass=NullPool)
    api = create_engine(API_POSTGRES_URL, pool_pre_ping=True, poolclass=NullPool)
    worker = create_engine(WORKER_POSTGRES_URL, pool_pre_ping=True, poolclass=NullPool)
    issuer = create_engine(ISSUER_POSTGRES_URL, pool_pre_ping=True, poolclass=NullPool)
    runner = create_engine(RUNNER_POSTGRES_URL, pool_pre_ping=True, poolclass=NullPool)
    try:
        with issuer.begin() as connection:
            assert connection.execute(
                _ISSUE_SQL,
                _issue_parameters(
                    grant_id=grant_id,
                    nonce_id=uuid4(),
                    facts=facts,
                ),
            ).scalar_one() == grant_id
            assert connection.execute(
                _AUTHORIZE_SQL,
                {
                    "authorization_id": authorization_id,
                    "grant_id": grant_id,
                    "execution_id": execution_id,
                },
            ).scalar_one() == authorization_id

        # The runner has only the exact SECURITY DEFINER entrypoints.  It
        # cannot enumerate public locks/attempts directly, even before we
        # demonstrate the corresponding standard-role RLS hiding behavior.
        with owner.connect() as connection:
            for function in (
                "des_reserve_phase_a_execution_lock(uuid,uuid)",
                "des_claim_phase_a_execution_lock(uuid,uuid,text,text,text,text,integer)",
                "des_heartbeat_phase_a_execution_lock(uuid,uuid,bigint,text,integer)",
                "des_require_phase_a_execution_recovery(uuid,uuid,bigint,text,text)",
                "des_release_phase_a_execution_lock(uuid,uuid,bigint,text,text)",
                "des_read_phase_a_execution_lock(uuid)",
            ):
                assert connection.execute(
                    text(
                        "SELECT has_function_privilege("
                        "'datax_phase_a_runner', "
                        "to_regprocedure(:function_name), 'EXECUTE')"
                    ),
                    {"function_name": f"{_SCHEMA}.{function}"},
                ).scalar_one() is True
            for table_name in ("public.target_copy_locks", "public.execution_attempts"):
                assert connection.execute(
                    text(
                        "SELECT has_table_privilege("
                        "'datax_phase_a_runner', :table_name, 'SELECT,INSERT,UPDATE,DELETE')"
                    ),
                    {"table_name": table_name},
                ).scalar_one() is False

        with runner.begin() as connection:
            assert connection.execute(
                _RESERVE_LOCK_SQL,
                {"lock_id": lock_id, "execution_id": execution_id},
            ).scalar_one() == lock_id

        # A standard runtime sees neither the protected parent nor its shared
        # global lock.  The next assertion drives the same namespace through a
        # STANDARD child as datax_api: the RLS check permits that child, then
        # the one public partial-unique index rejects the conflicting private
        # reservation with 23505.  The normal API service maps this race-safe
        # database outcome to generic TARGET_ACTIVE_EXECUTION (unit-covered).
        with owner.begin() as connection:
            connection.execute(
                text(
                    "UPDATE public.executions "
                    "SET target_namespace_id = :target_namespace_id "
                    "WHERE id = :execution_id"
                ),
                {
                    "target_namespace_id": UUID(facts["target_namespace_id"]),
                    "execution_id": standard_execution_id,
                },
            )
        with pytest.raises(DBAPIError) as failure, api.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO public.target_copy_locks "
                    "(id, target_namespace_id, physical_table_identity_hash, execution_id, "
                    "attempt_id, fence_epoch, state, reserved_at, acquired_at, released_at) "
                    "VALUES (:id, :target_namespace_id, :physical_table_identity_hash, "
                    ":execution_id, NULL, NULL, 'RESERVED', clock_timestamp(), NULL, NULL)"
                ),
                {
                    "id": uuid4(),
                    "target_namespace_id": UUID(facts["target_namespace_id"]),
                    "physical_table_identity_hash": facts["target_table_hash"],
                    "execution_id": standard_execution_id,
                },
            )
        _assert_sqlstate(failure.value, "23505")

        with runner.begin() as connection:
            claim = connection.execute(
                _CLAIM_LOCK_SQL,
                {
                    "execution_id": execution_id,
                    "attempt_id": attempt_id,
                    "worker_id": "phase-a-e2-runner",
                    "lease_token_hash": lease_token_hash,
                    "host_boot_id": "phase-a-e2-boot",
                    "cgroup_identity": "/phase-a/e2/runner",
                    "lease_seconds": 30,
                },
            ).mappings().one()
        assert claim["attempt_id"] == attempt_id
        assert claim["fence_epoch"] == 1
        assert claim["lease_expires_at"] > datetime.now(UTC)

        for role_engine in (api, worker):
            with role_engine.connect() as connection:
                assert connection.execute(
                    text(
                        "SELECT count(*) FROM public.target_copy_locks "
                        "WHERE execution_id = :execution_id"
                    ),
                    {"execution_id": execution_id},
                ).scalar_one() == 0
                assert connection.execute(
                    text(
                        "SELECT count(*) FROM public.execution_attempts "
                        "WHERE execution_id = :execution_id"
                    ),
                    {"execution_id": execution_id},
                ).scalar_one() == 0

        # A second claim cannot create a second active attempt or advance the
        # same execution's fence.  A stale-fence heartbeat is rejected too.
        with pytest.raises(DBAPIError) as failure, runner.begin() as connection:
            connection.execute(
                _CLAIM_LOCK_SQL,
                {
                    "execution_id": execution_id,
                    "attempt_id": uuid4(),
                    "worker_id": "phase-a-e2-runner-2",
                    "lease_token_hash": _hash("phase-a-lock-e2:second-lease"),
                    "host_boot_id": "phase-a-e2-boot-2",
                    "cgroup_identity": "/phase-a/e2/runner-2",
                    "lease_seconds": 30,
                },
            )
        _assert_sqlstate(failure.value, "22023")
        with pytest.raises(DBAPIError) as failure, runner.begin() as connection:
            connection.execute(
                _HEARTBEAT_LOCK_SQL,
                {
                    "execution_id": execution_id,
                    "attempt_id": attempt_id,
                    "fence_epoch": 2,
                    "lease_token_hash": lease_token_hash,
                    "lease_seconds": 30,
                },
            )
        _assert_sqlstate(failure.value, "P0001")
        with runner.begin() as connection:
            assert connection.execute(
                _HEARTBEAT_LOCK_SQL,
                {
                    "execution_id": execution_id,
                    "attempt_id": attempt_id,
                    "fence_epoch": 1,
                    "lease_token_hash": lease_token_hash,
                    "lease_seconds": 30,
                },
            ).scalar_one() > datetime.now(UTC)

        # Revocation fails closed at the next active checkpoint.  The holder
        # can still only move into RECOVERY_REQUIRED and later release that
        # recovery lock; no automatic retry, re-claim, or process launch is
        # available through this slice.
        with issuer.begin() as connection:
            assert connection.execute(_REVOKE_SQL, {"grant_id": grant_id}).scalar_one() is True
        with pytest.raises(DBAPIError) as failure, runner.begin() as connection:
            connection.execute(
                _HEARTBEAT_LOCK_SQL,
                {
                    "execution_id": execution_id,
                    "attempt_id": attempt_id,
                    "fence_epoch": 1,
                    "lease_token_hash": lease_token_hash,
                    "lease_seconds": 30,
                },
            )
        _assert_sqlstate(failure.value, "P0001")
        with runner.begin() as connection:
            assert connection.execute(
                _RECOVERY_LOCK_SQL,
                {
                    "execution_id": execution_id,
                    "attempt_id": attempt_id,
                    "fence_epoch": 1,
                    "lease_token_hash": lease_token_hash,
                    "reason": "GRANT_REVOKED",
                },
            ).scalar_one() is True
            assert connection.execute(
                _RELEASE_LOCK_SQL,
                {
                    "execution_id": execution_id,
                    "attempt_id": attempt_id,
                    "fence_epoch": 1,
                    "lease_token_hash": lease_token_hash,
                    "reason": "RECOVERY_CONFIRMED",
                },
            ).scalar_one() is True

        with owner.connect() as connection:
            execution = dict(connection.execute(
                text(
                    "SELECT process_state, data_effect, verification_state, fence_epoch "
                    "FROM public.executions WHERE id = :execution_id"
                ),
                {"execution_id": execution_id},
            ).mappings().one())
            lock = dict(connection.execute(
                text(
                    "SELECT state, attempt_id, fence_epoch FROM public.target_copy_locks "
                    "WHERE execution_id = :execution_id"
                ),
                {"execution_id": execution_id},
            ).mappings().one())
            attempts = tuple(connection.execute(
                text(
                    "SELECT count(*), min(fence_epoch), max(fence_epoch) "
                    "FROM public.execution_attempts WHERE execution_id = :execution_id"
                ),
                {"execution_id": execution_id},
            ).one())
        assert execution == {
            "process_state": "LOST",
            "data_effect": "UNKNOWN",
            "verification_state": "INCONCLUSIVE",
            "fence_epoch": 1,
        }
        assert lock == {"state": "RELEASED", "attempt_id": attempt_id, "fence_epoch": 1}
        assert attempts == (1, 1, 1)
    finally:
        runner.dispose()
        issuer.dispose()
        worker.dispose()
        api.dispose()
        owner.dispose()


@pytest.mark.skipif(
    not all((ISSUER_POSTGRES_URL, CONSUMER_POSTGRES_URL)),
    reason="private Phase-A PostgreSQL role URLs are not configured",
)
@pytest.mark.parametrize(
    "drift_target",
    (
        "project",
        "datasource",
        "endpoint_policy",
        "physical_identity",
        "target_namespace",
        "transfer_policy",
    ),
)
def test_phase_a_authorization_read_rejects_public_parent_drift(
    drift_target: str,
) -> None:
    """The consumer must reject a snapshot when any checked parent drifts.

    This remains a PostgreSQL E2 boundary test. It deliberately changes public
    facts as the privileged migration owner, then proves the consumer function
    fails closed instead of treating the PEA snapshot as an eternal permit.
    """

    assert POSTGRES_URL is not None
    assert ISSUER_POSTGRES_URL is not None
    assert CONSUMER_POSTGRES_URL is not None
    execution_id, facts = _seed_pending_private_execution(POSTGRES_URL)
    grant_id = uuid4()
    owner = create_engine(POSTGRES_URL, pool_pre_ping=True)
    issuer = create_engine(ISSUER_POSTGRES_URL, pool_pre_ping=True, poolclass=NullPool)
    consumer = create_engine(CONSUMER_POSTGRES_URL, pool_pre_ping=True, poolclass=NullPool)
    try:
        with issuer.begin() as connection:
            assert connection.execute(
                _ISSUE_SQL,
                _issue_parameters(
                    grant_id=grant_id,
                    nonce_id=uuid4(),
                    facts=facts,
                ),
            ).scalar_one() == grant_id
            assert connection.execute(
                _AUTHORIZE_SQL,
                {
                    "authorization_id": uuid4(),
                    "grant_id": grant_id,
                    "execution_id": execution_id,
                },
            ).scalar_one() is not None
        with consumer.begin() as connection:
            assert connection.execute(
                _READ_SQL,
                {"execution_id": execution_id},
            ).mappings().one_or_none() is not None

        statements = {
            "project": (
                "UPDATE public.projects SET status = 'ARCHIVED' WHERE id = :id",
                facts["project_id"],
            ),
            "datasource": (
                "UPDATE public.datasources SET status = 'DISABLED' WHERE id = :id",
                facts["source_datasource_id"],
            ),
            "endpoint_policy": (
                "UPDATE public.endpoint_policies SET status = 'DISABLED' WHERE id = :id",
                facts["source_policy_id"],
            ),
            "physical_identity": (
                "UPDATE public.physical_endpoint_identities "
                "SET server_identity_hash = :replacement WHERE id = :id",
                facts["source_identity_id"],
            ),
            "target_namespace": (
                "UPDATE public.target_namespaces "
                "SET physical_table_identity_hash = :replacement WHERE id = :id",
                facts["target_namespace_id"],
            ),
            "transfer_policy": (
                "UPDATE public.transfer_policies SET status = 'REVOKED' WHERE id = :id",
                facts["transfer_policy_id"],
            ),
        }
        statement, identifier = statements[drift_target]
        parameters: dict[str, object] = {"id": identifier}
        if ":replacement" in statement:
            parameters["replacement"] = _hash(f"{execution_id}:{drift_target}:replacement")
        with owner.begin() as connection:
            connection.execute(text(statement), parameters)

        with consumer.begin() as connection:
            assert connection.execute(
                _READ_SQL,
                {"execution_id": execution_id},
            ).mappings().one_or_none() is None
    finally:
        consumer.dispose()
        issuer.dispose()
        owner.dispose()
