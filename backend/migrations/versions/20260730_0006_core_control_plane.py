"""create the V1 core control-plane facts

Revision ID: 20260730_0006
Revises: 20260730_0005
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260730_0006"
down_revision: str | Sequence[str] | None = "20260730_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def _id(name: str = "id", *, nullable: bool = False) -> sa.Column:
    return sa.Column(name, UUID, nullable=nullable)


def _foreign_id(
    name: str,
    target: str,
    *,
    nullable: bool = False,
) -> sa.Column:
    return sa.Column(
        name,
        UUID,
        sa.ForeignKey(target, ondelete="RESTRICT"),
        nullable=nullable,
    )


def _hash_check(column: str, *, nullable: bool = False) -> sa.CheckConstraint:
    expression = f"{column} ~ '^[a-f0-9]{{64}}$'"
    if nullable:
        expression = f"{column} IS NULL OR {expression}"
    return sa.CheckConstraint(expression, name=f"ck_{column}_sha256")


def upgrade() -> None:
    op.create_table(
        "queue_scheduler_state",
        sa.Column("singleton_id", sa.SmallInteger(), nullable=False),
        sa.Column(
            "next_service_sequence",
            sa.BigInteger(),
            nullable=False,
            server_default="1",
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("singleton_id"),
        sa.CheckConstraint(
            "singleton_id = 1",
            name="ck_queue_scheduler_state_singleton",
        ),
        sa.CheckConstraint(
            "next_service_sequence >= 1",
            name="ck_queue_scheduler_state_sequence",
        ),
    )
    op.execute(
        """
        INSERT INTO queue_scheduler_state
            (singleton_id, next_service_sequence, updated_at)
        VALUES (1, 1, CURRENT_TIMESTAMP)
        """
    )

    op.create_table(
        "projects",
        _id(),
        _foreign_id("organization_id", "organizations.id"),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        _foreign_id("created_by", "users.id"),
        _foreign_id("archived_by", "users.id", nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "slug", name="uq_projects_org_slug"),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'ARCHIVED')",
            name="ck_projects_status",
        ),
        sa.CheckConstraint("row_version >= 1", name="ck_projects_row_version"),
    )
    op.create_index(
        "ix_projects_org_status_created",
        "projects",
        ["organization_id", "status", "created_at", "id"],
    )
    op.create_index(
        "uq_projects_org_name_ci",
        "projects",
        ["organization_id", sa.text("lower(name)")],
        unique=True,
    )

    op.create_table(
        "project_queue_service_cursors",
        _foreign_id("project_id", "projects.id"),
        sa.Column(
            "last_service_sequence",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("last_served_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "served_execution_count",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "served_recovery_probe_count",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("row_version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("project_id"),
        sa.CheckConstraint(
            "last_service_sequence >= 0",
            name="ck_pqsc_last_service_sequence",
        ),
        sa.CheckConstraint("row_version >= 1", name="ck_pqsc_row_version"),
    )
    op.create_index(
        "ix_pqsc_service_sequence",
        "project_queue_service_cursors",
        ["last_service_sequence", "project_id"],
    )

    op.create_table(
        "endpoint_policies",
        _id(),
        _foreign_id("organization_id", "organizations.id"),
        sa.Column("name", sa.String(length=128), nullable=False),
        _id("current_revision_id", nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        _foreign_id("created_by", "users.id"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED')",
            name="ck_endpoint_policies_status",
        ),
        sa.CheckConstraint(
            "row_version >= 1",
            name="ck_endpoint_policies_row_version",
        ),
    )
    op.create_index(
        "ix_endpoint_policies_org_status_created",
        "endpoint_policies",
        ["organization_id", "status", "created_at", "id"],
    )
    op.create_index(
        "uq_endpoint_policies_org_name_ci",
        "endpoint_policies",
        ["organization_id", sa.text("lower(name)")],
        unique=True,
    )

    op.create_table(
        "endpoint_policy_revisions",
        _id(),
        _foreign_id("endpoint_policy_id", "endpoint_policies.id"),
        sa.Column("revision_no", sa.Integer(), nullable=False),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("host_kind", sa.String(length=16), nullable=False),
        sa.Column("host_value", sa.String(length=253), nullable=False),
        sa.Column("allowed_cidrs", JSONB, nullable=False),
        sa.Column("allowed_ports", JSONB, nullable=False),
        sa.Column("tls_required", sa.Boolean(), nullable=False),
        sa.Column("dns_ttl_ceiling_seconds", sa.Integer(), nullable=False),
        sa.Column("resolver_policy_version", sa.String(length=64), nullable=False),
        sa.Column("egress_policy_version", sa.String(length=64), nullable=False),
        sa.Column("policy_hash", sa.String(length=64), nullable=False),
        _foreign_id("created_by", "users.id"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "endpoint_policy_id",
            "revision_no",
            name="uq_epr_policy_revision",
        ),
        sa.UniqueConstraint(
            "endpoint_policy_id",
            "policy_hash",
            name="uq_epr_policy_hash",
        ),
        sa.CheckConstraint(
            "engine IN ('MYSQL_8', 'POSTGRESQL_15')",
            name="ck_epr_engine",
        ),
        sa.CheckConstraint(
            "host_kind IN ('EXACT_FQDN', 'EXACT_IP')",
            name="ck_epr_host_kind",
        ),
        sa.CheckConstraint(
            "dns_ttl_ceiling_seconds BETWEEN 1 AND 3600",
            name="ck_epr_dns_ttl",
        ),
        _hash_check("policy_hash"),
    )
    op.create_index(
        "ix_epr_policy_revision",
        "endpoint_policy_revisions",
        ["endpoint_policy_id", "revision_no"],
    )

    op.create_table(
        "physical_endpoint_identities",
        _id(),
        _foreign_id("organization_id", "organizations.id"),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("identity_scheme", sa.String(length=40), nullable=False),
        sa.Column("server_identity_hash", sa.String(length=64), nullable=False),
        sa.Column("verification_evidence", JSONB, nullable=False),
        sa.Column(
            "verification_evidence_hash",
            sa.String(length=64),
            nullable=False,
        ),
        _foreign_id("created_by", "users.id"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "engine",
            "identity_scheme",
            "server_identity_hash",
            name="uq_pei_org_engine_identity",
        ),
        sa.CheckConstraint(
            "engine IN ('MYSQL_8', 'POSTGRESQL_15')",
            name="ck_pei_engine",
        ),
        sa.CheckConstraint(
            "identity_scheme IN "
            "('MYSQL_SERVER_UUID', 'POSTGRES_SYSTEM_IDENTIFIER')",
            name="ck_pei_scheme",
        ),
        _hash_check("server_identity_hash"),
        _hash_check("verification_evidence_hash"),
    )

    op.create_table(
        "datasources",
        _id(),
        _foreign_id("project_id", "projects.id"),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        _id("current_revision_id", nullable=True),
        _id("current_secret_id", nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_test_status", sa.String(length=16), nullable=True),
        sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_test_error_code", sa.String(length=64), nullable=True),
        _foreign_id("created_by", "users.id"),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED', 'DELETED')",
            name="ck_datasources_status",
        ),
        sa.CheckConstraint("row_version >= 1", name="ck_datasources_row_version"),
    )
    op.create_index(
        "ix_datasources_project_status_created",
        "datasources",
        ["project_id", "status", "created_at", "id"],
    )
    op.create_index(
        "uq_datasources_project_name_ci_active",
        "datasources",
        ["project_id", sa.text("lower(name)")],
        unique=True,
        postgresql_where=sa.text("status <> 'DELETED'"),
    )

    op.create_table(
        "datasource_revisions",
        _id(),
        _foreign_id("datasource_id", "datasources.id"),
        sa.Column("revision_no", sa.Integer(), nullable=False),
        _foreign_id(
            "endpoint_policy_revision_id",
            "endpoint_policy_revisions.id",
        ),
        _foreign_id(
            "physical_endpoint_identity_id",
            "physical_endpoint_identities.id",
        ),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("host", sa.String(length=253), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("database_name", sa.String(length=128), nullable=False),
        sa.Column("default_schema", sa.String(length=128), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("ssl_mode", sa.String(length=16), nullable=False),
        sa.Column("connection_options", JSONB, nullable=False),
        sa.Column("config_hash", sa.String(length=64), nullable=False),
        _foreign_id("created_by", "users.id"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "datasource_id",
            "revision_no",
            name="uq_dsr_datasource_revision",
        ),
        sa.UniqueConstraint(
            "datasource_id",
            "config_hash",
            name="uq_dsr_datasource_hash",
        ),
        sa.CheckConstraint(
            "engine IN ('MYSQL_8', 'POSTGRESQL_15')",
            name="ck_dsr_engine",
        ),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_dsr_port"),
        sa.CheckConstraint(
            "ssl_mode IN ('DISABLE', 'REQUIRE', 'VERIFY_CA', 'VERIFY_FULL')",
            name="ck_dsr_ssl_mode",
        ),
        _hash_check("config_hash"),
    )
    op.create_index(
        "ix_dsr_datasource_revision",
        "datasource_revisions",
        ["datasource_id", "revision_no"],
    )

    op.create_table(
        "datasource_usage_grants",
        _id(),
        _foreign_id("datasource_id", "datasources.id"),
        _foreign_id("organization_member_id", "organization_members.id"),
        sa.Column("usage", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        _foreign_id("granted_by", "users.id"),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        _foreign_id("revoked_by", "users.id", nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "datasource_id",
            "organization_member_id",
            "usage",
            name="uq_dsug_datasource_member_usage",
        ),
        sa.CheckConstraint(
            "usage IN ('SOURCE_USE', 'TARGET_USE')",
            name="ck_dsug_usage",
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'REVOKED')",
            name="ck_dsug_status",
        ),
    )
    op.create_index(
        "ix_dsug_member_datasource_usage",
        "datasource_usage_grants",
        ["organization_member_id", "datasource_id", "usage", "status"],
    )

    op.create_table(
        "target_namespaces",
        _id(),
        _foreign_id(
            "physical_endpoint_identity_id",
            "physical_endpoint_identities.id",
        ),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("normalized_catalog_name", sa.String(length=128), nullable=False),
        sa.Column("normalized_schema_name", sa.String(length=128), nullable=False),
        sa.Column("normalized_table_name", sa.String(length=128), nullable=False),
        sa.Column(
            "normalization_version",
            sa.String(length=16),
            nullable=False,
            server_default="1.0",
        ),
        sa.Column(
            "physical_table_identity_hash",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "physical_table_identity_hash",
            name="uq_tn_physical_table_hash",
        ),
        sa.UniqueConstraint(
            "physical_endpoint_identity_id",
            "normalized_catalog_name",
            "normalized_schema_name",
            "normalized_table_name",
            "normalization_version",
            name="uq_tn_physical_names",
        ),
        sa.CheckConstraint(
            "engine IN ('MYSQL_8', 'POSTGRESQL_15')",
            name="ck_tn_engine",
        ),
        _hash_check("physical_table_identity_hash"),
    )

    op.create_table(
        "transfer_policies",
        _id(),
        _foreign_id("project_id", "projects.id"),
        _foreign_id(
            "source_datasource_revision_id",
            "datasource_revisions.id",
        ),
        _foreign_id(
            "target_datasource_revision_id",
            "datasource_revisions.id",
        ),
        _foreign_id(
            "source_physical_endpoint_identity_id",
            "physical_endpoint_identities.id",
        ),
        _foreign_id(
            "target_physical_endpoint_identity_id",
            "physical_endpoint_identities.id",
        ),
        sa.Column("scope_json", JSONB, nullable=False),
        sa.Column("scope_hash", sa.String(length=64), nullable=False),
        sa.Column("classification", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        _foreign_id("requested_by", "users.id"),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        _foreign_id("revoked_by", "users.id", nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "classification IN ('STANDARD', 'SENSITIVE')",
            name="ck_transfer_policies_classification",
        ),
        sa.CheckConstraint(
            "status IN "
            "('DRAFT', 'PENDING_APPROVAL', 'ACTIVE', 'REJECTED', 'REVOKED')",
            name="ck_transfer_policies_status",
        ),
        sa.CheckConstraint(
            "row_version >= 1",
            name="ck_transfer_policies_row_version",
        ),
        _hash_check("scope_hash"),
    )
    op.create_index(
        "ix_transfer_policies_project_status",
        "transfer_policies",
        [
            "project_id",
            "status",
            "source_datasource_revision_id",
            "target_datasource_revision_id",
            "scope_hash",
        ],
    )

    op.create_table(
        "transfer_policy_approvals",
        _id(),
        _foreign_id("transfer_policy_id", "transfer_policies.id"),
        _foreign_id("approved_by", "users.id"),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("comment", sa.String(length=500), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "transfer_policy_id",
            "approved_by",
            name="uq_tpa_policy_admin",
        ),
        sa.CheckConstraint(
            "decision IN ('APPROVED', 'REJECTED')",
            name="ck_tpa_decision",
        ),
    )

    op.create_table(
        "sync_jobs",
        _id(),
        _foreign_id("project_id", "projects.id"),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("draft_spec_json", JSONB, nullable=False),
        sa.Column("draft_spec_hash", sa.String(length=64), nullable=False),
        sa.Column("validated_spec_hash", sa.String(length=64), nullable=True),
        sa.Column("validation_report", JSONB, nullable=True),
        _id("latest_published_version_id", nullable=True),
        _foreign_id("created_by", "users.id"),
        _foreign_id("archived_by", "users.id", nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('DRAFT', 'VALID', 'PUBLISHED', 'ARCHIVED')",
            name="ck_sync_jobs_status",
        ),
        sa.CheckConstraint("row_version >= 1", name="ck_sync_jobs_row_version"),
        _hash_check("draft_spec_hash"),
        _hash_check("validated_spec_hash", nullable=True),
    )
    op.create_index(
        "ix_sync_jobs_project_status_updated",
        "sync_jobs",
        ["project_id", "status", "updated_at", "id"],
    )
    op.create_index(
        "uq_sync_jobs_project_name_ci",
        "sync_jobs",
        ["project_id", sa.text("lower(name)")],
        unique=True,
    )

    op.create_table(
        "job_versions",
        _id(),
        _foreign_id("job_id", "sync_jobs.id"),
        sa.Column("version_no", sa.Integer(), nullable=False),
        sa.Column("job_spec_schema_version", sa.String(length=16), nullable=False),
        sa.Column("spec_json", JSONB, nullable=False),
        sa.Column("spec_hash", sa.String(length=64), nullable=False),
        _foreign_id(
            "source_datasource_revision_id",
            "datasource_revisions.id",
        ),
        _foreign_id(
            "target_datasource_revision_id",
            "datasource_revisions.id",
        ),
        _foreign_id(
            "source_endpoint_policy_revision_id",
            "endpoint_policy_revisions.id",
        ),
        _foreign_id(
            "target_endpoint_policy_revision_id",
            "endpoint_policy_revisions.id",
        ),
        sa.Column(
            "source_physical_table_identity_hash",
            sa.String(length=64),
            nullable=False,
        ),
        _foreign_id("target_namespace_id", "target_namespaces.id"),
        _foreign_id("transfer_policy_id", "transfer_policies.id"),
        sa.Column(
            "transfer_policy_scope_hash",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("source_schema_snapshot", JSONB, nullable=False),
        sa.Column("target_schema_snapshot", JSONB, nullable=False),
        sa.Column("source_schema_hash", sa.String(length=64), nullable=False),
        sa.Column("target_schema_hash", sa.String(length=64), nullable=False),
        sa.Column("reader_plugin_name", sa.String(length=64), nullable=False),
        sa.Column("reader_plugin_sha256", sa.String(length=64), nullable=False),
        sa.Column("writer_plugin_name", sa.String(length=64), nullable=False),
        sa.Column("writer_plugin_sha256", sa.String(length=64), nullable=False),
        sa.Column("datax_release", sa.String(length=32), nullable=False),
        sa.Column("runtime_sha256", sa.String(length=64), nullable=False),
        sa.Column("version_artifact_hash", sa.String(length=64), nullable=False),
        _foreign_id("published_by", "users.id"),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "job_id",
            "version_no",
            name="uq_job_versions_job_version",
        ),
        sa.UniqueConstraint(
            "job_id",
            "version_artifact_hash",
            name="uq_job_versions_artifact",
        ),
        sa.CheckConstraint(
            "job_spec_schema_version = '1.0'",
            name="ck_job_versions_schema_version",
        ),
        _hash_check("spec_hash"),
        _hash_check("source_physical_table_identity_hash"),
        _hash_check("transfer_policy_scope_hash"),
        _hash_check("source_schema_hash"),
        _hash_check("target_schema_hash"),
        _hash_check("reader_plugin_sha256"),
        _hash_check("writer_plugin_sha256"),
        _hash_check("runtime_sha256"),
        _hash_check("version_artifact_hash"),
    )
    op.create_index(
        "ix_job_versions_job_version",
        "job_versions",
        ["job_id", "version_no"],
    )

    op.create_table(
        "executions",
        _id(),
        _foreign_id("project_id", "projects.id"),
        _foreign_id("job_id", "sync_jobs.id"),
        _foreign_id("job_version_id", "job_versions.id"),
        _foreign_id("rerun_of_execution_id", "executions.id", nullable=True),
        sa.Column(
            "trigger_type",
            sa.String(length=16),
            nullable=False,
            server_default="MANUAL",
        ),
        _foreign_id("requested_by", "users.id"),
        sa.Column("process_state", sa.String(length=24), nullable=False),
        sa.Column("data_effect", sa.String(length=16), nullable=False),
        sa.Column("verification_state", sa.String(length=16), nullable=False),
        sa.Column("state_version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("fence_epoch", sa.BigInteger(), nullable=False, server_default="0"),
        _id("active_attempt_id", nullable=True),
        sa.Column("queue_priority", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("capacity_profile", sa.String(length=16), nullable=False),
        sa.Column("service_reservation_seconds", sa.Integer(), nullable=False),
        sa.Column(
            "log_reservation_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "workspace_reservation_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("queue_eligibility_state", sa.String(length=16), nullable=False),
        sa.Column("queue_block_reason", sa.String(length=64), nullable=True),
        sa.Column("queue_state_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "eligible_wait_milliseconds",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("datax_finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        _foreign_id(
            "source_datasource_revision_id",
            "datasource_revisions.id",
        ),
        _foreign_id(
            "target_datasource_revision_id",
            "datasource_revisions.id",
        ),
        _foreign_id(
            "source_endpoint_policy_revision_id",
            "endpoint_policy_revisions.id",
        ),
        _foreign_id(
            "target_endpoint_policy_revision_id",
            "endpoint_policy_revisions.id",
        ),
        _foreign_id("target_namespace_id", "target_namespaces.id"),
        _id("source_secret_id", nullable=True),
        _id("target_secret_id", nullable=True),
        _id("source_secret_envelope_id", nullable=True),
        _id("target_secret_envelope_id", nullable=True),
        sa.Column("source_secret_version", sa.Integer(), nullable=True),
        sa.Column("target_secret_version", sa.Integer(), nullable=True),
        _id("source_connection_evidence_id", nullable=True),
        _id("target_connection_evidence_id", nullable=True),
        sa.Column("source_quiescence_confirmation", JSONB, nullable=False),
        sa.Column("target_exclusivity_confirmation", JSONB, nullable=False),
        sa.Column("target_exclusivity_status", sa.String(length=16), nullable=False),
        sa.Column(
            "target_exclusivity_revoked_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "target_exclusivity_revocation_reason",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column("target_empty_evidence", JSONB, nullable=True),
        sa.Column("runtime_snapshot", JSONB, nullable=True),
        sa.Column("resolved_config_hash", sa.String(length=64), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_message", sa.String(length=2000), nullable=True),
        sa.Column(
            "summary_parse_status",
            sa.String(length=16),
            nullable=False,
            server_default="PENDING",
        ),
        sa.Column("run_summary", JSONB, nullable=True),
        sa.Column("verification_report", JSONB, nullable=True),
        sa.Column(
            "verification_evidence_hash",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "log_truncated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "log_incomplete",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "log_raw_received_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "log_redacted_received_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "log_stored_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "log_dropped_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("first_truncated_sequence", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "trigger_type = 'MANUAL'",
            name="ck_executions_trigger_type",
        ),
        sa.CheckConstraint(
            "process_state IN "
            "('QUEUED','STARTING','RUNNING','VERIFYING','CANCEL_REQUESTED',"
            "'SUCCEEDED','FAILED','TIMED_OUT','CANCELED','LOST')",
            name="ck_executions_process_state",
        ),
        sa.CheckConstraint(
            "data_effect IN ('NONE','POSSIBLE','CONFIRMED','UNKNOWN')",
            name="ck_executions_data_effect",
        ),
        sa.CheckConstraint(
            "verification_state IN "
            "('NOT_STARTED','VERIFYING','PASSED','FAILED','INCONCLUSIVE')",
            name="ck_executions_verification_state",
        ),
        sa.CheckConstraint(
            "target_exclusivity_status IN ('ACTIVE','REVOKED','EXPIRED')",
            name="ck_executions_target_exclusivity_status",
        ),
        sa.CheckConstraint(
            "("
            "target_exclusivity_status = 'ACTIVE' "
            "AND target_exclusivity_revoked_at IS NULL "
            "AND target_exclusivity_revocation_reason IS NULL"
            ") OR ("
            "target_exclusivity_status = 'REVOKED' "
            "AND target_exclusivity_revoked_at IS NOT NULL "
            "AND target_exclusivity_revocation_reason IN "
            "('OPERATOR_REVOKED','DBA_REVOKED','EXTERNAL_DML_DDL_REPORTED',"
            "'CHANGE_FREEZE_BROKEN')"
            ") OR ("
            "target_exclusivity_status = 'EXPIRED' "
            "AND target_exclusivity_revoked_at IS NULL "
            "AND target_exclusivity_revocation_reason = "
            "'VALIDITY_WINDOW_EXPIRED'"
            ")",
            name="ck_executions_target_exclusivity_lifecycle",
        ),
        sa.CheckConstraint(
            "NOT (process_state = 'SUCCEEDED') OR "
            "(data_effect = 'CONFIRMED' "
            "AND verification_state = 'PASSED' "
            "AND verification_evidence_hash IS NOT NULL "
            "AND target_exclusivity_status = 'ACTIVE')",
            name="ck_executions_success_verified",
        ),
        sa.CheckConstraint("fence_epoch >= 0", name="ck_executions_fence_epoch"),
        sa.CheckConstraint("state_version >= 1", name="ck_executions_state_version"),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_executions_attempt_count",
        ),
        sa.CheckConstraint(
            "capacity_profile IN ('LIGHTWEIGHT','LARGE')",
            name="ck_executions_capacity_profile",
        ),
        sa.CheckConstraint(
            "service_reservation_seconds IN (360,3600)",
            name="ck_executions_service_reservation",
        ),
        sa.CheckConstraint(
            "queue_eligibility_state IN ('ELIGIBLE','BLOCKED')",
            name="ck_executions_queue_eligibility",
        ),
        sa.CheckConstraint(
            "summary_parse_status IN ('PENDING','SUCCEEDED','FAILED')",
            name="ck_executions_summary_parse_status",
        ),
        sa.CheckConstraint(
            "source_secret_version IS NULL OR source_secret_version >= 1",
            name="ck_executions_source_secret_version",
        ),
        sa.CheckConstraint(
            "target_secret_version IS NULL OR target_secret_version >= 1",
            name="ck_executions_target_secret_version",
        ),
        sa.CheckConstraint(
            "log_raw_received_bytes >= 0 "
            "AND log_redacted_received_bytes >= 0 "
            "AND log_stored_bytes >= 0 "
            "AND log_dropped_bytes >= 0",
            name="ck_executions_log_nonnegative",
        ),
        sa.CheckConstraint(
            "log_dropped_bytes = "
            "log_redacted_received_bytes - log_stored_bytes",
            name="ck_executions_log_byte_accounting",
        ),
        _hash_check("resolved_config_hash", nullable=True),
        _hash_check("verification_evidence_hash", nullable=True),
    )
    op.create_index(
        "ix_executions_project_state_queued",
        "executions",
        ["project_id", "process_state", "queued_at", "id"],
    )
    op.create_index(
        "ix_executions_queue",
        "executions",
        ["process_state", "queue_priority", "queued_at", "id"],
    )

    op.create_table(
        "execution_attempts",
        _id(),
        _foreign_id("execution_id", "executions.id"),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("lease_token_hash", sa.String(length=64), nullable=False),
        sa.Column("fence_epoch", sa.BigInteger(), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("host_boot_id", sa.String(length=128), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("pid_start_time", sa.BigInteger(), nullable=True),
        sa.Column("process_group_id", sa.Integer(), nullable=True),
        sa.Column("cgroup_identity", sa.String(length=256), nullable=True),
        sa.Column("workspace_path_hash", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("termination_reason", sa.String(length=64), nullable=True),
        sa.Column("workspace_deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "execution_id",
            "attempt_no",
            name="uq_execution_attempts_number",
        ),
        sa.UniqueConstraint(
            "execution_id",
            "fence_epoch",
            name="uq_execution_attempts_fence",
        ),
        sa.CheckConstraint(
            "attempt_no >= 1",
            name="ck_execution_attempts_attempt_no",
        ),
        sa.CheckConstraint(
            "fence_epoch >= 1",
            name="ck_execution_attempts_fence_epoch",
        ),
        _hash_check("lease_token_hash"),
        _hash_check("workspace_path_hash", nullable=True),
    )

    op.create_table(
        "target_copy_locks",
        _id(),
        _foreign_id("target_namespace_id", "target_namespaces.id"),
        sa.Column(
            "physical_table_identity_hash",
            sa.String(length=64),
            nullable=False,
        ),
        _foreign_id("execution_id", "executions.id"),
        _foreign_id("attempt_id", "execution_attempts.id", nullable=True),
        sa.Column("fence_epoch", sa.BigInteger(), nullable=True),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "execution_id",
            name="uq_target_copy_locks_execution",
        ),
        sa.CheckConstraint(
            "state IN ('RESERVED','ACTIVE','RECOVERY_REQUIRED','RELEASED')",
            name="ck_target_copy_locks_state",
        ),
        sa.CheckConstraint(
            "("
            "state = 'RESERVED' AND attempt_id IS NULL "
            "AND fence_epoch IS NULL AND acquired_at IS NULL "
            "AND released_at IS NULL"
            ") OR ("
            "state = 'ACTIVE' AND attempt_id IS NOT NULL "
            "AND fence_epoch >= 1 AND acquired_at IS NOT NULL "
            "AND released_at IS NULL"
            ") OR ("
            "state = 'RECOVERY_REQUIRED' AND attempt_id IS NOT NULL "
            "AND fence_epoch >= 1 AND acquired_at IS NOT NULL "
            "AND released_at IS NULL"
            ") OR ("
            "state = 'RELEASED' AND released_at IS NOT NULL"
            ")",
            name="ck_target_copy_locks_lifecycle",
        ),
        _hash_check("physical_table_identity_hash"),
    )
    op.create_index(
        "ix_target_copy_locks_namespace_state",
        "target_copy_locks",
        ["target_namespace_id", "state"],
    )
    op.create_index(
        "uq_target_copy_locks_unreleased_namespace",
        "target_copy_locks",
        ["target_namespace_id"],
        unique=True,
        postgresql_where=sa.text(
            "state IN ('RESERVED','ACTIVE','RECOVERY_REQUIRED')"
        ),
    )

    op.create_table(
        "execution_events",
        _id(),
        _foreign_id("execution_id", "executions.id"),
        sa.Column("sequence_no", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("from_state", sa.String(length=24), nullable=True),
        sa.Column("to_state", sa.String(length=24), nullable=True),
        _foreign_id("attempt_id", "execution_attempts.id", nullable=True),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "execution_id",
            "sequence_no",
            name="uq_execution_events_sequence",
        ),
    )
    op.create_index(
        "ix_execution_events_execution_sequence",
        "execution_events",
        ["execution_id", "sequence_no"],
    )

    op.create_table(
        "execution_cancel_requests",
        _id(),
        _foreign_id("execution_id", "executions.id"),
        _foreign_id("requested_by", "users.id"),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('PENDING','ACKNOWLEDGED','COMPLETED','REJECTED')",
            name="ck_execution_cancel_requests_status",
        ),
    )
    op.create_index(
        "uq_execution_cancel_requests_active",
        "execution_cancel_requests",
        ["execution_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('PENDING','ACKNOWLEDGED')"),
    )


def downgrade() -> None:
    op.drop_table("execution_cancel_requests")
    op.drop_table("execution_events")
    op.drop_table("target_copy_locks")
    op.drop_table("execution_attempts")
    op.drop_table("executions")
    op.drop_table("job_versions")
    op.drop_table("sync_jobs")
    op.drop_table("transfer_policy_approvals")
    op.drop_table("transfer_policies")
    op.drop_table("target_namespaces")
    op.drop_table("datasource_usage_grants")
    op.drop_table("datasource_revisions")
    op.drop_table("datasources")
    op.drop_table("physical_endpoint_identities")
    op.drop_table("endpoint_policy_revisions")
    op.drop_table("endpoint_policies")
    op.drop_table("project_queue_service_cursors")
    op.drop_table("projects")
    op.drop_table("queue_scheduler_state")
