from __future__ import annotations

from datetime import datetime
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
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from datax_studio.auth.db import Base


class SystemControl(Base):
    __tablename__ = "system_control"
    __table_args__ = (
        CheckConstraint("singleton_id = 1", name="ck_system_control_singleton"),
    )

    singleton_id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    draining: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    host_boot_id: Mapped[str | None] = mapped_column(String(128))
    reconcile_epoch: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint("status IN ('ACTIVE', 'ARCHIVED')", name="ck_projects_status"),
        CheckConstraint("row_version >= 1", name="ck_projects_row_version"),
        UniqueConstraint("organization_id", "slug", name="uq_projects_org_slug"),
        Index("ix_projects_org_status_created", "organization_id", "status", "created_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    archived_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
    )
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class EndpointPolicy(Base):
    __tablename__ = "endpoint_policies"
    __table_args__ = (
        CheckConstraint("status IN ('ACTIVE', 'DISABLED')", name="ck_endpoint_policies_status"),
        CheckConstraint("row_version >= 1", name="ck_endpoint_policies_row_version"),
        Index(
            "ix_endpoint_policies_org_status_created",
            "organization_id",
            "status",
            "created_at",
            "id",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # Nullable only to break the insert-time cycle. The service creates revision 1
    # and switches this pointer in the same transaction.
    current_revision_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class EndpointPolicyRevision(Base):
    __tablename__ = "endpoint_policy_revisions"
    __table_args__ = (
        CheckConstraint("engine IN ('MYSQL_8', 'POSTGRESQL_15')", name="ck_epr_engine"),
        CheckConstraint("host_kind IN ('EXACT_FQDN', 'EXACT_IP')", name="ck_epr_host_kind"),
        CheckConstraint(
            "dns_ttl_ceiling_seconds BETWEEN 1 AND 3600",
            name="ck_epr_dns_ttl",
        ),
        UniqueConstraint("endpoint_policy_id", "revision_no", name="uq_epr_policy_revision"),
        UniqueConstraint("endpoint_policy_id", "policy_hash", name="uq_epr_policy_hash"),
        Index("ix_epr_policy_revision", "endpoint_policy_id", "revision_no"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    endpoint_policy_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("endpoint_policies.id", ondelete="RESTRICT"),
        nullable=False,
    )
    revision_no: Mapped[int] = mapped_column(Integer, nullable=False)
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    host_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    host_value: Mapped[str] = mapped_column(String(253), nullable=False)
    allowed_cidrs: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    allowed_ports: Mapped[list[int]] = mapped_column(JSON, nullable=False)
    tls_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    dns_ttl_ceiling_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    resolver_policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    egress_policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PhysicalEndpointIdentity(Base):
    __tablename__ = "physical_endpoint_identities"
    __table_args__ = (
        CheckConstraint("engine IN ('MYSQL_8', 'POSTGRESQL_15')", name="ck_pei_engine"),
        CheckConstraint(
            "identity_scheme IN ('MYSQL_SERVER_UUID', 'POSTGRES_SYSTEM_IDENTIFIER')",
            name="ck_pei_scheme",
        ),
        UniqueConstraint(
            "organization_id",
            "engine",
            "identity_scheme",
            "server_identity_hash",
            name="uq_pei_org_engine_identity",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    identity_scheme: Mapped[str] = mapped_column(String(40), nullable=False)
    server_identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    verification_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    verification_evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Datasource(Base):
    __tablename__ = "datasources"
    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED', 'DELETED')",
            name="ck_datasources_status",
        ),
        CheckConstraint("row_version >= 1", name="ck_datasources_row_version"),
        Index("ix_datasources_project_status_created", "project_id", "status", "created_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1000))
    current_revision_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    # Credential ownership is deliberately outside this non-secret slice. These
    # opaque references are fixed only by the credential service/claim transaction.
    current_secret_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    last_test_status: Mapped[str | None] = mapped_column(String(16))
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_error_code: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class DatasourceRevision(Base):
    __tablename__ = "datasource_revisions"
    __table_args__ = (
        CheckConstraint("engine IN ('MYSQL_8', 'POSTGRESQL_15')", name="ck_dsr_engine"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_dsr_port"),
        CheckConstraint(
            "ssl_mode IN ('DISABLE', 'REQUIRE', 'VERIFY_CA', 'VERIFY_FULL')",
            name="ck_dsr_ssl_mode",
        ),
        UniqueConstraint("datasource_id", "revision_no", name="uq_dsr_datasource_revision"),
        UniqueConstraint("datasource_id", "config_hash", name="uq_dsr_datasource_hash"),
        Index("ix_dsr_datasource_revision", "datasource_id", "revision_no"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    datasource_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasources.id", ondelete="RESTRICT"),
        nullable=False,
    )
    revision_no: Mapped[int] = mapped_column(Integer, nullable=False)
    endpoint_policy_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("endpoint_policy_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    physical_endpoint_identity_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("physical_endpoint_identities.id", ondelete="RESTRICT"),
        nullable=False,
    )
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    database_name: Mapped[str] = mapped_column(String(128), nullable=False)
    default_schema: Mapped[str] = mapped_column(String(128), nullable=False)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    ssl_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    connection_options: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DatasourceUsageGrant(Base):
    __tablename__ = "datasource_usage_grants"
    __table_args__ = (
        CheckConstraint("usage IN ('SOURCE_USE', 'TARGET_USE')", name="ck_dsug_usage"),
        CheckConstraint("status IN ('ACTIVE', 'REVOKED')", name="ck_dsug_status"),
        UniqueConstraint(
            "datasource_id",
            "organization_member_id",
            "usage",
            name="uq_dsug_datasource_member_usage",
        ),
        Index(
            "ix_dsug_member_datasource_usage",
            "organization_member_id",
            "datasource_id",
            "usage",
            "status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    datasource_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasources.id", ondelete="RESTRICT"),
        nullable=False,
    )
    organization_member_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organization_members.id", ondelete="RESTRICT"),
        nullable=False,
    )
    usage: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    granted_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TransferPolicy(Base):
    __tablename__ = "transfer_policies"
    __table_args__ = (
        CheckConstraint(
            "classification IN ('STANDARD', 'SENSITIVE')",
            name="ck_transfer_policies_classification",
        ),
        CheckConstraint(
            "status IN ('DRAFT', 'PENDING_APPROVAL', 'ACTIVE', 'REJECTED', 'REVOKED')",
            name="ck_transfer_policies_status",
        ),
        CheckConstraint("row_version >= 1", name="ck_transfer_policies_row_version"),
        Index(
            "ix_transfer_policies_project_status",
            "project_id",
            "status",
            "source_datasource_revision_id",
            "target_datasource_revision_id",
            "scope_hash",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_datasource_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasource_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_datasource_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasource_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_physical_endpoint_identity_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("physical_endpoint_identities.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_physical_endpoint_identity_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("physical_endpoint_identities.id", ondelete="RESTRICT"),
        nullable=False,
    )
    scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    classification: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    requested_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class TransferPolicyApproval(Base):
    __tablename__ = "transfer_policy_approvals"
    __table_args__ = (
        CheckConstraint("decision IN ('APPROVED', 'REJECTED')", name="ck_tpa_decision"),
        UniqueConstraint("transfer_policy_id", "approved_by", name="uq_tpa_policy_admin"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    transfer_policy_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("transfer_policies.id", ondelete="RESTRICT"),
        nullable=False,
    )
    approved_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    comment: Mapped[str | None] = mapped_column(String(500))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TargetNamespace(Base):
    __tablename__ = "target_namespaces"
    __table_args__ = (
        CheckConstraint("engine IN ('MYSQL_8', 'POSTGRESQL_15')", name="ck_tn_engine"),
        UniqueConstraint("physical_table_identity_hash", name="uq_tn_physical_table_hash"),
        UniqueConstraint(
            "physical_endpoint_identity_id",
            "normalized_catalog_name",
            "normalized_schema_name",
            "normalized_table_name",
            "normalization_version",
            name="uq_tn_physical_names",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    physical_endpoint_identity_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("physical_endpoint_identities.id", ondelete="RESTRICT"),
        nullable=False,
    )
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    normalized_catalog_name: Mapped[str] = mapped_column(String(128), nullable=False)
    normalized_schema_name: Mapped[str] = mapped_column(String(128), nullable=False)
    normalized_table_name: Mapped[str] = mapped_column(String(128), nullable=False)
    normalization_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    physical_table_identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SyncJob(Base):
    __tablename__ = "sync_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('DRAFT', 'VALID', 'PUBLISHED', 'ARCHIVED')",
            name="ck_sync_jobs_status",
        ),
        CheckConstraint("row_version >= 1", name="ck_sync_jobs_row_version"),
        Index("ix_sync_jobs_project_status_updated", "project_id", "status", "updated_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    draft_spec_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    draft_spec_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    validated_spec_hash: Mapped[str | None] = mapped_column(String(64))
    validation_report: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    latest_published_version_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    archived_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
    )
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class JobVersion(Base):
    __tablename__ = "job_versions"
    __table_args__ = (
        CheckConstraint(
            "job_spec_schema_version = '1.0'",
            name="ck_job_versions_schema_version",
        ),
        UniqueConstraint("job_id", "version_no", name="uq_job_versions_job_version"),
        UniqueConstraint("job_id", "version_artifact_hash", name="uq_job_versions_artifact"),
        Index("ix_job_versions_job_version", "job_id", "version_no"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("sync_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    version_no: Mapped[int] = mapped_column(Integer, nullable=False)
    job_spec_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    spec_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    spec_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_datasource_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasource_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_datasource_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasource_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_endpoint_policy_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("endpoint_policy_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_endpoint_policy_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("endpoint_policy_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_physical_table_identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    target_namespace_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("target_namespaces.id", ondelete="RESTRICT"),
        nullable=False,
    )
    transfer_policy_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("transfer_policies.id", ondelete="RESTRICT"),
        nullable=False,
    )
    transfer_policy_scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_schema_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    target_schema_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    source_schema_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    target_schema_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    reader_plugin_name: Mapped[str] = mapped_column(String(64), nullable=False)
    reader_plugin_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    writer_plugin_name: Mapped[str] = mapped_column(String(64), nullable=False)
    writer_plugin_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    datax_release: Mapped[str] = mapped_column(String(32), nullable=False)
    runtime_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    version_artifact_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    published_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Execution(Base):
    __tablename__ = "executions"
    __table_args__ = (
        CheckConstraint("trigger_type = 'MANUAL'", name="ck_executions_trigger_type"),
        CheckConstraint(
            "process_state IN "
            "('QUEUED','STARTING','RUNNING','VERIFYING','CANCEL_REQUESTED',"
            "'SUCCEEDED','FAILED','TIMED_OUT','CANCELED','LOST')",
            name="ck_executions_process_state",
        ),
        CheckConstraint(
            "data_effect IN ('NONE','POSSIBLE','CONFIRMED','UNKNOWN')",
            name="ck_executions_data_effect",
        ),
        CheckConstraint(
            "verification_state IN ('NOT_STARTED','VERIFYING','PASSED','FAILED','INCONCLUSIVE')",
            name="ck_executions_verification_state",
        ),
        CheckConstraint(
            "target_exclusivity_status IN ('ACTIVE','REVOKED','EXPIRED')",
            name="ck_executions_target_exclusivity_status",
        ),
        CheckConstraint(
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
            "AND target_exclusivity_revocation_reason = 'VALIDITY_WINDOW_EXPIRED'"
            ")",
            name="ck_executions_target_exclusivity_lifecycle",
        ),
        CheckConstraint(
            "NOT (process_state = 'SUCCEEDED') OR "
            "(data_effect = 'CONFIRMED' AND verification_state = 'PASSED' "
            "AND verification_evidence_hash IS NOT NULL "
            "AND target_exclusivity_status = 'ACTIVE')",
            name="ck_executions_success_verified",
        ),
        CheckConstraint("fence_epoch >= 0", name="ck_executions_fence_epoch"),
        CheckConstraint("state_version >= 1", name="ck_executions_state_version"),
        CheckConstraint("attempt_count >= 0", name="ck_executions_attempt_count"),
        CheckConstraint(
            "capacity_profile IN ('LIGHTWEIGHT','LARGE')",
            name="ck_executions_capacity_profile",
        ),
        CheckConstraint(
            "service_reservation_seconds IN (360,3600)",
            name="ck_executions_service_reservation",
        ),
        CheckConstraint(
            "queue_eligibility_state IN ('ELIGIBLE','BLOCKED')",
            name="ck_executions_queue_eligibility",
        ),
        CheckConstraint(
            "summary_parse_status IN ('PENDING','SUCCEEDED','FAILED')",
            name="ck_executions_summary_parse_status",
        ),
        CheckConstraint(
            "source_secret_version IS NULL OR source_secret_version >= 1",
            name="ck_executions_source_secret_version",
        ),
        CheckConstraint(
            "target_secret_version IS NULL OR target_secret_version >= 1",
            name="ck_executions_target_secret_version",
        ),
        CheckConstraint(
            "log_raw_received_bytes >= 0 "
            "AND log_redacted_received_bytes >= 0 "
            "AND log_stored_bytes >= 0 "
            "AND log_dropped_bytes >= 0",
            name="ck_executions_log_nonnegative",
        ),
        CheckConstraint(
            "log_dropped_bytes = log_redacted_received_bytes - log_stored_bytes",
            name="ck_executions_log_byte_accounting",
        ),
        Index(
            "ix_executions_project_state_queued",
            "project_id",
            "process_state",
            "queued_at",
            "id",
        ),
        Index("ix_executions_queue", "process_state", "queue_priority", "queued_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    job_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("sync_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    job_version_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("job_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    rerun_of_execution_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("executions.id", ondelete="RESTRICT"),
    )
    trigger_type: Mapped[str] = mapped_column(String(16), nullable=False, default="MANUAL")
    requested_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    process_state: Mapped[str] = mapped_column(String(24), nullable=False)
    data_effect: Mapped[str] = mapped_column(String(16), nullable=False)
    verification_state: Mapped[str] = mapped_column(String(16), nullable=False)
    state_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    fence_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    active_attempt_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    queue_priority: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    capacity_profile: Mapped[str] = mapped_column(String(16), nullable=False)
    service_reservation_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    log_reservation_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    workspace_reservation_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    queue_eligibility_state: Mapped[str] = mapped_column(String(16), nullable=False)
    queue_block_reason: Mapped[str | None] = mapped_column(String(64))
    queue_state_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    eligible_wait_milliseconds: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    datax_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    source_datasource_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasource_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_datasource_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasource_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_endpoint_policy_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("endpoint_policy_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_endpoint_policy_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("endpoint_policy_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_namespace_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("target_namespaces.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_secret_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    target_secret_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    source_secret_envelope_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    target_secret_envelope_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    source_secret_version: Mapped[int | None] = mapped_column(Integer)
    target_secret_version: Mapped[int | None] = mapped_column(Integer)
    source_connection_evidence_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    target_connection_evidence_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    source_quiescence_confirmation: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    target_exclusivity_confirmation: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    target_exclusivity_status: Mapped[str] = mapped_column(String(16), nullable=False)
    target_exclusivity_revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    target_exclusivity_revocation_reason: Mapped[str | None] = mapped_column(String(64))
    target_empty_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    runtime_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    resolved_config_hash: Mapped[str | None] = mapped_column(String(64))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    failure_code: Mapped[str | None] = mapped_column(String(64))
    failure_message: Mapped[str | None] = mapped_column(String(2000))
    summary_parse_status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    run_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    verification_report: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    verification_evidence_hash: Mapped[str | None] = mapped_column(String(64))
    log_truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    log_incomplete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    log_raw_received_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    log_redacted_received_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    log_stored_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    log_dropped_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    first_truncated_sequence: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ExecutionAttempt(Base):
    __tablename__ = "execution_attempts"
    __table_args__ = (
        CheckConstraint("attempt_no >= 1", name="ck_execution_attempts_attempt_no"),
        CheckConstraint("fence_epoch >= 1", name="ck_execution_attempts_fence_epoch"),
        UniqueConstraint("execution_id", "attempt_no", name="uq_execution_attempts_number"),
        UniqueConstraint("execution_id", "fence_epoch", name="uq_execution_attempts_fence"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("executions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False)
    lease_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    fence_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    host_boot_id: Mapped[str] = mapped_column(String(128), nullable=False)
    pid: Mapped[int | None] = mapped_column(Integer)
    pid_start_time: Mapped[int | None] = mapped_column(BigInteger)
    process_group_id: Mapped[int | None] = mapped_column(Integer)
    cgroup_identity: Mapped[str | None] = mapped_column(String(256))
    workspace_path_hash: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_code: Mapped[int | None] = mapped_column(Integer)
    termination_reason: Mapped[str | None] = mapped_column(String(64))
    workspace_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TargetCopyLock(Base):
    __tablename__ = "target_copy_locks"
    __table_args__ = (
        CheckConstraint(
            "state IN ('RESERVED','ACTIVE','RECOVERY_REQUIRED','RELEASED')",
            name="ck_target_copy_locks_state",
        ),
        CheckConstraint(
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
        Index("ix_target_copy_locks_namespace_state", "target_namespace_id", "state"),
        Index(
            "uq_target_copy_locks_unreleased_namespace",
            "target_namespace_id",
            unique=True,
            sqlite_where=text("state IN ('RESERVED','ACTIVE','RECOVERY_REQUIRED')"),
            postgresql_where=text("state IN ('RESERVED','ACTIVE','RECOVERY_REQUIRED')"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    target_namespace_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("target_namespaces.id", ondelete="RESTRICT"),
        nullable=False,
    )
    physical_table_identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("executions.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    attempt_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("execution_attempts.id", ondelete="RESTRICT"),
    )
    fence_epoch: Mapped[int | None] = mapped_column(BigInteger)
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    reserved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acquired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ExecutionEvent(Base):
    __tablename__ = "execution_events"
    __table_args__ = (
        UniqueConstraint("execution_id", "sequence_no", name="uq_execution_events_sequence"),
        Index("ix_execution_events_execution_sequence", "execution_id", "sequence_no"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("executions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    sequence_no: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(24))
    to_state: Mapped[str | None] = mapped_column(String(24))
    attempt_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("execution_attempts.id", ondelete="RESTRICT"),
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ExecutionCancelRequest(Base):
    __tablename__ = "execution_cancel_requests"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','ACKNOWLEDGED','COMPLETED','REJECTED')",
            name="ck_execution_cancel_requests_status",
        ),
        Index(
            "uq_execution_cancel_requests_active",
            "execution_id",
            unique=True,
            sqlite_where=text("status IN ('PENDING','ACKNOWLEDGED')"),
            postgresql_where=text("status IN ('PENDING','ACKNOWLEDGED')"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("executions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    requested_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    reason: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WorkTerminationRequest(Base):
    """Durable, Worker-consumed safety stop for one work item.

    This is intentionally not an HTTP-command queue.  Privileged control-plane
    facts (target-exclusivity withdrawal/expiry and emergency secret status)
    create a request; an emergency current-secret transition may do so before
    a queued work item binds its credential.  Only a fenced Worker or
    reconciler may acknowledge it and advance the affected work item to its
    safe terminal state.
    """

    __tablename__ = "work_termination_requests"
    __table_args__ = (
        CheckConstraint(
            "work_kind IN ('EXECUTION','RECOVERY_PROBE')",
            name="ck_work_termination_requests_work_kind",
        ),
        CheckConstraint(
            "reason_code IN "
            "('TARGET_EXCLUSIVITY_REVOKED','TARGET_EXCLUSIVITY_EXPIRED',"
            "'SECRET_REVOKED','SECRET_COMPROMISED')",
            name="ck_work_termination_requests_reason",
        ),
        CheckConstraint(
            "status IN ('PENDING','ACKNOWLEDGED','COMPLETED')",
            name="ck_work_termination_requests_status",
        ),
        CheckConstraint(
            "(status = 'PENDING' AND acknowledged_at IS NULL AND completed_at IS NULL) "
            "OR (status = 'ACKNOWLEDGED' AND acknowledged_at IS NOT NULL "
            "AND completed_at IS NULL) "
            "OR (status = 'COMPLETED' AND acknowledged_at IS NOT NULL "
            "AND completed_at IS NOT NULL)",
            name="ck_work_termination_requests_lifecycle",
        ),
        CheckConstraint(
            "(reason_code IN ('SECRET_REVOKED','SECRET_COMPROMISED') "
            "AND credential_secret_id IS NOT NULL) "
            "OR (reason_code IN ('TARGET_EXCLUSIVITY_REVOKED',"
            "'TARGET_EXCLUSIVITY_EXPIRED') AND credential_secret_id IS NULL "
            "AND work_kind = 'EXECUTION')",
            name="ck_work_termination_requests_secret_reason",
        ),
        Index(
            "uq_work_termination_requests_active_target",
            "work_kind",
            "work_id",
            "reason_code",
            unique=True,
            sqlite_where=text(
                "status IN ('PENDING','ACKNOWLEDGED') AND credential_secret_id IS NULL"
            ),
            postgresql_where=text(
                "status IN ('PENDING','ACKNOWLEDGED') AND credential_secret_id IS NULL"
            ),
        ),
        Index(
            "uq_work_termination_requests_active_secret",
            "work_kind",
            "work_id",
            "reason_code",
            "credential_secret_id",
            unique=True,
            sqlite_where=text(
                "status IN ('PENDING','ACKNOWLEDGED') AND credential_secret_id IS NOT NULL"
            ),
            postgresql_where=text(
                "status IN ('PENDING','ACKNOWLEDGED') AND credential_secret_id IS NOT NULL"
            ),
        ),
        Index(
            "ix_work_termination_requests_pending",
            "status",
            "requested_at",
            "id",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    work_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    work_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    credential_secret_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("credential_secrets.id", ondelete="RESTRICT"),
    )
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ProjectQueueServiceCursor(Base):
    __tablename__ = "project_queue_service_cursors"
    __table_args__ = (
        CheckConstraint("last_service_sequence >= 0", name="ck_pqsc_last_service_sequence"),
        CheckConstraint("row_version >= 1", name="ck_pqsc_row_version"),
        Index("ix_pqsc_service_sequence", "last_service_sequence", "project_id"),
    )

    project_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    last_service_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_served_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    served_execution_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    served_recovery_probe_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class QueueSchedulerState(Base):
    __tablename__ = "queue_scheduler_state"
    __table_args__ = (
        CheckConstraint("singleton_id = 1", name="ck_queue_scheduler_state_singleton"),
        CheckConstraint("next_service_sequence >= 1", name="ck_queue_scheduler_state_sequence"),
    )

    singleton_id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    next_service_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
