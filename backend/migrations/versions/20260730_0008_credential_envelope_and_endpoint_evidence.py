"""add credential envelope encryption and endpoint connection evidence

Revision ID: 20260730_0008
Revises: 20260730_0007
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260730_0008"
down_revision: str | Sequence[str] | None = "20260730_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid(name: str, *, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.Uuid(), nullable=nullable)


def _foreign_uuid(
    name: str,
    target: str,
    *,
    nullable: bool = False,
) -> sa.Column:
    return sa.Column(
        name,
        sa.Uuid(),
        sa.ForeignKey(target, ondelete="RESTRICT"),
        nullable=nullable,
    )


def upgrade() -> None:
    op.create_table(
        "kek_key_versions",
        sa.Column("key_version", sa.String(length=64), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("wrapping_algorithm", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decrypt_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("destroyed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key_version"),
        sa.CheckConstraint(
            "purpose = 'CREDENTIAL_DEK_WRAP'",
            name="ck_kek_key_versions_purpose",
        ),
        sa.CheckConstraint(
            "wrapping_algorithm = 'AES-256-KWP'",
            name="ck_kek_key_versions_algorithm",
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'DECRYPT_ONLY', 'RETIRED', 'DESTROYED')",
            name="ck_kek_key_versions_status",
        ),
        sa.CheckConstraint(
            "fingerprint_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_kek_key_versions_fingerprint",
        ),
    )
    op.create_index(
        "uq_kek_key_versions_one_active",
        "kek_key_versions",
        ["purpose"],
        unique=True,
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )

    op.create_table(
        "credential_secrets",
        _uuid("id"),
        _foreign_uuid("datasource_id", "datasources.id"),
        sa.Column("secret_version", sa.Integer(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column("data_algorithm", sa.String(length=32), nullable=False),
        sa.Column("aad_schema_version", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("status_reason_code", sa.String(length=64), nullable=True),
        _foreign_uuid("created_by", "users.id"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("compromised_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "datasource_id",
            "secret_version",
            name="uq_credential_secrets_datasource_version",
        ),
        sa.CheckConstraint(
            "data_algorithm = 'AES-256-GCM'",
            name="ck_credential_secrets_algorithm",
        ),
        sa.CheckConstraint(
            "aad_schema_version = '1.0'",
            name="ck_credential_secrets_aad_schema",
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'RETIRED', 'REVOKED', 'COMPROMISED')",
            name="ck_credential_secrets_status",
        ),
        sa.CheckConstraint(
            "octet_length(nonce) = 12",
            name="ck_credential_secrets_nonce_length",
        ),
        sa.CheckConstraint(
            "octet_length(ciphertext) >= 17",
            name="ck_credential_secrets_ciphertext_length",
        ),
    )
    op.create_index(
        "ix_credential_secrets_datasource_status",
        "credential_secrets",
        ["datasource_id", "status", "secret_version"],
    )

    op.create_table(
        "credential_secret_envelopes",
        _uuid("id"),
        _foreign_uuid("credential_secret_id", "credential_secrets.id"),
        sa.Column("envelope_version", sa.Integer(), nullable=False),
        sa.Column("encrypted_dek", sa.LargeBinary(), nullable=False),
        sa.Column(
            "kek_version",
            sa.String(length=64),
            sa.ForeignKey("kek_key_versions.key_version", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("wrapping_algorithm", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("wrapped_dek_sha256", sa.String(length=64), nullable=False),
        _foreign_uuid("created_by", "users.id"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "credential_secret_id",
            "envelope_version",
            name="uq_credential_envelopes_secret_version",
        ),
        sa.CheckConstraint(
            "wrapping_algorithm = 'AES-256-KWP'",
            name="ck_credential_envelopes_algorithm",
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'SUPERSEDED')",
            name="ck_credential_envelopes_status",
        ),
        sa.CheckConstraint(
            "octet_length(encrypted_dek) = 40",
            name="ck_credential_envelopes_dek_length",
        ),
        sa.CheckConstraint(
            "wrapped_dek_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_credential_envelopes_hash",
        ),
    )
    op.create_index(
        "uq_credential_envelopes_one_active",
        "credential_secret_envelopes",
        ["credential_secret_id"],
        unique=True,
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )
    op.create_index(
        "ix_credential_envelopes_kek_status",
        "credential_secret_envelopes",
        ["kek_version", "status"],
    )

    op.create_table(
        "endpoint_connection_evidences",
        _uuid("id"),
        sa.Column("operation_kind", sa.String(length=24), nullable=False),
        _foreign_uuid("datasource_revision_id", "datasource_revisions.id"),
        _foreign_uuid(
            "endpoint_policy_revision_id",
            "endpoint_policy_revisions.id",
        ),
        _foreign_uuid("execution_id", "executions.id", nullable=True),
        # RecoveryProbe is introduced by a later worker-owned migration. Keep
        # the identifier logical here so this revision can upgrade directly
        # from 0007 without referencing a table that does not yet exist.
        _uuid("recovery_probe_id", nullable=True),
        _uuid("attempt_id", nullable=True),
        sa.Column("fence_epoch", sa.BigInteger(), nullable=True),
        sa.Column("resolver_policy_version", sa.String(length=64), nullable=False),
        sa.Column("cname_chain", postgresql.JSONB(), nullable=False),
        sa.Column("resolved_ips", postgresql.JSONB(), nullable=False),
        sa.Column("selected_ip", postgresql.INET(), nullable=False),
        sa.Column("dns_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("egress_policy_version", sa.String(length=64), nullable=False),
        sa.Column("egress_enforcement_status", sa.String(length=16), nullable=False),
        sa.Column("egress_evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("peer_ip", postgresql.INET(), nullable=False),
        sa.Column("tls_peer_spki_sha256", sa.String(length=64), nullable=True),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "evidence_hash",
            name="uq_endpoint_connection_evidence_hash",
        ),
        sa.CheckConstraint(
            "operation_kind IN "
            "('TEST', 'METADATA', 'PREFLIGHT', 'DATAX', 'ORACLE', 'RECOVERY_PROBE')",
            name="ck_endpoint_connection_evidence_operation",
        ),
        sa.CheckConstraint(
            "decision IN ('ALLOWED', 'DENIED')",
            name="ck_endpoint_connection_evidence_decision",
        ),
        sa.CheckConstraint(
            "egress_enforcement_status IN ('VERIFIED', 'UNVERIFIED')",
            name="ck_endpoint_connection_evidence_egress_status",
        ),
        sa.CheckConstraint(
            "NOT (execution_id IS NOT NULL AND recovery_probe_id IS NOT NULL)",
            name="ck_endpoint_connection_evidence_work_owner",
        ),
        sa.CheckConstraint(
            "egress_evidence_hash ~ '^[a-f0-9]{64}$'",
            name="ck_endpoint_connection_evidence_egress_hash",
        ),
        sa.CheckConstraint(
            "evidence_hash ~ '^[a-f0-9]{64}$'",
            name="ck_endpoint_connection_evidence_hash",
        ),
    )
    op.create_index(
        "ix_endpoint_connection_evidence_revision_observed",
        "endpoint_connection_evidences",
        ["datasource_revision_id", "observed_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_endpoint_connection_evidence_revision_observed",
        table_name="endpoint_connection_evidences",
    )
    op.drop_table("endpoint_connection_evidences")
    op.drop_index(
        "ix_credential_envelopes_kek_status",
        table_name="credential_secret_envelopes",
    )
    op.drop_index(
        "uq_credential_envelopes_one_active",
        table_name="credential_secret_envelopes",
    )
    op.drop_table("credential_secret_envelopes")
    op.drop_index(
        "ix_credential_secrets_datasource_status",
        table_name="credential_secrets",
    )
    op.drop_table("credential_secrets")
    op.drop_index(
        "uq_kek_key_versions_one_active",
        table_name="kek_key_versions",
    )
    op.drop_table("kek_key_versions")
