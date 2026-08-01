from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from datax_studio.auth.db import Base


class KekKeyVersion(Base):
    """Non-secret registry metadata for an externally mounted KEK."""

    __tablename__ = "kek_key_versions"
    __table_args__ = (
        CheckConstraint(
            "purpose = 'CREDENTIAL_DEK_WRAP'",
            name="ck_kek_key_versions_purpose",
        ),
        CheckConstraint(
            "wrapping_algorithm = 'AES-256-KWP'",
            name="ck_kek_key_versions_algorithm",
        ),
        CheckConstraint(
            "status IN ('ACTIVE', 'DECRYPT_ONLY', 'RETIRED', 'DESTROYED')",
            name="ck_kek_key_versions_status",
        ),
        Index(
            "uq_kek_key_versions_one_active",
            "purpose",
            unique=True,
            sqlite_where=text("status = 'ACTIVE'"),
            postgresql_where=text("status = 'ACTIVE'"),
        ),
    )

    key_version: Mapped[str] = mapped_column(String(64), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    wrapping_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decrypt_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CredentialSecret(Base):
    """Stable AEAD ciphertext for one datasource credential version."""

    __tablename__ = "credential_secrets"
    __table_args__ = (
        UniqueConstraint(
            "datasource_id",
            "secret_version",
            name="uq_credential_secrets_datasource_version",
        ),
        CheckConstraint(
            "data_algorithm = 'AES-256-GCM'",
            name="ck_credential_secrets_algorithm",
        ),
        CheckConstraint(
            "aad_schema_version = '1.0'",
            name="ck_credential_secrets_aad_schema",
        ),
        CheckConstraint(
            "status IN ('ACTIVE', 'RETIRED', 'REVOKED', 'COMPROMISED')",
            name="ck_credential_secrets_status",
        ),
        Index(
            "ix_credential_secrets_datasource_status",
            "datasource_id",
            "status",
            "secret_version",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    datasource_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasources.id", ondelete="RESTRICT"),
        nullable=False,
    )
    secret_version: Mapped[int] = mapped_column(Integer, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    data_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    aad_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    status_reason_code: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    compromised_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CredentialSecretEnvelope(Base):
    """Versioned AES-KWP wrapping of a CredentialSecret DEK."""

    __tablename__ = "credential_secret_envelopes"
    __table_args__ = (
        UniqueConstraint(
            "credential_secret_id",
            "envelope_version",
            name="uq_credential_envelopes_secret_version",
        ),
        CheckConstraint(
            "wrapping_algorithm = 'AES-256-KWP'",
            name="ck_credential_envelopes_algorithm",
        ),
        CheckConstraint(
            "status IN ('ACTIVE', 'SUPERSEDED')",
            name="ck_credential_envelopes_status",
        ),
        Index(
            "uq_credential_envelopes_one_active",
            "credential_secret_id",
            unique=True,
            sqlite_where=text("status = 'ACTIVE'"),
            postgresql_where=text("status = 'ACTIVE'"),
        ),
        Index(
            "ix_credential_envelopes_kek_status",
            "kek_version",
            "status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    credential_secret_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("credential_secrets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    envelope_version: Mapped[int] = mapped_column(Integer, nullable=False)
    encrypted_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kek_version: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("kek_key_versions.key_version", ondelete="RESTRICT"),
        nullable=False,
    )
    wrapping_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    wrapped_dek_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EndpointConnectionEvidence(Base):
    """Immutable application/DNS/peer evidence for one outbound connection."""

    __tablename__ = "endpoint_connection_evidences"
    __table_args__ = (
        CheckConstraint(
            "operation_kind IN "
            "('TEST', 'METADATA', 'PREFLIGHT', 'DATAX', 'ORACLE', 'RECOVERY_PROBE')",
            name="ck_endpoint_connection_evidence_operation",
        ),
        CheckConstraint(
            "decision IN ('ALLOWED', 'DENIED')",
            name="ck_endpoint_connection_evidence_decision",
        ),
        CheckConstraint(
            "egress_enforcement_status IN ('VERIFIED', 'UNVERIFIED')",
            name="ck_endpoint_connection_evidence_egress_status",
        ),
        CheckConstraint(
            "("
            "peer_observation_status = 'OBSERVED' AND peer_ip IS NOT NULL"
            ") OR ("
            "operation_kind = 'DATAX' AND "
            "peer_observation_status = 'ENFORCED_NOT_OBSERVED' AND "
            "peer_ip IS NULL"
            ")",
            name="ck_endpoint_connection_evidence_peer_observation",
        ),
        CheckConstraint(
            "NOT (execution_id IS NOT NULL AND recovery_probe_id IS NOT NULL)",
            name="ck_endpoint_connection_evidence_work_owner",
        ),
        UniqueConstraint("evidence_hash", name="uq_endpoint_connection_evidence_hash"),
        Index(
            "ix_endpoint_connection_evidence_revision_observed",
            "datasource_revision_id",
            "observed_at",
            "id",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    operation_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    datasource_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("datasource_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    endpoint_policy_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("endpoint_policy_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    execution_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("executions.id", ondelete="RESTRICT"),
    )
    # RecoveryProbe lands in a later worker-owned migration. Keep this as a
    # logical UUID until that migration can add both the table and foreign key.
    recovery_probe_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    attempt_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    fence_epoch: Mapped[int | None] = mapped_column(BigInteger)
    resolver_policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    cname_chain: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    resolved_ips: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    selected_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dns_valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    egress_policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    egress_enforcement_status: Mapped[str] = mapped_column(String(16), nullable=False)
    egress_evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    peer_observation_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="OBSERVED",
    )
    peer_ip: Mapped[str | None] = mapped_column(String(45))
    tls_peer_spki_sha256: Mapped[str | None] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
