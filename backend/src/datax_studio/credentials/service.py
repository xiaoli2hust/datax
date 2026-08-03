from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import rfc8785
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import ValidationError
from sqlalchemy import Engine, and_, create_engine, func, or_, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from datax_studio.api.problems import ProblemException
from datax_studio.audit_integrity import advance_audit_chain_watermark
from datax_studio.auth.db import (
    AuditEvent,
    AuthSession,
    IdempotencyRecord,
    MembershipStatus,
    Organization,
    OrganizationMember,
    Role,
    RoleAssignment,
    ScopeType,
    User,
)
from datax_studio.auth.security import ensure_aware, utc_now
from datax_studio.auth.service import (
    IDEMPOTENCY_HASH_SCHEME,
    AuditContext,
    OperationResult,
    Principal,
)
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    DatasourceUsageGrant,
    EndpointPolicy,
    EndpointPolicyRevision,
    Execution,
    JobVersion,
    PhysicalEndpointIdentity,
    Project,
    SyncJob,
    TargetNamespace,
    TransferPolicy,
    WorkTerminationRequest,
)
from datax_studio.core.schemas import (
    ClaimedExecution,
    CredentialBinding,
    EndpointPolicyResponse,
    EndpointPolicyRevisionResponse,
    JobSpecV1,
    ValidationReport,
)
from datax_studio.core.service import (
    ControlService,
    RuntimeValidationMaterial,
    ValidationMaterial,
)
from datax_studio.credentials.connectors import DatabaseConnector, ProbeResult
from datax_studio.credentials.crypto import (
    AAD_SCHEMA_VERSION,
    DATA_ALGORITHM,
    WRAPPING_ALGORITHM,
    build_credential_aad,
    decrypt_credential,
    encrypt_credential,
)
from datax_studio.credentials.db import (
    CredentialSecret,
    CredentialSecretEnvelope,
    EndpointConnectionEvidence,
    KekKeyVersion,
)
from datax_studio.credentials.ingress import (
    DatasourceOperationAdmissionGuard,
    DatasourceOperationAdmissionLease,
    DatasourceOperationAdmissionRejection,
    DatasourceOperationKind,
)
from datax_studio.credentials.keyring import KekKeyring, zeroize
from datax_studio.credentials.network import EndpointPolicyGuard, ResolvedEndpoint
from datax_studio.credentials.operation_boundary import (
    CurrentCredentialMaterial,
    DatasourceOperationSnapshot,
    FrozenActorAuthorization,
    FrozenCredentialBinding,
    FrozenDatasourceRevision,
    FrozenEndpointPolicy,
    OperationDeadline,
    OperationDeadlineExpired,
)
from datax_studio.credentials.schemas import (
    ColumnSchema,
    CredentialSecretEnvelopeSummary,
    CredentialSecretPage,
    CredentialSecretStatusChange,
    CredentialSecretSummary,
    DatasourceAdminDetail,
    DatasourceCreate,
    DatasourcePage,
    DatasourcePatch,
    DatasourceRedactedSummary,
    DatasourceRevisionAdminDetail,
    DatasourceTestResult,
    DatasourceUsageGrantPage,
    DatasourceUsageGrantReplace,
    DatasourceUsageGrantResponse,
    EndpointConnectionEvidenceResponse,
    EndpointPolicyPatch,
    TableSchema,
    TableSchemaPage,
)
from datax_studio.egress_attestation import (
    EgressAttestationError,
    LoopbackEgressAttestationClient,
)
from datax_studio.recovery.db import RecoveryGate, RecoveryProbe
from datax_studio.schema_snapshot import SchemaSnapshot, schema_snapshot_hash
from datax_studio.settings import Settings
from datax_studio.worker.schema_probe import SchemaProbeError, assert_snapshot_matches_job

_LOGGER = logging.getLogger(__name__)
_IDEMPOTENCY_HASH_DOMAIN = b"DataXEnterpriseStudio\x00IdempotencyRequestHash\x00v1\x00"
_PASSWORD_REQUEST_FINGERPRINT_DOMAIN = (
    b"DataXEnterpriseStudio\x00DatasourcePasswordRequestFingerprint\x00v1"
)
_PASSWORD_REQUEST_FINGERPRINT_KDF_INFO = (
    b"DataXEnterpriseStudio\x00DatasourcePasswordRequestFingerprintKey\x00v1"
)
_AUDIT_USER_AGENT_HASH_DOMAIN = b"DataXEnterpriseStudio\x00AuditUserAgentHash\x00v1\x00"
_CURSOR_DOMAIN = b"DataXEnterpriseStudio\x00CredentialCursor\x00v1\x00"
_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
_TERMINAL_EXECUTION_STATES = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED", "LOST"}
_ACTIVE_RECOVERY_PROBE_STATES = {"QUEUED", "STARTING", "RUNNING"}
_ACTIVE_RECOVERY_GATE_STATES = {"OPEN", "REMEDIATION_SUBMITTED"}
_ACTIVE_TRANSFER_POLICY_STATES = {"DRAFT", "PENDING_APPROVAL", "ACTIVE"}
_ENDPOINT_POLICY_CONFIG_FIELDS = frozenset(
    {
        "host_kind",
        "host_value",
        "allowed_cidrs",
        "allowed_ports",
        "tls_required",
        "dns_ttl_ceiling_seconds",
    }
)
_DATASOURCE_REVISION_FIELDS = frozenset(
    {
        "endpoint_policy_id",
        "engine",
        "host",
        "port",
        "database_name",
        "default_schema",
        "username",
        "ssl_mode",
    }
)
_NON_RETRYABLE_METADATA_VALUE_ERRORS = frozenset(
    {
        "DNS_ADDRESS_OUTSIDE_POLICY",
        "DNS_CNAME_CHAIN_TOO_DEEP",
        "DNS_CNAME_LOOP",
        "DNS_REBINDING_DETECTED",
        "EGRESS_POLICY_VERSION_MISMATCH",
        "ENDPOINT_FQDN_REQUIRED",
        "ENDPOINT_HOST_DENIED",
        "ENDPOINT_HOST_KIND_INVALID",
        "ENDPOINT_IP_INVALID",
        "ENDPOINT_PEER_MISMATCH",
        "ENDPOINT_PORT_DENIED",
        "RESOLVER_POLICY_VERSION_MISMATCH",
        "SSL_MODE_INVALID",
        "UNSUPPORTED_ENGINE",
    }
)
_RETRYABLE_EGRESS_UNAVAILABLE_CODES = frozenset(
    {
        "EGRESS_ATTESTATION_UNAVAILABLE",
        "EGRESS_ATTESTATION_UNVERIFIED",
        "EGRESS_ATTESTATION_STALE",
        "EGRESS_LEASE_UNAVAILABLE",
        "EGRESS_NETWORK_NAMESPACE_UNAVAILABLE",
        "EGRESS_OPERATION_DEADLINE_EXCEEDED",
    }
)
_NON_RETRYABLE_MYSQL_ERROR_NUMBERS = frozenset(
    {
        1044,  # access denied to database
        1045,  # authentication failed
        1046,  # no database selected
        1049,  # unknown database
        1142,  # command denied
        1143,  # column command denied
        1227,  # privilege denied
    }
)


def _metadata_failure_retryable(exc: Exception) -> bool:
    """Classify metadata collection failures without leaking driver details."""

    if isinstance(exc, SchemaProbeError):
        return False
    if isinstance(exc, ValueError) and str(exc) in _NON_RETRYABLE_METADATA_VALUE_ERRORS:
        return False
    sqlstate = getattr(exc, "sqlstate", None)
    if isinstance(sqlstate, str) and (
        sqlstate == "3D000" or sqlstate.startswith("28") or sqlstate.startswith("42")
    ):
        return False
    return not (
        exc.args
        and isinstance(exc.args[0], int)
        and exc.args[0] in _NON_RETRYABLE_MYSQL_ERROR_NUMBERS
    )


@dataclass(frozen=True)
class DatasourceConnectionCandidate:
    engine: str
    host: str
    port: int
    database_name: str
    default_schema: str
    username: str
    ssl_mode: str


@dataclass(frozen=True)
class CreateDatasourceOperation:
    """Non-secret phase-A create hand-off used while B is outside the DB."""

    snapshot: DatasourceOperationSnapshot
    candidate: DatasourceConnectionCandidate
    request_body: dict[str, Any]


@dataclass(frozen=True)
class UpdateDatasourceOperation:
    """Detached phase-A update intent for a probe-required datasource patch.

    ``snapshot`` freezes the datasource's *current* binding, while
    ``candidate_policy`` freezes the possibly different policy selected for the
    proposed revision.  Keeping them separate is important: changing an
    endpoint policy is itself the intent under test, so it cannot be forced
    into ``DatasourceOperationSnapshot`` whose policy is structurally tied to
    the currently persisted revision.
    """

    snapshot: DatasourceOperationSnapshot
    candidate: DatasourceConnectionCandidate
    candidate_policy: FrozenEndpointPolicy
    connection_fields: frozenset[str]
    password_provided: bool


@dataclass(frozen=True)
class FrozenTransferPolicy:
    """The exact active transfer authorization observed in phase A."""

    id: UUID
    project_id: UUID
    source_datasource_revision_id: UUID
    target_datasource_revision_id: UUID
    source_physical_endpoint_identity_id: UUID
    target_physical_endpoint_identity_id: UUID
    status: str
    row_version: int
    scope_hash: str


@dataclass(frozen=True)
class FrozenTargetNamespace:
    """The registered target physical-table identity observed in phase A."""

    id: UUID
    physical_endpoint_identity_id: UUID
    engine: str
    normalized_catalog_name: str
    normalized_schema_name: str
    normalized_table_name: str
    normalization_version: str
    physical_table_identity_hash: str


@dataclass(frozen=True)
class JobValidationOperation:
    """Detached A-time binding for one dual-datasource validation operation."""

    operation_id: UUID
    job_id: UUID
    project_id: UUID
    project_status: str
    project_row_version: int
    job_status: str
    job_row_version: int
    job_draft_spec_hash: str
    source: DatasourceOperationSnapshot
    target: DatasourceOperationSnapshot
    transfer_policy: FrozenTransferPolicy
    target_namespace: FrozenTargetNamespace
    source_plugin_name: str
    target_plugin_name: str
    runtime: RuntimeValidationMaterial
    source_schema_name: str
    source_table_name: str
    target_schema_name: str
    target_table_name: str


@dataclass(frozen=True)
class ValidationSchemaProbe:
    """Non-ORM B-time schema result awaiting C-time persistence."""

    snapshot: SchemaSnapshot
    resolved: ResolvedEndpoint
    peer_ip: str


def build_credential_service(
    settings: Settings,
    *,
    engine: Engine | None = None,
    register_active_kek: bool = True,
) -> CredentialService:
    """Build credential services on an optional caller-owned database pool.

    API/bootstrap callers retain the default registration path.  The Worker
    must pass ``register_active_kek=False`` so its database role only needs to
    read an already registered active KEK and fails closed when that invariant
    is absent.
    """

    if engine is None:
        engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    integrity_key = settings.idempotency_hmac_key_file.read_bytes()
    if len(integrity_key) != 32:
        raise ValueError("idempotency HMAC key must contain exactly 32 bytes")
    egress_client = LoopbackEgressAttestationClient(
        url=settings.egress_attestation_url,
        timeout_seconds=settings.egress_attestation_timeout_seconds,
        max_age_seconds=settings.egress_attestation_max_age_seconds,
        policy_engine_version=settings.egress_policy_version,
        resolver_policy_version=settings.resolver_policy_version,
        lease_creation_capability_file=settings.egress_lease_creation_capability_file,
    )
    guard = EndpointPolicyGuard(
        resolver_policy_version=settings.resolver_policy_version,
        egress_policy_version=settings.egress_policy_version,
        egress_verifier=egress_client,
        egress_lease_client=egress_client,
        connect_timeout_seconds=settings.datasource_connect_timeout_seconds,
    )
    service = CredentialService(
        sessions=sessions,
        keyring=KekKeyring(settings.kek_keyring_dir),
        active_kek_version=settings.kek_active_version,
        integrity_hmac_key=integrity_key,
        guard=guard,
        connector=DatabaseConnector(
            guard=guard,
            connect_timeout_seconds=settings.datasource_connect_timeout_seconds,
            query_timeout_seconds=settings.datasource_query_timeout_seconds,
        ),
        # Worker-focused callers historically pass a narrow, read-only
        # settings-shaped object.  The production Settings model always has
        # this field; retain the explicit secure default for those test/helper
        # construction paths rather than making the Worker own an API setting.
        operation_deadline_seconds=float(
            getattr(settings, "datasource_operation_deadline_seconds", 30.0)
        ),
    )
    if register_active_kek:
        service.ensure_active_kek_registered()
    else:
        service.require_active_kek_registered()
    return service


class CredentialService:
    def __init__(
        self,
        *,
        sessions: sessionmaker[Session],
        keyring: KekKeyring,
        active_kek_version: str,
        integrity_hmac_key: bytes,
        guard: EndpointPolicyGuard,
        connector: DatabaseConnector,
        operation_deadline_seconds: float = 30.0,
    ) -> None:
        if len(integrity_hmac_key) != 32:
            raise ValueError("integrity HMAC key must contain exactly 32 bytes")
        if operation_deadline_seconds <= 0:
            raise ValueError("operation deadline must be positive")
        self.sessions = sessions
        self.keyring = keyring
        self.active_kek_version = active_kek_version
        self.integrity_hmac_key = integrity_hmac_key
        fingerprint_key = HKDF(
            algorithm=hashes.SHA512(),
            length=64,
            salt=None,
            info=_PASSWORD_REQUEST_FINGERPRINT_KDF_INFO,
        ).derive(integrity_hmac_key)
        self._password_request_fingerprint_cipher = AESSIV(fingerprint_key)
        self.guard = guard
        self.connector = connector
        self.operation_deadline_seconds = operation_deadline_seconds

    def new_operation_deadline(self) -> OperationDeadline:
        """Create one shared budget for a composite metadata caller.

        Direct API operations create their own budget inside the corresponding
        method.  A caller that coordinates more than one metadata read (the
        transfer-policy scope flow) must instead create one deadline here and
        pass it to every nested read so a second endpoint cannot reset the
        first endpoint's remaining budget.
        """

        return OperationDeadline(self.operation_deadline_seconds)

    def ensure_active_kek_registered(self) -> None:
        try:
            fingerprint = self.keyring.fingerprint(self.active_kek_version)
        except (OSError, ValueError) as exc:
            raise self._keyring_unavailable() from exc
        now = utc_now()
        try:
            with self.sessions.begin() as session:
                active = session.scalar(
                    select(KekKeyVersion).where(KekKeyVersion.status == "ACTIVE").with_for_update()
                )
                registered = session.get(KekKeyVersion, self.active_kek_version)
                if registered is None:
                    if active is not None:
                        raise self._keyring_unavailable()
                    session.add(
                        KekKeyVersion(
                            key_version=self.active_kek_version,
                            purpose="CREDENTIAL_DEK_WRAP",
                            wrapping_algorithm=WRAPPING_ALGORITHM,
                            status="ACTIVE",
                            fingerprint_sha256=fingerprint,
                            activated_at=now,
                            created_at=now,
                        )
                )
                    return
                if (
                    active is None
                    or active.key_version != registered.key_version
                    or registered.status != "ACTIVE"
                    or registered.purpose != "CREDENTIAL_DEK_WRAP"
                    or registered.wrapping_algorithm != WRAPPING_ALGORITHM
                    or not hmac.compare_digest(registered.fingerprint_sha256, fingerprint)
                ):
                    raise self._keyring_unavailable()
        except IntegrityError as exc:
            raise self._keyring_unavailable() from exc

    def require_active_kek_registered(self) -> None:
        """Read-only startup check for a configured, registered active KEK.

        This deliberately does not use ``FOR UPDATE`` or create a registration:
        the Worker must be unable to turn a missing key registry row into a
        writable credential-table requirement.  Credential binding still
        revalidates the relevant KEK at each work claim.
        """

        try:
            fingerprint = self.keyring.fingerprint(self.active_kek_version)
        except (OSError, ValueError) as exc:
            raise self._keyring_unavailable() from exc
        with self.sessions() as session:
            active = session.scalar(select(KekKeyVersion).where(KekKeyVersion.status == "ACTIVE"))
            registered = session.get(KekKeyVersion, self.active_kek_version)
            if (
                active is None
                or registered is None
                or active.key_version != registered.key_version
                or registered.status != "ACTIVE"
                or registered.purpose != "CREDENTIAL_DEK_WRAP"
                or registered.wrapping_algorithm != WRAPPING_ALGORITHM
                or not hmac.compare_digest(registered.fingerprint_sha256, fingerprint)
            ):
                raise self._keyring_unavailable()

    def validate_registered_keyring(self, session: Session) -> None:
        registrations = list(
            session.scalars(
                select(KekKeyVersion)
                .where(KekKeyVersion.status.in_(("ACTIVE", "DECRYPT_ONLY")))
                .order_by(KekKeyVersion.key_version)
            )
        )
        if not registrations or sum(item.status == "ACTIVE" for item in registrations) != 1:
            raise self._keyring_unavailable()
        for registration in registrations:
            try:
                fingerprint = self.keyring.fingerprint(registration.key_version)
            except (OSError, ValueError) as exc:
                raise self._keyring_unavailable() from exc
            if (
                registration.purpose != "CREDENTIAL_DEK_WRAP"
                or registration.wrapping_algorithm != WRAPPING_ALGORITHM
                or not hmac.compare_digest(
                    registration.fingerprint_sha256,
                    fingerprint,
                )
            ):
                raise self._keyring_unavailable()

    def select_active_binding(
        self,
        session: Session,
        *,
        source_datasource_id: UUID,
        target_datasource_id: UUID,
    ) -> CredentialBinding:
        datasource_ids = sorted(
            {source_datasource_id, target_datasource_id},
            key=str,
        )
        datasources = {
            datasource.id: datasource
            for datasource in session.scalars(
                select(Datasource)
                .where(Datasource.id.in_(datasource_ids))
                .order_by(Datasource.id)
                .with_for_update()
            )
        }
        if set(datasources) != set(datasource_ids):
            raise self._binding_unavailable()
        source = datasources[source_datasource_id]
        target = datasources[target_datasource_id]
        if (
            source.status != "ACTIVE"
            or target.status != "ACTIVE"
            or source.current_secret_id is None
            or target.current_secret_id is None
        ):
            raise self._binding_unavailable()

        secret_ids = sorted(
            {source.current_secret_id, target.current_secret_id},
            key=str,
        )
        secrets_by_id = {
            secret.id: secret
            for secret in session.scalars(
                select(CredentialSecret)
                .where(CredentialSecret.id.in_(secret_ids))
                .order_by(CredentialSecret.id)
                .with_for_update()
            )
        }
        if set(secrets_by_id) != set(secret_ids):
            raise self._binding_unavailable()
        source_secret = secrets_by_id[source.current_secret_id]
        target_secret = secrets_by_id[target.current_secret_id]
        if (
            source_secret.datasource_id != source.id
            or target_secret.datasource_id != target.id
            or source_secret.status != "ACTIVE"
            or target_secret.status != "ACTIVE"
        ):
            raise self._binding_unavailable()

        envelopes = list(
            session.scalars(
                select(CredentialSecretEnvelope)
                .where(
                    CredentialSecretEnvelope.credential_secret_id.in_(secret_ids),
                    CredentialSecretEnvelope.status == "ACTIVE",
                )
                .order_by(CredentialSecretEnvelope.credential_secret_id)
                .with_for_update()
            )
        )
        if len(envelopes) != len(secret_ids):
            raise self._binding_unavailable()
        envelopes_by_secret = {envelope.credential_secret_id: envelope for envelope in envelopes}
        if set(envelopes_by_secret) != set(secret_ids):
            raise self._binding_unavailable()

        key_versions = sorted(
            {envelope.kek_version for envelope in envelopes},
        )
        keys = {
            key.key_version: key
            for key in session.scalars(
                select(KekKeyVersion)
                .where(KekKeyVersion.key_version.in_(key_versions))
                .order_by(KekKeyVersion.key_version)
                .with_for_update()
            )
        }
        if set(keys) != set(key_versions):
            raise self._keyring_unavailable()
        for key in keys.values():
            if key.status not in {"ACTIVE", "DECRYPT_ONLY"}:
                raise self._keyring_unavailable()
            try:
                fingerprint = self.keyring.fingerprint(key.key_version)
            except (OSError, ValueError) as exc:
                raise self._keyring_unavailable() from exc
            if not hmac.compare_digest(key.fingerprint_sha256, fingerprint):
                raise self._keyring_unavailable()

        source_envelope = envelopes_by_secret[source_secret.id]
        target_envelope = envelopes_by_secret[target_secret.id]
        return CredentialBinding(
            source_secret_id=source_secret.id,
            target_secret_id=target_secret.id,
            source_secret_envelope_id=source_envelope.id,
            target_secret_envelope_id=target_envelope.id,
            source_secret_version=source_secret.secret_version,
            target_secret_version=target_secret.secret_version,
        )

    def validate_preflight_evidence(
        self,
        session: Session,
        *,
        claim: ClaimedExecution,
        source_evidence_id: UUID,
        target_evidence_id: UUID,
        source_revision_id: UUID,
        target_revision_id: UUID,
        source_policy_revision_id: UUID,
        target_policy_revision_id: UUID,
    ) -> None:
        """Fail closed unless both evidence rows belong to this fenced attempt."""

        if source_evidence_id == target_evidence_id:
            raise self._preflight_evidence_invalid()
        evidence_ids = sorted(
            (source_evidence_id, target_evidence_id),
            key=str,
        )
        evidence_by_id = {
            item.id: item
            for item in session.scalars(
                select(EndpointConnectionEvidence)
                .where(EndpointConnectionEvidence.id.in_(evidence_ids))
                .order_by(EndpointConnectionEvidence.id)
                .with_for_update()
            )
        }
        if set(evidence_by_id) != set(evidence_ids):
            raise self._preflight_evidence_invalid()
        expected = (
            (
                evidence_by_id[source_evidence_id],
                source_revision_id,
                source_policy_revision_id,
            ),
            (
                evidence_by_id[target_evidence_id],
                target_revision_id,
                target_policy_revision_id,
            ),
        )
        for evidence, revision_id, policy_revision_id in expected:
            if (
                evidence.operation_kind != "PREFLIGHT"
                or evidence.decision != "ALLOWED"
                or evidence.egress_enforcement_status != "VERIFIED"
                or evidence.execution_id != claim.execution_id
                or evidence.attempt_id != claim.attempt_id
                or evidence.fence_epoch != claim.fence_epoch
                or evidence.datasource_revision_id != revision_id
                or evidence.endpoint_policy_revision_id != policy_revision_id
                or ensure_aware(evidence.dns_valid_until) < ensure_aware(evidence.observed_at)
            ):
                raise self._preflight_evidence_invalid()

    @contextmanager
    def decrypted_worker_password(
        self,
        *,
        datasource_id: UUID,
        secret_id: UUID,
        envelope_id: UUID,
    ) -> Iterator[bytearray]:
        """Decrypt one bound secret under a fresh, short status lock.

        The transaction ends before plaintext is yielded.  Emergency status
        changes therefore serialize with the decision to begin decryption,
        without holding a database row lock for the lifetime of DataX or an
        oracle read.
        """

        plaintext = bytearray()
        try:
            with self.sessions.begin() as session:
                plaintext = self._decrypt_password_value(
                    session,
                    datasource_id=datasource_id,
                    secret_id=secret_id,
                    envelope_id=envelope_id,
                    lock_secret=True,
                )
            yield plaintext
        finally:
            zeroize(plaintext)

    def _decrypt_password_value(
        self,
        session: Session,
        *,
        datasource_id: UUID,
        secret_id: UUID,
        envelope_id: UUID,
        lock_secret: bool,
    ) -> bytearray:
        datasource = session.get(Datasource, datasource_id)
        secret = (
            session.scalar(
                select(CredentialSecret)
                .where(CredentialSecret.id == secret_id)
                .execution_options(populate_existing=True)
                .with_for_update()
            )
            if lock_secret
            else session.get(CredentialSecret, secret_id)
        )
        envelope = session.get(CredentialSecretEnvelope, envelope_id)
        if (
            datasource is None
            or secret is None
            or envelope is None
            or secret.datasource_id != datasource.id
            or envelope.credential_secret_id != secret.id
            or envelope.status not in {"ACTIVE", "SUPERSEDED"}
            or secret.status in {"REVOKED", "COMPROMISED"}
            or secret.status not in {"ACTIVE", "RETIRED"}
        ):
            raise self._binding_unavailable()
        key = session.get(KekKeyVersion, envelope.kek_version)
        if key is None or key.status not in {"ACTIVE", "DECRYPT_ONLY"}:
            raise self._keyring_unavailable()
        try:
            actual_fingerprint = self.keyring.fingerprint(key.key_version)
        except (OSError, ValueError) as exc:
            raise self._keyring_unavailable() from exc
        if not hmac.compare_digest(key.fingerprint_sha256, actual_fingerprint):
            raise self._keyring_unavailable()

        project = session.get(Project, datasource.project_id)
        if project is None:
            raise self._binding_unavailable()
        aad = build_credential_aad(
            organization_id=project.organization_id,
            project_id=project.id,
            datasource_id=datasource.id,
            credential_secret_id=secret.id,
            secret_version=secret.secret_version,
        )
        with self.keyring.open_key(key.key_version) as kek:
            return decrypt_credential(
                ciphertext=secret.ciphertext,
                nonce=secret.nonce,
                encrypted_dek=envelope.encrypted_dek,
                aad=aad,
                kek=kek,
            )

    # API-facing methods are below. Responses use dedicated schemas that never
    # include secret IDs, ciphertext, nonce, encrypted DEKs, or key bytes.

    def update_endpoint_policy(
        self,
        *,
        principal: Principal,
        endpoint_policy_id: UUID,
        request: EndpointPolicyPatch,
        expected_version: int,
        audit: AuditContext,
    ) -> EndpointPolicyResponse:
        self._require_admin(principal)
        now = utc_now()
        try:
            with self.sessions.begin() as session:
                organization = self._lock_organization(
                    session,
                    principal.organization_id,
                )
                policy = session.scalar(
                    select(EndpointPolicy)
                    .where(
                        EndpointPolicy.id == endpoint_policy_id,
                        EndpointPolicy.organization_id == principal.organization_id,
                    )
                    .with_for_update()
                )
                if policy is None:
                    self._not_found()
                if policy.row_version != expected_version:
                    raise ProblemException(
                        status=409,
                        code="VERSION_CONFLICT",
                        title="端点策略已被修改",
                        detail="请刷新后重试。",
                    )
                current_revision = session.scalar(
                    select(EndpointPolicyRevision).where(
                        EndpointPolicyRevision.id == policy.current_revision_id,
                        EndpointPolicyRevision.endpoint_policy_id == policy.id,
                    )
                )
                if current_revision is None:
                    raise ProblemException(
                        status=409,
                        code="ENDPOINT_POLICY_REVISION_MISSING",
                        title="端点策略当前修订不可用",
                        detail="当前指针与不可变修订不一致，已拒绝更新。",
                    )

                changed_fields: list[str] = []
                if "name" in request.model_fields_set:
                    assert request.name is not None
                    normalized_name = request.name.strip()
                    conflict = session.scalar(
                        select(EndpointPolicy.id).where(
                            EndpointPolicy.organization_id == principal.organization_id,
                            EndpointPolicy.id != policy.id,
                            func.lower(EndpointPolicy.name) == normalized_name.casefold(),
                        )
                    )
                    if conflict is not None:
                        raise ProblemException(
                            status=409,
                            code="ENDPOINT_POLICY_NAME_CONFLICT",
                            title="端点策略名称已存在",
                            detail="请使用新的端点策略名称。",
                        )
                    if policy.name != normalized_name:
                        policy.name = normalized_name
                        changed_fields.append("name")

                revision = current_revision
                config_fields = request.model_fields_set & _ENDPOINT_POLICY_CONFIG_FIELDS
                if config_fields:
                    normalized = self._normalize_endpoint_policy_patch(
                        current_revision,
                        request,
                    )
                    if normalized["policy_hash"] != current_revision.policy_hash:
                        revision = EndpointPolicyRevision(
                            id=uuid4(),
                            endpoint_policy_id=policy.id,
                            revision_no=current_revision.revision_no + 1,
                            created_by=principal.user_id,
                            created_at=now,
                            **normalized,
                        )
                        session.add(revision)
                        session.flush()
                        policy.current_revision_id = revision.id
                        changed_fields.extend(
                            [
                                *sorted(config_fields),
                                "current_revision_id",
                                "policy_hash",
                            ]
                        )

                if (
                    "status" in request.model_fields_set
                    and request.status is not None
                    and policy.status != request.status
                ):
                    policy.status = request.status
                    changed_fields.append("status")

                if not changed_fields:
                    return self._endpoint_policy_response(policy, revision)
                policy.updated_at = now
                policy.row_version += 1
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=None,
                    action=(
                        "ENDPOINT_POLICY_REVISION_CREATED"
                        if revision.id != current_revision.id
                        else (
                            "ENDPOINT_POLICY_DISABLED"
                            if policy.status == "DISABLED" and changed_fields == ["status"]
                            else "ENDPOINT_POLICY_UPDATED"
                        )
                    ),
                    actor_id=principal.user_id,
                    target_type="ENDPOINT_POLICY",
                    target_id=policy.id,
                    target_name=policy.name,
                    changed_fields=[*changed_fields, "row_version"],
                    audit=audit,
                    metadata={
                        "revision_id": str(revision.id),
                        "revision_no": revision.revision_no,
                        "policy_hash": revision.policy_hash,
                        "status": policy.status,
                    },
                )
                return self._endpoint_policy_response(policy, revision)
        except IntegrityError as exc:
            raise ProblemException(
                status=409,
                code="ENDPOINT_POLICY_CONFLICT",
                title="端点策略更新冲突",
                detail="请刷新后重试。",
            ) from exc

    def get_endpoint_policy_revision(
        self,
        *,
        principal: Principal,
        endpoint_policy_id: UUID,
        revision_id: UUID,
    ) -> EndpointPolicyRevisionResponse:
        self._require_admin(principal)
        with self.sessions() as session:
            policy = session.scalar(
                select(EndpointPolicy).where(
                    EndpointPolicy.id == endpoint_policy_id,
                    EndpointPolicy.organization_id == principal.organization_id,
                )
            )
            if policy is None:
                self._not_found()
            revision = session.scalar(
                select(EndpointPolicyRevision).where(
                    EndpointPolicyRevision.id == revision_id,
                    EndpointPolicyRevision.endpoint_policy_id == policy.id,
                )
            )
            if revision is None:
                self._not_found()
            return self._endpoint_policy_revision_response(revision)

    def get_endpoint_connection_evidence(
        self,
        *,
        principal: Principal,
        connection_evidence_id: UUID,
    ) -> EndpointConnectionEvidenceResponse:
        self._require_admin(principal)
        with self.sessions() as session:
            # A public evidence row may be unbound (TEST/METADATA) or belong
            # to standard work.  The ordinary Admin reader has no protected
            # Phase-A authorization, so a private execution/probe owner must
            # fail closed even when the caller knows the evidence UUID.
            standard_execution_owner = (
                select(Execution.id)
                .where(
                    Execution.id == EndpointConnectionEvidence.execution_id,
                    Execution.project_id == Datasource.project_id,
                    Execution.authorization_mode == "STANDARD",
                )
                .exists()
            )
            standard_probe_owner = (
                select(RecoveryProbe.id)
                .join(RecoveryGate, RecoveryGate.id == RecoveryProbe.recovery_gate_id)
                .join(Execution, Execution.id == RecoveryGate.execution_id)
                .where(
                    RecoveryProbe.id == EndpointConnectionEvidence.recovery_probe_id,
                    RecoveryProbe.project_id == Datasource.project_id,
                    Execution.authorization_mode == "STANDARD",
                )
                .exists()
            )
            evidence = session.scalar(
                select(EndpointConnectionEvidence)
                .join(
                    DatasourceRevision,
                    DatasourceRevision.id == EndpointConnectionEvidence.datasource_revision_id,
                )
                .join(
                    Datasource,
                    Datasource.id == DatasourceRevision.datasource_id,
                )
                .join(Project, Project.id == Datasource.project_id)
                .where(
                    EndpointConnectionEvidence.id == connection_evidence_id,
                    Project.organization_id == principal.organization_id,
                    or_(
                        and_(
                            EndpointConnectionEvidence.execution_id.is_(None),
                            EndpointConnectionEvidence.recovery_probe_id.is_(None),
                        ),
                        standard_execution_owner,
                        standard_probe_owner,
                    ),
                )
            )
            if evidence is None:
                self._not_found()
            return EndpointConnectionEvidenceResponse(
                id=evidence.id,
                operation_kind=evidence.operation_kind,
                datasource_revision_id=evidence.datasource_revision_id,
                endpoint_policy_revision_id=(evidence.endpoint_policy_revision_id),
                resolver_policy_version=evidence.resolver_policy_version,
                resolved_ips=[str(value) for value in evidence.resolved_ips],
                selected_ip=str(evidence.selected_ip),
                peer_observation_status=evidence.peer_observation_status,
                peer_ip=(str(evidence.peer_ip) if evidence.peer_ip is not None else None),
                egress_policy_version=evidence.egress_policy_version,
                egress_evidence_hash=evidence.egress_evidence_hash,
                decision=evidence.decision,
                evidence_hash=evidence.evidence_hash,
                observed_at=ensure_aware(evidence.observed_at),
            )

    def _create_candidate(
        self,
        request: DatasourceCreate,
    ) -> DatasourceConnectionCandidate:
        return DatasourceConnectionCandidate(
            engine=request.engine.value,
            host=request.host.rstrip(".").casefold(),
            port=request.port,
            database_name=request.database_name,
            default_schema=request.default_schema,
            username=request.username,
            ssl_mode=request.ssl_mode.value,
        )

    def _capture_create_datasource_operation(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        request: DatasourceCreate,
        request_body: dict[str, Any],
    ) -> CreateDatasourceOperation:
        candidate = self._create_candidate(request)
        self._validate_connection_input(candidate)
        with self.sessions.begin() as session:
            organization = self._lock_organization(session, principal.organization_id)
            project = self._visible_project(
                session,
                principal,
                project_id,
                lock=True,
            )
            if project.status != "ACTIVE":
                raise ProblemException(
                    status=409,
                    code="PROJECT_ARCHIVED",
                    title="项目已归档",
                    detail="归档项目不能新增数据源。",
                )
            policy = session.scalar(
                select(EndpointPolicy)
                .where(
                    EndpointPolicy.id == request.endpoint_policy_id,
                    EndpointPolicy.organization_id == principal.organization_id,
                )
                .with_for_update()
            )
            if policy is None or policy.status != "ACTIVE" or policy.current_revision_id is None:
                raise ProblemException(
                    status=422,
                    code="ENDPOINT_POLICY_NOT_ACTIVE",
                    title="端点策略不可用",
                    detail="必须选择当前有效的端点策略。",
                )
            policy_revision = session.get(
                EndpointPolicyRevision,
                policy.current_revision_id,
            )
            if policy_revision is None or policy_revision.engine != candidate.engine:
                raise ProblemException(
                    status=422,
                    code="ENDPOINT_POLICY_DENIED",
                    title="端点策略不匹配",
                    detail="数据源引擎或连接端点不在允许范围。",
                )
            if policy_revision.tls_required and candidate.ssl_mode == "DISABLE":
                raise ProblemException(
                    status=422,
                    code="ENDPOINT_POLICY_DENIED",
                    title="端点策略要求 TLS",
                    detail="该端点策略不允许关闭数据库 TLS。",
                )
            actor_authorization = self._read_live_operation_authorization(
                session,
                principal=principal,
                project=project,
                datasource=None,
                usage=None,
            )
            candidate_hash = self._domain_hash(
                "DXDATASOURCECREATEv1",
                {
                    "project_id": str(project.id),
                    "endpoint_policy_revision_id": str(policy_revision.id),
                    "candidate": {
                        "engine": candidate.engine,
                        "host": candidate.host,
                        "port": candidate.port,
                        "database_name": candidate.database_name,
                        "default_schema": candidate.default_schema,
                        "username": candidate.username,
                        "ssl_mode": candidate.ssl_mode,
                    },
                    "request": request_body,
                },
            )
            snapshot = DatasourceOperationSnapshot(
                operation_kind=DatasourceOperationKind.CREATE,
                operation_id=uuid4(),
                organization_id=organization.id,
                organization_status=organization.status,
                organization_row_version=organization.row_version,
                project_id=project.id,
                project_status=project.status,
                project_row_version=project.row_version,
                datasource_id=None,
                datasource_status=None,
                datasource_row_version=None,
                datasource_current_revision_id=None,
                datasource_current_secret_id=None,
                datasource_revision=None,
                endpoint_policy=self._freeze_endpoint_policy(
                    policy=policy,
                    revision=policy_revision,
                ),
                credential_binding=None,
                actor_authorization=actor_authorization,
                candidate_config_hash=candidate_hash,
            )
            return CreateDatasourceOperation(
                snapshot=snapshot,
                candidate=candidate,
                request_body=dict(request_body),
            )

    def _revalidate_create_datasource_operation(
        self,
        session: Session,
        *,
        principal: Principal,
        request: DatasourceCreate,
        operation: CreateDatasourceOperation,
    ) -> tuple[Organization, Project, EndpointPolicyRevision]:
        snapshot = operation.snapshot
        try:
            organization = self._lock_organization(session, snapshot.organization_id)
            project = self._visible_project(
                session,
                principal,
                snapshot.project_id,
                lock=True,
            )
            if project.status != "ACTIVE" or snapshot.endpoint_policy is None:
                raise self._operation_stale()
            policy = session.scalar(
                select(EndpointPolicy)
                .where(
                    EndpointPolicy.id == snapshot.endpoint_policy.endpoint_policy_id,
                    EndpointPolicy.organization_id == organization.id,
                )
                .with_for_update()
            )
            if policy is None or policy.current_revision_id is None:
                raise self._operation_stale()
            policy_revision = session.get(
                EndpointPolicyRevision,
                policy.current_revision_id,
            )
            if policy_revision is None:
                raise self._operation_stale()
            actor_authorization = self._read_live_operation_authorization(
                session,
                principal=principal,
                project=project,
                datasource=None,
                usage=None,
            )
        except ProblemException as exc:
            if exc.code == "DATASOURCE_OPERATION_STALE":
                raise
            raise self._operation_stale() from exc
        if (
            organization.status != snapshot.organization_status
            or organization.row_version != snapshot.organization_row_version
            or project.status != snapshot.project_status
            or project.row_version != snapshot.project_row_version
            or
            self._freeze_endpoint_policy(policy=policy, revision=policy_revision)
            != snapshot.endpoint_policy
            or actor_authorization != snapshot.actor_authorization
            or self._create_candidate(request) != operation.candidate
        ):
            raise self._operation_stale()
        return organization, project, policy_revision

    def _ensure_create_datasource_name_available(
        self,
        session: Session,
        *,
        project: Project,
        request: DatasourceCreate,
    ) -> None:
        """Check a new-create name only after the completed replay decision.

        A successfully completed idempotent request necessarily owns this name.
        Checking the name before looking up its completed response makes a
        legitimate retry look like an unrelated conflict.
        """

        if session.scalar(
            select(Datasource.id).where(
                Datasource.project_id == project.id,
                func.lower(Datasource.name) == request.name.strip().casefold(),
                Datasource.status != "DELETED",
            )
        ):
            raise ProblemException(
                status=409,
                code="DATASOURCE_NAME_CONFLICT",
                title="数据源名称已存在",
                detail="请使用其他名称。",
            )

    def _read_completed_create_idempotency_replay(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        idempotency_key: str,
        request_body: dict[str, Any],
    ) -> OperationResult[DatasourceAdminDetail] | None:
        """Return a completed create replay without reserving a new record.

        ADR-0014 forbids persisting a partial idempotency record before phase
        B.  This read-only A-time check preserves normal retries without
        creating the incomplete reservation used by ``_claim_idempotency``.
        """

        now = utc_now()
        scope = "POST /projects/{project_id}/datasources"
        request_hash = self._idempotency_hash(
            actor_id=principal.user_id,
            scope=scope,
            body=request_body,
        )
        with self.sessions.begin() as session:
            organization = self._lock_organization(session, principal.organization_id)
            project = self._visible_project(
                session,
                principal,
                project_id,
                lock=True,
            )
            self._read_live_operation_authorization(
                session,
                principal=principal,
                project=project,
                datasource=None,
                usage=None,
            )
            # Keep organization in scope so a missing/inconsistent hierarchy is
            # treated exactly as the normal phase-A capture path.
            if organization.id != principal.organization_id:
                self._not_found()
            record = session.scalar(
                select(IdempotencyRecord)
                .where(
                    IdempotencyRecord.actor_id == principal.user_id,
                    IdempotencyRecord.scope == scope,
                    IdempotencyRecord.idempotency_key == idempotency_key,
                )
                .with_for_update()
            )
            if record is None or ensure_aware(record.expires_at) <= now:
                return None
            if record.request_hash_scheme != IDEMPOTENCY_HASH_SCHEME or not hmac.compare_digest(
                record.request_hash, request_hash
            ):
                raise ProblemException(
                    status=409,
                    code="IDEMPOTENCY_CONFLICT",
                    title="Idempotency-Key 已用于不同请求",
                    detail="请为新的业务意图使用新的 Idempotency-Key。",
                )
            if record.response_status is None or record.response_body is None:
                raise ProblemException(
                    status=409,
                    code="IDEMPOTENCY_IN_PROGRESS",
                    title="相同请求仍在处理中",
                    detail="请稍后使用相同 Idempotency-Key 重试。",
                    retryable=True,
                    headers={"Retry-After": "1"},
                )
            return OperationResult(
                self._create_datasource_replay_response(
                    session,
                    record=record,
                    project_id=project.id,
                ),
                replayed=True,
            )

    @staticmethod
    def _create_datasource_replay_conflict() -> ProblemException:
        """Fail closed when a create replay is not bound to this Project."""

        return ProblemException(
            status=409,
            code="IDEMPOTENCY_CONFLICT",
            title="Idempotency-Key 已用于不同请求",
            detail="该 Idempotency-Key 已绑定到另一项目的数据源创建请求。",
        )

    def _create_datasource_replay_response(
        self,
        session: Session,
        *,
        record: IdempotencyRecord,
        project_id: UUID,
    ) -> DatasourceAdminDetail:
        """Bind a completed create replay to the requested Project.

        The idempotency scope is the route template, so it deliberately omits
        the concrete ``project_id``.  A matching body/key must therefore also
        prove that the durable datasource and stored response both belong to
        the requested project before a replay is exposed.
        """

        if record.resource_type != "DATASOURCE" or record.resource_id is None:
            raise self._create_datasource_replay_conflict()
        datasource = session.get(Datasource, record.resource_id)
        if datasource is None or datasource.project_id != project_id:
            raise self._create_datasource_replay_conflict()
        try:
            response = DatasourceAdminDetail.model_validate(record.response_body)
        except (TypeError, ValueError) as exc:
            raise self._create_datasource_replay_conflict() from exc
        if response.id != datasource.id:
            raise self._create_datasource_replay_conflict()
        return response

    def create_datasource(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        request: DatasourceCreate,
        idempotency_key: str,
        audit: AuditContext,
        admission: DatasourceOperationAdmissionGuard | None = None,
    ) -> OperationResult[DatasourceAdminDetail]:
        self._require_admin(principal)
        password = bytearray(request.password.get_secret_value().encode("utf-8"))
        request_body = request.model_dump(mode="json", exclude={"password"})
        request_body["password_fingerprint"] = self._password_request_fingerprint(password)
        lease: DatasourceOperationAdmissionLease | None = None
        try:
            replay = self._read_completed_create_idempotency_replay(
                principal=principal,
                project_id=project_id,
                idempotency_key=idempotency_key,
                request_body=request_body,
            )
            if replay is not None:
                return replay
            lease = self._acquire_datasource_operation_admission(
                admission=admission,
                organization_id=principal.organization_id,
                datasource_ids=(),
                operation_kind=DatasourceOperationKind.CREATE,
            )
            operation = self._capture_create_datasource_operation(
                principal=principal,
                project_id=project_id,
                request=request,
                request_body=request_body,
            )
            snapshot = operation.snapshot
            assert snapshot.endpoint_policy is not None
            deadline = OperationDeadline(self.operation_deadline_seconds)
            try:
                deadline.check_expired()
                resolved = self.guard.resolve(
                    snapshot.endpoint_policy,
                    host=operation.candidate.host,
                    port=operation.candidate.port,
                    deadline=deadline,
                )
                deadline.check_expired()
                self.guard.verify_rebinding(
                    snapshot.endpoint_policy,
                    resolved,
                    deadline=deadline,
                )
                deadline.check_expired()
                probe = self.connector.probe(
                    operation.candidate,
                    password=password,
                    resolved=resolved,
                    deadline=deadline,
                )
                deadline.check_expired()
            except OperationDeadlineExpired as exc:
                # The remaining budget is already zero.  Do not start an
                # unbounded C revalidation just to decide whether to report a
                # response that cannot persist any B-phase material.
                raise self._operation_deadline_problem(
                    "本次连接验证超过总时限；没有创建数据源或幂等记录。"
                ) from exc
            except ProblemException:
                with self._deadline_transaction(deadline) as session:
                    self._revalidate_create_datasource_operation(
                        session,
                        principal=principal,
                        request=request,
                        operation=operation,
                    )
                raise
            except Exception as exc:
                # A connector/DNS implementation may report its own timeout
                # instead of OperationDeadlineExpired.  The fixed operation
                # deadline remains authoritative: once exhausted, do not
                # downgrade it to a generic probe failure.
                if deadline.remaining_seconds() <= 0.0:
                    raise self._operation_deadline_problem(
                        "本次连接验证超过总时限；没有创建数据源或幂等记录。"
                    ) from exc
                with self._deadline_transaction(deadline) as session:
                    self._revalidate_create_datasource_operation(
                        session,
                        principal=principal,
                        request=request,
                        operation=operation,
                    )
                raise self._safe_probe_problem(exc) from exc
            now = utc_now()
            with self._deadline_transaction(deadline) as session:
                organization, project, policy_revision = (
                    self._revalidate_create_datasource_operation(
                        session,
                        principal=principal,
                        request=request,
                        operation=operation,
                    )
                )
                deadline.check_expired()
                replay = self._claim_idempotency(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /projects/{project_id}/datasources",
                    key=idempotency_key,
                    body=request_body,
                    now=now,
                )
                if replay is not None:
                    return OperationResult(
                        self._create_datasource_replay_response(
                            session,
                            record=replay,
                            project_id=project.id,
                        ),
                        replayed=True,
                    )
                self._ensure_create_datasource_name_available(
                    session,
                    project=project,
                    request=request,
                )
                datasource = self._persist_new_datasource(
                    session,
                    principal=principal,
                    project=project,
                    organization=organization,
                    request=request,
                    policy_revision=policy_revision,
                    resolved=resolved,
                    probe=probe,
                    password=password,
                    now=now,
                    audit=audit,
                )
                response = self._admin_detail(session, datasource)
                self._complete_idempotency(
                    session,
                    actor_id=principal.user_id,
                    scope="POST /projects/{project_id}/datasources",
                    key=idempotency_key,
                    status=201,
                    body=response.model_dump(mode="json"),
                    resource_type="DATASOURCE",
                    resource_id=datasource.id,
                )
                return OperationResult(response)
        except OperationDeadlineExpired as exc:
            raise self._operation_deadline_problem(
                "本次连接验证超过总时限；没有创建数据源或幂等记录。"
            ) from exc
        except ProblemException:
            raise
        except IntegrityError as exc:
            raise ProblemException(
                status=409,
                code="DATASOURCE_CONFLICT",
                title="数据源创建冲突",
                detail="请刷新后重试。",
            ) from exc
        finally:
            if lease is not None:
                lease.release()
            zeroize(password)

    def _prepare_update_datasource_operation(
        self,
        session: Session,
        *,
        principal: Principal,
        datasource: Datasource,
        project: Project,
        organization: Organization,
        request: DatasourcePatch,
    ) -> UpdateDatasourceOperation | None:
        """Freeze an update probe intent while the original binding is locked.

        A password-supplied repair intentionally does not require the old
        secret to be usable: it probes the supplied secret and replaces the
        broken one only after phase C.  A password-less update does require the
        strict active binding because phase B will decrypt it.
        """

        connection_fields = frozenset(request.model_fields_set & _DATASOURCE_REVISION_FIELDS)
        activating = (
            "status" in request.model_fields_set
            and request.status == "ACTIVE"
            and datasource.status != "ACTIVE"
        )
        requires_probe = bool(connection_fields or request.password is not None or activating)
        if not requires_probe:
            return None

        current_revision = self._datasource_revision_record(session, datasource)
        if connection_fields:
            candidate, candidate_policy_revision = self._datasource_patch_candidate(
                session,
                principal=principal,
                current=current_revision,
                request=request,
            )
        else:
            current_revision, candidate_policy_revision = self._current_revisions(
                session,
                datasource,
            )
            candidate = DatasourceConnectionCandidate(
                engine=current_revision.engine,
                host=current_revision.host,
                port=current_revision.port,
                database_name=current_revision.database_name,
                default_schema=current_revision.default_schema,
                username=current_revision.username,
                ssl_mode=current_revision.ssl_mode,
            )
        candidate_policy = session.scalar(
            select(EndpointPolicy)
            .where(
                EndpointPolicy.id == candidate_policy_revision.endpoint_policy_id,
                EndpointPolicy.organization_id == organization.id,
            )
            .with_for_update()
        )
        if candidate_policy is None:
            raise self._binding_unavailable()
        snapshot = self._freeze_current_datasource_operation(
            session,
            principal=principal,
            organization=organization,
            project=project,
            datasource=datasource,
            operation_kind=DatasourceOperationKind.UPDATE,
            usage=None,
            # A changed endpoint policy is the proposal being probed.  The
            # current policy only has to remain comparable through phase C.
            require_current_policy_active=False,
            require_credential_binding=request.password is None,
            # A disabled datasource with an ACTIVE secret must be able to be
            # re-probed and activated without pretending it was already live.
            require_datasource_active_for_credential=False,
        )
        candidate_hash = self._domain_hash(
            "DXDATASOURCEUPDATEv1",
            {
                "datasource_id": str(datasource.id),
                "expected_row_version": datasource.row_version,
                "candidate": {
                    "engine": candidate.engine,
                    "host": candidate.host,
                    "port": candidate.port,
                    "database_name": candidate.database_name,
                    "default_schema": candidate.default_schema,
                    "username": candidate.username,
                    "ssl_mode": candidate.ssl_mode,
                },
                "candidate_policy_revision_id": str(candidate_policy_revision.id),
                "connection_fields": sorted(connection_fields),
                "password_supplied": request.password is not None,
            },
        )
        return UpdateDatasourceOperation(
            snapshot=replace(snapshot, candidate_config_hash=candidate_hash),
            candidate=candidate,
            candidate_policy=self._freeze_endpoint_policy(
                policy=candidate_policy,
                revision=candidate_policy_revision,
            ),
            connection_fields=connection_fields,
            password_provided=request.password is not None,
        )

    def _apply_non_probe_datasource_update(
        self,
        session: Session,
        *,
        principal: Principal,
        datasource: Datasource,
        project: Project,
        organization: Organization,
        request: DatasourcePatch,
        audit: AuditContext,
    ) -> DatasourceAdminDetail:
        """Commit the ordinary short-transaction PATCH variants.

        Name, description and disable operations deliberately do not enter the
        expensive external-I/O lane.  The caller already holds the normal
        organization/project/datasource lock hierarchy.
        """

        now = utc_now()
        revision = self._datasource_revision_record(session, datasource)
        changed_fields: list[str] = []
        actions: list[str] = []
        if "name" in request.model_fields_set:
            assert request.name is not None
            normalized_name = request.name.strip()
            conflict = session.scalar(
                select(Datasource.id).where(
                    Datasource.project_id == project.id,
                    Datasource.id != datasource.id,
                    func.lower(Datasource.name) == normalized_name.casefold(),
                    Datasource.status != "DELETED",
                )
            )
            if conflict is not None:
                raise ProblemException(
                    status=409,
                    code="DATASOURCE_NAME_CONFLICT",
                    title="数据源名称已存在",
                    detail="请使用其他名称。",
                )
            if datasource.name != normalized_name:
                datasource.name = normalized_name
                changed_fields.append("name")
                actions.append("DATASOURCE_UPDATED")
        if "description" in request.model_fields_set:
            description = request.description.strip() if request.description else None
            if datasource.description != description:
                datasource.description = description
            changed_fields.append("description")
            actions.append("DATASOURCE_UPDATED")
        requested_status = request.status if "status" in request.model_fields_set else None
        if requested_status == "ACTIVE":
            self._assert_datasource_can_activate(session, datasource)
        if requested_status is not None and datasource.status != requested_status:
            datasource.status = requested_status
            changed_fields.append("status")
            actions.append(
                "DATASOURCE_DISABLED" if requested_status == "DISABLED" else "DATASOURCE_UPDATED"
            )
        if not changed_fields:
            return self._admin_detail(session, datasource)
        datasource.row_version += 1
        datasource.updated_at = now
        self._append_audit(
            session,
            organization=organization,
            project_id=project.id,
            action=actions[-1],
            actor_id=principal.user_id,
            target_type="DATASOURCE",
            target_id=datasource.id,
            target_name=datasource.name,
            changed_fields=[*changed_fields, "row_version"],
            audit=audit,
            metadata={
                "credential_rotated": False,
                "connection_validated": False,
                "revision_id": str(revision.id),
                "revision_no": revision.revision_no,
                "config_hash": revision.config_hash,
                "secret_version": None,
            },
        )
        return self._admin_detail(session, datasource)

    def _revalidate_update_datasource_operation(
        self,
        session: Session,
        *,
        principal: Principal,
        datasource_id: UUID,
        request: DatasourcePatch,
        expected_version: int,
        operation: UpdateDatasourceOperation,
    ) -> tuple[
        Datasource,
        Project,
        Organization,
        EndpointPolicyRevision,
    ]:
        """Phase C for a probe-required PATCH; every B-time drift is stale."""

        try:
            datasource, project, organization = self._locked_datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            if (
                datasource.status == "DELETED"
                or datasource.row_version != expected_version
                or datasource.row_version != operation.snapshot.datasource_row_version
            ):
                raise self._operation_stale()
            current = self._freeze_current_datasource_operation(
                session,
                principal=principal,
                organization=organization,
                project=project,
                datasource=datasource,
                operation_kind=DatasourceOperationKind.UPDATE,
                usage=None,
                require_current_policy_active=False,
                require_credential_binding=not operation.password_provided,
                require_datasource_active_for_credential=False,
            )
            if not self._operation_snapshot_state_matches(operation.snapshot, current):
                raise self._operation_stale()
            current_revision = self._datasource_revision_record(session, datasource)
            candidate, candidate_policy_revision = self._datasource_patch_candidate(
                session,
                principal=principal,
                current=current_revision,
                request=request,
            )
            candidate_policy = session.scalar(
                select(EndpointPolicy)
                .where(
                    EndpointPolicy.id == candidate_policy_revision.endpoint_policy_id,
                    EndpointPolicy.organization_id == organization.id,
                )
                .with_for_update()
            )
            if candidate_policy is None:
                raise self._operation_stale()
            current_candidate_policy = self._freeze_endpoint_policy(
                policy=candidate_policy,
                revision=candidate_policy_revision,
            )
        except ProblemException as exc:
            if exc.code == "DATASOURCE_OPERATION_STALE":
                raise
            raise self._operation_stale() from exc
        if (
            candidate != operation.candidate
            or current_candidate_policy != operation.candidate_policy
        ):
            raise self._operation_stale()
        if "name" in request.model_fields_set:
            assert request.name is not None
            conflict = session.scalar(
                select(Datasource.id).where(
                    Datasource.project_id == project.id,
                    Datasource.id != datasource.id,
                    func.lower(Datasource.name) == request.name.strip().casefold(),
                    Datasource.status != "DELETED",
                )
            )
            if conflict is not None:
                raise ProblemException(
                    status=409,
                    code="DATASOURCE_NAME_CONFLICT",
                    title="数据源名称已存在",
                    detail="请使用其他名称。",
                )
        return datasource, project, organization, candidate_policy_revision

    def _persist_probed_datasource_update(
        self,
        session: Session,
        *,
        principal: Principal,
        datasource: Datasource,
        project: Project,
        organization: Organization,
        request: DatasourcePatch,
        operation: UpdateDatasourceOperation,
        candidate_policy_revision: EndpointPolicyRevision,
        resolved: ResolvedEndpoint,
        probe: ProbeResult,
        password: bytearray | None,
        audit: AuditContext,
    ) -> DatasourceAdminDetail:
        """The only phase allowed to persist a successful external probe."""

        now = utc_now()
        revision = self._datasource_revision_record(session, datasource)
        changed_fields: list[str] = []
        actions: list[str] = []
        if operation.connection_fields:
            identity = self._physical_identity_from_probe(
                session,
                principal=principal,
                organization=organization,
                policy_revision=candidate_policy_revision,
                candidate=operation.candidate,
                resolved=resolved,
                probe=probe,
                now=now,
            )
            config = self._datasource_revision_config(
                policy_revision=candidate_policy_revision,
                physical_endpoint_identity_id=identity.id,
                candidate=operation.candidate,
            )
            config_hash = self._domain_hash("DXDATASOURCEREVISIONv1", config)
            if config_hash != revision.config_hash:
                revision = DatasourceRevision(
                    id=uuid4(),
                    datasource_id=datasource.id,
                    revision_no=revision.revision_no + 1,
                    endpoint_policy_revision_id=candidate_policy_revision.id,
                    physical_endpoint_identity_id=identity.id,
                    engine=operation.candidate.engine,
                    host=operation.candidate.host,
                    port=operation.candidate.port,
                    database_name=operation.candidate.database_name,
                    default_schema=operation.candidate.default_schema,
                    username=operation.candidate.username,
                    ssl_mode=operation.candidate.ssl_mode,
                    connection_options={},
                    config_hash=config_hash,
                    created_by=principal.user_id,
                    created_at=now,
                )
                session.add(revision)
                session.flush()
                datasource.current_revision_id = revision.id
                changed_fields.extend([*sorted(operation.connection_fields), "current_revision_id"])
                actions.append("DATASOURCE_REVISION_CREATED")
        if "name" in request.model_fields_set:
            assert request.name is not None
            normalized_name = request.name.strip()
            if datasource.name != normalized_name:
                datasource.name = normalized_name
                changed_fields.append("name")
                actions.append("DATASOURCE_UPDATED")
        if "description" in request.model_fields_set:
            description = request.description.strip() if request.description else None
            if datasource.description != description:
                datasource.description = description
            changed_fields.append("description")
            actions.append("DATASOURCE_UPDATED")
        if password is not None:
            previous = session.get(CredentialSecret, datasource.current_secret_id)
            if previous is not None and previous.status == "ACTIVE":
                previous.status = "RETIRED"
                previous.status_reason_code = "ROTATED"
                previous.status_changed_at = now
                previous.retired_at = now
            self._install_secret(
                session,
                organization_id=organization.id,
                project_id=project.id,
                datasource=datasource,
                password=password,
                actor_id=principal.user_id,
                now=now,
            )
            changed_fields.append("current_secret_id")
            actions.append("DATASOURCE_CREDENTIAL_ROTATED")
        self._persist_connection_evidence(
            session,
            operation_kind="TEST",
            datasource_revision=revision,
            resolved=resolved,
            peer_ip=probe.peer_ip,
            tls_peer_spki_sha256=probe.tls_peer_spki_sha256,
            observed_at=now,
        )
        datasource.last_test_status = "SUCCEEDED"
        datasource.last_tested_at = now
        datasource.last_test_error_code = None
        changed_fields.extend(["last_test_status", "last_tested_at", "last_test_error_code"])
        actions.append("DATASOURCE_TESTED")
        requested_status = (
            request.status
            if "status" in request.model_fields_set
            else ("ACTIVE" if password is not None else None)
        )
        if requested_status == "ACTIVE":
            self._assert_datasource_can_activate(session, datasource)
        if requested_status is not None and datasource.status != requested_status:
            datasource.status = requested_status
            changed_fields.append("status")
            actions.append(
                "DATASOURCE_DISABLED" if requested_status == "DISABLED" else "DATASOURCE_UPDATED"
            )
        datasource.row_version += 1
        datasource.updated_at = now
        self._append_audit(
            session,
            organization=organization,
            project_id=project.id,
            action=(
                "DATASOURCE_CREDENTIAL_ROTATED"
                if "DATASOURCE_CREDENTIAL_ROTATED" in actions
                else (
                    "DATASOURCE_REVISION_CREATED"
                    if "DATASOURCE_REVISION_CREATED" in actions
                    else actions[-1]
                )
            ),
            actor_id=principal.user_id,
            target_type="DATASOURCE",
            target_id=datasource.id,
            target_name=datasource.name,
            changed_fields=[*changed_fields, "row_version"],
            audit=audit,
            metadata={
                "credential_rotated": password is not None,
                "connection_validated": True,
                "revision_id": str(revision.id),
                "revision_no": revision.revision_no,
                "config_hash": revision.config_hash,
                "secret_version": (
                    self._current_secret_record(session, datasource).secret_version
                    if password is not None
                    else None
                ),
            },
        )
        return self._admin_detail(session, datasource)

    def update_datasource(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        request: DatasourcePatch,
        expected_version: int,
        audit: AuditContext,
        admission: DatasourceOperationAdmissionGuard | None = None,
    ) -> DatasourceAdminDetail:
        """Update a datasource without holding product locks during I/O."""

        self._require_admin(principal)
        password = (
            bytearray(request.password.get_secret_value().encode("utf-8"))
            if request.password is not None
            else None
        )
        lease: DatasourceOperationAdmissionLease | None = None
        try:
            with self.sessions.begin() as session:
                datasource, project, organization = self._locked_datasource_context(
                    session,
                    principal=principal,
                    datasource_id=datasource_id,
                )
                if datasource.status == "DELETED":
                    raise ProblemException(
                        status=409,
                        code="DATASOURCE_DELETED",
                        title="数据源已删除",
                        detail="软删除数据源不能恢复、更新或轮换凭据。",
                    )
                if datasource.row_version != expected_version:
                    raise ProblemException(
                        status=409,
                        code="VERSION_CONFLICT",
                        title="数据源已被修改",
                        detail="请刷新后重试。",
                    )
                operation = self._prepare_update_datasource_operation(
                    session,
                    principal=principal,
                    datasource=datasource,
                    project=project,
                    organization=organization,
                    request=request,
                )
                if operation is None:
                    return self._apply_non_probe_datasource_update(
                        session,
                        principal=principal,
                        datasource=datasource,
                        project=project,
                        organization=organization,
                        request=request,
                        audit=audit,
                    )
            # Ordinary name, description and DISABLED-only PATCHes commit in
            # the short transaction above and never enter the expensive
            # external-I/O lane. Only a candidate that really needs a probe
            # consumes a permit, after phase A has released its product
            # database locks. A saturated probe lane therefore cannot block
            # an emergency disable.
            lease = self._acquire_datasource_operation_admission(
                admission=admission,
                organization_id=principal.organization_id,
                datasource_ids=(datasource_id,),
                operation_kind=DatasourceOperationKind.UPDATE,
            )
            deadline = OperationDeadline(self.operation_deadline_seconds)
            try:
                deadline.check_expired()
                if password is None:
                    material = self._copy_strict_current_credential_material(
                        operation.snapshot,
                        deadline=deadline,
                        require_datasource_active=False,
                    )
                    deadline.check_expired()
                    with self._decrypt_current_operation_material(
                        snapshot=operation.snapshot,
                        material=material,
                    ) as current_password:
                        resolved = self.guard.resolve(
                            operation.candidate_policy,
                            host=operation.candidate.host,
                            port=operation.candidate.port,
                            deadline=deadline,
                        )
                        deadline.check_expired()
                        self.guard.verify_rebinding(
                            operation.candidate_policy,
                            resolved,
                            deadline=deadline,
                        )
                        deadline.check_expired()
                        probe = self.connector.probe(
                            operation.candidate,
                            password=current_password,
                            resolved=resolved,
                            deadline=deadline,
                        )
                        deadline.check_expired()
                else:
                    resolved = self.guard.resolve(
                        operation.candidate_policy,
                        host=operation.candidate.host,
                        port=operation.candidate.port,
                        deadline=deadline,
                    )
                    deadline.check_expired()
                    self.guard.verify_rebinding(
                        operation.candidate_policy,
                        resolved,
                        deadline=deadline,
                    )
                    deadline.check_expired()
                    probe = self.connector.probe(
                        operation.candidate,
                        password=password,
                        resolved=resolved,
                        deadline=deadline,
                    )
                    deadline.check_expired()
            except OperationDeadlineExpired as exc:
                raise self._operation_deadline_problem(
                    "本次数据源更新验证超过总时限；没有保存更新。"
                ) from exc
            except ProblemException:
                with self._deadline_transaction(deadline) as session:
                    self._revalidate_update_datasource_operation(
                        session,
                        principal=principal,
                        datasource_id=datasource_id,
                        request=request,
                        expected_version=expected_version,
                        operation=operation,
                    )
                raise
            except Exception as exc:
                # See create_datasource(): an adapter-level timeout at the
                # total-deadline boundary must not become a generic failure.
                if deadline.remaining_seconds() <= 0.0:
                    raise self._operation_deadline_problem(
                        "本次数据源更新验证超过总时限；没有保存更新。"
                    ) from exc
                with self._deadline_transaction(deadline) as session:
                    self._revalidate_update_datasource_operation(
                        session,
                        principal=principal,
                        datasource_id=datasource_id,
                        request=request,
                        expected_version=expected_version,
                        operation=operation,
                    )
                raise self._safe_probe_problem(exc) from exc
            with self._deadline_transaction(deadline) as session:
                (
                    datasource,
                    project,
                    organization,
                    candidate_policy_revision,
                ) = self._revalidate_update_datasource_operation(
                    session,
                    principal=principal,
                    datasource_id=datasource_id,
                    request=request,
                    expected_version=expected_version,
                    operation=operation,
                )
                deadline.check_expired()
                return self._persist_probed_datasource_update(
                    session,
                    principal=principal,
                    datasource=datasource,
                    project=project,
                    organization=organization,
                    request=request,
                    operation=operation,
                    candidate_policy_revision=candidate_policy_revision,
                    resolved=resolved,
                    probe=probe,
                    password=password,
                    audit=audit,
                )
        except OperationDeadlineExpired as exc:
            raise self._operation_deadline_problem(
                "本次数据源更新验证超过总时限；没有保存更新。"
            ) from exc
        except ProblemException:
            raise
        except IntegrityError as exc:
            raise ProblemException(
                status=409,
                code="DATASOURCE_CONFLICT",
                title="数据源更新冲突",
                detail="请刷新后重试。",
            ) from exc
        finally:
            if lease is not None:
                lease.release()
            if password is not None:
                zeroize(password)

    def delete_datasource(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        expected_version: int,
        audit: AuditContext,
    ) -> None:
        self._require_admin(principal)
        with self.sessions.begin() as session:
            datasource, project, organization = self._lock_admin_datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            if datasource.status == "DELETED":
                self._not_found()
            if datasource.row_version != expected_version:
                raise ProblemException(
                    status=409,
                    code="VERSION_CONFLICT",
                    title="数据源已被修改",
                    detail="请刷新后重试。",
                )
            active_reference = self._datasource_active_reference(
                session,
                datasource=datasource,
                project=project,
            )
            if active_reference is not None:
                raise ProblemException(
                    status=409,
                    code="DATASOURCE_HAS_ACTIVE_REFERENCES",
                    title="数据源仍有活动引用",
                    detail="请先归档任务、撤销传输策略并完成执行或恢复处置。",
                    details={"reference_type": active_reference},
                )
            now = utc_now()
            grants = list(
                session.scalars(
                    select(DatasourceUsageGrant)
                    .where(
                        DatasourceUsageGrant.datasource_id == datasource.id,
                        DatasourceUsageGrant.status == "ACTIVE",
                    )
                    .order_by(
                        DatasourceUsageGrant.organization_member_id,
                        DatasourceUsageGrant.usage,
                    )
                    .with_for_update()
                )
            )
            for grant in grants:
                grant.status = "REVOKED"
                grant.revoked_by = principal.user_id
                grant.revoked_at = now
                # A datasource deletion is still a grant revocation.  Preserve
                # the monotonic generation so any A/B/C operation that froze
                # this row cannot accept work after the grant was removed.
                grant.row_version += 1
            datasource.status = "DELETED"
            datasource.deleted_at = now
            datasource.updated_at = now
            datasource.row_version += 1
            self._append_audit(
                session,
                organization=organization,
                project_id=project.id,
                action="DATASOURCE_DELETED",
                actor_id=principal.user_id,
                target_type="DATASOURCE",
                target_id=datasource.id,
                target_name=datasource.name,
                changed_fields=[
                    "status",
                    "deleted_at",
                    "row_version",
                    *(["usage_grants"] if grants else []),
                ],
                audit=audit,
                metadata={"revoked_usage_grant_count": len(grants)},
            )

    def get_datasource_revision(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        revision_id: UUID,
    ) -> DatasourceRevisionAdminDetail:
        self._require_admin(principal)
        with self.sessions() as session:
            datasource, _, _ = self._datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            revision = session.scalar(
                select(DatasourceRevision).where(
                    DatasourceRevision.id == revision_id,
                    DatasourceRevision.datasource_id == datasource.id,
                )
            )
            if revision is None:
                self._not_found()
            return self._revision_detail(revision)

    def list_datasource_usage_grants(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        limit: int,
        cursor: str | None,
    ) -> DatasourceUsageGrantPage:
        self._require_admin(principal)
        with self.sessions() as session:
            datasource, _, _ = self._datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            scope = f"GET /datasources/{datasource.id}/grants"
            statement = select(DatasourceUsageGrant).where(
                DatasourceUsageGrant.datasource_id == datasource.id
            )
            if cursor is not None:
                granted_at, grant_id = self._decode_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    scope=scope,
                )
                statement = statement.where(
                    or_(
                        DatasourceUsageGrant.granted_at < granted_at,
                        and_(
                            DatasourceUsageGrant.granted_at == granted_at,
                            DatasourceUsageGrant.id < grant_id,
                        ),
                    )
                )
            rows = list(
                session.scalars(
                    statement.order_by(
                        DatasourceUsageGrant.granted_at.desc(),
                        DatasourceUsageGrant.id.desc(),
                    ).limit(limit + 1)
                )
            )
            has_more = len(rows) > limit
            rows = rows[:limit]
            next_cursor = None
            if has_more and rows:
                next_cursor = self._encode_cursor(
                    actor_id=principal.user_id,
                    scope=scope,
                    created_at=ensure_aware(rows[-1].granted_at),
                    resource_id=rows[-1].id,
                )
            return DatasourceUsageGrantPage(
                items=[self._usage_grant_response(item) for item in rows],
                next_cursor=next_cursor,
                has_more=has_more,
            )

    def replace_datasource_usage_grants(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        member_id: UUID,
        request: DatasourceUsageGrantReplace,
        audit: AuditContext,
    ) -> DatasourceUsageGrantPage:
        self._require_admin(principal)
        with self.sessions.begin() as session:
            datasource, project, organization = self._lock_admin_datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            if datasource.status == "DELETED":
                raise ProblemException(
                    status=409,
                    code="DATASOURCE_DELETED",
                    title="数据源已删除",
                    detail="软删除数据源不能新增或恢复用途授权。",
                )
            member = session.scalar(
                select(OrganizationMember)
                .where(
                    OrganizationMember.id == member_id,
                    OrganizationMember.organization_id == principal.organization_id,
                )
                .with_for_update()
            )
            if member is None:
                self._not_found()
            if member.status != MembershipStatus.ACTIVE:
                raise ProblemException(
                    status=422,
                    code="ORGANIZATION_MEMBER_NOT_ACTIVE",
                    title="组织成员不可用",
                    detail="只能向当前 ACTIVE 组织成员授予数据源用途。",
                )
            project_membership = session.scalar(
                select(RoleAssignment.id).where(
                    RoleAssignment.organization_member_id == member.id,
                    RoleAssignment.scope_type == ScopeType.PROJECT,
                    RoleAssignment.scope_id == project.id,
                    RoleAssignment.role.in_((Role.DEVELOPER, Role.OPERATOR, Role.VIEWER)),
                )
            )
            if project_membership is None:
                raise ProblemException(
                    status=422,
                    code="PROJECT_MEMBERSHIP_REQUIRED",
                    title="成员不属于数据源项目",
                    detail="用途授权不能绕过当前项目成员关系。",
                )

            existing = {
                item.usage: item
                for item in session.scalars(
                    select(DatasourceUsageGrant)
                    .where(
                        DatasourceUsageGrant.datasource_id == datasource.id,
                        DatasourceUsageGrant.organization_member_id == member.id,
                    )
                    .order_by(DatasourceUsageGrant.usage)
                    .with_for_update()
                )
            }
            desired = set(request.usages)
            activated: list[str] = []
            revoked: list[str] = []
            now = utc_now()
            for usage in ("SOURCE_USE", "TARGET_USE"):
                grant = existing.get(usage)
                if usage in desired:
                    if grant is None:
                        grant = DatasourceUsageGrant(
                            id=uuid4(),
                            datasource_id=datasource.id,
                            organization_member_id=member.id,
                            usage=usage,
                            status="ACTIVE",
                            granted_by=principal.user_id,
                            granted_at=now,
                        )
                        session.add(grant)
                        existing[usage] = grant
                        activated.append(usage)
                    elif grant.status != "ACTIVE":
                        grant.status = "ACTIVE"
                        grant.granted_by = principal.user_id
                        grant.granted_at = now
                        grant.revoked_by = None
                        grant.revoked_at = None
                        grant.row_version += 1
                        activated.append(usage)
                elif grant is not None and grant.status == "ACTIVE":
                    grant.status = "REVOKED"
                    grant.revoked_by = principal.user_id
                    grant.revoked_at = now
                    grant.row_version += 1
                    revoked.append(usage)
            session.flush()
            active = [
                existing[usage]
                for usage in ("SOURCE_USE", "TARGET_USE")
                if usage in existing and existing[usage].status == "ACTIVE"
            ]
            audit_actions = [
                *(["DATASOURCE_USAGE_GRANTED"] if activated else []),
                *(["DATASOURCE_USAGE_REVOKED"] if revoked else []),
            ] or ["DATASOURCE_UPDATED"]
            for action in audit_actions:
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=project.id,
                    action=action,
                    actor_id=principal.user_id,
                    target_type="DATASOURCE",
                    target_id=datasource.id,
                    target_name=datasource.name,
                    changed_fields=(["usage_grants"] if activated or revoked else []),
                    audit=audit,
                    metadata={
                        "organization_member_id": str(member.id),
                        "active_usages": sorted(desired),
                        "activated_usages": activated,
                        "revoked_usages": revoked,
                    },
                )
            return DatasourceUsageGrantPage(
                items=[self._usage_grant_response(item) for item in active],
                next_cursor=None,
                has_more=False,
            )

    def list_credential_secrets(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
    ) -> CredentialSecretPage:
        self._require_admin(principal)
        with self.sessions() as session:
            datasource, _, _ = self._datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            secrets = list(
                session.scalars(
                    select(CredentialSecret)
                    .where(CredentialSecret.datasource_id == datasource.id)
                    .order_by(CredentialSecret.secret_version.desc())
                )
            )
            return CredentialSecretPage(
                items=[self._secret_summary(session, item) for item in secrets]
            )

    def change_secret_status(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        secret_version: int,
        request: CredentialSecretStatusChange,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[CredentialSecretSummary]:
        self._require_admin(principal)
        with self.sessions.begin() as session:
            # Read only enough to identify the immutable secret before taking
            # work-row locks.  Emergency status changes use the deterministic
            # Execution/Probe -> Organization -> Project -> Datasource ->
            # Secret order; once the datasource lock is held we rescan, so a
            # claim that won the datasource race cannot bind the secret after
            # the scan.
            candidate_secret_id = session.scalar(
                select(CredentialSecret.id)
                .join(Datasource, Datasource.id == CredentialSecret.datasource_id)
                .join(Project, Project.id == Datasource.project_id)
                .where(
                    CredentialSecret.datasource_id == datasource_id,
                    CredentialSecret.secret_version == secret_version,
                    Project.organization_id == principal.organization_id,
                )
            )
            if candidate_secret_id is None:
                self._not_found()
            emergency_stop = request.status in {"REVOKED", "COMPROMISED"}
            locked_executions: list[Execution] = []
            locked_probes: list[RecoveryProbe] = []
            if emergency_stop:
                # Queued work has not bound a secret yet.  Lock both its
                # immutable datasource reference and already-bound work
                # before taking the datasource gate, so a worker that wins a
                # concurrent claim is observed by the second scan below.
                # The final current-secret check is deliberately deferred
                # until after the datasource row is locked: revoking an old
                # retired secret must not cancel queued work that will bind a
                # newer current secret.
                locked_executions, locked_probes = self._lock_potential_work_for_secret_status(
                    session,
                    secret_id=candidate_secret_id,
                    datasource_id=datasource_id,
                )
            datasource, project, organization = self._lock_admin_datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            # A status transition can wait behind a Worker or another control
            # transaction.  Its durable termination/audit timestamps must be
            # ordered by the database clock *after* that wait, rather than by
            # the stale application time captured before the lock sequence.
            now = self._database_now(session)
            replay = self._claim_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /datasources/{datasource_id}/credential-secrets/{version}/status",
                key=idempotency_key,
                body={
                    "datasource_id": str(datasource.id),
                    "secret_version": secret_version,
                    **request.model_dump(mode="json"),
                },
                now=now,
            )
            if replay is not None:
                return OperationResult(
                    self._credential_secret_status_replay_response(
                        session,
                        record=replay,
                        datasource_id=datasource.id,
                        secret_id=candidate_secret_id,
                        secret_version=secret_version,
                    ),
                    replayed=True,
                )
            secret = session.scalar(
                select(CredentialSecret)
                .where(
                    CredentialSecret.datasource_id == datasource.id,
                    CredentialSecret.secret_version == secret_version,
                )
                .with_for_update()
            )
            if secret is None:
                self._not_found()
            if secret.id != candidate_secret_id:
                raise RuntimeError("credential secret identity changed during status update")
            is_current_secret = datasource.current_secret_id == secret.id
            # Retirement is a normal post-rotation lifecycle state.  Allowing
            # it on the current secret would leave the datasource formally
            # ACTIVE but make future Worker binding fail, stranding a queued
            # Execution's RESERVED TargetCopyLock or a RecoveryGate probe.
            # V1 has no atomic "install replacement + retire old" API, so
            # require the replacement current secret to be selected first.
            if request.status == "RETIRED" and is_current_secret:
                raise ProblemException(
                    status=409,
                    code="CREDENTIAL_STATUS_CONFLICT",
                    title="当前凭据不能直接退役",
                    detail="请先完成凭据轮换并切换数据源 current secret，再退役历史版本。",
                )
            allowed_statuses = {
                "ACTIVE": {"RETIRED", "REVOKED", "COMPROMISED"},
                # Retirement is a normal rotation state, not evidence that
                # the already-bound credential can never be discovered as
                # leaked.  Escalation remains terminal and creates the same
                # durable stop as a direct emergency revocation.
                "RETIRED": {"REVOKED", "COMPROMISED"},
            }
            if request.status not in allowed_statuses.get(secret.status, set()):
                raise ProblemException(
                    status=409,
                    code="CREDENTIAL_STATUS_CONFLICT",
                    title="凭据状态不能再次变更",
                    detail="凭据不能重新激活、降级、重复撤销或从终态回退。",
                )
            secret.status = request.status
            secret.status_reason_code = request.reason_code
            secret.status_changed_at = now
            if request.status == "RETIRED":
                secret.retired_at = now
            elif request.status == "REVOKED":
                secret.revoked_at = now
            else:
                secret.compromised_at = now
            if is_current_secret:
                datasource.status = "DISABLED"
                datasource.row_version += 1
                datasource.updated_at = now
            # Re-scan after the datasource gate.  The initial scan follows
            # the global Work -> Organization -> Project -> Datasource order;
            # this second pass intentionally does *not* take Work row locks.
            # Taking those locks after Datasource would invert the Worker
            # claim order and can deadlock an emergency revocation.  New
            # execution/probe producers now lock their Datasource before
            # enqueueing, and claimers re-check the durable request after
            # their Datasource/credential gate, so this non-locking read is
            # enough to turn every interleaving into a durable stop.
            affected_executions: list[Execution] = []
            affected_probes: list[RecoveryProbe] = []
            if emergency_stop:
                affected_executions, affected_probes = self._find_bound_work_for_secret(
                    session,
                    secret_id=secret.id,
                )
                if is_current_secret:
                    # The first lock pass covers the work that had not bound
                    # a secret when the status change began.  A current
                    # secret's emergency terminal status is also a durable
                    # stop for those queued execution/probe intentions; they
                    # cannot safely remain RESERVED/REMEDIATION_SUBMITTED and
                    # wait for a secret that has just become unusable.
                    late_queued_executions, late_queued_probes = (
                        self._find_queued_work_for_current_secret_status(
                            session,
                            datasource_id=datasource.id,
                        )
                    )
                    affected_executions = list(
                        {
                            execution.id: execution
                            for execution in [
                                *affected_executions,
                                *locked_executions,
                                *late_queued_executions,
                            ]
                        }.values()
                    )
                    affected_probes = list(
                        {
                            probe.id: probe
                            for probe in [
                                *affected_probes,
                                *locked_probes,
                                *late_queued_probes,
                            ]
                        }.values()
                    )
            termination_requests: list[WorkTerminationRequest] = []
            if emergency_stop:
                reason_code = f"SECRET_{request.status}"
                for execution in affected_executions:
                    termination_requests.append(
                        ControlService._ensure_work_termination_request(  # noqa: SLF001
                            session,
                            work_kind="EXECUTION",
                            work_id=execution.id,
                            reason_code=reason_code,
                            credential_secret_id=secret.id,
                            now=now,
                        )
                    )
                for probe in affected_probes:
                    termination_requests.append(
                        ControlService._ensure_work_termination_request(  # noqa: SLF001
                            session,
                            work_kind="RECOVERY_PROBE",
                            work_id=probe.id,
                            reason_code=reason_code,
                            credential_secret_id=secret.id,
                            now=now,
                        )
                    )
            self._append_audit(
                session,
                organization=organization,
                project_id=project.id,
                action="DATASOURCE_SECRET_STATUS_CHANGED",
                actor_id=principal.user_id,
                target_type="DATASOURCE",
                target_id=datasource.id,
                target_name=datasource.name,
                changed_fields=[
                    "credential_status",
                    "datasource_status",
                    *(["work_termination_requests"] if termination_requests else []),
                ],
                audit=audit,
                metadata={
                    "secret_version": secret.secret_version,
                    "reason_code": request.reason_code,
                    "affected_nonterminal_execution_count": len(affected_executions),
                    "affected_nonterminal_recovery_probe_count": len(affected_probes),
                    "termination_request_ids": [str(item.id) for item in termination_requests],
                },
            )
            response = self._secret_summary(session, secret)
            self._complete_idempotency(
                session,
                actor_id=principal.user_id,
                scope="POST /datasources/{datasource_id}/credential-secrets/{version}/status",
                key=idempotency_key,
                status=200,
                body=response.model_dump(mode="json"),
                resource_type="DATASOURCE",
                resource_id=datasource.id,
            )
            return OperationResult(response)

    def get_admin_detail(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
    ) -> DatasourceAdminDetail:
        self._require_admin(principal)
        with self.sessions() as session:
            datasource, _, _ = self._datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            return self._admin_detail(session, datasource)

    def get_redacted(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
    ) -> DatasourceRedactedSummary:
        with self.sessions() as session:
            datasource, _, _ = self._datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            return self._redacted_summary(session, datasource)

    def list_datasources(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        cursor: str | None = None,
        limit: int = 50,
        engine: str | None = None,
    ) -> DatasourcePage:
        with self.sessions() as session:
            self._visible_project(session, principal, project_id)
            cursor_scope = self._cursor_scope(
                "GET /projects/{project_id}/datasources",
                {
                    "project_id": str(project_id),
                    "engine": engine,
                    "order": "created_at_desc_id_desc",
                },
            )
            cursor_position = (
                self._decode_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    scope=cursor_scope,
                )
                if cursor is not None
                else None
            )
            filters = [
                Datasource.project_id == project_id,
                Datasource.status != "DELETED",
            ]
            if engine is not None:
                filters.append(
                    Datasource.current_revision_id.in_(
                        select(DatasourceRevision.id).where(DatasourceRevision.engine == engine)
                    )
                )
            if cursor_position is not None:
                created_at, datasource_id = cursor_position
                filters.append(
                    or_(
                        Datasource.created_at < created_at,
                        and_(
                            Datasource.created_at == created_at,
                            Datasource.id < datasource_id,
                        ),
                    )
                )
            rows = list(
                session.scalars(
                    select(Datasource)
                    .where(*filters)
                    .order_by(Datasource.created_at.desc(), Datasource.id.desc())
                    .limit(limit + 1)
                )
            )
            has_more = len(rows) > limit
            rows = rows[:limit]
            next_cursor = None
            if has_more and rows:
                last = rows[-1]
                next_cursor = self._encode_cursor(
                    actor_id=principal.user_id,
                    scope=cursor_scope,
                    created_at=ensure_aware(last.created_at),
                    resource_id=last.id,
                )
            return DatasourcePage(
                items=[self._redacted_summary(session, item) for item in rows],
                next_cursor=next_cursor,
                has_more=has_more,
            )

    def _acquire_datasource_operation_admission(
        self,
        *,
        admission: DatasourceOperationAdmissionGuard | None,
        organization_id: UUID,
        datasource_ids: tuple[UUID, ...],
        operation_kind: DatasourceOperationKind,
    ) -> DatasourceOperationAdmissionLease | None:
        """Take a non-blocking API ingress permit before external I/O.

        The public routes pass the app-scoped guard. Most operations acquire
        it before phase A; PATCH acquires it after phase A proves it needs a
        probe, keeping ordinary local control-plane edits available while the
        external lane is saturated. The optional argument keeps direct service
        tests and non-HTTP construction explicit without introducing a global
        mutable guard into the Worker credential service.
        """

        if admission is None:
            return None
        result = admission.try_acquire(
            organization_id=organization_id,
            datasource_ids=datasource_ids,
            operation_kind=operation_kind,
        )
        if isinstance(result, DatasourceOperationAdmissionRejection):
            raise ProblemException(
                status=429,
                code="DATASOURCE_OPERATION_ADMISSION_LIMITED",
                title="数据源外部操作暂时受限",
                detail="请等待后手动重新提交；系统没有执行本次外部连接。",
                retryable=True,
                headers={"Retry-After": str(result.retry_after_seconds)},
            )
        return result

    def _freeze_datasource_revision(
        self,
        revision: DatasourceRevision,
    ) -> FrozenDatasourceRevision:
        return FrozenDatasourceRevision(
            id=revision.id,
            datasource_id=revision.datasource_id,
            revision_no=revision.revision_no,
            endpoint_policy_revision_id=revision.endpoint_policy_revision_id,
            physical_endpoint_identity_id=revision.physical_endpoint_identity_id,
            engine=revision.engine,
            host=revision.host,
            port=revision.port,
            database_name=revision.database_name,
            default_schema=revision.default_schema,
            username=revision.username,
            ssl_mode=revision.ssl_mode,
            config_hash=revision.config_hash,
        )

    def _freeze_endpoint_policy(
        self,
        *,
        policy: EndpointPolicy,
        revision: EndpointPolicyRevision,
    ) -> FrozenEndpointPolicy:
        return FrozenEndpointPolicy(
            id=revision.id,
            endpoint_policy_id=policy.id,
            endpoint_policy_current_revision_id=(policy.current_revision_id),
            endpoint_policy_status=policy.status,
            endpoint_policy_row_version=policy.row_version,
            revision_no=revision.revision_no,
            engine=revision.engine,
            host_kind=revision.host_kind,
            host_value=revision.host_value,
            allowed_cidrs=tuple(revision.allowed_cidrs),
            allowed_ports=tuple(revision.allowed_ports),
            tls_required=revision.tls_required,
            dns_ttl_ceiling_seconds=revision.dns_ttl_ceiling_seconds,
            resolver_policy_version=revision.resolver_policy_version,
            egress_policy_version=revision.egress_policy_version,
            policy_hash=revision.policy_hash,
        )

    def _strict_active_credential_binding(
        self,
        session: Session,
        *,
        datasource: Datasource,
        lock: bool,
        require_datasource_active: bool = True,
    ) -> tuple[CredentialSecret, CredentialSecretEnvelope, KekKeyVersion, FrozenCredentialBinding]:
        if (
            require_datasource_active and datasource.status != "ACTIVE"
        ) or datasource.current_secret_id is None:
            raise self._binding_unavailable()
        secret_statement = select(CredentialSecret).where(
            CredentialSecret.id == datasource.current_secret_id,
            CredentialSecret.datasource_id == datasource.id,
        )
        if lock:
            secret_statement = secret_statement.with_for_update()
        secret = session.scalar(secret_statement)
        if secret is None or secret.status != "ACTIVE":
            raise self._binding_unavailable()
        envelope_statement = select(CredentialSecretEnvelope).where(
            CredentialSecretEnvelope.credential_secret_id == secret.id,
            CredentialSecretEnvelope.status == "ACTIVE",
        )
        if lock:
            envelope_statement = envelope_statement.with_for_update()
        envelope = session.scalar(envelope_statement)
        if envelope is None:
            raise self._binding_unavailable()
        key_statement = select(KekKeyVersion).where(
            KekKeyVersion.key_version == envelope.kek_version,
        )
        if lock:
            key_statement = key_statement.with_for_update()
        key = session.scalar(key_statement)
        if (
            key is None
            or key.status not in {"ACTIVE", "DECRYPT_ONLY"}
            or key.purpose != "CREDENTIAL_DEK_WRAP"
            or key.wrapping_algorithm != WRAPPING_ALGORITHM
            or secret.data_algorithm != DATA_ALGORITHM
            or secret.aad_schema_version != AAD_SCHEMA_VERSION
            or envelope.wrapping_algorithm != WRAPPING_ALGORITHM
        ):
            raise self._binding_unavailable()
        return (
            secret,
            envelope,
            key,
            FrozenCredentialBinding(
                datasource_id=datasource.id,
                secret_id=secret.id,
                secret_version=secret.secret_version,
                secret_status=secret.status,
                envelope_id=envelope.id,
                envelope_version=envelope.envelope_version,
                envelope_status=envelope.status,
                kek_version=key.key_version,
                kek_status=key.status,
                kek_fingerprint_sha256=key.fingerprint_sha256,
                kek_wrapping_algorithm=key.wrapping_algorithm,
                data_algorithm=secret.data_algorithm,
                aad_schema_version=secret.aad_schema_version,
            ),
        )

    def _read_live_operation_authorization(
        self,
        session: Session,
        *,
        principal: Principal,
        project: Project,
        datasource: Datasource | None,
        usage: str | None,
    ) -> FrozenActorAuthorization:
        """Read exact live role/grant bindings without trusting a stale JWT.

        Authorization was already checked by the route, but a long external
        operation can overlap a role or grant revocation.  Both phase A and
        phase C call this helper under their short transactions so a detached
        result is never committed under a role/grant observed only at request
        entry.
        """

        # Do not trust the JWT's user flags after Phase A.  A password reset,
        # disable, or login lockout may commit while Phase B is performing
        # external I/O.  Lock and freeze the durable User row so Phase C
        # cannot publish a result under an account that is no longer active.
        user = session.scalar(
            select(User).where(User.id == principal.user_id).with_for_update()
        )
        if user is None or user.status != "ACTIVE":
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限执行数据源外部操作",
                detail="当前用户已被锁定、停用或不存在。",
            )
        if user.must_change_password:
            raise ProblemException(
                status=403,
                code="PASSWORD_CHANGE_REQUIRED",
                title="必须先修改临时密码",
                detail="完成本人密码修改后才能执行数据源外部操作。",
            )
        auth_session = session.scalar(
            select(AuthSession)
            .where(
                AuthSession.id == principal.session_id,
                AuthSession.user_id == principal.user_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > utc_now(),
            )
            .with_for_update()
        )
        if auth_session is None:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限执行数据源外部操作",
                detail="当前登录会话已失效、过期或被撤回。",
            )
        membership = session.scalar(
            select(OrganizationMember)
            .where(
                OrganizationMember.organization_id == principal.organization_id,
                OrganizationMember.user_id == principal.user_id,
            )
            .with_for_update()
        )
        if membership is None or membership.status != MembershipStatus.ACTIVE:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限执行数据源外部操作",
                detail="当前组织成员资格已不可用。",
            )
        if principal.is_admin:
            role = session.scalar(
                select(RoleAssignment)
                .where(
                    RoleAssignment.organization_member_id == membership.id,
                    RoleAssignment.scope_type == ScopeType.ORGANIZATION,
                    RoleAssignment.scope_id == principal.organization_id,
                    RoleAssignment.role == Role.ADMIN,
                )
                .with_for_update()
            )
            if role is None:
                raise ProblemException(
                    status=403,
                    code="FORBIDDEN",
                    title="无权限执行数据源外部操作",
                    detail="组织级 Admin 权限已不可用。",
                )
            return FrozenActorAuthorization(
                actor_id=principal.user_id,
                actor_user_status=user.status,
                actor_user_row_version=user.row_version,
                session_id=principal.session_id,
                organization_id=principal.organization_id,
                project_id=project.id,
                organization_member_id=membership.id,
                organization_member_status=membership.status,
                actor_must_change_password=user.must_change_password,
                authorization_mode="ORGANIZATION_ADMIN",
                role_assignment_id=role.id,
                usage=usage,
                usage_grant_id=None,
                usage_grant_status=None,
                usage_grant_row_version=None,
            )
        if usage not in {"SOURCE_USE", "TARGET_USE"}:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限执行数据源外部操作",
                detail="需要组织级 Admin 或项目 Developer 权限。",
            )
        if datasource is None:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限执行数据源外部操作",
                detail="创建数据源需要组织级 Admin 权限。",
            )
        if not any(
            assignment.scope_type == ScopeType.PROJECT
            and assignment.scope_id == project.id
            and Role.DEVELOPER in assignment.roles
            for assignment in principal.role_assignments
        ):
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限读取数据源元数据",
                detail="需要当前项目 Developer 角色及有效数据源用途授权。",
            )
        role = session.scalar(
            select(RoleAssignment)
            .where(
                RoleAssignment.organization_member_id == membership.id,
                RoleAssignment.scope_type == ScopeType.PROJECT,
                RoleAssignment.scope_id == project.id,
                RoleAssignment.role == Role.DEVELOPER,
            )
            .with_for_update()
        )
        if role is None:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限读取数据源元数据",
                detail="需要当前项目 Developer 角色及有效数据源用途授权。",
            )
        grant = session.scalar(
            select(DatasourceUsageGrant)
            .where(
                DatasourceUsageGrant.datasource_id == datasource.id,
                DatasourceUsageGrant.organization_member_id == membership.id,
                DatasourceUsageGrant.usage == usage,
                DatasourceUsageGrant.status == "ACTIVE",
            )
            .with_for_update()
        )
        if grant is None:
            raise ProblemException(
                status=403,
                code="DATASOURCE_USAGE_NOT_GRANTED",
                title="缺少数据源用途授权",
                detail=f"Developer 缺少该数据源的 {usage} 元数据用途授权。",
            )
        return FrozenActorAuthorization(
            actor_id=principal.user_id,
            actor_user_status=user.status,
            actor_user_row_version=user.row_version,
            session_id=principal.session_id,
            organization_id=principal.organization_id,
            project_id=project.id,
            organization_member_id=membership.id,
            organization_member_status=membership.status,
            actor_must_change_password=user.must_change_password,
            authorization_mode="PROJECT_DEVELOPER",
            role_assignment_id=role.id,
            usage=usage,
            usage_grant_id=grant.id,
            usage_grant_status=grant.status,
            usage_grant_row_version=grant.row_version,
        )

    def _freeze_current_datasource_operation(
        self,
        session: Session,
        *,
        principal: Principal,
        organization: Organization,
        project: Project,
        datasource: Datasource,
        operation_kind: DatasourceOperationKind,
        usage: str | None,
        schema_name: str | None = None,
        table_name: str | None = None,
        limit: int | None = None,
        require_current_policy_active: bool = True,
        require_credential_binding: bool = True,
        require_datasource_active_for_credential: bool = True,
    ) -> DatasourceOperationSnapshot:
        if project.status != "ACTIVE":
            raise ProblemException(
                status=409,
                code="PROJECT_ARCHIVED",
                title="项目已归档",
                detail="归档项目不能执行数据源外部操作。",
            )
        revision = self._datasource_revision_record(session, datasource)
        policy_revision = session.get(
            EndpointPolicyRevision,
            revision.endpoint_policy_revision_id,
        )
        if policy_revision is None:
            raise self._binding_unavailable()
        policy = session.scalar(
            select(EndpointPolicy)
            .where(
                EndpointPolicy.id == policy_revision.endpoint_policy_id,
                EndpointPolicy.organization_id == organization.id,
            )
            .with_for_update()
        )
        if policy is None or policy.current_revision_id is None:
            raise ProblemException(
                status=409,
                code="ENDPOINT_POLICY_NOT_ACTIVE",
                title="端点策略不再有效",
                detail="当前数据源需要重新配置并验证。",
            )
        if require_current_policy_active and (
            policy.status != "ACTIVE" or policy.current_revision_id != policy_revision.id
        ):
            raise ProblemException(
                status=409,
                code="ENDPOINT_POLICY_NOT_ACTIVE",
                title="端点策略不再有效",
                detail="当前数据源需要重新配置并验证。",
            )
        actor_authorization = self._read_live_operation_authorization(
            session,
            principal=principal,
            project=project,
            datasource=datasource,
            usage=usage,
        )
        credential_binding: FrozenCredentialBinding | None = None
        if require_credential_binding:
            _, _, _, credential_binding = self._strict_active_credential_binding(
                session,
                datasource=datasource,
                lock=True,
                require_datasource_active=(require_datasource_active_for_credential),
            )
        return DatasourceOperationSnapshot(
            operation_kind=operation_kind,
            operation_id=uuid4(),
            organization_id=organization.id,
            organization_status=organization.status,
            organization_row_version=organization.row_version,
            project_id=project.id,
            project_status=project.status,
            project_row_version=project.row_version,
            datasource_id=datasource.id,
            datasource_status=datasource.status,
            datasource_row_version=datasource.row_version,
            datasource_current_revision_id=datasource.current_revision_id,
            datasource_current_secret_id=datasource.current_secret_id,
            datasource_revision=self._freeze_datasource_revision(revision),
            endpoint_policy=self._freeze_endpoint_policy(
                policy=policy,
                revision=policy_revision,
            ),
            credential_binding=credential_binding,
            actor_authorization=actor_authorization,
            metadata_usage=usage,
            metadata_schema_name=schema_name,
            metadata_table_name=table_name,
            metadata_limit=limit,
        )

    def _capture_test_operation_snapshot(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
    ) -> DatasourceOperationSnapshot:
        with self.sessions.begin() as session:
            datasource, project, organization = self._locked_datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            return self._freeze_current_datasource_operation(
                session,
                principal=principal,
                organization=organization,
                project=project,
                datasource=datasource,
                operation_kind=DatasourceOperationKind.TEST,
                usage=None,
            )

    def _capture_metadata_operation_snapshot(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        usage: str,
        schema_name: str | None,
        table_name: str | None,
        limit: int,
        cursor: str | None,
    ) -> DatasourceOperationSnapshot:
        with self.sessions.begin() as session:
            datasource, project, organization = self._locked_datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            # Preserve the existing cursor contract: a signed cursor is bound
            # to the authenticated actor and current revision before any
            # credential lookup.  This is still within phase A and performs no
            # outbound work; live authorization runs first so an unauthorized
            # caller cannot use cursor errors as an oracle.
            self._read_live_operation_authorization(
                session,
                principal=principal,
                project=project,
                datasource=datasource,
                usage=usage,
            )
            revision = self._datasource_revision_record(session, datasource)
            cursor_scope = self._cursor_scope(
                "GET /datasources/{datasource_id}/schema/tables",
                {
                    "datasource_id": str(datasource.id),
                    "datasource_revision_id": str(revision.id),
                    "usage": usage,
                    "schema_name": schema_name,
                    "table_name": table_name,
                    "order": "schema_name_asc_table_name_asc",
                },
            )
            after = (
                self._decode_table_cursor(
                    cursor,
                    actor_id=principal.user_id,
                    scope=cursor_scope,
                )
                if cursor is not None
                else None
            )
            snapshot = self._freeze_current_datasource_operation(
                session,
                principal=principal,
                organization=organization,
                project=project,
                datasource=datasource,
                operation_kind=DatasourceOperationKind.METADATA,
                usage=usage,
                schema_name=schema_name,
                table_name=table_name,
                limit=limit,
            )
            return replace(
                snapshot,
                metadata_cursor_scope=cursor_scope,
                metadata_after=after,
                metadata_cursor=cursor,
            )

    @staticmethod
    def _operation_stale() -> ProblemException:
        return ProblemException(
            status=409,
            code="DATASOURCE_OPERATION_STALE",
            title="数据源外部操作结果已过期",
            detail="数据源、凭据、授权或端点策略在探测期间发生变化；请刷新后手动重试。",
            retryable=True,
        )

    @staticmethod
    def _operation_deadline_problem(detail: str) -> ProblemException:
        """Return the single public outcome for an exhausted operation budget."""

        return ProblemException(
            status=503,
            code="DATASOURCE_OPERATION_DEADLINE_EXCEEDED",
            title="数据源外部操作超时",
            detail=detail,
            retryable=True,
        )

    @staticmethod
    def _is_product_database_deadline_error(exc: DBAPIError) -> bool:
        """Recognize the PostgreSQL errors caused by our transaction-local cap."""

        original = exc.orig
        sqlstate = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
        # 55P03 is lock_not_available (including lock_timeout); 57014 is the
        # query-canceled code used by statement_timeout.  Both can only be
        # interpreted as this operation's deadline after _deadline_transaction
        # has installed the remaining budget as a transaction-local setting.
        return sqlstate in {"55P03", "57014"}

    def _configure_deadline_transaction(
        self,
        session: Session,
        *,
        deadline: OperationDeadline,
    ) -> None:
        """Clamp product-DB lock and statement waits to the shared budget.

        The product database is PostgreSQL in the supported Windows topology.
        SQLite remains intentionally unconfigured for unit tests; the explicit
        pre/post checks still make an expired synthetic deadline fail closed.
        """

        remaining_ms = max(1, math.floor(deadline.check_expired() * 1000.0))
        if session.get_bind().dialect.name != "postgresql":
            return
        timeout = f"{remaining_ms}ms"
        session.execute(
            text("SELECT set_config('lock_timeout', :timeout, true)"),
            {"timeout": timeout},
        )
        deadline.check_expired()
        session.execute(
            text("SELECT set_config('statement_timeout', :timeout, true)"),
            {"timeout": timeout},
        )
        deadline.check_expired()

    @contextmanager
    def _deadline_transaction(self, deadline: OperationDeadline) -> Iterator[Session]:
        """Run a short product-DB phase without donating time beyond deadline.

        The final check occurs before the transaction context commits.  Thus a
        late C phase rolls back evidence, result state and audit writes instead
        of returning a successful response after the shared deadline.
        """

        deadline.check_expired()
        try:
            with self.sessions.begin() as session:
                self._configure_deadline_transaction(session, deadline=deadline)
                yield session
                deadline.check_expired()
        except DBAPIError as exc:
            if self._is_product_database_deadline_error(exc):
                raise OperationDeadlineExpired(
                    "DATASOURCE_OPERATION_DEADLINE_EXCEEDED"
                ) from exc
            raise

    def _copy_strict_current_credential_material(
        self,
        snapshot: DatasourceOperationSnapshot,
        *,
        deadline: OperationDeadline,
        require_datasource_active: bool = True,
    ) -> CurrentCredentialMaterial:
        """Perform B's short current-active credential barrier, then commit.

        No keyring file access, decrypt, resolver, lease, or connector call is
        allowed while this transaction is open.  The copied encrypted material
        is private and only survives long enough to decrypt outside the product
        database.
        """

        if (
            snapshot.datasource_id is None
            or snapshot.datasource_revision is None
            or snapshot.endpoint_policy is None
            or snapshot.credential_binding is None
        ):
            raise self._operation_stale()
        with self._deadline_transaction(deadline) as session:
            datasource = session.scalar(
                select(Datasource).where(Datasource.id == snapshot.datasource_id).with_for_update()
            )
            if datasource is None or datasource.project_id != snapshot.project_id:
                raise self._operation_stale()
            revision = self._datasource_revision_record(session, datasource)
            policy_revision = session.get(
                EndpointPolicyRevision,
                revision.endpoint_policy_revision_id,
            )
            if policy_revision is None:
                raise self._operation_stale()
            policy = session.scalar(
                select(EndpointPolicy)
                .where(EndpointPolicy.id == policy_revision.endpoint_policy_id)
                .with_for_update()
            )
            if policy is None:
                raise self._operation_stale()
            try:
                secret, envelope, key, binding = self._strict_active_credential_binding(
                    session,
                    datasource=datasource,
                    lock=True,
                    require_datasource_active=require_datasource_active,
                )
            except ProblemException as exc:
                raise self._operation_stale() from exc
            if not self._snapshot_security_matches(
                snapshot,
                datasource=datasource,
                revision=revision,
                policy=policy,
                policy_revision=policy_revision,
                binding=binding,
            ):
                raise self._operation_stale()
            if key.key_version != binding.kek_version:
                raise self._operation_stale()
            return CurrentCredentialMaterial(
                binding=binding,
                ciphertext=secret.ciphertext,
                nonce=secret.nonce,
                encrypted_dek=envelope.encrypted_dek,
            )

    @contextmanager
    def _decrypt_current_operation_material(
        self,
        *,
        snapshot: DatasourceOperationSnapshot,
        material: CurrentCredentialMaterial,
    ) -> Iterator[bytearray]:
        """Yield a zeroized current-credential password outside any DB lock."""

        plaintext = bytearray()
        try:
            binding = material.binding
            try:
                actual_fingerprint = self.keyring.fingerprint(binding.kek_version)
            except (OSError, ValueError) as exc:
                raise self._keyring_unavailable() from exc
            if not hmac.compare_digest(
                binding.kek_fingerprint_sha256,
                actual_fingerprint,
            ):
                raise self._keyring_unavailable()
            if snapshot.datasource_id is None:
                raise self._operation_stale()
            aad = build_credential_aad(
                organization_id=snapshot.organization_id,
                project_id=snapshot.project_id,
                datasource_id=snapshot.datasource_id,
                credential_secret_id=binding.secret_id,
                secret_version=binding.secret_version,
            )
            with self.keyring.open_key(binding.kek_version) as kek:
                plaintext = decrypt_credential(
                    ciphertext=material.ciphertext,
                    nonce=material.nonce,
                    encrypted_dek=material.encrypted_dek,
                    aad=aad,
                    kek=kek,
                )
            yield plaintext
        finally:
            zeroize(plaintext)

    def _snapshot_security_matches(
        self,
        snapshot: DatasourceOperationSnapshot,
        *,
        datasource: Datasource,
        revision: DatasourceRevision,
        policy: EndpointPolicy,
        policy_revision: EndpointPolicyRevision,
        binding: FrozenCredentialBinding,
    ) -> bool:
        frozen_revision = snapshot.datasource_revision
        frozen_policy = snapshot.endpoint_policy
        return (
            frozen_revision is not None
            and frozen_policy is not None
            and snapshot.datasource_status == datasource.status
            and snapshot.datasource_row_version == datasource.row_version
            and snapshot.datasource_current_revision_id == datasource.current_revision_id
            and snapshot.datasource_current_secret_id == datasource.current_secret_id
            and frozen_revision == self._freeze_datasource_revision(revision)
            and frozen_policy
            == self._freeze_endpoint_policy(
                policy=policy,
                revision=policy_revision,
            )
            and snapshot.credential_binding == binding
        )

    @staticmethod
    def _operation_snapshot_state_matches(
        snapshot: DatasourceOperationSnapshot,
        current: DatasourceOperationSnapshot,
    ) -> bool:
        """Compare the mutable authorization/security state, not operation ID.

        Phase C intentionally creates a fresh immutable snapshot.  Its random
        operation ID and request-only metadata therefore cannot participate in
        the equality decision; every datasource, policy, credential, and live
        authorization pointer that can invalidate phase B does.
        """

        return (
            snapshot.organization_id == current.organization_id
            and snapshot.organization_status == current.organization_status
            and snapshot.organization_row_version == current.organization_row_version
            and snapshot.project_id == current.project_id
            and snapshot.project_status == current.project_status
            and snapshot.project_row_version == current.project_row_version
            and snapshot.datasource_id == current.datasource_id
            and snapshot.datasource_status == current.datasource_status
            and snapshot.datasource_row_version == current.datasource_row_version
            and (snapshot.datasource_current_revision_id == current.datasource_current_revision_id)
            and (snapshot.datasource_current_secret_id == current.datasource_current_secret_id)
            and snapshot.datasource_revision == current.datasource_revision
            and snapshot.endpoint_policy == current.endpoint_policy
            and snapshot.credential_binding == current.credential_binding
            and snapshot.actor_authorization == current.actor_authorization
        )

    def _revalidate_datasource_operation_snapshot(
        self,
        session: Session,
        *,
        principal: Principal,
        snapshot: DatasourceOperationSnapshot,
    ) -> tuple[Datasource, Project, Organization]:
        """Phase C: live reauthorization plus complete security comparison."""

        if snapshot.datasource_id is None:
            raise self._operation_stale()
        try:
            datasource, project, organization = self._locked_datasource_context(
                session,
                principal=principal,
                datasource_id=snapshot.datasource_id,
            )
            current = self._freeze_current_datasource_operation(
                session,
                principal=principal,
                organization=organization,
                project=project,
                datasource=datasource,
                operation_kind=snapshot.operation_kind,
                usage=snapshot.metadata_usage,
                schema_name=snapshot.metadata_schema_name,
                table_name=snapshot.metadata_table_name,
                limit=snapshot.metadata_limit,
            )
        except ProblemException as exc:
            raise self._operation_stale() from exc
        if not self._operation_snapshot_state_matches(snapshot, current):
            raise self._operation_stale()
        return datasource, project, organization

    def test_datasource(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        request_id: UUID,
        audit: AuditContext,
        admission: DatasourceOperationAdmissionGuard | None = None,
    ) -> DatasourceTestResult:
        self._require_admin(principal)
        lease: DatasourceOperationAdmissionLease | None = None
        try:
            snapshot = self._capture_test_operation_snapshot(
                principal=principal,
                datasource_id=datasource_id,
            )
            assert snapshot.datasource_revision is not None
            assert snapshot.endpoint_policy is not None
            # A validates the datasource and authorization first.  Never let
            # a caller-selected, nonexistent UUID become retained process
            # admission state; acquire only for real external work after A
            # has committed and released its product locks.
            lease = self._acquire_datasource_operation_admission(
                admission=admission,
                organization_id=principal.organization_id,
                datasource_ids=(datasource_id,),
                operation_kind=DatasourceOperationKind.TEST,
            )
            deadline = OperationDeadline(self.operation_deadline_seconds)
            try:
                deadline.check_expired()
                material = self._copy_strict_current_credential_material(
                    snapshot,
                    deadline=deadline,
                )
                deadline.check_expired()
                with self._decrypt_current_operation_material(
                    snapshot=snapshot,
                    material=material,
                ) as password:
                    deadline.check_expired()
                    resolved = self.guard.resolve(
                        snapshot.endpoint_policy,
                        host=snapshot.datasource_revision.host,
                        port=snapshot.datasource_revision.port,
                        deadline=deadline,
                    )
                    deadline.check_expired()
                    self.guard.verify_rebinding(
                        snapshot.endpoint_policy,
                        resolved,
                        deadline=deadline,
                    )
                    deadline.check_expired()
                    probe = self.connector.probe(
                        snapshot.datasource_revision,
                        password=password,
                        resolved=resolved,
                        deadline=deadline,
                    )
                    deadline.check_expired()
            except OperationDeadlineExpired as exc:
                raise self._operation_deadline_problem(
                    "本次连接测试超过总时限；没有写入测试结果。"
                ) from exc
            except ProblemException:
                with self._deadline_transaction(deadline) as session:
                    self._revalidate_datasource_operation_snapshot(
                        session,
                        principal=principal,
                        snapshot=snapshot,
                    )
                raise
            except EgressAttestationError as exc:
                # Egress availability is a platform dependency, not a failed
                # user database credential test.  Do not overwrite the last
                # test fact or emit a success-shaped 200/audit result.
                if deadline.remaining_seconds() <= 0.0:
                    raise self._operation_deadline_problem(
                        "本次连接测试超过总时限；没有写入测试结果。"
                    ) from exc
                with self._deadline_transaction(deadline) as session:
                    self._revalidate_datasource_operation_snapshot(
                        session,
                        principal=principal,
                        snapshot=snapshot,
                    )
                # A failed attestation can arrive after the one shared
                # operation budget is already exhausted.  The deadline is
                # the primary public outcome in that case, consistently with
                # metadata reads and job validation; never expose a
                # connector-specific late error instead.
                raise self._safe_probe_problem(exc) from exc
            except Exception as exc:
                # Do this before constructing a FAILED test result or audit
                # event.  A resolver/connector may throw a generic timeout
                # after it consumed the shared budget.
                if deadline.remaining_seconds() <= 0.0:
                    raise self._operation_deadline_problem(
                        "本次连接测试超过总时限；没有写入测试结果。"
                    ) from exc
                code = self._safe_probe_error_code(exc)
                tested_at = utc_now()
                with self._deadline_transaction(deadline) as session:
                    datasource, project, organization = (
                        self._revalidate_datasource_operation_snapshot(
                            session,
                            principal=principal,
                            snapshot=snapshot,
                        )
                    )
                    deadline.check_expired()
                    datasource.last_test_status = "FAILED"
                    datasource.last_tested_at = tested_at
                    datasource.last_test_error_code = code
                    self._append_audit(
                        session,
                        organization=organization,
                        project_id=project.id,
                        action="DATASOURCE_TESTED",
                        actor_id=principal.user_id,
                        target_type="DATASOURCE",
                        target_id=datasource.id,
                        target_name=datasource.name,
                        changed_fields=["last_test_status", "last_tested_at"],
                        audit=audit,
                        metadata={"error_code": code},
                        outcome="FAILED",
                        reason_code=code,
                    )
                    return DatasourceTestResult(
                        status="FAILED",
                        tested_at=tested_at,
                        latency_ms=0,
                        server_version=None,
                        error_code=code,
                        message="连接测试失败；请检查端点策略、网络、TLS 与数据库账号。",
                        request_id=request_id,
                    )
            tested_at = utc_now()
            with self._deadline_transaction(deadline) as session:
                datasource, project, organization = self._revalidate_datasource_operation_snapshot(
                    session,
                    principal=principal,
                    snapshot=snapshot,
                )
                deadline.check_expired()
                revision = self._datasource_revision_record(session, datasource)
                self._persist_connection_evidence(
                    session,
                    operation_kind="TEST",
                    datasource_revision=revision,
                    resolved=resolved,
                    peer_ip=probe.peer_ip,
                    tls_peer_spki_sha256=probe.tls_peer_spki_sha256,
                    observed_at=tested_at,
                )
                datasource.last_test_status = "SUCCEEDED"
                datasource.last_tested_at = tested_at
                datasource.last_test_error_code = None
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=project.id,
                    action="DATASOURCE_TESTED",
                    actor_id=principal.user_id,
                    target_type="DATASOURCE",
                    target_id=datasource.id,
                    target_name=datasource.name,
                    changed_fields=["last_test_status", "last_tested_at"],
                    audit=audit,
                    metadata={"egress_enforcement_status": (resolved.egress_enforcement_status)},
                )
                return DatasourceTestResult(
                    status="SUCCEEDED",
                    tested_at=tested_at,
                    latency_ms=probe.latency_ms,
                    server_version=probe.server_version[:128],
                    error_code=None,
                    message="数据库连接、身份与端点策略检查通过。",
                    request_id=request_id,
                )
        except OperationDeadlineExpired as exc:
            raise self._operation_deadline_problem(
                "本次连接测试超过总时限；没有写入测试结果。"
            ) from exc
        finally:
            if lease is not None:
                lease.release()

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
        cursor: str | None = None,
        admission: DatasourceOperationAdmissionGuard | None = None,
        admission_lease: DatasourceOperationAdmissionLease | None = None,
        operation_deadline: OperationDeadline | None = None,
    ) -> TableSchemaPage:
        lease: DatasourceOperationAdmissionLease | None = None
        owns_admission_lease = False
        try:
            snapshot = self._capture_metadata_operation_snapshot(
                principal=principal,
                datasource_id=datasource_id,
                usage=usage,
                schema_name=schema_name,
                table_name=table_name,
                limit=limit,
                cursor=cursor,
            )
            assert snapshot.datasource_revision is not None
            assert snapshot.endpoint_policy is not None
            assert snapshot.metadata_cursor_scope is not None
            # See test_datasource(): only a datasource that passed A is
            # eligible to consume retained admission state or external I/O.
            if admission_lease is not None:
                if not admission_lease.covers(
                    organization_id=principal.organization_id,
                    datasource_ids=(datasource_id,),
                ):
                    raise RuntimeError("nested metadata admission lease does not cover datasource")
                lease = admission_lease
            else:
                lease = self._acquire_datasource_operation_admission(
                    admission=admission,
                    organization_id=principal.organization_id,
                    datasource_ids=(datasource_id,),
                    operation_kind=DatasourceOperationKind.METADATA,
                )
                owns_admission_lease = lease is not None
            # A transfer-policy scope operation has already atomically
            # admitted both endpoints.  It supplies one live deadline to both
            # nested reads; standalone metadata calls retain their own budget.
            deadline = operation_deadline or self.new_operation_deadline()
            try:
                deadline.check_expired()
                material = self._copy_strict_current_credential_material(
                    snapshot,
                    deadline=deadline,
                )
                deadline.check_expired()
                with self._decrypt_current_operation_material(
                    snapshot=snapshot,
                    material=material,
                ) as password:
                    deadline.check_expired()
                    resolved = self.guard.resolve(
                        snapshot.endpoint_policy,
                        host=snapshot.datasource_revision.host,
                        port=snapshot.datasource_revision.port,
                        deadline=deadline,
                    )
                    deadline.check_expired()
                    self.guard.verify_rebinding(
                        snapshot.endpoint_policy,
                        resolved,
                        deadline=deadline,
                    )
                    deadline.check_expired()
                    if resolved.egress_enforcement_status != "VERIFIED":
                        raise ProblemException(
                            status=503,
                            code="EGRESS_ENFORCEMENT_UNVERIFIED",
                            title="数据库出口强制策略尚未验证",
                            detail="出口策略获得独立 VERIFIED 证据前不能读取真实元数据。",
                            retryable=False,
                        )
                    snapshots, peer_ip, has_more = self.connector.schema_snapshots(
                        snapshot.datasource_revision,
                        physical_endpoint_identity_id=(
                            snapshot.datasource_revision.physical_endpoint_identity_id
                        ),
                        password=password,
                        resolved=resolved,
                        schema_name=snapshot.metadata_schema_name,
                        table_name=snapshot.metadata_table_name,
                        limit=limit,
                        after=snapshot.metadata_after,
                        deadline=deadline,
                    )
                    deadline.check_expired()
            except OperationDeadlineExpired as exc:
                raise self._operation_deadline_problem(
                    "本次 Schema 读取超过总时限；没有返回或保存旧结果。"
                ) from exc
            except ProblemException:
                with self._deadline_transaction(deadline) as session:
                    self._revalidate_datasource_operation_snapshot(
                        session,
                        principal=principal,
                        snapshot=snapshot,
                    )
                raise
            except EgressAttestationError as exc:
                if deadline.remaining_seconds() <= 0.0:
                    raise self._operation_deadline_problem(
                        "本次 Schema 读取超过总时限；没有返回或保存旧结果。"
                    ) from exc
                with self._deadline_transaction(deadline) as session:
                    self._revalidate_datasource_operation_snapshot(
                        session,
                        principal=principal,
                        snapshot=snapshot,
                    )
                raise self._safe_probe_problem(exc) from exc
            except Exception as exc:
                # A generic I/O timeout after the total budget is exhausted
                # has the deadline contract, not METADATA_UNAVAILABLE.
                if deadline.remaining_seconds() <= 0.0:
                    raise self._operation_deadline_problem(
                        "本次 Schema 读取超过总时限；没有返回或保存旧结果。"
                    ) from exc
                with self._deadline_transaction(deadline) as session:
                    self._revalidate_datasource_operation_snapshot(
                        session,
                        principal=principal,
                        snapshot=snapshot,
                    )
                raise ProblemException(
                    status=503,
                    code="DATASOURCE_METADATA_UNAVAILABLE",
                    title="无法读取真实数据库元数据",
                    detail="数据库连接、端点身份或 Schema 探针失败；没有生成替代元数据。",
                    retryable=_metadata_failure_retryable(exc),
                ) from exc
            captured_at = utc_now()
            with self._deadline_transaction(deadline) as session:
                datasource, project, organization = self._revalidate_datasource_operation_snapshot(
                    session,
                    principal=principal,
                    snapshot=snapshot,
                )
                deadline.check_expired()
                revision = self._datasource_revision_record(session, datasource)
                self._persist_connection_evidence(
                    session,
                    operation_kind="METADATA",
                    datasource_revision=revision,
                    resolved=resolved,
                    peer_ip=peer_ip,
                    tls_peer_spki_sha256=None,
                    observed_at=captured_at,
                )
                items = [self._table_schema(item, captured_at) for item in snapshots]
                self._append_audit(
                    session,
                    organization=organization,
                    project_id=project.id,
                    action="DATASOURCE_METADATA_READ",
                    actor_id=principal.user_id,
                    target_type="DATASOURCE",
                    target_id=datasource.id,
                    target_name=datasource.name,
                    changed_fields=[],
                    audit=audit,
                    metadata={
                        "table_count": len(items),
                        "column_count": sum(len(item.columns) for item in items),
                    },
                )
                next_cursor = None
                if has_more and snapshots:
                    last = snapshots[-1]
                    cursor_schema = (
                        snapshot.datasource_revision.default_schema
                        if snapshot.datasource_revision.engine == "MYSQL_8"
                        else last.schema_name
                    )
                    next_cursor = self._encode_table_cursor(
                        actor_id=principal.user_id,
                        scope=snapshot.metadata_cursor_scope,
                        schema_name=cursor_schema,
                        table_name=last.table_name,
                    )
                return TableSchemaPage(
                    items=items,
                    next_cursor=next_cursor,
                    has_more=has_more,
                )
        except OperationDeadlineExpired as exc:
            raise self._operation_deadline_problem(
                "本次 Schema 读取超过总时限；没有返回或保存旧结果。"
            ) from exc
        finally:
            if owns_admission_lease and lease is not None:
                lease.release()

    @staticmethod
    def _freeze_transfer_policy(policy: TransferPolicy) -> FrozenTransferPolicy:
        return FrozenTransferPolicy(
            id=policy.id,
            project_id=policy.project_id,
            source_datasource_revision_id=policy.source_datasource_revision_id,
            target_datasource_revision_id=policy.target_datasource_revision_id,
            source_physical_endpoint_identity_id=(policy.source_physical_endpoint_identity_id),
            target_physical_endpoint_identity_id=(policy.target_physical_endpoint_identity_id),
            status=policy.status,
            row_version=policy.row_version,
            scope_hash=policy.scope_hash,
        )

    @staticmethod
    def _freeze_target_namespace(
        namespace: TargetNamespace,
    ) -> FrozenTargetNamespace:
        return FrozenTargetNamespace(
            id=namespace.id,
            physical_endpoint_identity_id=namespace.physical_endpoint_identity_id,
            engine=namespace.engine,
            normalized_catalog_name=namespace.normalized_catalog_name,
            normalized_schema_name=namespace.normalized_schema_name,
            normalized_table_name=namespace.normalized_table_name,
            normalization_version=namespace.normalization_version,
            physical_table_identity_hash=namespace.physical_table_identity_hash,
        )

    def _job_validation_target_namespace(
        self,
        session: Session,
        *,
        revision: DatasourceRevision,
        schema_name: str,
        table_name: str,
    ) -> TargetNamespace:
        normalized_schema = "" if revision.engine == "MYSQL_8" else schema_name
        namespace = session.scalar(
            select(TargetNamespace)
            .where(
                TargetNamespace.physical_endpoint_identity_id
                == revision.physical_endpoint_identity_id,
                TargetNamespace.engine == revision.engine,
                TargetNamespace.normalized_catalog_name == revision.database_name,
                TargetNamespace.normalized_schema_name == normalized_schema,
                TargetNamespace.normalized_table_name == table_name,
                TargetNamespace.normalization_version == "1.0",
            )
            .with_for_update()
        )
        if namespace is None:
            raise ProblemException(
                status=409,
                code="TARGET_NAMESPACE_NOT_REGISTERED",
                title="目标物理表尚未完成授权登记",
                detail="ACTIVE TransferPolicy 必须绑定已登记的 TargetNamespace。",
            )
        return namespace

    def _capture_job_validation_operation(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        control_service: ControlService,
    ) -> JobValidationOperation:
        """Phase A: freeze a job and both datasource security bindings."""

        with self.sessions.begin() as session:
            visible_job = session.get(SyncJob, job_id)
            if visible_job is None:
                self._not_found()
            # The request principal can be rejected from its signed role scope
            # without taking any product row lock.  Only an eligible developer
            # may then briefly lock SystemControl before the organization; this
            # establishes the product-wide SystemControl -> Organization order
            # shared with Worker/reconciliation/retention paths.
            self._require_project_developer(principal, visible_job.project_id)
            # Terminal jobs are rejected before requiring live runtime proof.
            # This is a request-state decision, not a validation operation;
            # the locked checks below repeat it to close the edit race.
            if visible_job.status == "ARCHIVED":
                raise ProblemException(
                    status=409,
                    code="JOB_ARCHIVED",
                    title="任务已归档",
                    detail="归档任务不能执行校验。",
                )
            if visible_job.status == "PUBLISHED":
                raise ProblemException(
                    status=409,
                    code="JOB_PUBLISHED",
                    title="任务已发布",
                    detail="请先修改草稿创建新的 DRAFT，再执行校验。",
                )
            control_service.lock_runtime_validation_state(session)
            organization = self._lock_organization(session, principal.organization_id)
            project = self._visible_project(
                session,
                principal,
                visible_job.project_id,
                lock=True,
            )
            if project.status != "ACTIVE":
                raise ProblemException(
                    status=409,
                    code="PROJECT_ARCHIVED",
                    title="项目已归档",
                    detail="归档项目不能执行任务校验。",
                )
            self._require_project_developer(principal, project.id)
            job = session.scalar(
                select(SyncJob)
                .where(SyncJob.id == job_id, SyncJob.project_id == project.id)
                .with_for_update()
            )
            if job is None:
                self._not_found()
            if job.status == "ARCHIVED":
                raise ProblemException(
                    status=409,
                    code="JOB_ARCHIVED",
                    title="任务已归档",
                    detail="归档任务不能执行校验。",
                )
            if job.status == "PUBLISHED":
                raise ProblemException(
                    status=409,
                    code="JOB_PUBLISHED",
                    title="任务已发布",
                    detail="请先修改草稿创建新的 DRAFT，再执行校验。",
                )
            spec = JobSpecV1.model_validate(job.draft_spec_json)
            # SystemControl is already locked before Organization.  Resolve the
            # plugin-specific material while retaining that lock, then continue
            # with the product order Organization -> Project -> Job ->
            # Datasource -> immutable revision/policy facts.
            runtime = control_service.runtime_validation_material_for_plugins(
                session,
                reader_plugin_name=spec.source.plugin_name,
                writer_plugin_name=spec.target.plugin_name,
            )
            datasource_ids = sorted(
                {spec.source.datasource_id, spec.target.datasource_id},
                key=str,
            )
            datasources = {
                row.id: row
                for row in session.scalars(
                    select(Datasource)
                    .where(Datasource.id.in_(datasource_ids))
                    .order_by(Datasource.id)
                    .with_for_update()
                )
            }
            if set(datasources) != set(datasource_ids):
                self._not_found()
            # Keep the same product-row lock order as phase C: organization,
            # project, job, datasource, then immutable revision/policy facts.
            # A concurrent update therefore cannot deadlock validation merely
            # because phase A happened to lock revisions first.
            revision_ids = sorted(
                {
                    spec.source.datasource_revision_id,
                    spec.target.datasource_revision_id,
                },
                key=str,
            )
            revisions = {
                row.id: row
                for row in session.scalars(
                    select(DatasourceRevision)
                    .where(DatasourceRevision.id.in_(revision_ids))
                    .order_by(DatasourceRevision.id)
                    .with_for_update()
                )
            }
            if set(revisions) != set(revision_ids):
                self._not_found()
            source_datasource = datasources[spec.source.datasource_id]
            target_datasource = datasources[spec.target.datasource_id]
            source_revision = revisions[spec.source.datasource_revision_id]
            target_revision = revisions[spec.target.datasource_revision_id]
            if (
                source_revision.datasource_id != source_datasource.id
                or target_revision.datasource_id != target_datasource.id
                or source_datasource.project_id != project.id
                or target_datasource.project_id != project.id
                or source_datasource.current_revision_id != source_revision.id
                or target_datasource.current_revision_id != target_revision.id
                or source_datasource.status != "ACTIVE"
                or target_datasource.status != "ACTIVE"
            ):
                raise ProblemException(
                    status=409,
                    code="DATASOURCE_REVISION_NOT_CURRENT",
                    title="任务绑定的数据源修订已不是当前版本",
                    detail="请刷新元数据并更新任务草稿后重新校验。",
                )
            source = self._freeze_current_datasource_operation(
                session,
                principal=principal,
                organization=organization,
                project=project,
                datasource=source_datasource,
                operation_kind=DatasourceOperationKind.JOB_VALIDATION,
                usage="SOURCE_USE",
            )
            target = self._freeze_current_datasource_operation(
                session,
                principal=principal,
                organization=organization,
                project=project,
                datasource=target_datasource,
                operation_kind=DatasourceOperationKind.JOB_VALIDATION,
                usage="TARGET_USE",
            )
            if (
                source.datasource_revision is None
                or target.datasource_revision is None
                or source.datasource_revision.id != source_revision.id
                or target.datasource_revision.id != target_revision.id
            ):
                raise ProblemException(
                    status=409,
                    code="DATASOURCE_REVISION_NOT_CURRENT",
                    title="任务绑定的数据源修订已不是当前版本",
                    detail="请刷新元数据并更新任务草稿后重新校验。",
                )
            policy = self._matching_active_transfer_policy(
                session,
                project_id=project.id,
                spec=spec,
                source_revision=source_revision,
                target_revision=target_revision,
            )
            target_namespace = self._job_validation_target_namespace(
                session,
                revision=target_revision,
                schema_name=spec.target.table.schema_name,
                table_name=spec.target.table.table_name,
            )
            return JobValidationOperation(
                operation_id=uuid4(),
                job_id=job.id,
                project_id=project.id,
                project_status=project.status,
                project_row_version=project.row_version,
                job_status=job.status,
                job_row_version=job.row_version,
                job_draft_spec_hash=job.draft_spec_hash,
                source=source,
                target=target,
                transfer_policy=self._freeze_transfer_policy(policy),
                target_namespace=self._freeze_target_namespace(target_namespace),
                source_plugin_name=spec.source.plugin_name,
                target_plugin_name=spec.target.plugin_name,
                runtime=runtime,
                source_schema_name=spec.source.table.schema_name,
                source_table_name=spec.source.table.table_name,
                target_schema_name=spec.target.table.schema_name,
                target_table_name=spec.target.table.table_name,
            )

    def _acquire_job_validation_operation(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        control_service: ControlService,
        admission: DatasourceOperationAdmissionGuard | None,
    ) -> tuple[JobValidationOperation, DatasourceOperationAdmissionLease | None]:
        """Freeze valid A-time bindings, then atomically admit both endpoints.

        Capturing the operation before admission means untrusted job input can
        never create retained admission buckets for nonexistent datasource
        UUIDs.  Phase A writes no audit or business state and releases all
        product locks before the process-local guard is consulted.
        """

        operation = self._capture_job_validation_operation(
            principal=principal,
            job_id=job_id,
            control_service=control_service,
        )
        source_id = operation.source.datasource_id
        target_id = operation.target.datasource_id
        if source_id is None or target_id is None:
            raise self._operation_stale()
        datasource_ids = tuple(sorted({source_id, target_id}, key=str))
        lease = self._acquire_datasource_operation_admission(
            admission=admission,
            organization_id=principal.organization_id,
            datasource_ids=datasource_ids,
            operation_kind=DatasourceOperationKind.JOB_VALIDATION,
        )
        return operation, lease

    def _capture_validation_schema_probe(
        self,
        *,
        datasource: DatasourceOperationSnapshot,
        schema_name: str,
        table_name: str,
        deadline: OperationDeadline,
    ) -> ValidationSchemaProbe:
        """Phase B for one job-validation datasource; no product session lives."""

        if datasource.datasource_revision is None or datasource.endpoint_policy is None:
            raise self._operation_stale()
        try:
            deadline.check_expired()
            material = self._copy_strict_current_credential_material(
                datasource,
                deadline=deadline,
            )
            deadline.check_expired()
            with self._decrypt_current_operation_material(
                snapshot=datasource,
                material=material,
            ) as password:
                resolved = self.guard.resolve(
                    datasource.endpoint_policy,
                    host=datasource.datasource_revision.host,
                    port=datasource.datasource_revision.port,
                    deadline=deadline,
                )
                deadline.check_expired()
                self.guard.verify_rebinding(
                    datasource.endpoint_policy,
                    resolved,
                    deadline=deadline,
                )
                deadline.check_expired()
                if resolved.egress_enforcement_status != "VERIFIED":
                    raise ProblemException(
                        status=503,
                        code="EGRESS_ENFORCEMENT_UNVERIFIED",
                        title="数据库出口强制策略尚未验证",
                        detail="在容器出口策略获得独立 VERIFIED 证据前，任务校验保持阻断。",
                        retryable=False,
                    )
                snapshots, peer_ip, has_more = self.connector.schema_snapshots(
                    datasource.datasource_revision,
                    physical_endpoint_identity_id=(
                        datasource.datasource_revision.physical_endpoint_identity_id
                    ),
                    password=password,
                    resolved=resolved,
                    schema_name=schema_name,
                    table_name=table_name,
                    limit=1,
                    deadline=deadline,
                )
                deadline.check_expired()
        except (OperationDeadlineExpired, ProblemException):
            raise
        except EgressAttestationError as exc:
            # Egress attestation is a platform dependency, not a malformed
            # metadata request.  Preserve its stable code and retryability,
            # while still letting the single total deadline take precedence.
            deadline.check_expired()
            raise self._safe_probe_problem(exc) from exc
        except Exception as exc:
            # This helper is called inside validate_job(), whose outer
            # deadline path performs C revalidation before returning 503.
            # Preserve that path if a DNS/connector timeout arrives as an
            # ordinary exception at the deadline boundary.
            deadline.check_expired()
            raise ProblemException(
                status=503,
                code="DATASOURCE_METADATA_UNAVAILABLE",
                title="无法采集真实数据库 Schema",
                detail="数据库连接、端点身份或完整 Schema 探针失败；未生成替代快照。",
                retryable=_metadata_failure_retryable(exc),
            ) from exc
        if has_more or len(snapshots) != 1:
            raise ProblemException(
                status=422,
                code="SCHEMA_TABLE_NOT_UNIQUE",
                title="无法唯一解析任务物理表",
                detail="任务中的 catalog、schema 与 table 必须唯一命中一张基础表。",
            )
        snapshot = snapshots[0]
        expected_schema = "" if datasource.datasource_revision.engine == "MYSQL_8" else schema_name
        if (
            snapshot.engine != datasource.datasource_revision.engine
            or snapshot.physical_endpoint_identity_id
            != datasource.datasource_revision.physical_endpoint_identity_id
            or snapshot.catalog_name != datasource.datasource_revision.database_name
            or snapshot.schema_name != expected_schema
            or snapshot.table_name != table_name
        ):
            raise ProblemException(
                status=422,
                code="SCHEMA_SNAPSHOT_BINDING_MISMATCH",
                title="Schema 快照与数据源修订不匹配",
                detail="探针结果未精确绑定任务声明的引擎、物理端点和表身份。",
            )
        return ValidationSchemaProbe(
            snapshot=snapshot,
            resolved=resolved,
            peer_ip=peer_ip,
        )

    def _revalidate_job_validation_operation(
        self,
        session: Session,
        *,
        principal: Principal,
        operation: JobValidationOperation,
        control_service: ControlService,
    ) -> tuple[
        Organization,
        Project,
        SyncJob,
        DatasourceRevision,
        DatasourceRevision,
    ]:
        """Phase C: re-authorize every job/datasource/policy namespace fact."""

        try:
            organization = self._lock_organization(session, operation.source.organization_id)
            project = self._visible_project(
                session,
                principal,
                operation.project_id,
                lock=True,
            )
            if (
                project.status != "ACTIVE"
                or project.status != operation.project_status
                or project.row_version != operation.project_row_version
            ):
                raise self._operation_stale()
            job = session.scalar(
                select(SyncJob)
                .where(SyncJob.id == operation.job_id, SyncJob.project_id == project.id)
                .with_for_update()
            )
            if (
                job is None
                or job.status in {"ARCHIVED", "PUBLISHED"}
                or job.status != operation.job_status
                or job.row_version != operation.job_row_version
                or job.draft_spec_hash != operation.job_draft_spec_hash
            ):
                raise self._operation_stale()
            spec = JobSpecV1.model_validate(job.draft_spec_json)
            if (
                spec.source.table.schema_name != operation.source_schema_name
                or spec.source.table.table_name != operation.source_table_name
                or spec.target.table.schema_name != operation.target_schema_name
                or spec.target.table.table_name != operation.target_table_name
                or spec.source.plugin_name != operation.source_plugin_name
                or spec.target.plugin_name != operation.target_plugin_name
            ):
                raise self._operation_stale()
            runtime = control_service.runtime_validation_material_for_plugins(
                session,
                reader_plugin_name=spec.source.plugin_name,
                writer_plugin_name=spec.target.plugin_name,
            )
            datasource_ids = sorted(
                {
                    operation.source.datasource_id,
                    operation.target.datasource_id,
                },
                key=str,
            )
            if None in datasource_ids:
                raise self._operation_stale()
            datasources = {
                row.id: row
                for row in session.scalars(
                    select(Datasource)
                    .where(Datasource.id.in_(datasource_ids))
                    .order_by(Datasource.id)
                    .with_for_update()
                )
            }
            source_id = operation.source.datasource_id
            target_id = operation.target.datasource_id
            if source_id is None or target_id is None:
                raise self._operation_stale()
            source_datasource = datasources.get(source_id)
            target_datasource = datasources.get(target_id)
            if source_datasource is None or target_datasource is None:
                raise self._operation_stale()
            source_current = self._freeze_current_datasource_operation(
                session,
                principal=principal,
                organization=organization,
                project=project,
                datasource=source_datasource,
                operation_kind=DatasourceOperationKind.JOB_VALIDATION,
                usage="SOURCE_USE",
            )
            target_current = self._freeze_current_datasource_operation(
                session,
                principal=principal,
                organization=organization,
                project=project,
                datasource=target_datasource,
                operation_kind=DatasourceOperationKind.JOB_VALIDATION,
                usage="TARGET_USE",
            )
            if (
                not self._operation_snapshot_state_matches(
                    operation.source,
                    source_current,
                )
                or not self._operation_snapshot_state_matches(
                    operation.target,
                    target_current,
                )
                or source_current.datasource_revision is None
                or target_current.datasource_revision is None
                or source_current.datasource_revision.id != spec.source.datasource_revision_id
                or target_current.datasource_revision.id != spec.target.datasource_revision_id
            ):
                raise self._operation_stale()
            source_revision = self._datasource_revision_record(session, source_datasource)
            target_revision = self._datasource_revision_record(session, target_datasource)
            policy = self._matching_active_transfer_policy(
                session,
                project_id=project.id,
                spec=spec,
                source_revision=source_revision,
                target_revision=target_revision,
            )
            namespace = self._job_validation_target_namespace(
                session,
                revision=target_revision,
                schema_name=spec.target.table.schema_name,
                table_name=spec.target.table.table_name,
            )
        except ProblemException as exc:
            if exc.code == "DATASOURCE_OPERATION_STALE":
                raise
            raise self._operation_stale() from exc
        if (
            self._freeze_transfer_policy(policy) != operation.transfer_policy
            or self._freeze_target_namespace(namespace) != operation.target_namespace
            or runtime != operation.runtime
        ):
            raise self._operation_stale()
        return organization, project, job, source_revision, target_revision

    @staticmethod
    def _job_validation_issue_code(problem_code: str) -> str | None:
        return {
            "SOURCE_TARGET_SAME_TABLE": "SOURCE_TARGET_SAME_TABLE",
            "DATASOURCE_REVISION_NOT_CURRENT": "DATASOURCE_DISABLED",
            "DATASOURCE_DISABLED": "DATASOURCE_DISABLED",
            "TARGET_NAMESPACE_NOT_REGISTERED": "TARGET_TABLE_NOT_FOUND",
            "SCHEMA_SNAPSHOT_MAPPING_MISMATCH": "SCHEMA_DRIFT_DETECTED",
            "SCHEMA_SNAPSHOT_BINDING_MISMATCH": "SCHEMA_DRIFT_DETECTED",
            "SCHEMA_SNAPSHOT_INVALID": "SCHEMA_DRIFT_DETECTED",
            "SCHEMA_SNAPSHOT_HASH_MISMATCH": "SCHEMA_DRIFT_DETECTED",
            "TRANSFER_POLICY_NOT_ACTIVE": "JOB_SPEC_INVALID",
            "TRANSFER_SCOPE_DENIED": "JOB_SPEC_INVALID",
        }.get(problem_code)

    def validate_job(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        control_service: ControlService,
        audit: AuditContext,
        admission: DatasourceOperationAdmissionGuard | None = None,
    ) -> ValidationReport:
        """Run A/B/C validation and accept its job state in C's transaction."""

        # A-time rejection has no detached operation token that could prove a
        # later report still belongs to the same draft.  Return it directly:
        # persisting it in a second transaction could attach an old failure to
        # a concurrently edited draft.  B-time failures use the C finalizer
        # below, which revalidates every captured pointer atomically.
        operation, lease = self._acquire_job_validation_operation(
            principal=principal,
            job_id=job_id,
            control_service=control_service,
            admission=admission,
        )
        deadline = OperationDeadline(self.operation_deadline_seconds)
        try:

            def refresh_validation_database_deadline(session: Session) -> None:
                """Re-clamp one C-phase database step to the shared budget.

                Core invokes this hook while it owns its transaction.  Avoid
                an incidental ORM autoflush before PostgreSQL has received the
                new transaction-local lock/statement timeout; the next
                database operation (or the terminal explicit flush) performs
                the write under that freshly computed remainder.
                """

                with session.no_autoflush:
                    self._configure_deadline_transaction(session, deadline=deadline)

            def lock_runtime_before_validation_c(session: Session) -> None:
                """Lock C's runtime proof before Organization and map drift stale."""

                refresh_validation_database_deadline(session)
                try:
                    control_service.runtime_validation_material_for_plugins(
                        session,
                        reader_plugin_name=operation.source_plugin_name,
                        writer_plugin_name=operation.target_plugin_name,
                    )
                except ProblemException as exc:
                    # A was allowed only after a READY proof.  If C cannot
                    # obtain that same proof, B's result is stale rather than
                    # a fresh dependency failure that may be persisted.
                    if exc.code == "RUNTIME_ATTESTATION_UNAVAILABLE":
                        raise self._operation_stale() from exc
                    raise
                deadline.check_expired()

            def finalize_operation(session: Session) -> None:
                refresh_validation_database_deadline(session)
                self._revalidate_job_validation_operation(
                    session,
                    principal=principal,
                    operation=operation,
                    control_service=control_service,
                )
                deadline.check_expired()

            def assert_deadline_before_validation_commit(session: Session) -> None:
                # Do not merely read the clock: force all pending connection
                # evidence, validation state and audit rows through the
                # freshly-clamped database budget, then reject a late commit.
                # no_autoflush prevents set_config() itself from flushing the
                # pending writes before it has installed that budget.
                refresh_validation_database_deadline(session)
                session.flush()
                deadline.check_expired()

            def report_validation_failure(
                *,
                code: str,
                message: str,
            ) -> ValidationReport:
                return control_service.validation_failure_report(
                    principal=principal,
                    job_id=job_id,
                    code=code,
                    message=message,
                    audit=audit,
                    finalizer=finalize_operation,
                    pre_organization_lock=lock_runtime_before_validation_c,
                    before_database_step=refresh_validation_database_deadline,
                    before_commit=assert_deadline_before_validation_commit,
                )

            try:
                source_probe = self._capture_validation_schema_probe(
                    datasource=operation.source,
                    schema_name=operation.source_schema_name,
                    table_name=operation.source_table_name,
                    deadline=deadline,
                )
                target_probe = self._capture_validation_schema_probe(
                    datasource=operation.target,
                    schema_name=operation.target_schema_name,
                    table_name=operation.target_table_name,
                    deadline=deadline,
                )
                source_hash = schema_snapshot_hash(source_probe.snapshot)
                target_hash = schema_snapshot_hash(target_probe.snapshot)
            except OperationDeadlineExpired as exc:
                raise self._operation_deadline_problem(
                    "任务校验超过总时限；没有写入 Schema 证据或校验结果。"
                ) from exc
            except ProblemException as problem:
                issue_code = self._job_validation_issue_code(problem.code)
                if issue_code is None:
                    with self._deadline_transaction(deadline) as session:
                        lock_runtime_before_validation_c(session)
                        refresh_validation_database_deadline(session)
                        self._revalidate_job_validation_operation(
                            session,
                            principal=principal,
                            operation=operation,
                            control_service=control_service,
                        )
                    raise
                return report_validation_failure(
                    code=issue_code,
                    message=problem.detail or problem.title,
                )
            # Re-read the immutable job spec in phase C rather than retaining
            # an ORM object across B.  The finalizer will compare its hash and
            # pointers before it writes either evidence or the job report.
            with self._deadline_transaction(deadline) as session:
                job = session.get(SyncJob, operation.job_id)
                if job is None:
                    self._not_found()
                spec = JobSpecV1.model_validate(job.draft_spec_json)
            try:
                assert_snapshot_matches_job(
                    source_probe.snapshot,
                    expected_hash=source_hash,
                    spec=spec,
                    side="source",
                )
                assert_snapshot_matches_job(
                    target_probe.snapshot,
                    expected_hash=target_hash,
                    spec=spec,
                    side="target",
                )
            except RuntimeError:
                problem = ProblemException(
                    status=422,
                    code="SCHEMA_SNAPSHOT_MAPPING_MISMATCH",
                    title="真实 Schema 与任务映射不兼容",
                    detail="字段、类型、生成列、触发器或表结构不满足 V1 校验要求。",
                )
                return report_validation_failure(
                    code="SCHEMA_DRIFT_DETECTED",
                    message=problem.detail or problem.title,
                )
            if (
                source_probe.snapshot.physical_table_identity_hash
                == target_probe.snapshot.physical_table_identity_hash
            ):
                return report_validation_failure(
                    code="SOURCE_TARGET_SAME_TABLE",
                    message="V1 insert-only 一次性复制禁止自复制。",
                )
            material = ValidationMaterial(
                source_schema_snapshot=source_probe.snapshot.model_dump(mode="json"),
                target_schema_snapshot=target_probe.snapshot.model_dump(mode="json"),
                source_schema_hash=source_hash,
                target_schema_hash=target_hash,
                source_physical_table_identity_hash=(
                    source_probe.snapshot.physical_table_identity_hash
                ),
                target_namespace_id=operation.target_namespace.id,
                transfer_policy_id=operation.transfer_policy.id,
                transfer_policy_scope_hash=operation.transfer_policy.scope_hash,
                runtime_sha256=operation.runtime.runtime_sha256,
                reader_plugin_sha256=operation.runtime.reader_plugin_sha256,
                writer_plugin_sha256=operation.runtime.writer_plugin_sha256,
            )

            def finalize_success(session: Session) -> None:
                refresh_validation_database_deadline(session)
                (
                    _organization,
                    _project,
                    _job,
                    source_revision,
                    target_revision,
                ) = self._revalidate_job_validation_operation(
                    session,
                    principal=principal,
                    operation=operation,
                    control_service=control_service,
                )
                deadline.check_expired()
                refresh_validation_database_deadline(session)
                self._persist_connection_evidence(
                    session,
                    operation_kind="METADATA",
                    datasource_revision=source_revision,
                    resolved=source_probe.resolved,
                    peer_ip=source_probe.peer_ip,
                    tls_peer_spki_sha256=None,
                    observed_at=utc_now(),
                )
                deadline.check_expired()
                refresh_validation_database_deadline(session)
                self._persist_connection_evidence(
                    session,
                    operation_kind="METADATA",
                    datasource_revision=target_revision,
                    resolved=target_probe.resolved,
                    peer_ip=target_probe.peer_ip,
                    tls_peer_spki_sha256=None,
                    observed_at=utc_now(),
                )
                deadline.check_expired()

            try:
                accepted = control_service.accept_validation_material(
                    principal=principal,
                    job_id=job_id,
                    material=material,
                    audit=audit,
                    finalizer=finalize_success,
                    pre_organization_lock=lock_runtime_before_validation_c,
                    before_database_step=refresh_validation_database_deadline,
                    before_commit=assert_deadline_before_validation_commit,
                )
            except ProblemException as problem:
                # Core rejects malformed or no-longer-compatible material in
                # the same transaction that ran C; its evidence writes roll
                # back.  Re-run C before recording the mapped failure report.
                issue_code = self._job_validation_issue_code(problem.code)
                if issue_code is None:
                    raise
                return report_validation_failure(
                    code=issue_code,
                    message=problem.detail or problem.title,
                )
            return ValidationReport(
                valid=True,
                draft_spec_hash=accepted.draft_spec_hash,
                source_schema_hash=source_hash,
                target_schema_hash=target_hash,
                errors=[],
                warnings=[],
            )
        except OperationDeadlineExpired as exc:
            raise self._operation_deadline_problem(
                "任务校验超过总时限；没有写入 Schema 证据或校验结果。"
            ) from exc
        except DBAPIError as exc:
            if self._is_product_database_deadline_error(exc) or deadline.remaining_seconds() <= 0.0:
                raise self._operation_deadline_problem(
                    "任务校验超过总时限；没有写入 Schema 证据或校验结果。"
                ) from exc
            raise
        finally:
            if lease is not None:
                lease.release()

    # Persistence and serialization helpers.

    def _datasource_revision_record(
        self,
        session: Session,
        datasource: Datasource,
    ) -> DatasourceRevision:
        if datasource.current_revision_id is None:
            raise self._binding_unavailable()
        revision = session.scalar(
            select(DatasourceRevision).where(
                DatasourceRevision.id == datasource.current_revision_id,
                DatasourceRevision.datasource_id == datasource.id,
            )
        )
        if revision is None:
            raise self._binding_unavailable()
        return revision

    def _datasource_patch_candidate(
        self,
        session: Session,
        *,
        principal: Principal,
        current: DatasourceRevision,
        request: DatasourcePatch,
    ) -> tuple[DatasourceConnectionCandidate, EndpointPolicyRevision]:
        current_policy_revision = session.get(
            EndpointPolicyRevision,
            current.endpoint_policy_revision_id,
        )
        if current_policy_revision is None:
            raise self._binding_unavailable()
        policy_id = (
            request.endpoint_policy_id
            if "endpoint_policy_id" in request.model_fields_set
            else current_policy_revision.endpoint_policy_id
        )
        policy = session.scalar(
            select(EndpointPolicy)
            .where(
                EndpointPolicy.id == policy_id,
                EndpointPolicy.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
        if policy is None or policy.status != "ACTIVE" or policy.current_revision_id is None:
            raise ProblemException(
                status=422,
                code="ENDPOINT_POLICY_NOT_ACTIVE",
                title="端点策略不可用",
                detail="连接修订必须绑定当前有效的端点策略。",
            )
        policy_revision = session.get(
            EndpointPolicyRevision,
            policy.current_revision_id,
        )
        if policy_revision is None:
            raise ProblemException(
                status=422,
                code="ENDPOINT_POLICY_NOT_ACTIVE",
                title="端点策略当前修订不可用",
                detail="端点策略当前指针没有对应的不可变修订。",
            )

        engine = (
            request.engine.value
            if "engine" in request.model_fields_set and request.engine is not None
            else current.engine
        )
        host = (
            (
                request.host
                if "host" in request.model_fields_set and request.host is not None
                else current.host
            )
            .rstrip(".")
            .casefold()
        )
        candidate = DatasourceConnectionCandidate(
            engine=engine,
            host=host,
            port=(
                request.port
                if "port" in request.model_fields_set and request.port is not None
                else current.port
            ),
            database_name=(
                request.database_name
                if "database_name" in request.model_fields_set and request.database_name is not None
                else current.database_name
            ),
            default_schema=(
                request.default_schema
                if "default_schema" in request.model_fields_set
                and request.default_schema is not None
                else current.default_schema
            ),
            username=(
                request.username
                if "username" in request.model_fields_set and request.username is not None
                else current.username
            ),
            ssl_mode=(
                request.ssl_mode.value
                if "ssl_mode" in request.model_fields_set and request.ssl_mode is not None
                else current.ssl_mode
            ),
        )
        self._validate_connection_input(candidate)
        if policy_revision.engine != candidate.engine:
            raise ProblemException(
                status=422,
                code="ENDPOINT_POLICY_DENIED",
                title="端点策略不匹配",
                detail="数据源引擎与端点策略引擎不一致。",
            )
        if policy_revision.tls_required and candidate.ssl_mode == "DISABLE":
            raise ProblemException(
                status=422,
                code="ENDPOINT_POLICY_DENIED",
                title="端点策略要求 TLS",
                detail="该端点策略不允许关闭数据库 TLS。",
            )
        return candidate, policy_revision

    def _physical_identity_from_probe(
        self,
        session: Session,
        *,
        principal: Principal,
        organization: Organization,
        policy_revision: EndpointPolicyRevision,
        candidate: DatasourceConnectionCandidate,
        resolved: ResolvedEndpoint,
        probe: ProbeResult,
        now: datetime,
    ) -> PhysicalEndpointIdentity:
        identity_scheme = (
            "MYSQL_SERVER_UUID" if candidate.engine == "MYSQL_8" else "POSTGRES_SYSTEM_IDENTIFIER"
        )
        identity_hash = hashlib.sha256(
            (
                "DXPHYSICALENDPOINTv1\n"
                f"{str(organization.id).lower()}\n"
                f"{candidate.engine}\n"
                f"{identity_scheme}\n"
                f"{probe.server_identity}"
            ).encode()
        ).hexdigest()
        identity = session.scalar(
            select(PhysicalEndpointIdentity).where(
                PhysicalEndpointIdentity.organization_id == organization.id,
                PhysicalEndpointIdentity.engine == candidate.engine,
                PhysicalEndpointIdentity.identity_scheme == identity_scheme,
                PhysicalEndpointIdentity.server_identity_hash == identity_hash,
            )
        )
        if identity is not None:
            return identity
        evidence = {
            "schema_version": "1.0",
            "operation_kind": "TEST",
            "endpoint_policy_revision_id": str(policy_revision.id),
            "selected_ip": resolved.selected_ip,
            "peer_ip": probe.peer_ip,
            "server_version": probe.server_version[:128],
        }
        identity = PhysicalEndpointIdentity(
            id=uuid4(),
            organization_id=organization.id,
            engine=candidate.engine,
            identity_scheme=identity_scheme,
            server_identity_hash=identity_hash,
            verification_evidence=evidence,
            verification_evidence_hash=self._domain_hash(
                "DXPHYSICALENDPOINTEVIDENCEv1",
                evidence,
            ),
            created_by=principal.user_id,
            created_at=now,
        )
        session.add(identity)
        session.flush()
        return identity

    @staticmethod
    def _datasource_revision_config(
        *,
        policy_revision: EndpointPolicyRevision,
        physical_endpoint_identity_id: UUID,
        candidate: DatasourceConnectionCandidate,
    ) -> dict[str, Any]:
        return {
            "endpoint_policy_revision_id": str(policy_revision.id),
            "physical_endpoint_identity_id": str(physical_endpoint_identity_id),
            "engine": candidate.engine,
            "host": candidate.host,
            "port": candidate.port,
            "database_name": candidate.database_name,
            "default_schema": candidate.default_schema,
            "username": candidate.username,
            "ssl_mode": candidate.ssl_mode,
            "connection_options": {},
        }

    def _persist_new_datasource(
        self,
        session: Session,
        *,
        principal: Principal,
        project: Project,
        organization: Organization,
        request: DatasourceCreate,
        policy_revision: EndpointPolicyRevision,
        resolved: ResolvedEndpoint,
        probe: ProbeResult,
        password: bytearray,
        now: datetime,
        audit: AuditContext,
    ) -> Datasource:
        candidate = DatasourceConnectionCandidate(
            engine=request.engine.value,
            host=request.host.rstrip(".").casefold(),
            port=request.port,
            database_name=request.database_name,
            default_schema=request.default_schema,
            username=request.username,
            ssl_mode=request.ssl_mode.value,
        )
        identity = self._physical_identity_from_probe(
            session,
            principal=principal,
            organization=organization,
            policy_revision=policy_revision,
            candidate=candidate,
            resolved=resolved,
            probe=probe,
            now=now,
        )

        datasource = Datasource(
            id=uuid4(),
            project_id=project.id,
            name=request.name.strip(),
            description=request.description.strip() if request.description else None,
            current_revision_id=None,
            current_secret_id=None,
            status="DISABLED",
            created_by=principal.user_id,
            created_at=now,
            updated_at=now,
            row_version=1,
        )
        session.add(datasource)
        session.flush()
        config = self._datasource_revision_config(
            policy_revision=policy_revision,
            physical_endpoint_identity_id=identity.id,
            candidate=candidate,
        )
        revision = DatasourceRevision(
            id=uuid4(),
            datasource_id=datasource.id,
            revision_no=1,
            endpoint_policy_revision_id=policy_revision.id,
            physical_endpoint_identity_id=identity.id,
            engine=candidate.engine,
            host=candidate.host,
            port=candidate.port,
            database_name=candidate.database_name,
            default_schema=candidate.default_schema,
            username=candidate.username,
            ssl_mode=candidate.ssl_mode,
            connection_options={},
            config_hash=self._domain_hash("DXDATASOURCEREVISIONv1", config),
            created_by=principal.user_id,
            created_at=now,
        )
        session.add(revision)
        session.flush()
        datasource.current_revision_id = revision.id
        self._install_secret(
            session,
            organization_id=organization.id,
            project_id=project.id,
            datasource=datasource,
            password=password,
            actor_id=principal.user_id,
            now=now,
        )
        datasource.status = "ACTIVE"
        self._persist_connection_evidence(
            session,
            operation_kind="TEST",
            datasource_revision=revision,
            resolved=resolved,
            peer_ip=probe.peer_ip,
            tls_peer_spki_sha256=probe.tls_peer_spki_sha256,
            observed_at=now,
        )
        self._append_audit(
            session,
            organization=organization,
            project_id=project.id,
            action="DATASOURCE_CREATED",
            actor_id=principal.user_id,
            target_type="DATASOURCE",
            target_id=datasource.id,
            target_name=datasource.name,
            changed_fields=[
                "current_revision_id",
                "current_secret_id",
                "status",
            ],
            audit=audit,
            metadata={
                "revision_id": str(revision.id),
                "config_hash": revision.config_hash,
                "credential_configured": True,
                "egress_enforcement_status": resolved.egress_enforcement_status,
            },
        )
        return datasource

    def _install_secret(
        self,
        session: Session,
        *,
        organization_id: UUID,
        project_id: UUID,
        datasource: Datasource,
        password: bytearray,
        actor_id: UUID,
        now: datetime,
    ) -> CredentialSecret:
        key = session.scalar(
            select(KekKeyVersion)
            .where(
                KekKeyVersion.key_version == self.active_kek_version,
                KekKeyVersion.status == "ACTIVE",
            )
            .with_for_update()
        )
        if key is None:
            raise self._keyring_unavailable()
        try:
            fingerprint = self.keyring.fingerprint(key.key_version)
        except (OSError, ValueError) as exc:
            raise self._keyring_unavailable() from exc
        if not hmac.compare_digest(key.fingerprint_sha256, fingerprint):
            raise self._keyring_unavailable()
        version = (
            session.scalar(
                select(func.max(CredentialSecret.secret_version)).where(
                    CredentialSecret.datasource_id == datasource.id
                )
            )
            or 0
        ) + 1
        secret = CredentialSecret(
            id=uuid4(),
            datasource_id=datasource.id,
            secret_version=version,
            ciphertext=b"pending",
            nonce=b"\x00" * 12,
            data_algorithm=DATA_ALGORITHM,
            aad_schema_version=AAD_SCHEMA_VERSION,
            status="ACTIVE",
            created_by=actor_id,
            created_at=now,
            status_changed_at=now,
        )
        aad = build_credential_aad(
            organization_id=organization_id,
            project_id=project_id,
            datasource_id=datasource.id,
            credential_secret_id=secret.id,
            secret_version=version,
        )
        with self.keyring.open_key(key.key_version) as kek:
            encrypted = encrypt_credential(password, aad=aad, kek=kek)
        secret.ciphertext = encrypted.ciphertext
        secret.nonce = encrypted.nonce
        session.add(secret)
        session.flush()
        envelope = CredentialSecretEnvelope(
            id=uuid4(),
            credential_secret_id=secret.id,
            envelope_version=1,
            encrypted_dek=encrypted.encrypted_dek,
            kek_version=key.key_version,
            wrapping_algorithm=WRAPPING_ALGORITHM,
            status="ACTIVE",
            wrapped_dek_sha256=encrypted.wrapped_dek_sha256,
            created_by=actor_id,
            created_at=now,
        )
        session.add(envelope)
        session.flush()
        datasource.current_secret_id = secret.id
        return secret

    def _persist_connection_evidence(
        self,
        session: Session,
        *,
        operation_kind: str,
        datasource_revision: DatasourceRevision,
        resolved: ResolvedEndpoint,
        peer_ip: str | None,
        tls_peer_spki_sha256: str | None,
        observed_at: datetime,
        peer_observation_status: str = "OBSERVED",
        execution_id: UUID | None = None,
        recovery_probe_id: UUID | None = None,
        attempt_id: UUID | None = None,
        fence_epoch: int | None = None,
    ) -> EndpointConnectionEvidence:
        normalized_peer = str(peer_ip) if peer_ip is not None else None
        if peer_observation_status == "OBSERVED":
            if normalized_peer != resolved.selected_ip:
                raise ValueError("ENDPOINT_PEER_MISMATCH")
        elif (
            peer_observation_status != "ENFORCED_NOT_OBSERVED"
            or operation_kind != "DATAX"
            or normalized_peer is not None
        ):
            raise ValueError("ENDPOINT_PEER_OBSERVATION_INVALID")
        egress_document = {
            "schema_version": "1.0",
            "policy_version": resolved.egress_policy_version,
            "enforcement_status": resolved.egress_enforcement_status,
            "attestation_hash": resolved.egress_attestation_hash,
            "lease_evidence_hash": resolved.egress_evidence_hash,
            "selected_ip": resolved.selected_ip,
            "port": resolved.port,
        }
        egress_hash = self._domain_hash("DXEGRESSEVIDENCEv1", egress_document)
        document = {
            "schema_version": "1.0",
            "operation_kind": operation_kind,
            "datasource_revision_id": str(datasource_revision.id),
            "endpoint_policy_revision_id": str(datasource_revision.endpoint_policy_revision_id),
            "execution_id": str(execution_id) if execution_id else None,
            "recovery_probe_id": (str(recovery_probe_id) if recovery_probe_id else None),
            "attempt_id": str(attempt_id) if attempt_id else None,
            "fence_epoch": fence_epoch,
            "resolver_policy_version": resolved.resolver_policy_version,
            "cname_chain": list(resolved.cname_chain),
            "resolved_ips": list(resolved.resolved_ips),
            "selected_ip": resolved.selected_ip,
            "dns_valid_until": self._rfc3339(resolved.dns_valid_until),
            "egress_policy_version": resolved.egress_policy_version,
            "egress_enforcement_status": resolved.egress_enforcement_status,
            "egress_evidence_hash": egress_hash,
            "peer_observation_status": peer_observation_status,
            "peer_ip": normalized_peer,
            "tls_peer_spki_sha256": tls_peer_spki_sha256,
            "decision": "ALLOWED",
            "observed_at": self._rfc3339(observed_at),
        }
        evidence = EndpointConnectionEvidence(
            id=uuid4(),
            operation_kind=operation_kind,
            datasource_revision_id=datasource_revision.id,
            endpoint_policy_revision_id=datasource_revision.endpoint_policy_revision_id,
            execution_id=execution_id,
            recovery_probe_id=recovery_probe_id,
            attempt_id=attempt_id,
            fence_epoch=fence_epoch,
            resolver_policy_version=resolved.resolver_policy_version,
            cname_chain=list(resolved.cname_chain),
            resolved_ips=list(resolved.resolved_ips),
            selected_ip=resolved.selected_ip,
            dns_valid_until=resolved.dns_valid_until,
            egress_policy_version=resolved.egress_policy_version,
            egress_enforcement_status=resolved.egress_enforcement_status,
            egress_evidence_hash=egress_hash,
            peer_observation_status=peer_observation_status,
            peer_ip=normalized_peer,
            tls_peer_spki_sha256=tls_peer_spki_sha256,
            decision="ALLOWED",
            evidence_hash=self._domain_hash("DXENDPOINTCONNECTIONv1", document),
            observed_at=observed_at,
        )
        session.add(evidence)
        session.flush()
        return evidence

    def persist_worker_connection_evidence(
        self,
        session: Session,
        *,
        operation_kind: str,
        datasource_revision: DatasourceRevision,
        resolved: ResolvedEndpoint,
        peer_ip: str | None,
        tls_peer_spki_sha256: str | None,
        observed_at: datetime,
        peer_observation_status: str = "OBSERVED",
        execution_id: UUID | None,
        recovery_probe_id: UUID | None,
        attempt_id: UUID,
        fence_epoch: int,
    ) -> EndpointConnectionEvidence:
        """Persist immutable evidence owned by one independently fenced work item."""

        if operation_kind not in {
            "PREFLIGHT",
            "DATAX",
            "ORACLE",
            "RECOVERY_PROBE",
        }:
            raise ValueError("WORKER_EVIDENCE_OPERATION_INVALID")
        if (
            (execution_id is None) == (recovery_probe_id is None)
            or fence_epoch < 1
            or (operation_kind == "RECOVERY_PROBE" and recovery_probe_id is None)
            or (operation_kind != "RECOVERY_PROBE" and execution_id is None)
        ):
            raise ValueError("WORKER_EVIDENCE_OWNER_INVALID")
        if resolved.egress_enforcement_status != "VERIFIED" or ensure_aware(
            resolved.dns_valid_until
        ) < ensure_aware(observed_at):
            raise ValueError("WORKER_EVIDENCE_NETWORK_UNVERIFIED")
        return self._persist_connection_evidence(
            session,
            operation_kind=operation_kind,
            datasource_revision=datasource_revision,
            resolved=resolved,
            peer_ip=peer_ip,
            peer_observation_status=peer_observation_status,
            tls_peer_spki_sha256=tls_peer_spki_sha256,
            observed_at=observed_at,
            execution_id=execution_id,
            recovery_probe_id=recovery_probe_id,
            attempt_id=attempt_id,
            fence_epoch=fence_epoch,
        )

    def _current_secret_record(
        self,
        session: Session,
        datasource: Datasource,
    ) -> CredentialSecret:
        if datasource.current_secret_id is None:
            raise self._binding_unavailable()
        secret = session.get(CredentialSecret, datasource.current_secret_id)
        if secret is None:
            raise self._binding_unavailable()
        return secret

    def _assert_datasource_can_activate(
        self,
        session: Session,
        datasource: Datasource,
    ) -> None:
        self._current_revisions(session, datasource)
        secret = self._current_secret_record(session, datasource)
        if secret.status != "ACTIVE":
            raise self._binding_unavailable()
        envelope = session.scalar(
            select(CredentialSecretEnvelope).where(
                CredentialSecretEnvelope.credential_secret_id == secret.id,
                CredentialSecretEnvelope.status == "ACTIVE",
            )
        )
        if envelope is None:
            raise self._binding_unavailable()
        key = session.get(KekKeyVersion, envelope.kek_version)
        if key is None or key.status not in {"ACTIVE", "DECRYPT_ONLY"}:
            raise self._keyring_unavailable()
        try:
            fingerprint = self.keyring.fingerprint(key.key_version)
        except (OSError, ValueError) as exc:
            raise self._keyring_unavailable() from exc
        if not hmac.compare_digest(key.fingerprint_sha256, fingerprint):
            raise self._keyring_unavailable()

    def _current_revisions(
        self,
        session: Session,
        datasource: Datasource,
    ) -> tuple[DatasourceRevision, EndpointPolicyRevision]:
        if datasource.current_revision_id is None:
            raise self._binding_unavailable()
        revision = session.get(DatasourceRevision, datasource.current_revision_id)
        if revision is None:
            raise self._binding_unavailable()
        policy_revision = session.get(
            EndpointPolicyRevision,
            revision.endpoint_policy_revision_id,
        )
        policy = (
            session.get(EndpointPolicy, policy_revision.endpoint_policy_id)
            if policy_revision
            else None
        )
        if (
            policy_revision is None
            or policy is None
            or policy.status != "ACTIVE"
            or policy.current_revision_id != policy_revision.id
        ):
            raise ProblemException(
                status=409,
                code="ENDPOINT_POLICY_NOT_ACTIVE",
                title="端点策略不再有效",
                detail="当前数据源需要重新配置并验证。",
            )
        return revision, policy_revision

    def _normalize_endpoint_policy_patch(
        self,
        current: EndpointPolicyRevision,
        request: EndpointPolicyPatch,
    ) -> dict[str, Any]:
        fields = request.model_fields_set

        def selected(name: str) -> Any:
            return getattr(request, name) if name in fields else getattr(current, name)

        host_kind = str(selected("host_kind"))
        host = str(selected("host_value")).rstrip(".").casefold()
        try:
            parsed_ip = ipaddress.ip_address(host)
        except ValueError:
            parsed_ip = None
        if host_kind == "EXACT_IP":
            if parsed_ip is None:
                self._endpoint_policy_validation_problem(
                    "host_value",
                    "EXACT_IP 必须是规范化 IP。",
                )
            host = parsed_ip.compressed
        elif host_kind == "EXACT_FQDN":
            if parsed_ip is not None or not _HOSTNAME_PATTERN.fullmatch(host):
                self._endpoint_policy_validation_problem(
                    "host_value",
                    "EXACT_FQDN 必须是精确主机名。",
                )
        else:
            self._endpoint_policy_validation_problem(
                "host_kind",
                "host_kind 只能是 EXACT_FQDN 或 EXACT_IP。",
            )
        try:
            cidrs = sorted(
                {
                    ipaddress.ip_network(str(value), strict=False).with_prefixlen
                    for value in selected("allowed_cidrs")
                }
            )
        except (TypeError, ValueError):
            self._endpoint_policy_validation_problem(
                "allowed_cidrs",
                "CIDR 格式无效。",
            )
        ports = sorted({int(value) for value in selected("allowed_ports")})
        if not ports or len(ports) > 16 or any(port < 1 or port > 65535 for port in ports):
            self._endpoint_policy_validation_problem(
                "allowed_ports",
                "端口必须为 1..65535 且最多 16 个。",
            )
        policy_document = {
            "engine": current.engine,
            "host_kind": host_kind,
            "host_value": host,
            "allowed_cidrs": cidrs,
            "allowed_ports": ports,
            "tls_required": bool(selected("tls_required")),
            "dns_ttl_ceiling_seconds": int(selected("dns_ttl_ceiling_seconds")),
            "resolver_policy_version": self.guard.resolver_policy_version,
            "egress_policy_version": self.guard.egress_policy_version,
        }
        return {
            **policy_document,
            "policy_hash": self._domain_hash(
                "DXENDPOINTPOLICYv1",
                policy_document,
            ),
        }

    def _endpoint_policy_response(
        self,
        policy: EndpointPolicy,
        revision: EndpointPolicyRevision,
    ) -> EndpointPolicyResponse:
        if policy.current_revision_id != revision.id:
            raise RuntimeError("EndpointPolicy response revision is not current")
        return EndpointPolicyResponse(
            id=policy.id,
            organization_id=policy.organization_id,
            name=policy.name,
            current_revision_id=revision.id,
            current_revision_no=revision.revision_no,
            current_revision=self._endpoint_policy_revision_response(revision),
            status=policy.status,
            row_version=policy.row_version,
        )

    @staticmethod
    def _endpoint_policy_revision_response(
        revision: EndpointPolicyRevision,
    ) -> EndpointPolicyRevisionResponse:
        return EndpointPolicyRevisionResponse(
            id=revision.id,
            endpoint_policy_id=revision.endpoint_policy_id,
            revision_no=revision.revision_no,
            engine=revision.engine,
            host_kind=revision.host_kind,
            host_value=revision.host_value,
            allowed_cidrs=revision.allowed_cidrs,
            allowed_ports=revision.allowed_ports,
            tls_required=revision.tls_required,
            dns_ttl_ceiling_seconds=revision.dns_ttl_ceiling_seconds,
            resolver_policy_version=revision.resolver_policy_version,
            egress_policy_version=revision.egress_policy_version,
            policy_hash=revision.policy_hash,
            created_by=revision.created_by,
            created_at=ensure_aware(revision.created_at),
        )

    def _admin_detail(
        self,
        session: Session,
        datasource: Datasource,
    ) -> DatasourceAdminDetail:
        revision = self._datasource_revision_record(session, datasource)
        secret = session.get(CredentialSecret, datasource.current_secret_id)
        if secret is None:
            raise self._binding_unavailable()
        return DatasourceAdminDetail(
            id=datasource.id,
            project_id=datasource.project_id,
            name=datasource.name,
            description=datasource.description,
            engine=revision.engine,
            current_revision=self._revision_detail(revision),
            current_secret=self._secret_summary(session, secret),
            status=datasource.status,
            row_version=datasource.row_version,
            created_at=ensure_aware(datasource.created_at),
            updated_at=ensure_aware(datasource.updated_at),
        )

    def _redacted_summary(
        self,
        session: Session,
        datasource: Datasource,
    ) -> DatasourceRedactedSummary:
        revision = session.get(DatasourceRevision, datasource.current_revision_id)
        if revision is None:
            raise self._binding_unavailable()
        ready = False
        if datasource.current_secret_id is not None:
            secret = session.get(CredentialSecret, datasource.current_secret_id)
            ready = (
                datasource.status == "ACTIVE"
                and secret is not None
                and secret.status == "ACTIVE"
                and session.scalar(
                    select(CredentialSecretEnvelope.id).where(
                        CredentialSecretEnvelope.credential_secret_id == secret.id,
                        CredentialSecretEnvelope.status == "ACTIVE",
                    )
                )
                is not None
            )
        return DatasourceRedactedSummary(
            id=datasource.id,
            project_id=datasource.project_id,
            name=datasource.name,
            description=datasource.description,
            engine=revision.engine,
            credential_configured=datasource.current_secret_id is not None,
            current_revision_id=revision.id,
            current_revision_no=revision.revision_no,
            credential_status="READY" if ready else "UNAVAILABLE",
            last_test_status=datasource.last_test_status,
            last_tested_at=(
                ensure_aware(datasource.last_tested_at) if datasource.last_tested_at else None
            ),
            last_test_error_code=datasource.last_test_error_code,
            status=datasource.status,
            row_version=datasource.row_version,
            created_at=ensure_aware(datasource.created_at),
            updated_at=ensure_aware(datasource.updated_at),
        )

    def _revision_detail(
        self,
        revision: DatasourceRevision,
    ) -> DatasourceRevisionAdminDetail:
        return DatasourceRevisionAdminDetail(
            id=revision.id,
            datasource_id=revision.datasource_id,
            revision_no=revision.revision_no,
            endpoint_policy_revision_id=revision.endpoint_policy_revision_id,
            physical_endpoint_identity_id=revision.physical_endpoint_identity_id,
            engine=revision.engine,
            host=revision.host,
            port=revision.port,
            database_name=revision.database_name,
            default_schema=revision.default_schema,
            username=revision.username,
            ssl_mode=revision.ssl_mode,
            connection_options=revision.connection_options,
            config_hash=revision.config_hash,
            created_by=revision.created_by,
            created_at=ensure_aware(revision.created_at),
        )

    @staticmethod
    def _usage_grant_response(
        grant: DatasourceUsageGrant,
    ) -> DatasourceUsageGrantResponse:
        return DatasourceUsageGrantResponse(
            id=grant.id,
            datasource_id=grant.datasource_id,
            organization_member_id=grant.organization_member_id,
            usage=grant.usage,
            status=grant.status,
            granted_by=grant.granted_by,
            granted_at=ensure_aware(grant.granted_at),
        )

    def _secret_summary(
        self,
        session: Session,
        secret: CredentialSecret,
    ) -> CredentialSecretSummary:
        envelope = session.scalar(
            select(CredentialSecretEnvelope).where(
                CredentialSecretEnvelope.credential_secret_id == secret.id,
                CredentialSecretEnvelope.status == "ACTIVE",
            )
        )
        return CredentialSecretSummary(
            secret_version=secret.secret_version,
            status=secret.status,
            status_reason_code=secret.status_reason_code,
            status_changed_at=ensure_aware(secret.status_changed_at),
            created_at=ensure_aware(secret.created_at),
            active_envelope=(
                CredentialSecretEnvelopeSummary(
                    envelope_version=envelope.envelope_version,
                    kek_version=envelope.kek_version,
                    wrapping_algorithm=envelope.wrapping_algorithm,
                    status=envelope.status,
                    wrapped_dek_sha256=envelope.wrapped_dek_sha256,
                    created_at=ensure_aware(envelope.created_at),
                )
                if envelope
                else None
            ),
        )

    def _table_schema(
        self,
        snapshot: SchemaSnapshot,
        captured_at: datetime,
    ) -> TableSchema:
        primary_key_columns = {
            column
            for constraint in snapshot.constraints
            if constraint.kind == "PRIMARY_KEY"
            for column in constraint.columns
        }
        columns = [
            ColumnSchema(
                name=item.name,
                ordinal=item.ordinal_position,
                native_type=item.native_type,
                logical_type=item.logical_type,
                nullable=item.nullable,
                primary_key=item.name in primary_key_columns,
                generated=item.generated,
                identity=item.identity,
                character_maximum_length=item.character_maximum_length,
                numeric_precision=item.numeric_precision,
                numeric_scale=item.numeric_scale,
                datetime_precision=item.datetime_precision,
                oracle_supported=not item.generated,
                unsupported_reason=("GENERATED_COLUMN_UNSUPPORTED" if item.generated else None),
            )
            for item in snapshot.columns
        ]
        reasons: list[str] = []
        if any(item.generated for item in snapshot.columns):
            reasons.append("GENERATED_COLUMN_PRESENT")
        if any(item.enabled for item in snapshot.triggers):
            reasons.append("ENABLED_TRIGGER_PRESENT")
        if snapshot.table_options.partitioned:
            reasons.append("PARTITIONED_TABLE_UNSUPPORTED")
        if snapshot.table_options.row_security_enabled:
            reasons.append("ROW_SECURITY_ENABLED")
        return TableSchema(
            schema_name=snapshot.schema_name or snapshot.catalog_name,
            table_name=snapshot.table_name,
            physical_table_identity_hash=snapshot.physical_table_identity_hash,
            columns=columns,
            schema_hash=schema_snapshot_hash(snapshot),
            oracle_compatible=not reasons,
            target_insert_compatible=not reasons,
            incompatibility_reasons=reasons,
            captured_at=captured_at,
        )

    # Authorization, audit, idempotency, and validation helpers.

    def _require_admin(self, principal: Principal) -> None:
        if not principal.is_admin or principal.must_change_password:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限执行此操作",
                detail="需要有效的组织级 Admin 权限并完成首次改密。",
            )

    def _require_metadata_access(
        self,
        session: Session,
        *,
        principal: Principal,
        datasource: Datasource,
        project: Project,
        usage: str,
    ) -> None:
        if usage not in {"SOURCE_USE", "TARGET_USE"}:
            raise ValueError("metadata usage is invalid")
        if principal.must_change_password:
            raise ProblemException(
                status=403,
                code="PASSWORD_CHANGE_REQUIRED",
                title="必须先修改临时密码",
                detail="完成本人密码修改后才能读取数据源元数据。",
            )
        if principal.is_admin:
            return
        is_project_developer = any(
            assignment.scope_type == ScopeType.PROJECT
            and assignment.scope_id == project.id
            and Role.DEVELOPER in assignment.roles
            for assignment in principal.role_assignments
        )
        if not is_project_developer:
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限读取数据源元数据",
                detail="需要当前项目 Developer 角色及有效数据源用途授权。",
            )
        membership = session.scalar(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == principal.organization_id,
                OrganizationMember.user_id == principal.user_id,
                OrganizationMember.status == MembershipStatus.ACTIVE,
            )
        )
        if (
            membership is None
            or session.scalar(
                select(DatasourceUsageGrant.id).where(
                    DatasourceUsageGrant.datasource_id == datasource.id,
                    DatasourceUsageGrant.organization_member_id == membership.id,
                    DatasourceUsageGrant.usage == usage,
                    DatasourceUsageGrant.status == "ACTIVE",
                )
            )
            is None
        ):
            raise ProblemException(
                status=403,
                code="DATASOURCE_USAGE_NOT_GRANTED",
                title="缺少数据源用途授权",
                detail=f"Developer 缺少该数据源的 {usage} 元数据用途授权。",
            )

    def _require_project_developer(
        self,
        principal: Principal,
        project_id: UUID,
    ) -> None:
        if principal.must_change_password:
            raise ProblemException(
                status=403,
                code="PASSWORD_CHANGE_REQUIRED",
                title="必须先修改临时密码",
                detail="完成本人密码修改后才能校验任务。",
            )
        if principal.is_admin:
            return
        if not any(
            assignment.scope_type == ScopeType.PROJECT
            and assignment.scope_id == project_id
            and Role.DEVELOPER in assignment.roles
            for assignment in principal.role_assignments
        ):
            raise ProblemException(
                status=403,
                code="FORBIDDEN",
                title="无权限校验任务",
                detail="只有当前项目 Developer 或组织 Admin 可以校验任务。",
            )

    def _require_validation_datasource_grants(
        self,
        session: Session,
        *,
        principal: Principal,
        source_datasource_id: UUID,
        target_datasource_id: UUID,
    ) -> None:
        if principal.is_admin:
            return
        membership = session.scalar(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == principal.organization_id,
                OrganizationMember.user_id == principal.user_id,
                OrganizationMember.status == MembershipStatus.ACTIVE,
            )
        )
        if membership is None:
            raise ProblemException(
                status=403,
                code="DATASOURCE_USAGE_NOT_GRANTED",
                title="缺少数据源用途授权",
                detail="任务校验需要精确 SOURCE_USE 与 TARGET_USE 授权。",
            )
        grants = set(
            session.execute(
                select(
                    DatasourceUsageGrant.datasource_id,
                    DatasourceUsageGrant.usage,
                ).where(
                    DatasourceUsageGrant.organization_member_id == membership.id,
                    DatasourceUsageGrant.status == "ACTIVE",
                )
            ).all()
        )
        required = {
            (source_datasource_id, "SOURCE_USE"),
            (target_datasource_id, "TARGET_USE"),
        }
        if not required.issubset(grants):
            raise ProblemException(
                status=403,
                code="DATASOURCE_USAGE_NOT_GRANTED",
                title="缺少数据源用途授权",
                detail="任务校验需要精确 SOURCE_USE 与 TARGET_USE 授权。",
            )

    def _matching_active_transfer_policy(
        self,
        session: Session,
        *,
        project_id: UUID,
        spec: JobSpecV1,
        source_revision: DatasourceRevision,
        target_revision: DatasourceRevision,
    ) -> TransferPolicy:
        policies = list(
            session.scalars(
                select(TransferPolicy)
                .where(
                    TransferPolicy.project_id == project_id,
                    TransferPolicy.source_datasource_revision_id == source_revision.id,
                    TransferPolicy.target_datasource_revision_id == target_revision.id,
                    TransferPolicy.status == "ACTIVE",
                )
                .order_by(TransferPolicy.id)
                .with_for_update()
            )
        )
        matches = [
            policy
            for policy in policies
            if self._transfer_policy_scope_covers(
                policy,
                spec=spec,
                source_revision=source_revision,
                target_revision=target_revision,
            )
        ]
        if len(matches) != 1:
            raise ProblemException(
                status=409,
                code="TRANSFER_POLICY_NOT_ACTIVE",
                title="没有唯一匹配的 ACTIVE 传输授权",
                detail=(
                    "必须存在且只能存在一条精确覆盖当前 revision、表和列的 ACTIVE TransferPolicy。"
                ),
            )
        return matches[0]

    @staticmethod
    def _transfer_policy_scope_covers(
        policy: TransferPolicy,
        *,
        spec: JobSpecV1,
        source_revision: DatasourceRevision,
        target_revision: DatasourceRevision,
    ) -> bool:
        scope = policy.scope_json
        source_scope = scope.get("source")
        target_scope = scope.get("target")
        if not isinstance(source_scope, dict) or not isinstance(target_scope, dict):
            return False
        source_allowed = source_scope.get("allowed_columns")
        target_allowed = target_scope.get("allowed_columns")
        if not isinstance(source_allowed, list) or not isinstance(target_allowed, list):
            return False
        return (
            scope.get("schema_version") == "1.0"
            and source_scope.get("catalog") == source_revision.database_name
            and source_scope.get("schema") == spec.source.table.schema_name
            and source_scope.get("table") == spec.source.table.table_name
            and target_scope.get("catalog") == target_revision.database_name
            and target_scope.get("schema") == spec.target.table.schema_name
            and target_scope.get("table") == spec.target.table.table_name
            and {item.source_column for item in spec.mappings}.issubset(
                {str(value) for value in source_allowed}
            )
            and {item.target_column for item in spec.mappings}.issubset(
                {str(value) for value in target_allowed}
            )
        )

    def _visible_project(
        self,
        session: Session,
        principal: Principal,
        project_id: UUID,
        *,
        lock: bool = False,
    ) -> Project:
        if not principal.is_admin and project_id not in self._visible_project_ids(principal):
            self._not_found()
        statement = select(Project).where(
            Project.id == project_id,
            Project.organization_id == principal.organization_id,
        )
        if lock:
            statement = statement.with_for_update()
        project = session.scalar(statement)
        if project is None:
            self._not_found()
        return project

    def _visible_project_ids(self, principal: Principal) -> set[UUID]:
        return {
            assignment.scope_id
            for assignment in principal.role_assignments
            if assignment.scope_type == ScopeType.PROJECT
            and any(
                role in {Role.DEVELOPER, Role.OPERATOR, Role.VIEWER} for role in assignment.roles
            )
        }

    def _datasource_context(
        self,
        session: Session,
        *,
        principal: Principal,
        datasource_id: UUID,
    ) -> tuple[Datasource, Project, Organization]:
        datasource = session.get(Datasource, datasource_id)
        if datasource is None:
            self._not_found()
        project = self._visible_project(session, principal, datasource.project_id)
        organization = session.get(Organization, project.organization_id)
        if organization is None:
            self._not_found()
        return datasource, project, organization

    def _locked_datasource_context(
        self,
        session: Session,
        *,
        principal: Principal,
        datasource_id: UUID,
    ) -> tuple[Datasource, Project, Organization]:
        # Every mutating datasource path follows Organization -> Project ->
        # Datasource.  Worker claim takes its work row before Datasource; the
        # emergency status path does the same.  Keeping all API control paths
        # on this order avoids a status/rotation/delete deadlock that would
        # make an emergency revocation randomly roll back.
        project_id = session.scalar(
            select(Datasource.project_id)
            .join(Project, Project.id == Datasource.project_id)
            .where(
                Datasource.id == datasource_id,
                Project.organization_id == principal.organization_id,
            )
        )
        if project_id is None:
            self._not_found()
        if not principal.is_admin and project_id not in self._visible_project_ids(principal):
            self._not_found()
        organization = self._lock_organization(session, principal.organization_id)
        project = session.scalar(
            select(Project)
            .where(
                Project.id == project_id,
                Project.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
        if project is None:
            self._not_found()
        datasource = session.scalar(
            select(Datasource)
            .where(
                Datasource.id == datasource_id,
                Datasource.project_id == project.id,
            )
            .with_for_update()
        )
        if datasource is None:
            self._not_found()
        return datasource, project, organization

    @staticmethod
    def _lock_potential_work_for_secret_status(
        session: Session,
        *,
        secret_id: UUID,
        datasource_id: UUID,
    ) -> tuple[list[Execution], list[RecoveryProbe]]:
        """Lock work affected by an emergency secret status change.

        A queued work item deliberately has no CredentialSecret binding until
        the Worker claims it.  Its immutable datasource revision is therefore
        the only durable link to a *current* secret emergency.  Bound work is
        still selected by exact secret ID so revoking a retired secret keeps
        its existing active-work stop behavior without cancelling unrelated
        queued work.

        The caller always acquires Execution rows before RecoveryProbe rows,
        both in UUID order, before it locks Organization/Project/Datasource.
        That matches Worker claim writers and makes the current-secret
        decision after the datasource lock safe to apply to the rows held by
        this transaction.
        """

        revision_ids = select(DatasourceRevision.id).where(
            DatasourceRevision.datasource_id == datasource_id
        )
        queued_execution_reference = and_(
            Execution.process_state == "QUEUED",
            Execution.active_attempt_id.is_(None),
            or_(
                Execution.source_datasource_revision_id.in_(revision_ids),
                Execution.target_datasource_revision_id.in_(revision_ids),
            ),
        )
        bound_execution_reference = and_(
            Execution.process_state.not_in(_TERMINAL_EXECUTION_STATES),
            or_(
                Execution.source_secret_id == secret_id,
                Execution.target_secret_id == secret_id,
            ),
        )
        executions = list(
            session.scalars(
                select(Execution)
                .where(
                    Execution.authorization_mode == "STANDARD",
                    or_(bound_execution_reference, queued_execution_reference),
                )
                .order_by(Execution.id)
                .with_for_update()
            )
        )

        queued_probe_reference = and_(
            RecoveryProbe.process_state == "QUEUED",
            RecoveryProbe.active_attempt_id.is_(None),
            RecoveryProbe.target_datasource_revision_id.in_(revision_ids),
        )
        bound_probe_reference = and_(
            RecoveryProbe.process_state.in_(_ACTIVE_RECOVERY_PROBE_STATES),
            RecoveryProbe.target_secret_id == secret_id,
        )
        probes = list(
            session.scalars(
                select(RecoveryProbe)
                .join(RecoveryGate, RecoveryGate.id == RecoveryProbe.recovery_gate_id)
                .join(Execution, Execution.id == RecoveryGate.execution_id)
                .where(
                    Execution.authorization_mode == "STANDARD",
                    or_(bound_probe_reference, queued_probe_reference),
                )
                .order_by(RecoveryProbe.id)
                .with_for_update(of=RecoveryProbe)
            )
        )
        return executions, probes

    @staticmethod
    def _find_bound_work_for_secret(
        session: Session,
        *,
        secret_id: UUID,
    ) -> tuple[list[Execution], list[RecoveryProbe]]:
        """Read bound work after the datasource gate without reversing locks.

        The emergency path already locked all work visible before it acquired
        Organization/Project/Datasource.  This second read only discovers a
        Worker that won that first Work-row race and committed a binding before
        the datasource gate.  It must stay non-locking: Work -> Datasource is
        the global ordering, and Datasource -> Work would deadlock a concurrent
        claim.  The Worker re-checks the resulting durable request before it
        can start or block the queue item.
        """

        executions = list(
            session.scalars(
                select(Execution)
                .where(
                    Execution.authorization_mode == "STANDARD",
                    Execution.process_state.not_in(_TERMINAL_EXECUTION_STATES),
                    (Execution.source_secret_id == secret_id)
                    | (Execution.target_secret_id == secret_id),
                )
                .order_by(Execution.id)
            )
        )
        probes = list(
            session.scalars(
                select(RecoveryProbe)
                .join(RecoveryGate, RecoveryGate.id == RecoveryProbe.recovery_gate_id)
                .join(Execution, Execution.id == RecoveryGate.execution_id)
                .where(
                    Execution.authorization_mode == "STANDARD",
                    RecoveryProbe.process_state.in_(_ACTIVE_RECOVERY_PROBE_STATES),
                    RecoveryProbe.target_secret_id == secret_id,
                )
                .order_by(RecoveryProbe.id)
            )
        )
        return executions, probes

    @staticmethod
    def _find_queued_work_for_current_secret_status(
        session: Session,
        *,
        datasource_id: UUID,
    ) -> tuple[list[Execution], list[RecoveryProbe]]:
        """Find queued work created before the current datasource gate closed.

        This is intentionally a non-locking read.  All execution/probe
        producers serialize on the datasource row before enqueueing, so once
        the emergency transition holds that row no later producer can commit
        a new queue intention.  Locking Work rows here would invert the
        Worker claim's Work -> Datasource order.
        """

        revision_ids = select(DatasourceRevision.id).where(
            DatasourceRevision.datasource_id == datasource_id
        )
        executions = list(
            session.scalars(
                select(Execution)
                .where(
                    Execution.authorization_mode == "STANDARD",
                    Execution.process_state == "QUEUED",
                    Execution.active_attempt_id.is_(None),
                    or_(
                        Execution.source_datasource_revision_id.in_(revision_ids),
                        Execution.target_datasource_revision_id.in_(revision_ids),
                    ),
                )
                .order_by(Execution.id)
            )
        )
        probes = list(
            session.scalars(
                select(RecoveryProbe)
                .join(RecoveryGate, RecoveryGate.id == RecoveryProbe.recovery_gate_id)
                .join(Execution, Execution.id == RecoveryGate.execution_id)
                .where(
                    Execution.authorization_mode == "STANDARD",
                    RecoveryProbe.process_state == "QUEUED",
                    RecoveryProbe.active_attempt_id.is_(None),
                    RecoveryProbe.target_datasource_revision_id.in_(revision_ids),
                )
                .order_by(RecoveryProbe.id)
            )
        )
        return executions, probes

    def _lock_admin_datasource_context(
        self,
        session: Session,
        *,
        principal: Principal,
        datasource_id: UUID,
    ) -> tuple[Datasource, Project, Organization]:
        project_id = session.scalar(
            select(Datasource.project_id)
            .join(Project, Project.id == Datasource.project_id)
            .where(
                Datasource.id == datasource_id,
                Project.organization_id == principal.organization_id,
            )
        )
        if project_id is None:
            self._not_found()
        organization = self._lock_organization(
            session,
            principal.organization_id,
        )
        project = session.scalar(
            select(Project)
            .where(
                Project.id == project_id,
                Project.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
        if project is None:
            self._not_found()
        datasource = session.scalar(
            select(Datasource)
            .where(
                Datasource.id == datasource_id,
                Datasource.project_id == project.id,
            )
            .with_for_update()
        )
        if datasource is None:
            self._not_found()
        return datasource, project, organization

    @staticmethod
    def _database_now(session: Session) -> datetime:
        """Return the transaction database clock as an aware UTC instant."""

        value = session.scalar(select(func.current_timestamp()))
        if not isinstance(value, datetime):
            raise RuntimeError("database did not return current timestamp")
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def _datasource_active_reference(
        self,
        session: Session,
        *,
        datasource: Datasource,
        project: Project,
    ) -> str | None:
        revision_ids = list(
            session.scalars(
                select(DatasourceRevision.id)
                .where(DatasourceRevision.datasource_id == datasource.id)
                .order_by(DatasourceRevision.id)
            )
        )
        if not revision_ids:
            return "DATASOURCE_REVISION_MISSING"
        revision_reference = or_(
            JobVersion.source_datasource_revision_id.in_(revision_ids),
            JobVersion.target_datasource_revision_id.in_(revision_ids),
        )
        if session.scalar(
            select(JobVersion.id)
            .join(SyncJob, SyncJob.id == JobVersion.job_id)
            .where(
                SyncJob.status != "ARCHIVED",
                revision_reference,
            )
            .limit(1)
        ):
            return "NON_ARCHIVED_JOB_VERSION"
        jobs = list(
            session.scalars(
                select(SyncJob)
                .where(
                    SyncJob.project_id == project.id,
                    SyncJob.status != "ARCHIVED",
                )
                .order_by(SyncJob.id)
                .with_for_update()
            )
        )
        for job in jobs:
            try:
                source_id = job.draft_spec_json["source"]["datasource_id"]
                target_id = job.draft_spec_json["target"]["datasource_id"]
            except (KeyError, TypeError):
                return "JOB_DRAFT_REFERENCE_UNREADABLE"
            if str(datasource.id) in {str(source_id), str(target_id)}:
                return "NON_ARCHIVED_JOB_DRAFT"
        if session.scalar(
            select(TransferPolicy.id)
            .where(
                TransferPolicy.status.in_(_ACTIVE_TRANSFER_POLICY_STATES),
                or_(
                    TransferPolicy.source_datasource_revision_id.in_(revision_ids),
                    TransferPolicy.target_datasource_revision_id.in_(revision_ids),
                ),
            )
            .limit(1)
        ):
            return "ACTIVE_TRANSFER_POLICY"
        if session.scalar(
            select(Execution.id)
            .where(
                Execution.process_state.not_in(_TERMINAL_EXECUTION_STATES),
                or_(
                    Execution.source_datasource_revision_id.in_(revision_ids),
                    Execution.target_datasource_revision_id.in_(revision_ids),
                ),
            )
            .limit(1)
        ):
            return "NONTERMINAL_EXECUTION"
        if session.scalar(
            select(RecoveryProbe.id)
            .where(
                RecoveryProbe.process_state.in_(_ACTIVE_RECOVERY_PROBE_STATES),
                RecoveryProbe.target_datasource_revision_id.in_(revision_ids),
            )
            .limit(1)
        ):
            return "ACTIVE_RECOVERY_PROBE"
        if session.scalar(
            select(RecoveryGate.id)
            .join(Execution, Execution.id == RecoveryGate.execution_id)
            .where(
                RecoveryGate.status.in_(_ACTIVE_RECOVERY_GATE_STATES),
                or_(
                    Execution.source_datasource_revision_id.in_(revision_ids),
                    Execution.target_datasource_revision_id.in_(revision_ids),
                ),
            )
            .limit(1)
        ):
            return "ACTIVE_RECOVERY_GATE"
        return None

    def _lock_organization(
        self,
        session: Session,
        organization_id: UUID,
    ) -> Organization:
        organization = session.scalar(
            select(Organization).where(Organization.id == organization_id).with_for_update()
        )
        # Every Phase-C revalidation goes through this lock after external
        # I/O.  The request-time principal was authenticated while the
        # organization was active, but it may be suspended during Phase B;
        # fail closed rather than persist detached evidence/audit state.
        if organization is None or organization.status != "ACTIVE":
            self._not_found()
        return organization

    def _validate_connection_input(
        self,
        request: DatasourceCreate | DatasourceConnectionCandidate,
    ) -> None:
        engine = request.engine.value if hasattr(request.engine, "value") else request.engine
        if engine == "MYSQL_8" and request.default_schema != request.database_name:
            raise ProblemException(
                status=422,
                code="VALIDATION_ERROR",
                title="MySQL Schema 无效",
                detail="MySQL default_schema 必须等于 database_name。",
            )
        for value in (request.database_name, request.default_schema, request.username):
            if (
                any(ord(character) < 32 or ord(character) == 127 for character in value)
                or "/" in value
                or "\\" in value
                or "://" in value
            ):
                raise ProblemException(
                    status=422,
                    code="VALIDATION_ERROR",
                    title="连接标识无效",
                    detail="数据库名、Schema 或用户名包含禁止字符。",
                )
        ssl_mode = (
            request.ssl_mode.value if hasattr(request.ssl_mode, "value") else request.ssl_mode
        )
        if ssl_mode == "DISABLE":
            # The policy check below remains authoritative; this keeps the error
            # independent from connector behavior.
            pass

    def _claim_idempotency(
        self,
        session: Session,
        *,
        actor_id: UUID,
        scope: str,
        key: str,
        body: dict[str, Any],
        now: datetime,
    ) -> IdempotencyRecord | None:
        request_hash = self._idempotency_hash(actor_id=actor_id, scope=scope, body=body)
        existing = session.scalar(
            select(IdempotencyRecord)
            .where(
                IdempotencyRecord.actor_id == actor_id,
                IdempotencyRecord.scope == scope,
                IdempotencyRecord.idempotency_key == key,
            )
            .with_for_update()
        )
        if existing is not None and ensure_aware(existing.expires_at) <= now:
            session.delete(existing)
            session.flush()
            existing = None
        if existing is not None:
            if existing.request_hash_scheme != IDEMPOTENCY_HASH_SCHEME or not hmac.compare_digest(
                existing.request_hash, request_hash
            ):
                raise ProblemException(
                    status=409,
                    code="IDEMPOTENCY_CONFLICT",
                    title="Idempotency-Key 已用于不同请求",
                    detail="请为新的业务意图使用新的 Idempotency-Key。",
                )
            if existing.response_status is None or existing.response_body is None:
                raise ProblemException(
                    status=409,
                    code="IDEMPOTENCY_IN_PROGRESS",
                    title="相同请求仍在处理中",
                    detail="请稍后使用相同 Idempotency-Key 重试。",
                    retryable=True,
                    headers={"Retry-After": "1"},
                )
            return existing
        session.add(
            IdempotencyRecord(
                id=uuid4(),
                actor_id=actor_id,
                scope=scope,
                idempotency_key=key,
                request_hash=request_hash,
                request_hash_scheme=IDEMPOTENCY_HASH_SCHEME,
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )
        session.flush()
        return None

    def _credential_secret_status_replay_response(
        self,
        session: Session,
        *,
        record: IdempotencyRecord,
        datasource_id: UUID,
        secret_id: UUID,
        secret_version: int,
    ) -> CredentialSecretSummary:
        """Bind a template-scoped status replay to its datasource and secret."""

        if (
            record.resource_type != "DATASOURCE"
            or record.resource_id != datasource_id
            or record.response_status != 200
            or record.response_body is None
        ):
            raise self._idempotency_resource_conflict()
        secret = session.scalar(
            select(CredentialSecret)
            .where(
                CredentialSecret.id == secret_id,
                CredentialSecret.datasource_id == datasource_id,
                CredentialSecret.secret_version == secret_version,
            )
            .with_for_update()
        )
        if secret is None:
            raise self._idempotency_resource_conflict()
        try:
            response = CredentialSecretSummary.model_validate(record.response_body)
        except ValidationError as exc:
            raise self._idempotency_resource_conflict() from exc
        if response.secret_version != secret.secret_version:
            raise self._idempotency_resource_conflict()
        return response

    def _complete_idempotency(
        self,
        session: Session,
        *,
        actor_id: UUID,
        scope: str,
        key: str,
        status: int,
        body: dict[str, Any],
        resource_type: str,
        resource_id: UUID,
    ) -> None:
        record = session.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.actor_id == actor_id,
                IdempotencyRecord.scope == scope,
                IdempotencyRecord.idempotency_key == key,
            )
        )
        if record is None:
            raise RuntimeError("idempotency record disappeared")
        record.response_status = status
        record.response_body = body
        record.resource_type = resource_type
        record.resource_id = resource_id

    def _append_audit(
        self,
        session: Session,
        *,
        organization: Organization,
        project_id: UUID | None,
        action: str,
        actor_id: UUID | None,
        target_type: str,
        target_id: UUID | None,
        target_name: str | None,
        changed_fields: list[str],
        audit: AuditContext,
        metadata: dict[str, Any] | None = None,
        outcome: str = "SUCCEEDED",
        reason_code: str | None = None,
    ) -> None:
        # This is the serialization point used by every audit writer.  It is
        # intentionally taken before both the tail lookup and the watermark
        # CAS so PostgreSQL and SQLite share the same append invariant.
        session.execute(
            select(Organization.id).where(Organization.id == organization.id).with_for_update()
        ).scalar_one()
        previous = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization.id)
            .order_by(AuditEvent.organization_sequence.desc())
            .limit(1)
        )
        sequence = (previous.organization_sequence + 1) if previous else 1
        previous_hash = previous.event_hash if previous else None
        occurred_at = utc_now()
        event_id = uuid4()
        actor = session.get(User, actor_id) if actor_id else None
        event: dict[str, Any] = {
            "schema_version": "1.0",
            "event_id": str(event_id),
            "organization_id": str(organization.id),
            "sequence": sequence,
            "project_id": str(project_id) if project_id else None,
            "occurred_at": self._rfc3339(occurred_at),
            "action": action,
            "actor": {
                "kind": "USER" if actor else "SYSTEM",
                "user_id": str(actor.id) if actor else None,
                "display_name": actor.display_name if actor else None,
            },
            "target": {
                "type": target_type,
                "id": str(target_id) if target_id else None,
                "name": target_name,
            },
            "request": {
                "request_id": str(audit.request_id),
                "source_ip": audit.source_ip[:45] if audit.source_ip else None,
                "user_agent": self._safe_user_agent(audit.user_agent),
            },
            "outcome": outcome,
            "reason_code": reason_code,
            "changes": {
                "before_hash": None,
                "after_hash": None,
                "changed_fields": sorted(set(changed_fields)),
            },
            "metadata": metadata or {},
            "integrity": {
                "algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "chain_scope": "ORGANIZATION_SEQUENCE",
                "previous_hash": previous_hash,
            },
        }
        prefix = (
            "DXAUDITv1\n"
            f"{str(organization.id).lower()}\n"
            f"{sequence}\n"
            f"{previous_hash or ('0' * 64)}\n"
        ).encode()
        event_hash = hashlib.sha256(prefix + rfc8785.dumps(event)).hexdigest()
        event["integrity"]["event_hash"] = event_hash
        advance_audit_chain_watermark(
            session,
            organization_id=organization.id,
            previous_sequence=sequence - 1,
            previous_hash=previous_hash,
            sequence=sequence,
            event_hash=event_hash,
            updated_at=occurred_at,
        )
        session.add(
            AuditEvent(
                id=event_id,
                organization_id=organization.id,
                organization_sequence=sequence,
                project_id=project_id,
                event_json=event,
                canonicalization_version="RFC8785-v1",
                previous_hash=previous_hash,
                event_hash=event_hash,
                occurred_at=occurred_at,
                expires_at=occurred_at + timedelta(days=730),
            )
        )
        session.flush()

    def _password_request_fingerprint(self, password: bytearray) -> str:
        return self._password_request_fingerprint_cipher.encrypt(
            bytes(password),
            [_PASSWORD_REQUEST_FINGERPRINT_DOMAIN],
        ).hex()

    def _idempotency_hash(
        self,
        *,
        actor_id: UUID,
        scope: str,
        body: dict[str, Any],
    ) -> str:
        scope_bytes = scope.encode()
        canonical = rfc8785.dumps(body)
        message = b"".join(
            (
                _IDEMPOTENCY_HASH_DOMAIN,
                actor_id.bytes,
                len(scope_bytes).to_bytes(4, "big"),
                scope_bytes,
                len(canonical).to_bytes(8, "big"),
                canonical,
            )
        )
        return hmac.new(self.integrity_hmac_key, message, hashlib.sha256).hexdigest()

    def _safe_user_agent(self, user_agent: str | None) -> str | None:
        if user_agent is None:
            return None
        digest = hmac.new(
            self.integrity_hmac_key,
            _AUDIT_USER_AGENT_HASH_DOMAIN + user_agent.encode(errors="replace"),
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256-v1:{digest}"

    def _encode_cursor(
        self,
        *,
        actor_id: UUID,
        scope: str,
        created_at: datetime,
        resource_id: UUID,
    ) -> str:
        payload = {
            "v": 1,
            "actor_id": str(actor_id),
            "scope": scope,
            "timestamp": self._rfc3339(created_at),
            "resource_id": str(resource_id),
        }
        body = rfc8785.dumps(payload)
        signature = hmac.new(
            self.integrity_hmac_key,
            _CURSOR_DOMAIN + body,
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(body + signature).rstrip(b"=").decode("ascii")

    def _decode_cursor(
        self,
        cursor: str,
        *,
        actor_id: UUID,
        scope: str,
    ) -> tuple[datetime, UUID]:
        try:
            padding = "=" * (-len(cursor) % 4)
            decoded = base64.b64decode(
                cursor + padding,
                altchars=b"-_",
                validate=True,
            )
            if len(decoded) <= 32:
                raise ValueError
            body, signature = decoded[:-32], decoded[-32:]
            expected = hmac.new(
                self.integrity_hmac_key,
                _CURSOR_DOMAIN + body,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            payload = json.loads(body)
            if (
                payload.get("v") != 1
                or payload.get("actor_id") != str(actor_id)
                or payload.get("scope") != scope
            ):
                raise ValueError
            timestamp = datetime.fromisoformat(str(payload["timestamp"]).replace("Z", "+00:00"))
            return ensure_aware(timestamp), UUID(payload["resource_id"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            raise ProblemException(
                status=400,
                code="CURSOR_INVALID",
                title="分页游标无效",
                detail="请从第一页重新加载。",
            ) from None

    @staticmethod
    def _cursor_scope(route: str, filters: dict[str, object]) -> str:
        filters_hash = hashlib.sha256(rfc8785.dumps(filters)).hexdigest()
        return f"{route}:{filters_hash}"

    def _encode_table_cursor(
        self,
        *,
        actor_id: UUID,
        scope: str,
        schema_name: str,
        table_name: str,
    ) -> str:
        payload = {
            "v": 1,
            "kind": "TABLE_METADATA",
            "actor_id": str(actor_id),
            "scope": scope,
            "schema_name": schema_name,
            "table_name": table_name,
        }
        body = rfc8785.dumps(payload)
        signature = hmac.new(
            self.integrity_hmac_key,
            _CURSOR_DOMAIN + body,
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(body + signature).rstrip(b"=").decode("ascii")

    def _decode_table_cursor(
        self,
        cursor: str,
        *,
        actor_id: UUID,
        scope: str,
    ) -> tuple[str, str]:
        try:
            padding = "=" * (-len(cursor) % 4)
            decoded = base64.b64decode(
                cursor + padding,
                altchars=b"-_",
                validate=True,
            )
            if len(decoded) <= 32:
                raise ValueError
            body, signature = decoded[:-32], decoded[-32:]
            expected = hmac.new(
                self.integrity_hmac_key,
                _CURSOR_DOMAIN + body,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            payload = json.loads(body)
            schema_name = payload.get("schema_name")
            table_name = payload.get("table_name")
            if (
                payload.get("v") != 1
                or payload.get("kind") != "TABLE_METADATA"
                or payload.get("actor_id") != str(actor_id)
                or payload.get("scope") != scope
                or not isinstance(schema_name, str)
                or not isinstance(table_name, str)
                or len(schema_name) > 128
                or not 1 <= len(table_name) <= 128
            ):
                raise ValueError
            return schema_name, table_name
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            raise ProblemException(
                status=400,
                code="CURSOR_INVALID",
                title="分页游标无效",
                detail="请从第一页重新加载。",
            ) from None

    @staticmethod
    def _endpoint_policy_validation_problem(
        path: str,
        message: str,
    ) -> None:
        raise ProblemException(
            status=422,
            code="VALIDATION_ERROR",
            title="端点策略字段无效",
            detail=message,
            field_errors=[
                {
                    "path": path,
                    "code": "INVALID",
                    "message": message,
                }
            ],
        )

    @staticmethod
    def _domain_hash(domain: str, value: Any) -> str:
        return hashlib.sha256(domain.encode() + b"\n" + rfc8785.dumps(value)).hexdigest()

    @staticmethod
    def _rfc3339(value: datetime) -> str:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _safe_probe_error_code(exc: Exception) -> str:
        if isinstance(exc, ValueError):
            code = str(exc)
            if code and code.isascii() and code.replace("_", "").isalnum():
                return code[:64]
        return "DATABASE_CONNECTION_FAILED"

    def _safe_probe_problem(self, exc: Exception) -> ProblemException:
        code = self._safe_probe_error_code(exc)
        retryable = False
        if isinstance(exc, EgressAttestationError):
            # The egress guard/lease proof belongs to the platform security
            # boundary. Even malformed, mismatched, or newly introduced
            # attestation codes are never fixed by changing a datasource
            # payload, so expose them as fail-closed 503 dependencies. Only
            # the explicitly listed availability subset is manually retryable.
            status = 503
            retryable = code in _RETRYABLE_EGRESS_UNAVAILABLE_CODES
        elif code in {
            "DNS_RESOLUTION_FAILED",
            "KEK_KEYRING_UNAVAILABLE",
            "RESOLVER_POLICY_VERSION_MISMATCH",
            "EGRESS_POLICY_VERSION_MISMATCH",
        }:
            status = 503
            retryable = True
        else:
            # User endpoint-policy denial and endpoint identity mismatches
            # remain validation errors. EgressAttestationError itself was
            # handled above as a platform-security dependency failure.
            status = 422
        return ProblemException(
            status=status,
            code=code,
            title="数据源连接验证失败",
            detail="请检查端点策略、DNS、TLS 和数据库账号；系统未保存本次明文密码。",
            retryable=retryable,
        )

    @staticmethod
    def _binding_unavailable() -> ProblemException:
        return ProblemException(
            status=409,
            code="CREDENTIAL_BINDING_NOT_ACTIVE",
            title="凭据绑定不可用",
            detail="数据源没有可供新工作使用的 ACTIVE 凭据与 Envelope。",
        )

    @staticmethod
    def _keyring_unavailable() -> ProblemException:
        return ProblemException(
            status=503,
            code="KEK_KEYRING_UNAVAILABLE",
            title="凭据密钥环不可用",
            detail="所需 KEK 缺失、格式无效或指纹不匹配；系统已拒绝凭据操作。",
            retryable=False,
        )

    @staticmethod
    def _preflight_evidence_invalid() -> ProblemException:
        return ProblemException(
            status=409,
            code="PREFLIGHT_EVIDENCE_INVALID",
            title="运行前连接证据无效",
            detail="连接证据与当前 Execution、Attempt、fence 或已验证出口策略不匹配。",
        )

    @staticmethod
    def _idempotency_resource_conflict() -> ProblemException:
        return ProblemException(
            status=409,
            code="IDEMPOTENCY_CONFLICT",
            title="Idempotency-Key 已用于不同请求",
            detail="幂等键保存的资源或响应与当前请求不一致。",
        )

    @staticmethod
    def _not_found() -> None:
        raise ProblemException(
            status=404,
            code="NOT_FOUND",
            title="资源不存在",
            detail="资源不存在或当前用户无权访问。",
        )
