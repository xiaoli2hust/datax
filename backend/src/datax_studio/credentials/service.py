from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import rfc8785
from sqlalchemy import and_, create_engine, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from datax_studio.api.problems import ProblemException
from datax_studio.auth.db import (
    AuditEvent,
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
)
from datax_studio.core.schemas import (
    ClaimedExecution,
    CredentialBinding,
    EndpointPolicyResponse,
    EndpointPolicyRevisionResponse,
    JobSpecV1,
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
from datax_studio.credentials.keyring import KekKeyring, zeroize
from datax_studio.credentials.network import EndpointPolicyGuard, ResolvedEndpoint
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
from datax_studio.egress_attestation import LoopbackEgressAttestationClient
from datax_studio.recovery.db import RecoveryGate, RecoveryProbe
from datax_studio.schema_snapshot import SchemaSnapshot, schema_snapshot_hash
from datax_studio.settings import Settings
from datax_studio.worker.schema_probe import SchemaProbeError, assert_snapshot_matches_job

_LOGGER = logging.getLogger(__name__)
_IDEMPOTENCY_HASH_DOMAIN = b"DataXEnterpriseStudio\x00IdempotencyRequestHash\x00v1\x00"
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
    if (
        isinstance(exc, ValueError)
        and str(exc) in _NON_RETRYABLE_METADATA_VALUE_ERRORS
    ):
        return False
    sqlstate = getattr(exc, "sqlstate", None)
    if isinstance(sqlstate, str) and (
        sqlstate == "3D000"
        or sqlstate.startswith("28")
        or sqlstate.startswith("42")
    ):
        return False
    return not (
        exc.args
        and isinstance(exc.args[0], int)
        and exc.args[0] in _NON_RETRYABLE_MYSQL_ERROR_NUMBERS
    )


@dataclass(frozen=True)
class SchemaValidationMaterial:
    source_schema_snapshot: dict[str, Any]
    target_schema_snapshot: dict[str, Any]
    source_schema_hash: str
    target_schema_hash: str
    source_physical_table_identity_hash: str
    target_namespace_id: UUID
    transfer_policy_id: UUID
    transfer_policy_scope_hash: str


@dataclass(frozen=True)
class DatasourceConnectionCandidate:
    engine: str
    host: str
    port: int
    database_name: str
    default_schema: str
    username: str
    ssl_mode: str


def build_credential_service(settings: Settings) -> CredentialService:
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
    )
    service.ensure_active_kek_registered()
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
    ) -> None:
        if len(integrity_hmac_key) != 32:
            raise ValueError("integrity HMAC key must contain exactly 32 bytes")
        self.sessions = sessions
        self.keyring = keyring
        self.active_kek_version = active_kek_version
        self.integrity_hmac_key = integrity_hmac_key
        self.guard = guard
        self.connector = connector

    def ensure_active_kek_registered(self) -> None:
        try:
            fingerprint = self.keyring.fingerprint(self.active_kek_version)
        except (OSError, ValueError) as exc:
            raise self._keyring_unavailable() from exc
        now = utc_now()
        try:
            with self.sessions.begin() as session:
                active = session.scalar(
                    select(KekKeyVersion)
                    .where(KekKeyVersion.status == "ACTIVE")
                    .with_for_update()
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
        envelopes_by_secret = {
            envelope.credential_secret_id: envelope for envelope in envelopes
        }
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
                or ensure_aware(evidence.dns_valid_until)
                < ensure_aware(evidence.observed_at)
            ):
                raise self._preflight_evidence_invalid()

    @contextmanager
    def decrypted_password(
        self,
        session: Session,
        *,
        datasource_id: UUID,
        secret_id: UUID,
        envelope_id: UUID,
    ) -> Iterator[bytearray]:
        datasource = session.get(Datasource, datasource_id)
        secret = session.get(CredentialSecret, secret_id)
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
        plaintext = bytearray()
        try:
            with self.keyring.open_key(key.key_version) as kek:
                plaintext = decrypt_credential(
                    ciphertext=secret.ciphertext,
                    nonce=secret.nonce,
                    encrypted_dek=envelope.encrypted_dek,
                    aad=aad,
                    kek=kek,
                )
            yield plaintext
        finally:
            zeroize(plaintext)

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
                        EndpointPolicy.organization_id
                        == principal.organization_id,
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
                        EndpointPolicyRevision.id
                        == policy.current_revision_id,
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
                            EndpointPolicy.organization_id
                            == principal.organization_id,
                            EndpointPolicy.id != policy.id,
                            func.lower(EndpointPolicy.name)
                            == normalized_name.casefold(),
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
                config_fields = (
                    request.model_fields_set & _ENDPOINT_POLICY_CONFIG_FIELDS
                )
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
                            if policy.status == "DISABLED"
                            and changed_fields == ["status"]
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
                    EndpointPolicy.organization_id
                    == principal.organization_id,
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
            evidence = session.scalar(
                select(EndpointConnectionEvidence)
                .join(
                    DatasourceRevision,
                    DatasourceRevision.id
                    == EndpointConnectionEvidence.datasource_revision_id,
                )
                .join(
                    Datasource,
                    Datasource.id == DatasourceRevision.datasource_id,
                )
                .join(Project, Project.id == Datasource.project_id)
                .where(
                    EndpointConnectionEvidence.id == connection_evidence_id,
                    Project.organization_id == principal.organization_id,
                )
            )
            if evidence is None:
                self._not_found()
            return EndpointConnectionEvidenceResponse(
                id=evidence.id,
                operation_kind=evidence.operation_kind,
                datasource_revision_id=evidence.datasource_revision_id,
                endpoint_policy_revision_id=(
                    evidence.endpoint_policy_revision_id
                ),
                resolver_policy_version=evidence.resolver_policy_version,
                resolved_ips=[str(value) for value in evidence.resolved_ips],
                selected_ip=str(evidence.selected_ip),
                peer_observation_status=evidence.peer_observation_status,
                peer_ip=(
                    str(evidence.peer_ip)
                    if evidence.peer_ip is not None
                    else None
                ),
                egress_policy_version=evidence.egress_policy_version,
                egress_evidence_hash=evidence.egress_evidence_hash,
                decision=evidence.decision,
                evidence_hash=evidence.evidence_hash,
                observed_at=ensure_aware(evidence.observed_at),
            )

    def create_datasource(
        self,
        *,
        principal: Principal,
        project_id: UUID,
        request: DatasourceCreate,
        idempotency_key: str,
        audit: AuditContext,
    ) -> OperationResult[DatasourceAdminDetail]:
        self._require_admin(principal)
        password = bytearray(request.password.get_secret_value().encode("utf-8"))
        request_body = request.model_dump(mode="json", exclude={"password"})
        request_body["password_hmac"] = self._password_request_hmac(password)
        now = utc_now()
        try:
            with self.sessions.begin() as session:
                organization = self._lock_organization(session, principal.organization_id)
                project = self._visible_project(
                    session,
                    principal,
                    project_id,
                    lock=True,
                )
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
                        DatasourceAdminDetail.model_validate(replay.response_body),
                        replayed=True,
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
                if (
                    policy is None
                    or policy.status != "ACTIVE"
                    or policy.current_revision_id is None
                ):
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
                if policy_revision is None or policy_revision.engine != request.engine.value:
                    raise ProblemException(
                        status=422,
                        code="ENDPOINT_POLICY_DENIED",
                        title="端点策略不匹配",
                        detail="数据源引擎或连接端点不在允许范围。",
                    )
                if policy_revision.tls_required and request.ssl_mode.value == "DISABLE":
                    raise ProblemException(
                        status=422,
                        code="ENDPOINT_POLICY_DENIED",
                        title="端点策略要求 TLS",
                        detail="该端点策略不允许关闭数据库 TLS。",
                    )
                self._validate_connection_input(request)
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

                resolved = self.guard.resolve(
                    policy_revision,
                    host=request.host,
                    port=request.port,
                    now=now,
                )
                self.guard.verify_rebinding(policy_revision, resolved)
                probe = self.connector.probe(
                    request,
                    password=password,
                    resolved=resolved,
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
        except ProblemException:
            raise
        except IntegrityError as exc:
            raise ProblemException(
                status=409,
                code="DATASOURCE_CONFLICT",
                title="数据源创建冲突",
                detail="请刷新后重试。",
            ) from exc
        except Exception as exc:
            raise self._safe_probe_problem(exc) from exc
        finally:
            zeroize(password)

    def update_datasource(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        request: DatasourcePatch,
        expected_version: int,
        audit: AuditContext,
    ) -> DatasourceAdminDetail:
        self._require_admin(principal)
        password = (
            bytearray(request.password.get_secret_value().encode("utf-8"))
            if request.password is not None
            else None
        )
        probe_attempted = False
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
                now = utc_now()
                changed_fields: list[str] = []
                actions: list[str] = []
                connection_fields = (
                    request.model_fields_set & _DATASOURCE_REVISION_FIELDS
                )
                activating = (
                    "status" in request.model_fields_set
                    and request.status == "ACTIVE"
                    and datasource.status != "ACTIVE"
                )
                requires_probe = bool(
                    connection_fields or password is not None or activating
                )
                probe: ProbeResult | None = None
                resolved: ResolvedEndpoint | None = None
                candidate: DatasourceConnectionCandidate | None = None
                revision = self._datasource_revision_record(
                    session,
                    datasource,
                )
                policy_revision: EndpointPolicyRevision | None = None

                if connection_fields:
                    candidate, policy_revision = (
                        self._datasource_patch_candidate(
                            session,
                            principal=principal,
                            current=revision,
                            request=request,
                        )
                    )
                elif requires_probe:
                    revision, policy_revision = self._current_revisions(
                        session,
                        datasource,
                    )
                    candidate = DatasourceConnectionCandidate(
                        engine=revision.engine,
                        host=revision.host,
                        port=revision.port,
                        database_name=revision.database_name,
                        default_schema=revision.default_schema,
                        username=revision.username,
                        ssl_mode=revision.ssl_mode,
                    )

                if requires_probe:
                    assert candidate is not None
                    assert policy_revision is not None
                    probe_attempted = True
                    resolved = self.guard.resolve(
                        policy_revision,
                        host=candidate.host,
                        port=candidate.port,
                        now=now,
                    )
                    self.guard.verify_rebinding(policy_revision, resolved)
                    if password is not None:
                        probe = self.connector.probe(
                            candidate,
                            password=password,
                            resolved=resolved,
                        )
                    else:
                        current_secret = self._current_secret_record(
                            session,
                            datasource,
                        )
                        active_envelope = session.scalar(
                            select(CredentialSecretEnvelope).where(
                                CredentialSecretEnvelope.credential_secret_id
                                == current_secret.id,
                                CredentialSecretEnvelope.status == "ACTIVE",
                            )
                        )
                        if (
                            current_secret.status != "ACTIVE"
                            or active_envelope is None
                        ):
                            raise self._binding_unavailable()
                        with self.decrypted_password(
                            session,
                            datasource_id=datasource.id,
                            secret_id=current_secret.id,
                            envelope_id=active_envelope.id,
                        ) as current_password:
                            probe = self.connector.probe(
                                candidate,
                                password=current_password,
                                resolved=resolved,
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
                    config = self._datasource_revision_config(
                        policy_revision=policy_revision,
                        physical_endpoint_identity_id=identity.id,
                        candidate=candidate,
                    )
                    config_hash = self._domain_hash(
                        "DXDATASOURCEREVISIONv1",
                        config,
                    )
                    if config_hash != revision.config_hash:
                        revision = DatasourceRevision(
                            id=uuid4(),
                            datasource_id=datasource.id,
                            revision_no=revision.revision_no + 1,
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
                            config_hash=config_hash,
                            created_by=principal.user_id,
                            created_at=now,
                        )
                        session.add(revision)
                        session.flush()
                        datasource.current_revision_id = revision.id
                        changed_fields.extend(
                            [
                                *sorted(connection_fields),
                                "current_revision_id",
                            ]
                        )
                        actions.append("DATASOURCE_REVISION_CREATED")

                if "name" in request.model_fields_set:
                    assert request.name is not None
                    normalized_name = request.name.strip()
                    conflict = session.scalar(
                        select(Datasource.id).where(
                            Datasource.project_id == project.id,
                            Datasource.id != datasource.id,
                            func.lower(Datasource.name)
                            == normalized_name.casefold(),
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
                    description = (
                        request.description.strip() if request.description else None
                    )
                    if datasource.description != description:
                        datasource.description = description
                    changed_fields.append("description")
                    actions.append("DATASOURCE_UPDATED")
                if password is not None:
                    previous = session.get(
                        CredentialSecret,
                        datasource.current_secret_id,
                    )
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

                if requires_probe:
                    assert probe is not None
                    assert resolved is not None
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
                    changed_fields.extend(
                        [
                            "last_test_status",
                            "last_tested_at",
                            "last_test_error_code",
                        ]
                    )
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
                        "DATASOURCE_DISABLED"
                        if requested_status == "DISABLED"
                        else "DATASOURCE_UPDATED"
                    )
                if not changed_fields:
                    return self._admin_detail(session, datasource)
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
                        "connection_validated": requires_probe,
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
        except ProblemException:
            raise
        except IntegrityError as exc:
            raise ProblemException(
                status=409,
                code="DATASOURCE_CONFLICT",
                title="数据源更新冲突",
                detail="请刷新后重试。",
            ) from exc
        except Exception as exc:
            if probe_attempted:
                raise self._safe_probe_problem(exc) from exc
            raise
        finally:
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
            datasource, project, organization = (
                self._lock_admin_datasource_context(
                    session,
                    principal=principal,
                    datasource_id=datasource_id,
                )
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
                    *(
                        ["usage_grants"]
                        if grants
                        else []
                    ),
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
            datasource, project, organization = (
                self._lock_admin_datasource_context(
                    session,
                    principal=principal,
                    datasource_id=datasource_id,
                )
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
                    OrganizationMember.organization_id
                    == principal.organization_id,
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
                    RoleAssignment.role.in_(
                        (Role.DEVELOPER, Role.OPERATOR, Role.VIEWER)
                    ),
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
                        activated.append(usage)
                elif grant is not None and grant.status == "ACTIVE":
                    grant.status = "REVOKED"
                    grant.revoked_by = principal.user_id
                    grant.revoked_at = now
                    revoked.append(usage)
            session.flush()
            active = [
                existing[usage]
                for usage in ("SOURCE_USE", "TARGET_USE")
                if usage in existing and existing[usage].status == "ACTIVE"
            ]
            audit_actions = [
                *(
                    ["DATASOURCE_USAGE_GRANTED"]
                    if activated
                    else []
                ),
                *(
                    ["DATASOURCE_USAGE_REVOKED"]
                    if revoked
                    else []
                ),
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
                    changed_fields=(
                        ["usage_grants"]
                        if activated or revoked
                        else []
                    ),
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
        now = utc_now()
        with self.sessions.begin() as session:
            datasource, project, organization = self._locked_datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
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
                    CredentialSecretSummary.model_validate(replay.response_body),
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
            if secret.status != "ACTIVE":
                raise ProblemException(
                    status=409,
                    code="CREDENTIAL_STATUS_CONFLICT",
                    title="凭据状态不能再次变更",
                    detail="历史凭据不能重新激活或重复撤销。",
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
            if datasource.current_secret_id == secret.id:
                datasource.status = "DISABLED"
                datasource.row_version += 1
                datasource.updated_at = now
            affected = list(
                session.scalars(
                    select(Execution)
                    .where(
                        Execution.process_state.not_in(_TERMINAL_EXECUTION_STATES),
                        (
                            (Execution.source_secret_id == secret.id)
                            | (Execution.target_secret_id == secret.id)
                        ),
                    )
                    .with_for_update()
                )
            )
            for execution in affected:
                execution.queue_eligibility_state = "BLOCKED"
                execution.queue_block_reason = f"CREDENTIAL_{request.status}"
                execution.queue_state_changed_at = now
                execution.state_version += 1
            self._append_audit(
                session,
                organization=organization,
                project_id=project.id,
                action="DATASOURCE_SECRET_STATUS_CHANGED",
                actor_id=principal.user_id,
                target_type="DATASOURCE",
                target_id=datasource.id,
                target_name=datasource.name,
                changed_fields=["credential_status", "datasource_status"],
                audit=audit,
                metadata={
                    "secret_version": secret.secret_version,
                    "reason_code": request.reason_code,
                    "affected_nonterminal_execution_count": len(affected),
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
                        select(DatasourceRevision.id).where(
                            DatasourceRevision.engine == engine
                        )
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

    def test_datasource(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        request_id: UUID,
        audit: AuditContext,
    ) -> DatasourceTestResult:
        self._require_admin(principal)
        with self.sessions.begin() as session:
            datasource, project, organization = self._locked_datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            revision, policy_revision = self._current_revisions(session, datasource)
            secret, envelope = self._active_secret_and_envelope(session, datasource)
            resolved = self.guard.resolve(
                policy_revision,
                host=revision.host,
                port=revision.port,
            )
            self.guard.verify_rebinding(policy_revision, resolved)
            tested_at = utc_now()
            try:
                with self.decrypted_password(
                    session,
                    datasource_id=datasource.id,
                    secret_id=secret.id,
                    envelope_id=envelope.id,
                ) as password:
                    probe = self.connector.probe(
                        revision,
                        password=password,
                        resolved=resolved,
                    )
            except ProblemException:
                raise
            except Exception as exc:
                code = self._safe_probe_error_code(exc)
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
                metadata={"egress_enforcement_status": resolved.egress_enforcement_status},
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

    def list_columns(
        self,
        *,
        principal: Principal,
        datasource_id: UUID,
        schema_name: str | None,
        table_name: str | None,
        limit: int,
        audit: AuditContext,
        cursor: str | None = None,
    ) -> TableSchemaPage:
        with self.sessions.begin() as session:
            datasource, project, organization = self._locked_datasource_context(
                session,
                principal=principal,
                datasource_id=datasource_id,
            )
            self._require_metadata_access(
                session,
                principal=principal,
                datasource=datasource,
                project=project,
            )
            revision, policy_revision = self._current_revisions(
                session,
                datasource,
            )
            cursor_scope = self._cursor_scope(
                "GET /datasources/{datasource_id}/schema/tables",
                {
                    "datasource_id": str(datasource.id),
                    "datasource_revision_id": str(revision.id),
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
            try:
                secret, envelope = self._active_secret_and_envelope(
                    session,
                    datasource,
                )
                resolved = self.guard.resolve(
                    policy_revision,
                    host=revision.host,
                    port=revision.port,
                )
                self.guard.verify_rebinding(policy_revision, resolved)
                if resolved.egress_enforcement_status != "VERIFIED":
                    raise ProblemException(
                        status=503,
                        code="EGRESS_ENFORCEMENT_UNVERIFIED",
                        title="数据库出口强制策略尚未验证",
                        detail="出口策略获得独立 VERIFIED 证据前不能读取真实元数据。",
                        retryable=False,
                    )
                with self.decrypted_password(
                    session,
                    datasource_id=datasource.id,
                    secret_id=secret.id,
                    envelope_id=envelope.id,
                ) as password:
                    snapshots, peer_ip, has_more = (
                        self.connector.schema_snapshots(
                            revision,
                            physical_endpoint_identity_id=(
                                revision.physical_endpoint_identity_id
                            ),
                            password=password,
                            resolved=resolved,
                            schema_name=schema_name,
                            table_name=table_name,
                            limit=limit,
                            after=after,
                        )
                    )
            except ProblemException:
                raise
            except Exception as exc:
                raise ProblemException(
                    status=503,
                    code="DATASOURCE_METADATA_UNAVAILABLE",
                    title="无法读取真实数据库元数据",
                    detail="数据库连接、端点身份或 Schema 探针失败；没有生成替代元数据。",
                    retryable=_metadata_failure_retryable(exc),
                ) from exc
            captured_at = utc_now()
            self._persist_connection_evidence(
                session,
                operation_kind="METADATA",
                datasource_revision=revision,
                resolved=resolved,
                peer_ip=peer_ip,
                tls_peer_spki_sha256=None,
                observed_at=captured_at,
            )
            items = [
                self._table_schema(snapshot, captured_at)
                for snapshot in snapshots
            ]
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
                    revision.default_schema
                    if revision.engine == "MYSQL_8"
                    else last.schema_name
                )
                next_cursor = self._encode_table_cursor(
                    actor_id=principal.user_id,
                    scope=cursor_scope,
                    schema_name=cursor_schema,
                    table_name=last.table_name,
                )
            return TableSchemaPage(
                items=items,
                next_cursor=next_cursor,
                has_more=has_more,
            )

    def collect_job_validation_material(
        self,
        *,
        principal: Principal,
        job_id: UUID,
        audit: AuditContext,
    ) -> SchemaValidationMaterial:
        """Collect server-owned dual-end schema facts for `/jobs/{id}/validate`."""

        with self.sessions.begin() as session:
            visible_job = session.get(SyncJob, job_id)
            if visible_job is None:
                self._not_found()
            organization = self._lock_organization(
                session,
                principal.organization_id,
            )
            project = self._visible_project(
                session,
                principal,
                visible_job.project_id,
                lock=True,
            )
            self._require_project_developer(principal, project.id)
            job = session.scalar(
                select(SyncJob)
                .where(
                    SyncJob.id == job_id,
                    SyncJob.project_id == project.id,
                )
                .with_for_update()
            )
            if job is None:
                self._not_found()
            spec = JobSpecV1.model_validate(job.draft_spec_json)
            revision_ids = sorted(
                {
                    spec.source.datasource_revision_id,
                    spec.target.datasource_revision_id,
                },
                key=str,
            )
            revisions = {
                item.id: item
                for item in session.scalars(
                    select(DatasourceRevision)
                    .where(DatasourceRevision.id.in_(revision_ids))
                    .order_by(DatasourceRevision.id)
                    .with_for_update()
                )
            }
            if set(revisions) != set(revision_ids):
                self._not_found()
            source_revision = revisions[spec.source.datasource_revision_id]
            target_revision = revisions[spec.target.datasource_revision_id]
            datasource_ids = sorted(
                {spec.source.datasource_id, spec.target.datasource_id},
                key=str,
            )
            datasources = {
                item.id: item
                for item in session.scalars(
                    select(Datasource)
                    .where(Datasource.id.in_(datasource_ids))
                    .order_by(Datasource.id)
                    .with_for_update()
                )
            }
            if set(datasources) != set(datasource_ids):
                self._not_found()
            source_datasource = datasources[spec.source.datasource_id]
            target_datasource = datasources[spec.target.datasource_id]
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
            self._require_validation_datasource_grants(
                session,
                principal=principal,
                source_datasource_id=source_datasource.id,
                target_datasource_id=target_datasource.id,
            )
            policy = self._matching_active_transfer_policy(
                session,
                project_id=project.id,
                spec=spec,
                source_revision=source_revision,
                target_revision=target_revision,
            )
            source_snapshot = self._capture_validation_snapshot(
                session,
                datasource=source_datasource,
                revision=source_revision,
                schema_name=spec.source.table.schema_name,
                table_name=spec.source.table.table_name,
            )
            target_snapshot = self._capture_validation_snapshot(
                session,
                datasource=target_datasource,
                revision=target_revision,
                schema_name=spec.target.table.schema_name,
                table_name=spec.target.table.table_name,
            )
            source_hash = schema_snapshot_hash(source_snapshot)
            target_hash = schema_snapshot_hash(target_snapshot)
            try:
                assert_snapshot_matches_job(
                    source_snapshot,
                    expected_hash=source_hash,
                    spec=spec,
                    side="source",
                )
                assert_snapshot_matches_job(
                    target_snapshot,
                    expected_hash=target_hash,
                    spec=spec,
                    side="target",
                )
            except RuntimeError as exc:
                raise ProblemException(
                    status=422,
                    code="SCHEMA_SNAPSHOT_MAPPING_MISMATCH",
                    title="真实 Schema 与任务映射不兼容",
                    detail="字段、类型、生成列、触发器或表结构不满足 V1 校验要求。",
                ) from exc
            if (
                source_snapshot.physical_table_identity_hash
                == target_snapshot.physical_table_identity_hash
            ):
                raise ProblemException(
                    status=422,
                    code="SOURCE_TARGET_SAME_TABLE",
                    title="源表和目标表不能是同一物理表",
                    detail="V1 insert-only 一次性复制禁止自复制。",
                )
            target_namespace = session.scalar(
                select(TargetNamespace)
                .where(
                    TargetNamespace.physical_table_identity_hash
                    == target_snapshot.physical_table_identity_hash,
                    TargetNamespace.physical_endpoint_identity_id
                    == target_revision.physical_endpoint_identity_id,
                    TargetNamespace.engine == target_revision.engine,
                    TargetNamespace.normalized_catalog_name
                    == target_snapshot.catalog_name,
                    TargetNamespace.normalized_schema_name
                    == target_snapshot.schema_name,
                    TargetNamespace.normalized_table_name
                    == target_snapshot.table_name,
                    TargetNamespace.normalization_version == "1.0",
                )
                .with_for_update()
            )
            if target_namespace is None:
                raise ProblemException(
                    status=409,
                    code="TARGET_NAMESPACE_NOT_REGISTERED",
                    title="目标物理表尚未完成授权登记",
                    detail="ACTIVE TransferPolicy 必须绑定已登记的 TargetNamespace。",
                )
            material = SchemaValidationMaterial(
                source_schema_snapshot=source_snapshot.model_dump(mode="json"),
                target_schema_snapshot=target_snapshot.model_dump(mode="json"),
                source_schema_hash=source_hash,
                target_schema_hash=target_hash,
                source_physical_table_identity_hash=(
                    source_snapshot.physical_table_identity_hash
                ),
                target_namespace_id=target_namespace.id,
                transfer_policy_id=policy.id,
                transfer_policy_scope_hash=policy.scope_hash,
            )
            self._append_audit(
                session,
                organization=organization,
                project_id=project.id,
                action="JOB_VALIDATION_SCHEMA_COLLECTED",
                actor_id=principal.user_id,
                target_type="SYNC_JOB",
                target_id=job.id,
                target_name=job.name,
                changed_fields=[],
                audit=audit,
                metadata={
                    "source_schema_hash": source_hash,
                    "target_schema_hash": target_hash,
                    "transfer_policy_id": str(policy.id),
                    "target_namespace_id": str(target_namespace.id),
                },
            )
            return material

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
        if (
            policy is None
            or policy.status != "ACTIVE"
            or policy.current_revision_id is None
        ):
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
            request.host
            if "host" in request.model_fields_set and request.host is not None
            else current.host
        ).rstrip(".").casefold()
        candidate = DatasourceConnectionCandidate(
            engine=engine,
            host=host,
            port=(
                request.port
                if "port" in request.model_fields_set
                and request.port is not None
                else current.port
            ),
            database_name=(
                request.database_name
                if "database_name" in request.model_fields_set
                and request.database_name is not None
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
                if "username" in request.model_fields_set
                and request.username is not None
                else current.username
            ),
            ssl_mode=(
                request.ssl_mode.value
                if "ssl_mode" in request.model_fields_set
                and request.ssl_mode is not None
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
            "MYSQL_SERVER_UUID"
            if candidate.engine == "MYSQL_8"
            else "POSTGRES_SYSTEM_IDENTIFIER"
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
            "physical_endpoint_identity_id": str(
                physical_endpoint_identity_id
            ),
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
            "endpoint_policy_revision_id": str(
                datasource_revision.endpoint_policy_revision_id
            ),
            "execution_id": str(execution_id) if execution_id else None,
            "recovery_probe_id": (
                str(recovery_probe_id) if recovery_probe_id else None
            ),
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
            or (
                operation_kind == "RECOVERY_PROBE"
                and recovery_probe_id is None
            )
            or (
                operation_kind != "RECOVERY_PROBE"
                and execution_id is None
            )
        ):
            raise ValueError("WORKER_EVIDENCE_OWNER_INVALID")
        if (
            resolved.egress_enforcement_status != "VERIFIED"
            or ensure_aware(resolved.dns_valid_until) < ensure_aware(observed_at)
        ):
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

    def _active_secret_and_envelope(
        self,
        session: Session,
        datasource: Datasource,
    ) -> tuple[CredentialSecret, CredentialSecretEnvelope]:
        if datasource.status != "ACTIVE" or datasource.current_secret_id is None:
            raise self._binding_unavailable()
        secret = session.get(CredentialSecret, datasource.current_secret_id)
        if secret is None or secret.status != "ACTIVE":
            raise self._binding_unavailable()
        envelope = session.scalar(
            select(CredentialSecretEnvelope).where(
                CredentialSecretEnvelope.credential_secret_id == secret.id,
                CredentialSecretEnvelope.status == "ACTIVE",
            )
        )
        if envelope is None:
            raise self._binding_unavailable()
        return secret, envelope

    def _capture_validation_snapshot(
        self,
        session: Session,
        *,
        datasource: Datasource,
        revision: DatasourceRevision,
        schema_name: str,
        table_name: str,
    ) -> SchemaSnapshot:
        current_revision, policy_revision = self._current_revisions(
            session,
            datasource,
        )
        if current_revision.id != revision.id:
            raise ProblemException(
                status=409,
                code="DATASOURCE_REVISION_NOT_CURRENT",
                title="数据源修订已变化",
                detail="校验只能使用当前已验证的数据源修订。",
            )
        try:
            resolved = self.guard.resolve(
                policy_revision,
                host=revision.host,
                port=revision.port,
            )
            self.guard.verify_rebinding(policy_revision, resolved)
            if resolved.egress_enforcement_status != "VERIFIED":
                raise ProblemException(
                    status=503,
                    code="EGRESS_ENFORCEMENT_UNVERIFIED",
                    title="数据库出口强制策略尚未验证",
                    detail="在容器出口策略获得独立 VERIFIED 证据前，任务校验保持阻断。",
                    retryable=False,
                )
            secret, envelope = self._active_secret_and_envelope(
                session,
                datasource,
            )
            with self.decrypted_password(
                session,
                datasource_id=datasource.id,
                secret_id=secret.id,
                envelope_id=envelope.id,
            ) as password:
                snapshots, peer_ip, has_more = self.connector.schema_snapshots(
                    revision,
                    physical_endpoint_identity_id=(
                        revision.physical_endpoint_identity_id
                    ),
                    password=password,
                    resolved=resolved,
                    schema_name=schema_name,
                    table_name=table_name,
                    limit=1,
                )
        except ProblemException:
            raise
        except Exception as exc:
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
        expected_schema = "" if revision.engine == "MYSQL_8" else schema_name
        if (
            snapshot.engine != revision.engine
            or snapshot.physical_endpoint_identity_id
            != revision.physical_endpoint_identity_id
            or snapshot.catalog_name != revision.database_name
            or snapshot.schema_name != expected_schema
            or snapshot.table_name != table_name
        ):
            raise ProblemException(
                status=422,
                code="SCHEMA_SNAPSHOT_BINDING_MISMATCH",
                title="Schema 快照与数据源修订不匹配",
                detail="探针结果未精确绑定任务声明的引擎、物理端点和表身份。",
            )
        self._persist_connection_evidence(
            session,
            operation_kind="METADATA",
            datasource_revision=revision,
            resolved=resolved,
            peer_ip=peer_ip,
            tls_peer_spki_sha256=None,
            observed_at=utc_now(),
        )
        return snapshot

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

    def _current_secret(
        self,
        session: Session,
        datasource: Datasource,
    ) -> CredentialSecret:
        secret, _ = self._active_secret_and_envelope(session, datasource)
        return secret

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
            return (
                getattr(request, name)
                if name in fields
                else getattr(current, name)
            )

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
        if (
            not ports
            or len(ports) > 16
            or any(port < 1 or port > 65535 for port in ports)
        ):
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
            "dns_ttl_ceiling_seconds": int(
                selected("dns_ttl_ceiling_seconds")
            ),
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
                ensure_aware(datasource.last_tested_at)
                if datasource.last_tested_at
                else None
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
                unsupported_reason=(
                    "GENERATED_COLUMN_UNSUPPORTED"
                    if item.generated
                    else None
                ),
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
    ) -> None:
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
        if membership is None or session.scalar(
            select(DatasourceUsageGrant.id).where(
                DatasourceUsageGrant.datasource_id == datasource.id,
                DatasourceUsageGrant.organization_member_id == membership.id,
                DatasourceUsageGrant.usage.in_(("SOURCE_USE", "TARGET_USE")),
                DatasourceUsageGrant.status == "ACTIVE",
            )
        ) is None:
            raise ProblemException(
                status=403,
                code="DATASOURCE_USAGE_NOT_GRANTED",
                title="缺少数据源用途授权",
                detail="Developer 只能读取获准 SOURCE_USE 或 TARGET_USE 的数据源元数据。",
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
                    DatasourceUsageGrant.organization_member_id
                    == membership.id,
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
                    TransferPolicy.source_datasource_revision_id
                    == source_revision.id,
                    TransferPolicy.target_datasource_revision_id
                    == target_revision.id,
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
                    "必须存在且只能存在一条精确覆盖当前 revision、表和列的 "
                    "ACTIVE TransferPolicy。"
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
        if (
            not principal.is_admin
            and project_id not in self._visible_project_ids(principal)
        ):
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
                role in {Role.DEVELOPER, Role.OPERATOR, Role.VIEWER}
                for role in assignment.roles
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
        datasource = session.scalar(
            select(Datasource).where(Datasource.id == datasource_id).with_for_update()
        )
        if datasource is None:
            self._not_found()
        project = self._visible_project(
            session,
            principal,
            datasource.project_id,
            lock=True,
        )
        organization = self._lock_organization(session, project.organization_id)
        return datasource, project, organization

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
                    TransferPolicy.source_datasource_revision_id.in_(
                        revision_ids
                    ),
                    TransferPolicy.target_datasource_revision_id.in_(
                        revision_ids
                    ),
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
                RecoveryProbe.process_state.in_(
                    _ACTIVE_RECOVERY_PROBE_STATES
                ),
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
            select(Organization)
            .where(Organization.id == organization_id)
            .with_for_update()
        )
        if organization is None:
            self._not_found()
        return organization

    def _validate_connection_input(
        self,
        request: DatasourceCreate | DatasourceConnectionCandidate,
    ) -> None:
        engine = (
            request.engine.value
            if hasattr(request.engine, "value")
            else request.engine
        )
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
            request.ssl_mode.value
            if hasattr(request.ssl_mode, "value")
            else request.ssl_mode
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
            if (
                existing.request_hash_scheme != IDEMPOTENCY_HASH_SCHEME
                or not hmac.compare_digest(existing.request_hash, request_hash)
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

    def _password_request_hmac(self, password: bytearray) -> str:
        return hmac.digest(
            self.integrity_hmac_key,
            b"DataXEnterpriseStudio\x00DatasourcePasswordRequest\x00v1\x00" + password,
            "sha256",
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
        return base64.urlsafe_b64encode(body + signature).rstrip(b"=").decode(
            "ascii"
        )

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
            timestamp = datetime.fromisoformat(
                str(payload["timestamp"]).replace("Z", "+00:00")
            )
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
        return base64.urlsafe_b64encode(body + signature).rstrip(b"=").decode(
            "ascii"
        )

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
        status = 503 if code in {
            "DNS_RESOLUTION_FAILED",
            "KEK_KEYRING_UNAVAILABLE",
            "RESOLVER_POLICY_VERSION_MISMATCH",
            "EGRESS_POLICY_VERSION_MISMATCH",
        } else 422
        return ProblemException(
            status=status,
            code=code,
            title="数据源连接验证失败",
            detail="请检查端点策略、DNS、TLS 和数据库账号；系统未保存本次明文密码。",
            retryable=status == 503,
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
    def _not_found() -> None:
        raise ProblemException(
            status=404,
            code="NOT_FOUND",
            title="资源不存在",
            detail="资源不存在或当前用户无权访问。",
        )
