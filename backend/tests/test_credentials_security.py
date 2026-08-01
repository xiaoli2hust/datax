from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from cryptography.exceptions import InvalidTag
from pydantic import ValidationError
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from datax_studio.api.problems import ProblemException
from datax_studio.auth.db import Base, Organization, Role, ScopeType, User
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
from datax_studio.core.schemas import ClaimedExecution
from datax_studio.credentials.connectors import DatabaseConnector
from datax_studio.credentials.crypto import (
    build_credential_aad,
    decrypt_credential,
    encrypt_credential,
)
from datax_studio.credentials.db import (
    CredentialSecret,
    EndpointConnectionEvidence,
)
from datax_studio.credentials.keyring import KekKeyring
from datax_studio.credentials.network import (
    DnsResolution,
    EndpointPolicyGuard,
    ResolvedEndpoint,
)
from datax_studio.credentials.schemas import (
    DatasourcePatch,
    EndpointConnectionEvidenceResponse,
)
from datax_studio.credentials.service import (
    CredentialService,
    _metadata_failure_retryable,
)
from datax_studio.egress_attestation import EgressVerification
from datax_studio.worker.schema_probe import SchemaProbeError


class SequenceResolver:
    def __init__(self, *answers: DnsResolution) -> None:
        self.answers = list(answers)

    def resolve(
        self,
        hostname: str,
        *,
        timeout_seconds: float,
        ttl_ceiling_seconds: int,
    ) -> DnsResolution:
        del hostname, timeout_seconds, ttl_ceiling_seconds
        return self.answers.pop(0)


class FixedEgressVerifier:
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


def _guard(*answers: DnsResolution) -> EndpointPolicyGuard:
    return EndpointPolicyGuard(
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        egress_verifier=FixedEgressVerifier(),
        resolver=SequenceResolver(*answers),
        connect_timeout_seconds=1,
    )


def _service(
    sessions: sessionmaker,
    keyring: KekKeyring,
) -> CredentialService:
    guard = _guard()
    return CredentialService(
        sessions=sessions,
        keyring=keyring,
        active_kek_version="v1",
        integrity_hmac_key=b"i" * 32,
        guard=guard,
        connector=DatabaseConnector(
            guard=guard,
            connect_timeout_seconds=1,
            query_timeout_seconds=1,
        ),
    )


def _sqlite_sessions() -> sessionmaker:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _admin(organization_id: UUID, user_id: UUID) -> Principal:
    return Principal(
        user_id=user_id,
        organization_id=organization_id,
        session_id=uuid4(),
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


def _audit() -> AuditContext:
    return AuditContext(
        request_id=uuid4(),
        source_ip="127.0.0.1",
        user_agent="credential-security-test",
    )


def test_password_request_fingerprint_is_deterministic_keyed_and_non_plaintext(
    tmp_path: Path,
) -> None:
    service = _service(_sqlite_sessions(), KekKeyring(tmp_path))
    first_password = bytearray(b"first datasource password")
    second_password = bytearray(b"second datasource password")

    first = service._password_request_fingerprint(first_password)
    replay = service._password_request_fingerprint(first_password)
    second = service._password_request_fingerprint(second_password)

    assert first == replay
    assert first != second
    assert first_password.hex() not in first
    assert second_password.hex() not in second


def test_aad_is_exact_and_ciphertext_is_randomized_and_bound() -> None:
    organization_id = UUID("11111111-1111-1111-1111-111111111111")
    project_id = UUID("22222222-2222-2222-2222-222222222222")
    datasource_id = UUID("33333333-3333-3333-3333-333333333333")
    secret_id = UUID("44444444-4444-4444-4444-444444444444")
    aad = build_credential_aad(
        organization_id=organization_id,
        project_id=project_id,
        datasource_id=datasource_id,
        credential_secret_id=secret_id,
        secret_version=7,
    )
    assert aad == (
        b"DXCREDENTIALv1\n"
        b"11111111-1111-1111-1111-111111111111\n"
        b"22222222-2222-2222-2222-222222222222\n"
        b"33333333-3333-3333-3333-333333333333\n"
        b"44444444-4444-4444-4444-444444444444\n"
        b"7\n1.0\nAES-256-GCM"
    )
    plaintext = bytearray("S3cret-密码".encode())
    kek = bytearray(b"k" * 32)
    first = encrypt_credential(plaintext, aad=aad, kek=kek)
    second = encrypt_credential(plaintext, aad=aad, kek=kek)
    assert len(first.nonce) == 12
    assert len(first.encrypted_dek) == 40
    assert first.nonce != second.nonce
    assert first.encrypted_dek != second.encrypted_dek
    assert decrypt_credential(
        ciphertext=first.ciphertext,
        nonce=first.nonce,
        encrypted_dek=first.encrypted_dek,
        aad=aad,
        kek=kek,
    ) == plaintext
    with pytest.raises(InvalidTag):
        decrypt_credential(
            ciphertext=first.ciphertext,
            nonce=first.nonce,
            encrypted_dek=first.encrypted_dek,
            aad=aad + b"tampered",
            kek=kek,
        )


def test_keyring_requires_exact_regular_non_writable_file(tmp_path: Path) -> None:
    key_path = tmp_path / "credential-kek-v1.key"
    key_path.write_bytes(b"a" * 32)
    key_path.chmod(0o600)
    keyring = KekKeyring(tmp_path)
    assert keyring.fingerprint("v1") == hashlib.sha256(b"a" * 32).hexdigest()

    key_path.write_bytes(b"a" * 31)
    with pytest.raises(ValueError, match="exactly 32"):
        keyring.fingerprint("v1")

    key_path.write_bytes(b"a" * 32)
    key_path.chmod(0o620)
    with pytest.raises(ValueError, match="world-writable"):
        keyring.fingerprint("v1")

    key_path.unlink()
    target = tmp_path / "target"
    target.write_bytes(b"b" * 32)
    os.symlink(target, key_path)
    with pytest.raises((OSError, ValueError)):
        keyring.fingerprint("v1")


def test_endpoint_policy_denies_mixed_answers_and_rebinding() -> None:
    revision = SimpleNamespace(
        id=uuid4(),
        host_kind="EXACT_FQDN",
        host_value="db.example.com",
        allowed_cidrs=["10.0.0.0/24"],
        allowed_ports=[5432],
        dns_ttl_ceiling_seconds=60,
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        policy_hash="a" * 64,
    )
    mixed = _guard(
        DnsResolution((), ("10.0.0.5", "203.0.113.9"), 30),
    )
    with pytest.raises(ValueError, match="DNS_ADDRESS_OUTSIDE_POLICY"):
        mixed.resolve(revision, host="db.example.com", port=5432)

    rebinding = _guard(
        DnsResolution((), ("10.0.0.5",), 30),
        DnsResolution((), ("10.0.0.6",), 30),
    )
    resolved = rebinding.resolve(
        revision,
        host="db.example.com",
        port=5432,
        now=datetime.now(UTC),
    )
    assert resolved.egress_enforcement_status == "VERIFIED"
    with pytest.raises(ValueError, match="DNS_REBINDING_DETECTED"):
        rebinding.verify_rebinding(revision, resolved)


def test_patch_omission_preserves_secret_but_null_and_empty_are_rejected(
    tmp_path: Path,
) -> None:
    sessions = _sqlite_sessions()
    key_path = tmp_path / "credential-kek-v1.key"
    key_path.write_bytes(b"z" * 32)
    key_path.chmod(0o600)
    service = _service(sessions, KekKeyring(tmp_path))
    service.ensure_active_kek_registered()
    now = datetime.now(UTC)
    organization_id = uuid4()
    user_id = uuid4()
    project_id = uuid4()
    policy_id = uuid4()
    policy_revision_id = uuid4()
    identity_id = uuid4()
    datasource_id = uuid4()
    revision_id = uuid4()
    with sessions.begin() as session:
        organization = Organization(
            id=organization_id,
            name="Test",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
            row_version=1,
        )
        user = User(
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
        )
        project = Project(
            id=project_id,
            organization_id=organization_id,
            name="Project",
            slug="project",
            status="ACTIVE",
            created_by=user_id,
            created_at=now,
            updated_at=now,
            row_version=1,
        )
        policy = EndpointPolicy(
            id=policy_id,
            organization_id=organization_id,
            name="Policy",
            current_revision_id=policy_revision_id,
            status="ACTIVE",
            created_by=user_id,
            created_at=now,
            updated_at=now,
            row_version=1,
        )
        policy_revision = EndpointPolicyRevision(
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
        identity = PhysicalEndpointIdentity(
            id=identity_id,
            organization_id=organization_id,
            engine="POSTGRESQL_15",
            identity_scheme="POSTGRES_SYSTEM_IDENTIFIER",
            server_identity_hash="b" * 64,
            verification_evidence={},
            verification_evidence_hash="c" * 64,
            created_by=user_id,
            created_at=now,
        )
        datasource = Datasource(
            id=datasource_id,
            project_id=project_id,
            name="Original",
            current_revision_id=revision_id,
            status="DISABLED",
            created_by=user_id,
            created_at=now,
            updated_at=now,
            row_version=1,
        )
        revision = DatasourceRevision(
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
        session.add_all(
            [
                organization,
                user,
                project,
                policy,
                policy_revision,
                identity,
                datasource,
                revision,
            ]
        )
        session.flush()
        secret = service._install_secret(
            session,
            organization_id=organization_id,
            project_id=project_id,
            datasource=datasource,
            password=bytearray(b"initial-password"),
            actor_id=user_id,
            now=now,
        )
        datasource.status = "ACTIVE"
        original_secret_id = secret.id

    result = service.update_datasource(
        principal=_admin(organization_id, user_id),
        datasource_id=datasource_id,
        request=DatasourcePatch(name="Renamed"),
        expected_version=1,
        audit=_audit(),
    )
    assert result.name == "Renamed"
    serialized = result.model_dump(mode="json")
    assert str(original_secret_id) not in str(serialized)
    assert "ciphertext" not in str(serialized)
    assert "nonce" not in str(serialized)
    assert "encrypted_dek" not in str(serialized)
    with sessions() as session:
        datasource = session.get(Datasource, datasource_id)
        assert datasource is not None
        assert datasource.current_secret_id == original_secret_id
        assert session.scalar(select(func.count(CredentialSecret.id))) == 1

    with pytest.raises(ValidationError):
        DatasourcePatch.model_validate({"password": None})
    with pytest.raises(ValidationError):
        DatasourcePatch.model_validate({"password": ""})


def test_preflight_evidence_is_bound_to_verified_attempt_and_fence(
    tmp_path: Path,
) -> None:
    sessions = _sqlite_sessions()
    key_path = tmp_path / "credential-kek-v1.key"
    key_path.write_bytes(b"q" * 32)
    service = _service(sessions, KekKeyring(tmp_path))
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=3,
        lease_token="x" * 32,
    )
    source_id = uuid4()
    target_id = uuid4()
    source_revision_id = uuid4()
    target_revision_id = uuid4()
    source_policy_id = uuid4()
    target_policy_id = uuid4()
    observed_at = datetime.now(UTC)
    with sessions.begin() as session:
        for evidence_id, revision_id, policy_id in (
            (source_id, source_revision_id, source_policy_id),
            (target_id, target_revision_id, target_policy_id),
        ):
            session.add(
                EndpointConnectionEvidence(
                    id=evidence_id,
                    operation_kind="PREFLIGHT",
                    datasource_revision_id=revision_id,
                    endpoint_policy_revision_id=policy_id,
                    execution_id=claim.execution_id,
                    attempt_id=claim.attempt_id,
                    fence_epoch=claim.fence_epoch,
                    resolver_policy_version="resolver-v1",
                    cname_chain=[],
                    resolved_ips=["10.0.0.5"],
                    selected_ip="10.0.0.5",
                    dns_valid_until=observed_at + timedelta(seconds=30),
                    egress_policy_version="egress-v1",
                    egress_enforcement_status="VERIFIED",
                    egress_evidence_hash=uuid4().hex * 2,
                    peer_ip="10.0.0.5",
                    decision="ALLOWED",
                    evidence_hash=uuid4().hex * 2,
                    observed_at=observed_at,
                )
            )
    with sessions.begin() as session:
        service.validate_preflight_evidence(
            session,
            claim=claim,
            source_evidence_id=source_id,
            target_evidence_id=target_id,
            source_revision_id=source_revision_id,
            target_revision_id=target_revision_id,
            source_policy_revision_id=source_policy_id,
            target_policy_revision_id=target_policy_id,
        )
    with sessions.begin() as session:
        target = session.get(EndpointConnectionEvidence, target_id)
        assert target is not None
        target.egress_enforcement_status = "UNVERIFIED"
    with sessions.begin() as session, pytest.raises(ProblemException) as invalid:
        service.validate_preflight_evidence(
            session,
            claim=claim,
            source_evidence_id=source_id,
            target_evidence_id=target_id,
            source_revision_id=source_revision_id,
            target_revision_id=target_revision_id,
            source_policy_revision_id=source_policy_id,
            target_policy_revision_id=target_policy_id,
        )
    assert invalid.value.code == "PREFLIGHT_EVIDENCE_INVALID"


def test_datax_evidence_never_copies_selected_ip_into_unobserved_peer() -> None:
    service = object.__new__(CredentialService)
    persisted: list[EndpointConnectionEvidence] = []

    class _Session:
        def add(self, value: EndpointConnectionEvidence) -> None:
            persisted.append(value)

        def flush(self) -> None:
            return None

    observed_at = datetime.now(UTC)
    resolved = ResolvedEndpoint(
        endpoint_policy_revision_id=uuid4(),
        endpoint_policy_hash="1" * 64,
        hostname="10.20.0.42",
        port=5432,
        cname_chain=(),
        resolved_ips=("10.20.0.42",),
        selected_ip="10.20.0.42",
        dns_valid_until=observed_at + timedelta(seconds=30),
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        egress_enforcement_status="VERIFIED",
        egress_attestation_hash="2" * 64,
    )
    revision = SimpleNamespace(
        id=uuid4(),
        endpoint_policy_revision_id=resolved.endpoint_policy_revision_id,
    )

    evidence = service._persist_connection_evidence(  # noqa: SLF001
        _Session(),  # type: ignore[arg-type]
        operation_kind="DATAX",
        datasource_revision=revision,  # type: ignore[arg-type]
        resolved=resolved,
        peer_ip=None,
        peer_observation_status="ENFORCED_NOT_OBSERVED",
        tls_peer_spki_sha256=None,
        observed_at=observed_at,
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
    )

    assert persisted == [evidence]
    assert evidence.selected_ip == "10.20.0.42"
    assert evidence.peer_observation_status == "ENFORCED_NOT_OBSERVED"
    assert evidence.peer_ip is None


@pytest.mark.parametrize(
    ("operation_kind", "status", "peer_ip"),
    [
        ("PREFLIGHT", "ENFORCED_NOT_OBSERVED", None),
        ("DATAX", "ENFORCED_NOT_OBSERVED", "10.20.0.42"),
        ("DATAX", "OBSERVED", None),
        ("DATAX", "OBSERVED", "10.20.0.43"),
    ],
)
def test_connection_evidence_rejects_false_peer_observations(
    operation_kind: str,
    status: str,
    peer_ip: str | None,
) -> None:
    with pytest.raises(ValidationError):
        EndpointConnectionEvidenceResponse.model_validate(
            {
                "id": str(uuid4()),
                "operation_kind": operation_kind,
                "datasource_revision_id": str(uuid4()),
                "endpoint_policy_revision_id": str(uuid4()),
                "resolver_policy_version": "resolver-v1",
                "resolved_ips": ["10.20.0.42"],
                "selected_ip": "10.20.0.42",
                "peer_observation_status": status,
                "peer_ip": peer_ip,
                "egress_policy_version": "egress-v1",
                "egress_evidence_hash": "3" * 64,
                "decision": "ALLOWED",
                "evidence_hash": "4" * 64,
                "observed_at": datetime.now(UTC),
            }
        )


def test_metadata_failure_is_503_and_retryability_is_classified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions = _sqlite_sessions()
    key_path = tmp_path / "credential-kek-v1.key"
    key_path.write_bytes(b"r" * 32)
    service = _service(sessions, KekKeyring(tmp_path))
    revision = SimpleNamespace(id=uuid4())
    policy_revision = SimpleNamespace(id=uuid4())
    datasource = SimpleNamespace(id=uuid4())
    monkeypatch.setattr(
        service,
        "_current_revisions",
        lambda session, candidate: (revision, policy_revision),
    )

    def transient_failure(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TimeoutError("database did not respond")

    monkeypatch.setattr(service.guard, "resolve", transient_failure)
    with pytest.raises(ProblemException) as unavailable:
        service._capture_validation_snapshot(
            object(),
            datasource=datasource,
            revision=revision,
            schema_name="public",
            table_name="orders",
        )
    assert unavailable.value.status == 503
    assert unavailable.value.code == "DATASOURCE_METADATA_UNAVAILABLE"
    assert unavailable.value.retryable is True

    assert _metadata_failure_retryable(
        ValueError("DNS_ADDRESS_OUTSIDE_POLICY")
    ) is False
    assert _metadata_failure_retryable(
        SchemaProbeError("native database type is not certified in V1")
    ) is False
