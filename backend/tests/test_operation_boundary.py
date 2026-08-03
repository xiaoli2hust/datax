from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from uuid import uuid4

import pytest

from datax_studio.credentials.ingress import DatasourceOperationKind
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


class _Clock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _binding(datasource_id: object | None = None) -> FrozenCredentialBinding:
    return FrozenCredentialBinding(
        datasource_id=datasource_id if datasource_id is not None else uuid4(),  # type: ignore[arg-type]
        secret_id=uuid4(),
        secret_version=3,
        secret_status="ACTIVE",
        envelope_id=uuid4(),
        envelope_version=2,
        envelope_status="ACTIVE",
        kek_version="kek-v2",
        kek_status="ACTIVE",
        kek_fingerprint_sha256="a" * 64,
        kek_wrapping_algorithm="AES-256-KWP",
        data_algorithm="AES-256-GCM",
        aad_schema_version="1.0",
    )


def test_encrypted_material_is_frozen_and_never_reveals_ciphertext_in_repr() -> None:
    material = CurrentCredentialMaterial(
        binding=_binding(),
        ciphertext=b"ciphertext-do-not-log",
        nonce=b"nonce-do-not-log",
        encrypted_dek=b"wrapped-dek-do-not-log",
    )

    rendered = repr(material)
    assert "ciphertext" not in rendered
    assert "nonce" not in rendered
    assert "encrypted_dek" not in rendered
    assert "do-not-log" not in rendered
    with pytest.raises(FrozenInstanceError):
        material.ciphertext = b"replacement"  # type: ignore[misc]


def test_snapshot_is_immutable_and_rejects_mismatched_security_pointers() -> None:
    organization_id = uuid4()
    project_id = uuid4()
    datasource_id = uuid4()
    revision = FrozenDatasourceRevision(
        id=uuid4(),
        datasource_id=datasource_id,
        revision_no=4,
        endpoint_policy_revision_id=uuid4(),
        physical_endpoint_identity_id=uuid4(),
        engine="POSTGRESQL_15",
        host="db.example.test",
        port=5432,
        database_name="warehouse",
        default_schema="public",
        username="reader",
        ssl_mode="VERIFY_FULL",
        config_hash="b" * 64,
    )
    policy = FrozenEndpointPolicy(
        id=revision.endpoint_policy_revision_id,
        endpoint_policy_id=uuid4(),
        endpoint_policy_current_revision_id=revision.endpoint_policy_revision_id,
        endpoint_policy_status="ACTIVE",
        endpoint_policy_row_version=7,
        revision_no=2,
        engine="POSTGRESQL_15",
        host_kind="EXACT_FQDN",
        host_value="db.example.test",
        allowed_cidrs=["192.0.2.0/24"],
        allowed_ports=[5432],
        tls_required=True,
        dns_ttl_ceiling_seconds=60,
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        policy_hash="c" * 64,
    )
    binding = _binding(datasource_id)
    actor = FrozenActorAuthorization(
        actor_id=uuid4(),
        actor_user_status="ACTIVE",
        actor_user_row_version=1,
        session_id=uuid4(),
        organization_id=organization_id,
        project_id=project_id,
        organization_member_id=uuid4(),
        organization_member_status="ACTIVE",
        actor_must_change_password=False,
        authorization_mode="PROJECT_DEVELOPER",
        role_assignment_id=uuid4(),
        usage="SOURCE_USE",
        usage_grant_id=uuid4(),
        usage_grant_status="ACTIVE",
        usage_grant_row_version=1,
    )
    snapshot = DatasourceOperationSnapshot(
        operation_kind=DatasourceOperationKind.METADATA,
        operation_id=uuid4(),
        organization_id=organization_id,
        organization_status="ACTIVE",
        organization_row_version=1,
        project_id=project_id,
        project_status="ACTIVE",
        project_row_version=1,
        datasource_id=datasource_id,
        datasource_status="ACTIVE",
        datasource_row_version=8,
        datasource_current_revision_id=revision.id,
        datasource_current_secret_id=binding.secret_id,
        datasource_revision=revision,
        endpoint_policy=policy,
        credential_binding=binding,
        actor_authorization=actor,
        metadata_usage="SOURCE_USE",
        metadata_after=["public", "orders"],
    )

    assert snapshot.endpoint_policy.allowed_cidrs == ("192.0.2.0/24",)
    assert snapshot.metadata_after == ("public", "orders")
    # Regranting the same row back to ACTIVE must still make a C-time actor
    # authorization snapshot unequal to the A-time grant generation.
    assert actor != replace(actor, usage_grant_row_version=2)
    with pytest.raises(FrozenInstanceError):
        snapshot.datasource_status = "DISABLED"  # type: ignore[misc]
    with pytest.raises(ValueError, match="current secret pointer"):
        DatasourceOperationSnapshot(
            operation_kind=DatasourceOperationKind.TEST,
            operation_id=uuid4(),
            organization_id=organization_id,
            organization_status="ACTIVE",
            organization_row_version=1,
            project_id=project_id,
            project_status="ACTIVE",
            project_row_version=1,
            datasource_id=datasource_id,
            datasource_status="ACTIVE",
            datasource_row_version=8,
            datasource_current_revision_id=revision.id,
            datasource_current_secret_id=uuid4(),
            datasource_revision=revision,
            endpoint_policy=policy,
            credential_binding=binding,
            actor_authorization=actor,
        )


def test_deadline_uses_one_fixed_total_budget_and_fails_closed() -> None:
    clock = _Clock(10.0)
    deadline = OperationDeadline(total_seconds=5.0, monotonic_clock=clock)

    assert deadline.started_at == 10.0
    assert deadline.remaining_seconds() == 5.0
    clock.value = 12.5
    assert deadline.check_expired() == 2.5
    assert deadline.bounded_timeout(10.0) == 2.5
    assert deadline.bounded_timeout(1.0) == 1.0
    clock.value = 15.0
    assert deadline.remaining_seconds() == 0.0
    with pytest.raises(OperationDeadlineExpired, match="DEADLINE_EXCEEDED"):
        deadline.check_expired()
