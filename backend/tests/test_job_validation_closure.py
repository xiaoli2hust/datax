from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, text
from test_core_control_plane import (
    CoreStack,
    _seed_published_job,
    core_stack,
)

from datax_studio.auth.db import AuditEvent
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    JobVersion,
    SyncJob,
    SystemControl,
)
from datax_studio.credentials.connectors import DatabaseConnector
from datax_studio.credentials.db import EndpointConnectionEvidence
from datax_studio.credentials.keyring import KekKeyring, zeroize
from datax_studio.credentials.network import (
    DnsResolution,
    EndpointPolicyGuard,
    ResolvedEndpoint,
)
from datax_studio.credentials.routes import get_credential_service
from datax_studio.credentials.service import CredentialService
from datax_studio.egress_attestation import EgressVerification
from datax_studio.schema_snapshot import SchemaSnapshot, schema_snapshot_hash

__all__ = ["core_stack"]

_RUNTIME_SHA256 = "d" * 64
_MYSQL_READER_SHA256 = "b" * 64
_POSTGRES_WRITER_SHA256 = "c" * 64


@dataclass(frozen=True)
class _BoundaryResolver:
    """Deterministic DNS boundary; it does not claim a real database connection."""

    addresses_by_hostname: dict[str, str]

    def resolve(
        self,
        hostname: str,
        *,
        timeout_seconds: float,
        ttl_ceiling_seconds: int,
    ) -> DnsResolution:
        del timeout_seconds
        return DnsResolution(
            cname_chain=(),
            addresses=(self.addresses_by_hostname[hostname],),
            ttl_seconds=min(60, ttl_ceiling_seconds),
        )


class _ContractSchemaProbeBoundary(DatabaseConnector):
    """Return contract facts at the DB connector seam, never external-DB E3 evidence."""

    def __init__(
        self,
        *,
        guard: EndpointPolicyGuard,
        snapshots: dict[UUID, SchemaSnapshot],
        password_hashes: dict[UUID, str],
    ) -> None:
        super().__init__(
            guard=guard,
            connect_timeout_seconds=1,
            query_timeout_seconds=1,
        )
        self._snapshots = snapshots
        self._password_hashes = password_hashes
        self.calls: list[UUID] = []

    def schema_snapshots(
        self,
        revision: DatasourceRevision,
        *,
        physical_endpoint_identity_id: UUID,
        password: bytearray,
        resolved: ResolvedEndpoint,
        schema_name: str | None,
        table_name: str | None,
        limit: int,
    ) -> tuple[list[SchemaSnapshot], str, bool]:
        snapshot = self._snapshots[revision.id]
        assert limit == 1
        assert resolved.egress_enforcement_status == "VERIFIED"
        assert physical_endpoint_identity_id == snapshot.physical_endpoint_identity_id
        assert table_name == snapshot.table_name
        assert schema_name == (
            revision.database_name
            if revision.engine == "MYSQL_8"
            else snapshot.schema_name
        )
        assert hashlib.sha256(password).hexdigest() == self._password_hashes[
            revision.id
        ]
        self.calls.append(revision.id)
        return [snapshot.model_copy(deep=True)], resolved.selected_ip, False


class _NeverCollectMetadata:
    def __init__(self) -> None:
        self.calls = 0

    def collect_job_validation_material(self, **kwargs: object) -> None:
        del kwargs
        self.calls += 1
        raise AssertionError(
            "invalid Worker attestation must fail before metadata collection"
        )


class _FixedEgressVerifier:
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


def _prepare_draft(core_stack: CoreStack, job_id: UUID) -> int:
    with core_stack.sessions.begin() as session:
        job = session.get(SyncJob, job_id)
        assert job is not None
        job.status = "DRAFT"
        job.validated_spec_hash = None
        job.validation_report = None
        job.updated_at = datetime.now(UTC)
        job.row_version += 1
        return job.row_version


def _persist_worker_attestation(
    core_stack: CoreStack,
    *,
    fault: str | None = None,
) -> None:
    now = datetime.now(UTC)
    control_epoch = uuid4()
    worker_epoch = uuid4() if fault == "reconcile_epoch" else control_epoch
    worker_reconciled_at = (
        now - timedelta(seconds=1)
        if fault == "reconciled_at"
        else now
    )
    updated_at = (
        now - timedelta(minutes=1)
        if fault == "stale"
        else now
    )
    runtime_sha256 = (
        "not-a-runtime-hash"
        if fault == "runtime_hash"
        else _RUNTIME_SHA256
    )
    with core_stack.sessions.begin() as session:
        control = session.get(SystemControl, 1)
        assert control is not None
        control.draining = False
        control.reason = "READY"
        control.host_boot_id = "boot-validation-closure"
        control.reconcile_epoch = control_epoch
        control.reconciled_at = now
        control.updated_at = now
        session.execute(
            text(
                """
                CREATE TABLE worker_heartbeats (
                    worker_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    runtime_code TEXT NOT NULL,
                    oracle_code TEXT NOT NULL,
                    datax_release TEXT,
                    runtime_sha256 TEXT,
                    mysqlreader_plugin_sha256 TEXT,
                    postgresqlreader_plugin_sha256 TEXT,
                    mysqlwriter_plugin_sha256 TEXT,
                    postgresqlwriter_plugin_sha256 TEXT,
                    host_boot_id TEXT,
                    reconcile_epoch CHAR(32),
                    reconciled_at DATETIME,
                    updated_at DATETIME NOT NULL
                )
                """
            )
        )
        session.execute(
            text(
                """
                INSERT INTO worker_heartbeats (
                    worker_id,
                    status,
                    runtime_code,
                    oracle_code,
                    datax_release,
                    runtime_sha256,
                    mysqlreader_plugin_sha256,
                    postgresqlreader_plugin_sha256,
                    mysqlwriter_plugin_sha256,
                    postgresqlwriter_plugin_sha256,
                    host_boot_id,
                    reconcile_epoch,
                    reconciled_at,
                    updated_at
                ) VALUES (
                    'worker-1',
                    'READY',
                    'RUNTIME_OK',
                    'ORACLE_OK',
                    'datax_v202309',
                    :runtime_sha256,
                    :mysqlreader,
                    :postgresqlreader,
                    :mysqlwriter,
                    :postgresqlwriter,
                    'boot-validation-closure',
                    :reconcile_epoch,
                    :reconciled_at,
                    :updated_at
                )
                """
            ),
            {
                "runtime_sha256": runtime_sha256,
                "mysqlreader": _MYSQL_READER_SHA256,
                "postgresqlreader": "e" * 64,
                "mysqlwriter": "f" * 64,
                "postgresqlwriter": _POSTGRES_WRITER_SHA256,
                "reconcile_epoch": worker_epoch.hex,
                "reconciled_at": worker_reconciled_at,
                "updated_at": updated_at,
            },
        )


def _credential_service_at_database_boundary(
    core_stack: CoreStack,
    tmp_path: Path,
    *,
    source_revision: DatasourceRevision,
    target_revision: DatasourceRevision,
    source_snapshot: SchemaSnapshot,
    target_snapshot: SchemaSnapshot,
) -> tuple[CredentialService, _ContractSchemaProbeBoundary]:
    key_path = tmp_path / "credential-kek-v1.key"
    key_path.write_bytes(b"k" * 32)
    key_path.chmod(0o600)
    resolver = _BoundaryResolver(
        {
            source_revision.host: "10.10.0.10",
            target_revision.host: "10.20.0.10",
        }
    )
    guard = EndpointPolicyGuard(
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        egress_verifier=_FixedEgressVerifier(),
        resolver=resolver,
        connect_timeout_seconds=1,
    )
    source_password = bytearray(b"s" * 32)
    target_password = bytearray(b"t" * 32)
    connector = _ContractSchemaProbeBoundary(
        guard=guard,
        snapshots={
            source_revision.id: source_snapshot,
            target_revision.id: target_snapshot,
        },
        password_hashes={
            source_revision.id: hashlib.sha256(source_password).hexdigest(),
            target_revision.id: hashlib.sha256(target_password).hexdigest(),
        },
    )
    service = CredentialService(
        sessions=core_stack.sessions,
        keyring=KekKeyring(tmp_path),
        active_kek_version="v1",
        integrity_hmac_key=b"v" * 32,
        guard=guard,
        connector=connector,
    )
    service.ensure_active_kek_registered()
    try:
        with core_stack.sessions.begin() as session:
            source_datasource = session.get(
                Datasource,
                source_revision.datasource_id,
            )
            target_datasource = session.get(
                Datasource,
                target_revision.datasource_id,
            )
            assert source_datasource is not None
            assert target_datasource is not None
            service._install_secret(
                session,
                organization_id=core_stack.principal.organization_id,
                project_id=source_datasource.project_id,
                datasource=source_datasource,
                password=source_password,
                actor_id=core_stack.principal.user_id,
                now=datetime.now(UTC),
            )
            service._install_secret(
                session,
                organization_id=core_stack.principal.organization_id,
                project_id=target_datasource.project_id,
                datasource=target_datasource,
                password=target_password,
                actor_id=core_stack.principal.user_id,
                now=datetime.now(UTC),
            )
    finally:
        zeroize(source_password)
        zeroize(target_password)
    return service, connector


def test_validate_persists_real_service_boundary_facts_and_can_publish(
    core_stack: CoreStack,
    tmp_path: Path,
) -> None:
    """This closes API/service persistence, not a real MySQL/PostgreSQL/DataX E3."""

    seeded = _seed_published_job(core_stack, "validationclosure")
    draft_row_version = _prepare_draft(core_stack, seeded.job_id)
    _persist_worker_attestation(core_stack)
    with core_stack.sessions() as session:
        prior_version = session.get(JobVersion, seeded.job_version_id)
        assert prior_version is not None
        source_revision = session.get(
            DatasourceRevision,
            prior_version.source_datasource_revision_id,
        )
        target_revision = session.get(
            DatasourceRevision,
            prior_version.target_datasource_revision_id,
        )
        assert source_revision is not None
        assert target_revision is not None
        source_snapshot = SchemaSnapshot.model_validate(
            prior_version.source_schema_snapshot
        )
        target_snapshot = SchemaSnapshot.model_validate(
            prior_version.target_schema_snapshot
        )
    credential_service, connector = _credential_service_at_database_boundary(
        core_stack,
        tmp_path,
        source_revision=source_revision,
        target_revision=target_revision,
        source_snapshot=source_snapshot,
        target_snapshot=target_snapshot,
    )
    assert type(credential_service) is CredentialService
    core_stack.client.app.dependency_overrides[
        get_credential_service
    ] = lambda: credential_service

    validation = core_stack.client.post(
        f"/api/v1/jobs/{seeded.job_id}/validate"
    )
    assert validation.status_code == 200, validation.text
    validation_payload = validation.json()
    assert validation_payload == {
        "valid": True,
        "draft_spec_hash": "b" * 64,
        "source_schema_hash": schema_snapshot_hash(source_snapshot),
        "target_schema_hash": schema_snapshot_hash(target_snapshot),
        "errors": [],
        "warnings": [],
    }
    assert connector.calls == [source_revision.id, target_revision.id]

    with core_stack.sessions() as session:
        job = session.get(SyncJob, seeded.job_id)
        assert job is not None
        assert job.status == "VALID"
        assert job.validated_spec_hash == job.draft_spec_hash == "b" * 64
        assert job.row_version == draft_row_version + 1
        report = job.validation_report
        assert report is not None
        assert report["valid"] is True
        assert report["draft_spec_hash"] == job.draft_spec_hash
        assert report["source_schema_snapshot"] == source_snapshot.model_dump(
            mode="json"
        )
        assert report["target_schema_snapshot"] == target_snapshot.model_dump(
            mode="json"
        )
        assert report["source_schema_hash"] == schema_snapshot_hash(
            source_snapshot
        )
        assert report["target_schema_hash"] == schema_snapshot_hash(
            target_snapshot
        )
        assert report["runtime_sha256"] == _RUNTIME_SHA256
        assert report["reader_plugin_sha256"] == _MYSQL_READER_SHA256
        assert report["writer_plugin_sha256"] == _POSTGRES_WRITER_SHA256
        evidence = list(
            session.scalars(
                select(EndpointConnectionEvidence).order_by(
                    EndpointConnectionEvidence.datasource_revision_id
                )
            )
        )
        assert len(evidence) == 2
        assert {item.operation_kind for item in evidence} == {"METADATA"}
        assert {item.egress_enforcement_status for item in evidence} == {
            "VERIFIED"
        }
        audit_actions = {
            row.event_json["action"]
            for row in session.scalars(select(AuditEvent))
            if row.event_json["target"]["id"] == str(seeded.job_id)
        }
        assert {
            "JOB_VALIDATION_SCHEMA_COLLECTED",
            "JOB_VALIDATED",
        }.issubset(audit_actions)
        validated_row_version = job.row_version

    published = core_stack.client.post(
        f"/api/v1/jobs/{seeded.job_id}/versions",
        headers={
            "Idempotency-Key": "publish-validation-closure-001",
            "If-Match": f'W/"{validated_row_version}"',
        },
        json={"expected_draft_spec_hash": "b" * 64},
    )
    assert published.status_code == 201, published.text
    assert published.json()["version_no"] == 2
    published_version_id = UUID(published.json()["id"])
    with core_stack.sessions() as session:
        job = session.get(SyncJob, seeded.job_id)
        version = session.get(JobVersion, published_version_id)
        assert job is not None
        assert version is not None
        assert job.status == "PUBLISHED"
        assert job.latest_published_version_id == version.id
        assert version.spec_hash == job.validated_spec_hash == "b" * 64
        assert version.source_schema_hash == schema_snapshot_hash(
            source_snapshot
        )
        assert version.target_schema_hash == schema_snapshot_hash(
            target_snapshot
        )
        assert version.runtime_sha256 == _RUNTIME_SHA256
        assert version.reader_plugin_sha256 == _MYSQL_READER_SHA256
        assert version.writer_plugin_sha256 == _POSTGRES_WRITER_SHA256


@pytest.mark.parametrize(
    "fault",
    [
        "reconcile_epoch",
        "reconciled_at",
        "stale",
        "runtime_hash",
    ],
)
def test_invalid_worker_attestation_never_reaches_metadata_or_valid_state(
    core_stack: CoreStack,
    fault: str,
) -> None:
    seeded = _seed_published_job(core_stack, f"invalid{fault}")
    draft_row_version = _prepare_draft(core_stack, seeded.job_id)
    _persist_worker_attestation(core_stack, fault=fault)
    never_collect = _NeverCollectMetadata()
    core_stack.client.app.dependency_overrides[
        get_credential_service
    ] = lambda: never_collect

    validation = core_stack.client.post(
        f"/api/v1/jobs/{seeded.job_id}/validate"
    )
    assert validation.status_code == 503
    assert validation.json()["code"] == "RUNTIME_ATTESTATION_UNAVAILABLE"
    assert never_collect.calls == 0
    with core_stack.sessions() as session:
        job = session.get(SyncJob, seeded.job_id)
        assert job is not None
        assert job.status == "DRAFT"
        assert job.validated_spec_hash is None
        assert job.validation_report is None
        assert job.row_version == draft_row_version
