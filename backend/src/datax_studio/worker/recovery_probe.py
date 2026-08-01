from __future__ import annotations

import hashlib
import threading
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import rfc8785

from datax_studio.api.problems import ProblemException
from datax_studio.core.db import (
    Datasource,
    DatasourceRevision,
    EndpointPolicyRevision,
    Execution,
    JobVersion,
    PhysicalEndpointIdentity,
    Project,
    TargetNamespace,
)
from datax_studio.core.schemas import JobSpecV1, TargetEmptyEvidence
from datax_studio.core.service import ControlService
from datax_studio.credentials.network import ResolvedEndpoint
from datax_studio.credentials.service import CredentialService
from datax_studio.recovery.db import RecoveryGate, RecoveryProbe
from datax_studio.recovery.service import (
    ClaimedRecoveryProbe,
    RecoveryService,
)
from datax_studio.settings import Settings
from datax_studio.worker.oracle_database import count_target_rows
from datax_studio.worker.reconcile import RuntimeIdentity
from datax_studio.worker.schema_probe import (
    TableIdentity,
    assert_snapshot_matches_job,
    probe_schema_snapshot,
)


@dataclass(frozen=True)
class ProbeContext:
    probe: RecoveryProbe
    gate: RecoveryGate
    execution: Execution
    version: JobVersion
    revision: DatasourceRevision
    policy: EndpointPolicyRevision
    datasource: Datasource
    namespace: TargetNamespace
    organization_id: UUID
    spec: JobSpecV1


class RecoveryProbeTerminationRequested(RuntimeError):
    """Bounded Worker signal for an acknowledged probe safety stop."""


class ProbeLeaseKeeper:
    def __init__(
        self,
        *,
        service: RecoveryService,
        claim: ClaimedRecoveryProbe,
        lease_seconds: int,
    ) -> None:
        self.service = service
        self.claim = claim
        self.lease_seconds = lease_seconds
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._terminated = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"recovery-lease-{claim.recovery_probe_id}",
            daemon=True,
        )

    def __enter__(self) -> ProbeLeaseKeeper:
        self._thread.start()
        return self

    def __exit__(
        self,
        _type: object,
        _value: object,
        _traceback: object,
    ) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, self.lease_seconds / 2))

    def assert_owned(self) -> None:
        if self._terminated.is_set():
            raise RecoveryProbeTerminationRequested
        if self._lost.is_set():
            raise ProblemException(
                status=409,
                code="RECOVERY_PROBE_FENCE_LOST",
                title="恢复探针围栏已失效",
                detail="旧 Worker 已停止写入恢复探针事实。",
            )

    def _run(self) -> None:
        interval = max(1.0, min(10.0, self.lease_seconds / 3))
        while not self._stop.wait(interval):
            try:
                self.service.heartbeat_probe(
                    self.claim,
                    lease_seconds=self.lease_seconds,
                )
            except ProblemException as exc:
                if exc.code == "RECOVERY_PROBE_TERMINATION_PENDING":
                    self._terminated.set()
                else:
                    self._lost.set()
                return
            except BaseException:
                self._lost.set()
                return


class RecoveryProbeWorker:
    def __init__(
        self,
        *,
        settings: Settings,
        control: ControlService,
        credentials: CredentialService,
        recovery: RecoveryService,
    ) -> None:
        self.settings = settings
        self.control = control
        self.credentials = credentials
        self.recovery = recovery

    def claim_and_run(self, *, identity: RuntimeIdentity) -> bool:
        claim = self.recovery.claim_next_probe(
            worker_id=self.settings.worker_id,
            host_boot_id=identity.host_boot_id,
            cgroup_identity=identity.cgroup_identity,
            credential_selector=self.credentials.select_active_binding,
            lease_seconds=self.settings.worker_lease_seconds,
        )
        if claim is None:
            return False
        self.run_claimed(claim)
        return True

    def run_claimed(self, claim: ClaimedRecoveryProbe) -> None:
        context = self._load_context(claim)
        with ProbeLeaseKeeper(
            service=self.recovery,
            claim=claim,
            lease_seconds=self.settings.worker_lease_seconds,
        ) as lease:
            try:
                self._assert_control(claim=claim, lease=lease)
                self.recovery.start_claimed_probe(claim)
                self._assert_control(claim=claim, lease=lease)
                with ExitStack() as stack:
                    # The short worker decrypt transaction serializes only the
                    # status/decrypt decision, never the RecoveryProbe I/O.
                    self._assert_control(claim=claim, lease=lease)
                    password = stack.enter_context(
                        self.credentials.decrypted_worker_password(
                            datasource_id=context.datasource.id,
                            secret_id=self._required(context.probe.target_secret_id),
                            envelope_id=self._required(context.probe.target_secret_envelope_id),
                        )
                    )
                    self._assert_control(claim=claim, lease=lease)
                    resolved = self.credentials.guard.resolve(
                        context.policy,
                        host=context.revision.host,
                        port=context.revision.port,
                    )
                    # DNS resolution is a bounded external action. Re-read the
                    # durable safety/fence facts before opening a database
                    # connection through the resolved endpoint.
                    self._assert_control(claim=claim, lease=lease)
                    probe_result = self.credentials.connector.probe(
                        context.revision,
                        password=password,
                        resolved=resolved,
                        control_callback=lambda: self._assert_control(
                            claim=claim,
                            lease=lease,
                        ),
                    )
                    self._assert_control(claim=claim, lease=lease)
                    self._assert_physical_endpoint(
                        context=context,
                        server_identity=probe_result.server_identity,
                        server_version=probe_result.server_version,
                    )
                    identity = TableIdentity(
                        physical_endpoint_identity_id=(
                            context.namespace.physical_endpoint_identity_id
                        ),
                        physical_table_identity_hash=(
                            context.namespace.physical_table_identity_hash
                        ),
                        catalog_name=(context.namespace.normalized_catalog_name),
                        schema_name=(context.namespace.normalized_schema_name),
                        table_name=context.namespace.normalized_table_name,
                    )
                    self._assert_control(claim=claim, lease=lease)
                    with self.credentials.connector.connection(
                        context.revision,
                        password=password,
                        resolved=resolved,
                        read_only=True,
                        control_callback=lambda: self._assert_control(
                            claim=claim,
                            lease=lease,
                        ),
                    ) as connection:
                        # Opening the context performs the outbound connect;
                        # do not send schema queries if the stop won while it
                        # was being established.
                        self._assert_control(claim=claim, lease=lease)
                        snapshot = probe_schema_snapshot(
                            connection,
                            engine=context.revision.engine,
                            identity=identity,
                            control_callback=lambda: self._assert_control(
                                claim=claim,
                                lease=lease,
                            ),
                        )
                    self._assert_control(claim=claim, lease=lease)
                    assert_snapshot_matches_job(
                        snapshot,
                        expected_hash=context.version.target_schema_hash,
                        spec=context.spec,
                        side="target",
                    )
                    self._assert_control(claim=claim, lease=lease)
                    with self.credentials.connector.connection(
                        context.revision,
                        password=password,
                        resolved=resolved,
                        control_callback=lambda: self._assert_control(
                            claim=claim,
                            lease=lease,
                        ),
                    ) as connection:
                        # As above, poll immediately after the bounded connect
                        # and before reading socket/database metadata.
                        self._assert_control(claim=claim, lease=lease)
                        peer_ip = self.credentials.connector.connection_peer_ip(
                            connection,
                            engine=context.revision.engine,
                        )
                        self._assert_control(claim=claim, lease=lease)
                        observed_at = datetime.now(UTC)
                        self._assert_control(claim=claim, lease=lease)
                        row_count, checked_at = count_target_rows(
                            connection,
                            engine=context.revision.engine,
                            schema_name=context.spec.target.table.schema_name,
                            table_name=context.spec.target.table.table_name,
                            control_callback=lambda: self._assert_control(
                                claim=claim,
                                lease=lease,
                            ),
                        )
                    self._assert_control(claim=claim, lease=lease)
                    evidence_id = self._persist_evidence(
                        claim=claim,
                        context=context,
                        resolved=resolved,
                        peer_ip=peer_ip,
                        observed_at=observed_at,
                    )
                    self._assert_control(claim=claim, lease=lease)
                    if row_count != 0:
                        self._assert_control(claim=claim, lease=lease)
                        self.recovery.complete_probe(
                            claim=claim,
                            result="NONEMPTY",
                            target_connection_evidence_id=evidence_id,
                            failure_code="TARGET_NONEMPTY",
                        )
                        return
                    document: dict[str, Any] = {
                        "result": "EMPTY",
                        "checked_at": checked_at.isoformat().replace(
                            "+00:00",
                            "Z",
                        ),
                        "observed_row_count": 0,
                        "target_datasource_revision_id": str(context.revision.id),
                        "target_endpoint_policy_revision_id": str(context.policy.id),
                        "target_namespace_id": str(context.namespace.id),
                        "physical_table_identity_hash": (
                            context.namespace.physical_table_identity_hash
                        ),
                        "connection_evidence_id": str(evidence_id),
                    }
                    document["evidence_hash"] = self._domain_hash(
                        "DXTARGETEMPTYv1",
                        document,
                    )
                    evidence = TargetEmptyEvidence.model_validate(document)
                    self._assert_control(claim=claim, lease=lease)
                    self.recovery.complete_probe(
                        claim=claim,
                        result="EMPTY",
                        target_connection_evidence_id=evidence_id,
                        target_empty_evidence=evidence.model_dump(mode="json"),
                    )
            except RecoveryProbeTerminationRequested:
                self.recovery.complete_claimed_probe_termination(claim)
                return
            except ProblemException as exc:
                if exc.code == "RECOVERY_PROBE_FENCE_LOST":
                    return
                if exc.code == "RECOVERY_PROBE_TERMINATION_PENDING":
                    self.recovery.complete_claimed_probe_termination(claim)
                    return
                self._complete_inconclusive(claim)
            except BaseException:
                self._complete_inconclusive(claim)

    def _complete_inconclusive(
        self,
        claim: ClaimedRecoveryProbe,
    ) -> None:
        try:
            self.recovery.complete_probe(
                claim=claim,
                result="INCONCLUSIVE",
                failure_code="RECOVERY_PROBE_FAILED_CLOSED",
            )
        except ProblemException:
            return

    def _assert_control(
        self,
        *,
        claim: ClaimedRecoveryProbe,
        lease: ProbeLeaseKeeper,
    ) -> None:
        lease.assert_owned()
        if self.recovery.poll_claimed_probe_termination(claim):
            raise RecoveryProbeTerminationRequested

    def _load_context(
        self,
        claim: ClaimedRecoveryProbe,
    ) -> ProbeContext:
        with self.control.sessions() as session:
            probe = session.get(RecoveryProbe, claim.recovery_probe_id)
            gate = session.get(RecoveryGate, probe.recovery_gate_id) if probe is not None else None
            execution = session.get(Execution, gate.execution_id) if gate is not None else None
            version = (
                session.get(JobVersion, execution.job_version_id) if execution is not None else None
            )
            revision = (
                session.get(
                    DatasourceRevision,
                    probe.target_datasource_revision_id,
                )
                if probe is not None
                else None
            )
            policy = (
                session.get(
                    EndpointPolicyRevision,
                    probe.target_endpoint_policy_revision_id,
                )
                if probe is not None
                else None
            )
            datasource = (
                session.get(Datasource, revision.datasource_id) if revision is not None else None
            )
            namespace = (
                session.get(TargetNamespace, probe.target_namespace_id)
                if probe is not None
                else None
            )
            project = session.get(Project, probe.project_id) if probe is not None else None
            if (
                probe is None
                or probe.active_attempt_id != claim.attempt_id
                or probe.fence_epoch != claim.fence_epoch
                or probe.process_state != "STARTING"
                or gate is None
                or execution is None
                or version is None
                or revision is None
                or policy is None
                or datasource is None
                or namespace is None
                or project is None
            ):
                raise RuntimeError("claimed recovery probe binding is stale")
            return ProbeContext(
                probe=probe,
                gate=gate,
                execution=execution,
                version=version,
                revision=revision,
                policy=policy,
                datasource=datasource,
                namespace=namespace,
                organization_id=project.organization_id,
                spec=JobSpecV1.model_validate(version.spec_json),
            )

    def _persist_evidence(
        self,
        *,
        claim: ClaimedRecoveryProbe,
        context: ProbeContext,
        resolved: ResolvedEndpoint,
        peer_ip: str,
        observed_at: datetime,
    ) -> UUID:
        with self.credentials.sessions.begin() as session:
            revision = session.get(
                DatasourceRevision,
                context.revision.id,
            )
            if revision is None:
                raise RuntimeError("recovery datasource revision disappeared")
            evidence = self.credentials.persist_worker_connection_evidence(
                session,
                operation_kind="RECOVERY_PROBE",
                datasource_revision=revision,
                resolved=resolved,
                peer_ip=peer_ip,
                tls_peer_spki_sha256=None,
                observed_at=observed_at,
                execution_id=None,
                recovery_probe_id=claim.recovery_probe_id,
                attempt_id=claim.attempt_id,
                fence_epoch=claim.fence_epoch,
            )
            return evidence.id

    def _assert_physical_endpoint(
        self,
        *,
        context: ProbeContext,
        server_identity: str,
        server_version: str,
    ) -> None:
        expected_major = "8." if context.revision.engine == "MYSQL_8" else "15."
        identity_scheme = (
            "MYSQL_SERVER_UUID"
            if context.revision.engine == "MYSQL_8"
            else "POSTGRES_SYSTEM_IDENTIFIER"
        )
        actual_hash = hashlib.sha256(
            (
                "DXPHYSICALENDPOINTv1\n"
                f"{str(context.organization_id).lower()}\n"
                f"{context.revision.engine}\n"
                f"{identity_scheme}\n"
                f"{server_identity}"
            ).encode()
        ).hexdigest()
        with self.control.sessions() as session:
            identity = session.get(
                PhysicalEndpointIdentity,
                context.revision.physical_endpoint_identity_id,
            )
            if (
                not server_version.startswith(expected_major)
                or identity is None
                or identity.server_identity_hash != actual_hash
            ):
                raise ProblemException(
                    status=409,
                    code="RECOVERY_TARGET_IDENTITY_MISMATCH",
                    title="恢复目标物理身份不匹配",
                    detail="RecoveryProbe 不会对未授权物理目标写入 VERIFIED。",
                )

    @staticmethod
    def _required(value: UUID | None) -> UUID:
        if value is None:
            raise RuntimeError("recovery credential binding is incomplete")
        return value

    @staticmethod
    def _domain_hash(domain: str, value: object) -> str:
        return hashlib.sha256(domain.encode("ascii") + b"\n" + rfc8785.dumps(value)).hexdigest()
