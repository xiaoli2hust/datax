from __future__ import annotations

import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from datax_studio.api.problems import ProblemException
from datax_studio.core.schemas import ClaimedExecution
from datax_studio.credentials.network import ResolvedEndpoint
from datax_studio.worker import executor as executor_module
from datax_studio.worker.executor import (
    ExecutionWorker,
    VerificationCanceled,
    VerificationTerminated,
)
from datax_studio.worker.process import ProcessAction, ProcessEndReason
from datax_studio.worker.reconcile import WorkerReconciler


def _resolved(
    *,
    hostname: str,
    addresses: tuple[str, ...],
) -> ResolvedEndpoint:
    return ResolvedEndpoint(
        endpoint_policy_revision_id=uuid4(),
        endpoint_policy_hash="1" * 64,
        hostname=hostname,
        port=5432,
        cname_chain=(),
        resolved_ips=addresses,
        selected_ip=addresses[0],
        dns_valid_until=datetime.now(UTC) + timedelta(seconds=30),
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        egress_enforcement_status="VERIFIED",
        egress_attestation_hash="2" * 64,
    )


def test_datax_exact_ip_endpoint_passes_pinning_gate() -> None:
    resolved = _resolved(hostname="10.20.0.42", addresses=("10.20.0.42",))

    ExecutionWorker._assert_datax_endpoint_pinning(
        revision=SimpleNamespace(host="10.20.0.42", ssl_mode="VERIFY_CA"),
        policy=SimpleNamespace(host_kind="EXACT_IP", host_value="10.20.0.42"),
        resolved=resolved,
    )


@pytest.mark.parametrize(
    "addresses",
    [
        ("10.20.0.42", "172.29.0.10"),
        ("172.29.0.10",),
    ],
)
def test_datax_fqdn_multi_address_or_control_rebinding_fails_closed(
    addresses: tuple[str, ...],
) -> None:
    resolved = _resolved(hostname="db.example.com", addresses=addresses)

    with pytest.raises(ProblemException) as failure:
        ExecutionWorker._assert_datax_endpoint_pinning(
            revision=SimpleNamespace(
                host="db.example.com",
                ssl_mode="VERIFY_CA",
            ),
            policy=SimpleNamespace(
                host_kind="EXACT_FQDN",
                host_value="db.example.com",
            ),
            resolved=resolved,
        )

    assert failure.value.code == "DATAX_ENDPOINT_PINNING_UNSUPPORTED"


def test_datax_verify_full_exact_ip_is_blocked_until_ip_san_is_certified() -> None:
    resolved = _resolved(hostname="10.20.0.42", addresses=("10.20.0.42",))

    with pytest.raises(ProblemException) as failure:
        ExecutionWorker._assert_datax_endpoint_pinning(
            revision=SimpleNamespace(
                host="10.20.0.42",
                ssl_mode="VERIFY_FULL",
            ),
            policy=SimpleNamespace(
                host_kind="EXACT_IP",
                host_value="10.20.0.42",
            ),
            resolved=resolved,
        )

    assert failure.value.code == "DATAX_VERIFY_FULL_IP_UNCERTIFIED"


def test_worker_start_rechecks_windows_e4_before_workspace_or_credentials() -> None:
    calls: list[tuple[str, object]] = []

    def reject_certification(**_kwargs: object) -> None:
        calls.append(("certification", None))
        raise ProblemException(
            status=409,
            code="PLUGIN_WINDOWS_E4_CERTIFICATION_REQUIRED",
            title="certification required",
        )

    worker = object.__new__(ExecutionWorker)
    worker.control = SimpleNamespace(
        require_job_version_plugin_certification=reject_certification,
    )
    worker._load_context = lambda _claim: SimpleNamespace(  # type: ignore[method-assign]
        version=SimpleNamespace()
    )
    worker._create_workspace = lambda _claim: pytest.fail(  # type: ignore[method-assign]
        "workspace must remain behind the E4 gate"
    )
    worker._fail_current_state = (  # type: ignore[method-assign]
        lambda **kwargs: calls.append(("failed", kwargs["code"]))
    )
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    worker.run_claimed(claim)

    assert calls == [
        ("certification", None),
        ("failed", "PLUGIN_WINDOWS_E4_CERTIFICATION_REQUIRED"),
    ]


def test_datax_phase_records_unobserved_peer_evidence_before_process_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evidence: list[dict[str, object]] = []
    process_started = False

    class _Lease:
        lost = False

        def assert_active(self) -> None:
            return None

    class _Guard:
        def verify_rebinding(self, *_args: object) -> None:
            return None

        @contextmanager
        def lease(self, _resolved_endpoint: ResolvedEndpoint):
            yield _Lease()

    worker = object.__new__(ExecutionWorker)
    worker.credentials = SimpleNamespace(guard=_Guard())
    worker.settings = SimpleNamespace(
        runtime_manifest_path=tmp_path / "runtime-manifest.json",
        java_binary_path=tmp_path / "java",
        execution_log_limit_bytes=1024,
        execution_log_line_limit_bytes=256,
        worker_control_poll_seconds=0.1,
    )
    worker.runtime_manifest = SimpleNamespace(datax_home="datax")
    worker.reconciler = SimpleNamespace(
        poll_claim_action=lambda _claim: None,
        record_process_identity=lambda **_kwargs: None,
    )

    class _WorkerLease:
        def __init__(self) -> None:
            self._lost = threading.Event()
            self._terminated = threading.Event()

        def assert_owned(self) -> None:
            return None

    def persist(**kwargs: object) -> None:
        evidence.append(kwargs)

    worker._persist_connection_evidence = persist  # type: ignore[method-assign]
    monkeypatch.setattr(
        executor_module,
        "build_datax_command",
        lambda **_kwargs: ("java", "datax"),
    )

    def run_process(*_args: object, **_kwargs: object) -> SimpleNamespace:
        nonlocal process_started
        process_started = True
        assert len(evidence) == 2
        assert all(item["operation_kind"] == "DATAX" for item in evidence)
        assert all(item["peer_ip"] is None for item in evidence)
        assert all(item["peer_observation_status"] == "ENFORCED_NOT_OBSERVED" for item in evidence)
        return SimpleNamespace(end_reason=ProcessEndReason.EXITED)

    monkeypatch.setattr(executor_module, "run_managed_process", run_process)
    source_resolved = _resolved(
        hostname="10.20.0.41",
        addresses=("10.20.0.41",),
    )
    target_resolved = _resolved(
        hostname="10.20.0.42",
        addresses=("10.20.0.42",),
    )
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    worker._run_datax(
        claim=claim,
        context=SimpleNamespace(
            execution=SimpleNamespace(timeout_seconds=60),
            source_policy=SimpleNamespace(),
            target_policy=SimpleNamespace(),
            source_revision=SimpleNamespace(id=uuid4()),
            target_revision=SimpleNamespace(id=uuid4()),
        ),
        job_file=tmp_path / "job.json",
        runtime_log_directory=tmp_path / "runtime-logs",
        runtime_workspace=tmp_path / "sensitive-process",
        log_path=tmp_path / "run.log",
        source_password=bytearray(b"source"),
        target_password=bytearray(b"target"),
        lease=_WorkerLease(),  # type: ignore[arg-type]
        source_resolved=source_resolved,
        target_resolved=target_resolved,
    )

    assert process_started


def test_preflight_stops_before_target_probe_when_safety_stop_arrives(
    tmp_path: Path,
) -> None:
    events: list[str] = []

    class _Lease:
        def assert_owned(self) -> None:
            return None

    class _Guard:
        def resolve(self, policy: SimpleNamespace, **_kwargs: object) -> object:
            events.append(f"resolve-{policy.name}")
            return SimpleNamespace()

    class _Connector:
        def probe(self, revision: SimpleNamespace, **_kwargs: object) -> object:
            events.append(f"probe-{revision.name}")
            control_callback = _kwargs.get("control_callback")
            assert callable(control_callback)
            control_callback()
            return SimpleNamespace(server_identity="server", server_version="8.0")

    worker = object.__new__(ExecutionWorker)
    worker.credentials = SimpleNamespace(
        guard=_Guard(),
        connector=_Connector(),
    )
    worker.reconciler = SimpleNamespace(
        poll_claim_action=lambda _claim: (
            ProcessAction.TERMINATE
            if "probe-source" in events
            else ProcessAction.CONTINUE
        )
    )
    worker._assert_datax_endpoint_pinning = lambda **_kwargs: None  # type: ignore[method-assign]
    worker._assert_physical_endpoint = lambda **_kwargs: None  # type: ignore[method-assign]
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    with pytest.raises(VerificationTerminated):
        worker._preflight(  # noqa: SLF001
            claim=claim,
            context=SimpleNamespace(
                source_policy=SimpleNamespace(name="source"),
                target_policy=SimpleNamespace(name="target"),
                source_revision=SimpleNamespace(
                    name="source",
                    host="10.20.0.41",
                    port=5432,
                ),
                target_revision=SimpleNamespace(
                    name="target",
                    host="10.20.0.42",
                    port=5432,
                ),
            ),
            workspace=tmp_path,
            source_password=bytearray(b"source"),
            target_password=bytearray(b"target"),
            lease=_Lease(),  # type: ignore[arg-type]
        )

    assert events == ["resolve-source", "resolve-target", "probe-source"]


def test_worker_checks_control_before_writing_plaintext_job_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _Lease:
        def assert_owned(self) -> None:
            return None

    worker = object.__new__(ExecutionWorker)
    worker.reconciler = SimpleNamespace(
        poll_claim_action=lambda _claim: ProcessAction.TERMINATE,
    )
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )
    monkeypatch.setattr(
        executor_module,
        "write_job_file",
        lambda *_args, **_kwargs: pytest.fail("job file must remain unwritten"),
    )

    with pytest.raises(VerificationTerminated):
        worker._write_job_file_after_control(  # noqa: SLF001
            claim=claim,
            lease=_Lease(),  # type: ignore[arg-type]
            job_file=tmp_path / "job.json",
            datax_job={"job": {"content": []}},
        )


def test_datax_last_control_check_blocks_popen_after_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evidence: list[dict[str, object]] = []

    class _EgressLease:
        lost = False

        def assert_active(self) -> None:
            return None

    class _Guard:
        def verify_rebinding(self, *_args: object) -> None:
            return None

        @contextmanager
        def lease(self, _resolved_endpoint: ResolvedEndpoint):
            yield _EgressLease()

    class _WorkerLease:
        def __init__(self) -> None:
            self._lost = threading.Event()
            self._terminated = threading.Event()

        def assert_owned(self) -> None:
            return None

    worker = object.__new__(ExecutionWorker)
    worker.credentials = SimpleNamespace(guard=_Guard())
    worker.settings = SimpleNamespace(
        runtime_manifest_path=tmp_path / "runtime-manifest.json",
        java_binary_path=tmp_path / "java",
        execution_log_limit_bytes=1024,
        execution_log_line_limit_bytes=256,
        worker_control_poll_seconds=0.1,
    )
    worker.runtime_manifest = SimpleNamespace(datax_home="datax")
    worker.reconciler = SimpleNamespace(
        poll_claim_action=lambda _claim: (
            ProcessAction.TERMINATE
            if len(evidence) == 2
            else ProcessAction.CONTINUE
        ),
        record_process_identity=lambda **_kwargs: None,
    )
    worker._persist_connection_evidence = (  # type: ignore[method-assign]
        lambda **kwargs: evidence.append(kwargs)
    )
    monkeypatch.setattr(
        executor_module,
        "build_datax_command",
        lambda **_kwargs: ("java", "datax"),
    )
    monkeypatch.setattr(
        executor_module,
        "run_managed_process",
        lambda *_args, **_kwargs: pytest.fail("Popen must remain behind final control"),
    )
    source_resolved = _resolved(
        hostname="10.20.0.41",
        addresses=("10.20.0.41",),
    )
    target_resolved = _resolved(
        hostname="10.20.0.42",
        addresses=("10.20.0.42",),
    )
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    with pytest.raises(VerificationTerminated):
        worker._run_datax(  # noqa: SLF001
            claim=claim,
            context=SimpleNamespace(
                execution=SimpleNamespace(timeout_seconds=60),
                source_policy=SimpleNamespace(),
                target_policy=SimpleNamespace(),
                source_revision=SimpleNamespace(id=uuid4()),
                target_revision=SimpleNamespace(id=uuid4()),
            ),
            job_file=tmp_path / "job.json",
            runtime_log_directory=tmp_path / "runtime-logs",
            runtime_workspace=tmp_path / "sensitive-process",
            log_path=tmp_path / "run.log",
            source_password=bytearray(b"source"),
            target_password=bytearray(b"target"),
            lease=_WorkerLease(),  # type: ignore[arg-type]
            source_resolved=source_resolved,
            target_resolved=target_resolved,
        )

    assert len(evidence) == 2


@pytest.mark.parametrize(
    ("oracle_started", "expected"),
    [(False, "NOT_STARTED"), (True, "INCONCLUSIVE")],
)
def test_worker_failure_uses_actual_oracle_start_boundary(
    oracle_started: bool,
    expected: str,
) -> None:
    transitions: list[dict[str, object]] = []
    worker = object.__new__(ExecutionWorker)
    worker.control = SimpleNamespace(
        transition_claimed_execution=lambda **kwargs: transitions.append(kwargs)
    )
    worker.reconciler = SimpleNamespace(ensure_terminal_gate=lambda _id: None)
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    worker._fail_current_state(
        claim=claim,
        state="VERIFYING",
        code="ORACLE_READ_FAILED",
        oracle_started=oracle_started,
    )

    assert transitions[0]["verification_state"] == expected


def test_verification_control_acknowledges_cancel_and_interrupts_oracle() -> None:
    lease_checks = 0

    class _Lease:
        def assert_owned(self) -> None:
            nonlocal lease_checks
            lease_checks += 1

    worker = object.__new__(ExecutionWorker)
    worker.reconciler = SimpleNamespace(
        poll_claim_action=lambda _claim: ProcessAction.CANCEL,
    )
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    with pytest.raises(VerificationCanceled):
        worker._poll_verification_control(  # noqa: SLF001
            claim=claim,
            lease=_Lease(),  # type: ignore[arg-type]
        )

    assert lease_checks == 1


@pytest.mark.parametrize("oracle_started", [False, True])
def test_worker_failure_converges_cancel_that_won_terminal_ordering(
    oracle_started: bool,
) -> None:
    completed: list[dict[str, object]] = []

    def reject_terminal(**_kwargs: object) -> None:
        raise ProblemException(
            status=409,
            code="EXECUTION_CANCEL_PENDING",
            title="cancel pending",
            detail="cancel won terminal ordering",
        )

    worker = object.__new__(ExecutionWorker)
    worker.control = SimpleNamespace(
        transition_claimed_execution=reject_terminal,
    )
    worker.reconciler = SimpleNamespace(
        poll_claim_action=lambda _claim: ProcessAction.CANCEL,
        complete_claimed_cancel=lambda **kwargs: completed.append(kwargs),
        ensure_terminal_gate=lambda _id: None,
    )
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    worker._fail_current_state(  # noqa: SLF001
        claim=claim,
        state="VERIFYING" if oracle_started else "RUNNING",
        code="WORKER_INTERNAL_FAILURE",
        oracle_started=oracle_started,
    )

    assert completed == [
        {
            "claim": claim,
            "oracle_started": oracle_started,
        }
    ]


@pytest.mark.parametrize("oracle_started", [False, True])
def test_worker_failure_converges_safety_termination_that_won_terminal_ordering(
    oracle_started: bool,
) -> None:
    completed: list[dict[str, object]] = []

    def reject_terminal(**_kwargs: object) -> None:
        raise ProblemException(
            status=409,
            code="WORK_TERMINATION_PENDING",
            title="safety termination pending",
            detail="safety stop won terminal ordering",
        )

    worker = object.__new__(ExecutionWorker)
    worker.control = SimpleNamespace(
        transition_claimed_execution=reject_terminal,
    )
    worker.reconciler = SimpleNamespace(
        complete_claimed_termination=lambda **kwargs: completed.append(kwargs),
    )
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    worker._fail_current_state(  # noqa: SLF001
        claim=claim,
        state="VERIFYING" if oracle_started else "RUNNING",
        code="WORKER_INTERNAL_FAILURE",
        oracle_started=oracle_started,
    )

    assert completed == [
        {
            "claim": claim,
            "oracle_started": oracle_started,
        }
    ]


@pytest.mark.parametrize(
    "code",
    [
        "WORK_TERMINATION_PENDING",
        "TARGET_EXCLUSIVITY_NOT_ACTIVE",
        "TARGET_EXCLUSIVITY_BROKEN",
    ],
)
@pytest.mark.parametrize(
    ("oracle_started", "verification_state"),
    [(False, "NOT_STARTED"), (True, "INCONCLUSIVE")],
)
def test_complete_claimed_cancel_converges_safety_termination_that_won_ordering(
    code: str,
    oracle_started: bool,
    verification_state: str,
) -> None:
    transitions: list[dict[str, object]] = []
    completed: list[dict[str, object]] = []

    def reject_canceled(**kwargs: object) -> None:
        transitions.append(kwargs)
        raise ProblemException(
            status=409,
            code=code,
            title="safety termination pending",
            detail="safety stop won cancel terminal ordering",
        )

    reconciler = object.__new__(WorkerReconciler)
    reconciler.control = SimpleNamespace(
        transition_claimed_execution=reject_canceled,
        complete_claimed_execution_termination=lambda **kwargs: completed.append(kwargs),
    )
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    reconciler.complete_claimed_cancel(
        claim=claim,
        oracle_started=oracle_started,
    )

    assert transitions == [
        {
            "claim": claim,
            "expected_state": "CANCEL_REQUESTED",
            "new_state": "CANCELED",
            "data_effect": "UNKNOWN",
            "verification_state": verification_state,
            "failure_code": "OPERATOR_CANCELED",
            "failure_message": "Execution was canceled after Worker acknowledgement.",
        }
    ]
    assert completed == [
        {
            "claim": claim,
            "oracle_started": oracle_started,
        }
    ]


def test_verification_control_checks_target_exclusivity_at_every_boundary() -> None:
    exclusivity_checks: list[ClaimedExecution] = []

    class _Lease:
        def assert_owned(self) -> None:
            return None

    worker = object.__new__(ExecutionWorker)
    worker.reconciler = SimpleNamespace(
        poll_claim_action=lambda _claim: ProcessAction.CONTINUE,
    )
    worker.control = SimpleNamespace(
        assert_claimed_verification_exclusivity=(lambda *, claim: exclusivity_checks.append(claim))
    )
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    worker._poll_verification_control(  # noqa: SLF001
        claim=claim,
        lease=_Lease(),  # type: ignore[arg-type]
    )

    assert exclusivity_checks == [claim]


def test_verification_control_preserves_target_exclusivity_failure_code() -> None:
    class _Lease:
        def assert_owned(self) -> None:
            return None

    def fail_exclusivity(*, claim: ClaimedExecution) -> None:
        del claim
        raise ProblemException(
            status=409,
            code="TARGET_EXCLUSIVITY_BROKEN",
            title="目标独占声明已失效",
            detail="Oracle 必须中断。",
        )

    worker = object.__new__(ExecutionWorker)
    worker.reconciler = SimpleNamespace(
        poll_claim_action=lambda _claim: ProcessAction.CONTINUE,
    )
    worker.control = SimpleNamespace(
        assert_claimed_verification_exclusivity=fail_exclusivity,
    )
    claim = ClaimedExecution(
        execution_id=uuid4(),
        attempt_id=uuid4(),
        fence_epoch=1,
        lease_token="x" * 32,
    )

    with pytest.raises(ProblemException) as broken:
        worker._poll_verification_control(  # noqa: SLF001
            claim=claim,
            lease=_Lease(),  # type: ignore[arg-type]
        )

    assert broken.value.code == "TARGET_EXCLUSIVITY_BROKEN"
