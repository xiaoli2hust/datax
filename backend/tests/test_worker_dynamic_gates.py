from __future__ import annotations

from datetime import UTC, datetime

import pytest

from datax_studio.egress_attestation import (
    EgressAttestationError,
    EgressVerification,
)
from datax_studio.settings import Settings
from datax_studio.worker.main import (
    collect_dynamic_worker_attestation,
    decide_worker_loop,
    startup_reconciliation_allowed,
)
from datax_studio.worker.storage_attestation import (
    StorageAttestationError,
    StorageVerification,
)


def _egress_verification() -> EgressVerification:
    return EgressVerification(
        policy_engine_version="des-nftables-egress-v1",
        resolver_policy_version="des-system-dns-v1",
        network_namespace_id="net:[1234]",
        policy_set_hash="a" * 64,
        ruleset_hash="b" * 64,
        checked_at=datetime.now(UTC),
    )


def _storage_verification() -> StorageVerification:
    return StorageVerification(
        log_mount_identity_hash="c" * 64,
        workspace_mount_identity_hash="d" * 64,
        log_free_bytes=1024 * 1024 * 1024,
        workspace_free_bytes=1024 * 1024 * 1024,
        checked_at=datetime.now(UTC),
    )


class _SequenceEgressVerifier:
    def __init__(
        self,
        outcomes: list[EgressVerification | EgressAttestationError],
    ) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def verify_runtime(self) -> EgressVerification:
        outcome = self.outcomes[self.calls]
        self.calls += 1
        if isinstance(outcome, EgressAttestationError):
            raise outcome
        return outcome


class _FixedStorageVerifier:
    def __init__(
        self,
        outcome: StorageVerification | StorageAttestationError,
    ) -> None:
        self.outcome = outcome
        self.calls = 0

    def verify_runtime(self) -> StorageVerification:
        self.calls += 1
        if isinstance(self.outcome, StorageAttestationError):
            raise self.outcome
        return self.outcome


@pytest.mark.parametrize(
    "failure_code",
    [
        "EGRESS_ATTESTATION_STALE",
        "EGRESS_NETWORK_NAMESPACE_MISMATCH",
        "EGRESS_ATTESTATION_UNAVAILABLE",
    ],
)
def test_each_dynamic_check_immediately_blocks_invalid_egress(
    failure_code: str,
) -> None:
    egress = _SequenceEgressVerifier(
        [
            _egress_verification(),
            EgressAttestationError(failure_code),
        ]
    )
    storage = _FixedStorageVerifier(_storage_verification())

    first = collect_dynamic_worker_attestation(
        egress_verifier=egress,
        storage_verifier=storage,
    )
    second = collect_dynamic_worker_attestation(
        egress_verifier=egress,
        storage_verifier=storage,
    )
    ready = decide_worker_loop(
        runtime_ready=True,
        runtime_code="RUNTIME_OK",
        egress_verified=first.egress_verified,
        egress_code=first.egress_code,
        storage_verified=first.storage_verified,
        storage_code=first.storage_code,
        dispatcher_available=True,
        reconciliation_current=True,
        draining=False,
    )
    blocked = decide_worker_loop(
        runtime_ready=True,
        runtime_code="RUNTIME_OK",
        egress_verified=second.egress_verified,
        egress_code=second.egress_code,
        storage_verified=second.storage_verified,
        storage_code=second.storage_code,
        dispatcher_available=True,
        reconciliation_current=True,
        draining=False,
    )

    assert egress.calls == 2
    assert storage.calls == 2
    assert ready.status == "READY"
    assert ready.reconcile_expired_leases is True
    assert ready.dispatch is True
    assert blocked.status == "BLOCKED_EGRESS"
    assert blocked.code == failure_code
    assert blocked.reconcile_expired_leases is False
    assert blocked.dispatch is False
    assert (
        startup_reconciliation_allowed(
            runtime_ready=True,
            dynamic_attestation=second,
            dispatcher_available=True,
        )
        is False
    )


def test_storage_attestation_failure_blocks_reconcile_and_dispatch() -> None:
    failure_code = "STORAGE_MOUNTS_NOT_INDEPENDENT"
    dynamic = collect_dynamic_worker_attestation(
        egress_verifier=_SequenceEgressVerifier(
            [_egress_verification()]
        ),
        storage_verifier=_FixedStorageVerifier(
            StorageAttestationError(failure_code)
        ),
    )

    decision = decide_worker_loop(
        runtime_ready=True,
        runtime_code="RUNTIME_OK",
        egress_verified=dynamic.egress_verified,
        egress_code=dynamic.egress_code,
        storage_verified=dynamic.storage_verified,
        storage_code=dynamic.storage_code,
        dispatcher_available=True,
        reconciliation_current=True,
        draining=False,
    )

    assert decision.status == "BLOCKED_STORAGE"
    assert decision.code == failure_code
    assert decision.reconcile_expired_leases is False
    assert decision.dispatch is False
    assert (
        startup_reconciliation_allowed(
            runtime_ready=True,
            dynamic_attestation=dynamic,
            dispatcher_available=True,
        )
        is False
    )


def test_environment_boolean_cannot_authorize_worker_egress() -> None:
    assert "egress_enforcement_verified" not in Settings.model_fields
