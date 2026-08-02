from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from datax_studio.credentials.network import (
    DnsResolution,
    EndpointPolicyGuard,
)
from datax_studio.egress_attestation import (
    EgressAttestationError,
    EgressLease,
    EgressVerification,
)


class _Resolver:
    def resolve(self, *_args: object, **_kwargs: object) -> DnsResolution:
        return DnsResolution((), ("10.20.30.40",), 30)


class _Verifier:
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


class _LeaseClient:
    def __init__(
        self,
        *,
        renew_after_seconds: float = 60,
        fail_renew: bool = False,
        returned_ip: str = "10.20.30.40",
        expires_after_seconds: float = 30,
    ) -> None:
        self.renew_after_seconds = renew_after_seconds
        self.fail_renew = fail_renew
        self.returned_ip = returned_ip
        self.expires_after_seconds = expires_after_seconds
        self.created = 0
        self.renewed = 0
        self.released = 0

    def create_lease(
        self,
        *,
        revision_id: UUID,
        policy_hash: str,
        selected_ip: str,
        port: int,
        timeout_seconds: float | None = None,
    ) -> EgressLease:
        del selected_ip, timeout_seconds
        self.created += 1
        return self._lease(
            revision_id=revision_id,
            policy_hash=policy_hash,
            port=port,
        )

    def renew_lease(
        self,
        lease: EgressLease,
        *,
        timeout_seconds: float | None = None,
    ) -> EgressLease:
        del timeout_seconds
        self.renewed += 1
        if self.fail_renew:
            raise EgressAttestationError("LEASE_POLICY_NOT_ACTIVE")
        return self._lease(
            revision_id=lease.revision_id,
            policy_hash=lease.policy_hash,
            port=lease.port,
            lease_id=lease.lease_id,
        )

    def release_lease(
        self,
        lease: EgressLease,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        del lease, timeout_seconds
        self.released += 1

    def _lease(
        self,
        *,
        revision_id: UUID,
        policy_hash: str,
        port: int,
        lease_id: UUID | None = None,
    ) -> EgressLease:
        return EgressLease(
            lease_id=lease_id or uuid4(),
            revision_id=revision_id,
            policy_hash=policy_hash,
            selected_ip=self.returned_ip,
            port=port,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=self.expires_after_seconds),
            renew_after_seconds=self.renew_after_seconds,  # type: ignore[arg-type]
            kernel_timeout_seconds=15,
            ruleset_hash="3" * 64,
            bearer_token="A" * 43,
        )


class _Revision:
    id = UUID("11111111-1111-1111-1111-111111111111")
    host_kind = "EXACT_FQDN"
    host_value = "db.example.com"
    allowed_cidrs = ["10.20.30.0/24"]
    allowed_ports = [5432]
    dns_ttl_ceiling_seconds = 30
    resolver_policy_version = "resolver-v1"
    egress_policy_version = "egress-v1"
    policy_hash = "4" * 64


def _guard(client: _LeaseClient) -> EndpointPolicyGuard:
    return EndpointPolicyGuard(
        resolver_policy_version="resolver-v1",
        egress_policy_version="egress-v1",
        egress_verifier=_Verifier(),
        egress_lease_client=client,
        resolver=_Resolver(),
    )


def test_exact_ip_lease_is_recorded_and_released() -> None:
    client = _LeaseClient()
    guard = _guard(client)
    resolved = guard.resolve(
        _Revision(),
        host="db.example.com",
        port=5432,
    )
    attestation_hash = resolved.egress_evidence_hash

    with guard.lease(resolved) as lease:
        lease.assert_active()
        assert resolved.egress_evidence_hash != attestation_hash

    assert client.created == 1
    assert client.released == 1


def test_lease_renewal_failure_is_observable_before_success() -> None:
    client = _LeaseClient(renew_after_seconds=0.01, fail_renew=True)
    guard = _guard(client)
    resolved = guard.resolve(
        _Revision(),
        host="db.example.com",
        port=5432,
    )

    with guard.lease(resolved) as lease:
        deadline = time.monotonic() + 1
        while not lease.lost and time.monotonic() < deadline:
            time.sleep(0.005)
        assert lease.lost
        with pytest.raises(EgressAttestationError, match="EGRESS_LEASE_LOST"):
            lease.assert_active()

    assert client.renewed == 1
    assert client.released == 1


def test_guard_rejects_lease_for_a_different_selected_ip() -> None:
    client = _LeaseClient(returned_ip="10.20.30.41")
    guard = _guard(client)
    resolved = guard.resolve(
        _Revision(),
        host="db.example.com",
        port=5432,
    )

    with (
        pytest.raises(
            EgressAttestationError,
            match="EGRESS_LEASE_ENDPOINT_MISMATCH",
        ),
        guard.lease(resolved),
    ):
        pass

    assert client.released == 1


def test_guard_rejects_and_releases_an_already_expired_lease() -> None:
    client = _LeaseClient(expires_after_seconds=-1)
    guard = _guard(client)
    resolved = guard.resolve(
        _Revision(),
        host="db.example.com",
        port=5432,
    )

    with (
        pytest.raises(EgressAttestationError, match="EGRESS_LEASE_EXPIRED"),
        guard.lease(resolved),
    ):
        pass

    assert client.released == 1


def test_local_expiry_is_observable_even_before_the_renew_thread_runs() -> None:
    client = _LeaseClient(
        expires_after_seconds=0.02,
        renew_after_seconds=60,
    )
    guard = _guard(client)
    resolved = guard.resolve(
        _Revision(),
        host="db.example.com",
        port=5432,
    )

    with guard.lease(resolved) as lease:
        time.sleep(0.03)
        with pytest.raises(EgressAttestationError, match="EGRESS_LEASE_LOST"):
            lease.assert_active()
        assert lease.lost

    assert client.released == 1
