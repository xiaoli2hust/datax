from __future__ import annotations

import ipaddress
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol

import dns.exception
import dns.resolver

from datax_studio.credentials.operation_boundary import (
    OperationDeadline,
    OperationDeadlineExpired,
)
from datax_studio.egress_attestation import (
    EgressAttestationError,
    EgressLease,
    EgressLeaseClient,
    EgressVerification,
    EgressVerifier,
    UnavailableEgressLeaseClient,
    UnavailableEgressVerifier,
)


class EndpointPolicyLike(Protocol):
    id: object
    host_kind: str
    host_value: str
    allowed_cidrs: list[str]
    allowed_ports: list[int]
    dns_ttl_ceiling_seconds: int
    resolver_policy_version: str
    egress_policy_version: str
    policy_hash: str


@dataclass(frozen=True)
class DnsResolution:
    cname_chain: tuple[str, ...]
    addresses: tuple[str, ...]
    ttl_seconds: int


@dataclass
class ResolvedEndpoint:
    endpoint_policy_revision_id: object
    endpoint_policy_hash: str
    hostname: str
    port: int
    cname_chain: tuple[str, ...]
    resolved_ips: tuple[str, ...]
    selected_ip: str
    dns_valid_until: datetime
    resolver_policy_version: str
    egress_policy_version: str
    egress_enforcement_status: str
    egress_attestation_hash: str
    _egress_lease_evidence_hash: str | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _evidence_lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
        compare=False,
    )

    @property
    def egress_evidence_hash(self) -> str:
        with self._evidence_lock:
            return self._egress_lease_evidence_hash or self.egress_attestation_hash

    def record_lease_evidence(self, lease: EgressLease) -> None:
        if (
            lease.revision_id != self.endpoint_policy_revision_id
            or lease.policy_hash != self.endpoint_policy_hash
            or lease.selected_ip != self.selected_ip
            or lease.port != self.port
        ):
            raise EgressAttestationError("EGRESS_LEASE_ENDPOINT_MISMATCH")
        with self._evidence_lock:
            self._egress_lease_evidence_hash = lease.evidence_hash


class EgressLeaseSession:
    """Own and renew one exact-IP kernel allowance without exposing its token."""

    def __init__(
        self,
        *,
        client: EgressLeaseClient,
        resolved: ResolvedEndpoint,
        deadline: OperationDeadline | None = None,
    ) -> None:
        self._client = client
        self._resolved = resolved
        self._deadline = deadline
        self._lease: EgressLease | None = None
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._lock = threading.Lock()
        self._failure: EgressAttestationError | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> EgressLeaseSession:
        self._check_deadline()
        lease = self._client.create_lease(
            revision_id=self._resolved.endpoint_policy_revision_id,
            policy_hash=self._resolved.endpoint_policy_hash,
            selected_ip=self._resolved.selected_ip,
            port=self._resolved.port,
            timeout_seconds=self._remaining_timeout(),
        )
        try:
            self._check_deadline()
            self._assert_matches(lease)
            self._assert_not_expired(lease)
        except (EgressAttestationError, OperationDeadlineExpired):
            # A malformed response may still refer to a real short-lived kernel
            # allowance. Revoke it when possible; its independent 15-second
            # timeout remains the fail-closed backstop.
            with suppress(EgressAttestationError):
                self._client.release_lease(
                    lease,
                    timeout_seconds=self._remaining_timeout(),
                )
            raise
        self._resolved.record_lease_evidence(lease)
        with self._lock:
            self._lease = lease
        self._thread = threading.Thread(
            target=self._renew_loop,
            name=f"egress-lease-{lease.lease_id}",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(
        self,
        _exception_type: object,
        _exception: object,
        _traceback: object,
    ) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            join_timeout = 6.0
            if self._deadline is not None:
                join_timeout = min(
                    join_timeout,
                    self._deadline.remaining_seconds(),
                )
            thread.join(timeout=max(0.0, join_timeout))
        with self._lock:
            lease = self._lease
        if lease is not None:
            # The kernel element is independently bounded to 15 seconds.
            # Callers decide success before closing and must call
            # assert_active(); release is therefore best-effort cleanup.
            try:
                timeout_seconds = self._remaining_timeout()
            except OperationDeadlineExpired:
                # Do not extend the user-visible total operation deadline for
                # cleanup. The kernel's independent 15-second expiry is the
                # fail-closed fallback when no time remains for DELETE.
                return
            with suppress(EgressAttestationError):
                self._client.release_lease(lease, timeout_seconds=timeout_seconds)

    @property
    def lost(self) -> bool:
        return self._lost.is_set()

    def assert_active(self) -> None:
        self._check_deadline()
        if self._lost.is_set():
            with self._lock:
                failure = self._failure
            raise EgressAttestationError("EGRESS_LEASE_LOST") from failure
        with self._lock:
            lease = self._lease
        if lease is None:
            raise EgressAttestationError("EGRESS_LEASE_NOT_STARTED")
        try:
            self._assert_matches(lease)
            self._assert_not_expired(lease)
        except EgressAttestationError as exc:
            self._mark_lost(exc)
            raise EgressAttestationError("EGRESS_LEASE_LOST") from exc

    def _renew_loop(self) -> None:
        while True:
            with self._lock:
                lease = self._lease
            if lease is None:
                self._mark_lost(EgressAttestationError("EGRESS_LEASE_NOT_STARTED"))
                return
            if self._stop.wait(lease.renew_after_seconds):
                return
            try:
                renewed = self._client.renew_lease(
                    lease,
                    timeout_seconds=self._remaining_timeout(),
                )
                self._assert_matches(renewed)
                self._assert_not_expired(renewed)
                self._resolved.record_lease_evidence(renewed)
            except (EgressAttestationError, OperationDeadlineExpired) as exc:
                self._mark_lost(exc)
                return
            with self._lock:
                self._lease = renewed

    def _mark_lost(self, failure: EgressAttestationError) -> None:
        with self._lock:
            self._failure = failure
        self._lost.set()

    def _check_deadline(self) -> None:
        if self._deadline is not None:
            self._deadline.check_expired()

    def _remaining_timeout(self) -> float | None:
        if self._deadline is None:
            return None
        return self._deadline.check_expired()

    def _assert_matches(self, lease: EgressLease) -> None:
        if (
            lease.revision_id != self._resolved.endpoint_policy_revision_id
            or lease.policy_hash != self._resolved.endpoint_policy_hash
            or lease.selected_ip != self._resolved.selected_ip
            or lease.port != self._resolved.port
        ):
            raise EgressAttestationError("EGRESS_LEASE_ENDPOINT_MISMATCH")

    @staticmethod
    def _assert_not_expired(lease: EgressLease) -> None:
        if lease.expires_at.tzinfo is None or lease.expires_at <= datetime.now(UTC):
            raise EgressAttestationError("EGRESS_LEASE_EXPIRED")


class Resolver(Protocol):
    def resolve(
        self,
        hostname: str,
        *,
        timeout_seconds: float,
        ttl_ceiling_seconds: int,
        deadline: OperationDeadline | None = None,
    ) -> DnsResolution: ...


class SystemDnsResolver:
    """Bounded A/AAAA/CNAME resolver used before every connection stage."""

    def __init__(self) -> None:
        self._resolver = dns.resolver.Resolver(configure=True)

    def resolve(
        self,
        hostname: str,
        *,
        timeout_seconds: float,
        ttl_ceiling_seconds: int,
        deadline: OperationDeadline | None = None,
    ) -> DnsResolution:
        current = hostname.rstrip(".").casefold()
        chain: list[str] = []
        ttl_values: list[int] = []

        def resolve_record(record_type: str) -> dns.resolver.Answer:
            if deadline is not None:
                query_timeout = deadline.bounded_timeout(timeout_seconds)
            else:
                query_timeout = timeout_seconds
            answer = self._resolver.resolve(
                current,
                record_type,
                lifetime=query_timeout,
                search=False,
                raise_on_no_answer=False,
            )
            if deadline is not None:
                deadline.check_expired()
            return answer

        for _ in range(8):
            try:
                answer = resolve_record("CNAME")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                break
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                raise ValueError("DNS_RESOLUTION_FAILED") from exc
            if answer.rrset is None or not answer:
                break
            target = str(answer[0].target).rstrip(".").casefold()
            if not target or target in chain or target == current:
                raise ValueError("DNS_CNAME_LOOP")
            chain.append(target)
            ttl_values.append(int(answer.rrset.ttl))
            current = target
        else:
            raise ValueError("DNS_CNAME_CHAIN_TOO_DEEP")

        addresses: set[str] = set()
        for record_type in ("A", "AAAA"):
            try:
                answer = resolve_record(record_type)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                raise ValueError("DNS_RESOLUTION_FAILED") from exc
            if answer.rrset is None:
                continue
            ttl_values.append(int(answer.rrset.ttl))
            addresses.update(ipaddress.ip_address(str(item)).compressed for item in answer)
        if not addresses:
            raise ValueError("DNS_NO_ADDRESS")
        ttl = min([ttl_ceiling_seconds, *ttl_values])
        ordered = tuple(
            str(address)
            for address in sorted(
                (ipaddress.ip_address(value) for value in addresses),
                key=lambda item: (item.version, int(item)),
            )
        )
        return DnsResolution(tuple(chain), ordered, max(1, ttl))


class EndpointPolicyGuard:
    def __init__(
        self,
        *,
        resolver_policy_version: str,
        egress_policy_version: str,
        egress_verifier: EgressVerifier | None = None,
        egress_lease_client: EgressLeaseClient | None = None,
        resolver: Resolver | None = None,
        connect_timeout_seconds: float = 5.0,
    ) -> None:
        self.resolver_policy_version = resolver_policy_version
        self.egress_policy_version = egress_policy_version
        self.egress_verifier = egress_verifier or UnavailableEgressVerifier()
        self.egress_lease_client = egress_lease_client or UnavailableEgressLeaseClient()
        self.resolver = resolver or SystemDnsResolver()
        self.connect_timeout_seconds = connect_timeout_seconds

    def resolve(
        self,
        revision: EndpointPolicyLike,
        *,
        host: str,
        port: int,
        now: datetime | None = None,
        deadline: OperationDeadline | None = None,
    ) -> ResolvedEndpoint:
        if deadline is not None:
            deadline.check_expired()
        normalized_host = host.rstrip(".").casefold()
        if port not in revision.allowed_ports:
            raise ValueError("ENDPOINT_PORT_DENIED")
        if revision.resolver_policy_version != self.resolver_policy_version:
            raise ValueError("RESOLVER_POLICY_VERSION_MISMATCH")
        if revision.egress_policy_version != self.egress_policy_version:
            raise ValueError("EGRESS_POLICY_VERSION_MISMATCH")
        verification = self._verify_policy(revision, deadline=deadline)

        expected_host = revision.host_value.rstrip(".").casefold()
        if revision.host_kind == "EXACT_IP":
            try:
                normalized_host = ipaddress.ip_address(normalized_host).compressed
                expected_host = ipaddress.ip_address(expected_host).compressed
            except ValueError as exc:
                raise ValueError("ENDPOINT_IP_INVALID") from exc
            if normalized_host != expected_host:
                raise ValueError("ENDPOINT_HOST_DENIED")
            resolution = DnsResolution((), (normalized_host,), revision.dns_ttl_ceiling_seconds)
        elif revision.host_kind == "EXACT_FQDN":
            try:
                ipaddress.ip_address(normalized_host)
            except ValueError:
                pass
            else:
                raise ValueError("ENDPOINT_FQDN_REQUIRED")
            if normalized_host != expected_host:
                raise ValueError("ENDPOINT_HOST_DENIED")
            resolution = self.resolver.resolve(
                normalized_host,
                # Pass the remaining operation budget to generic resolvers too.
                # SystemDnsResolver will recalculate it for each CNAME/A/AAAA
                # lookup, so neither implementation can turn a single total
                # deadline into one full timeout per DNS record.
                timeout_seconds=(
                    deadline.bounded_timeout(self.connect_timeout_seconds)
                    if deadline is not None
                    else self.connect_timeout_seconds
                ),
                ttl_ceiling_seconds=revision.dns_ttl_ceiling_seconds,
                deadline=deadline,
            )
        else:
            raise ValueError("ENDPOINT_HOST_KIND_INVALID")
        if deadline is not None:
            deadline.check_expired()

        networks = tuple(
            ipaddress.ip_network(value, strict=False) for value in revision.allowed_cidrs
        )
        denied = [
            value
            for value in resolution.addresses
            if not any(ipaddress.ip_address(value) in network for network in networks)
        ]
        if denied:
            # A mixed allowed/denied answer is denied as a whole.
            raise ValueError("DNS_ADDRESS_OUTSIDE_POLICY")
        selected_ip = resolution.addresses[0]
        observed_at = (now or datetime.now(UTC)).astimezone(UTC)
        return ResolvedEndpoint(
            endpoint_policy_revision_id=revision.id,
            endpoint_policy_hash=revision.policy_hash,
            hostname=normalized_host,
            port=port,
            cname_chain=resolution.cname_chain,
            resolved_ips=resolution.addresses,
            selected_ip=selected_ip,
            dns_valid_until=observed_at + timedelta(seconds=resolution.ttl_seconds),
            resolver_policy_version=revision.resolver_policy_version,
            egress_policy_version=revision.egress_policy_version,
            egress_enforcement_status="VERIFIED",
            egress_attestation_hash=verification.evidence_hash,
        )

    def verify_rebinding(
        self,
        revision: EndpointPolicyLike,
        resolved: ResolvedEndpoint,
        *,
        deadline: OperationDeadline | None = None,
    ) -> None:
        if deadline is not None:
            deadline.check_expired()
        current = self.resolve(
            revision,
            host=resolved.hostname,
            port=resolved.port,
            deadline=deadline,
        )
        if (
            current.resolved_ips != resolved.resolved_ips
            or resolved.selected_ip not in current.resolved_ips
        ):
            raise ValueError("DNS_REBINDING_DETECTED")

    @contextmanager
    def open_tcp(
        self,
        resolved: ResolvedEndpoint,
        *,
        deadline: OperationDeadline | None = None,
    ) -> Iterator[socket.socket]:
        with self.lease(resolved, deadline=deadline) as lease:
            connection = self.connect_tcp(resolved, lease=lease, deadline=deadline)
            try:
                yield connection
                lease.assert_active()
            finally:
                connection.close()

    def lease(
        self,
        resolved: ResolvedEndpoint,
        *,
        deadline: OperationDeadline | None = None,
    ) -> EgressLeaseSession:
        return EgressLeaseSession(
            client=self.egress_lease_client,
            resolved=resolved,
            deadline=deadline,
        )

    def connect_tcp(
        self,
        resolved: ResolvedEndpoint,
        *,
        lease: EgressLeaseSession,
        deadline: OperationDeadline | None = None,
    ) -> socket.socket:
        if deadline is not None:
            deadline.check_expired()
        lease.assert_active()
        self._verify_policy(resolved, deadline=deadline)
        family = (
            socket.AF_INET6
            if ipaddress.ip_address(resolved.selected_ip).version == 6
            else socket.AF_INET
        )
        connection = socket.socket(family, socket.SOCK_STREAM)
        connection.settimeout(
            deadline.bounded_timeout(self.connect_timeout_seconds)
            if deadline is not None
            else self.connect_timeout_seconds
        )
        try:
            connection.connect((resolved.selected_ip, resolved.port))
            peer = ipaddress.ip_address(connection.getpeername()[0]).compressed
            if peer != resolved.selected_ip:
                raise ValueError("ENDPOINT_PEER_MISMATCH")
            lease.assert_active()
            if deadline is not None:
                deadline.check_expired()
            return connection
        except BaseException:
            connection.close()
            raise

    def _verify_policy(
        self,
        endpoint: EndpointPolicyLike | ResolvedEndpoint,
        *,
        deadline: OperationDeadline | None,
    ) -> EgressVerification:
        if deadline is not None:
            deadline.check_expired()
        if isinstance(endpoint, ResolvedEndpoint):
            revision_id = endpoint.endpoint_policy_revision_id
            policy_hash = endpoint.endpoint_policy_hash
        else:
            revision_id = endpoint.id
            policy_hash = endpoint.policy_hash
        verification = self.egress_verifier.verify_policy(
            revision_id=revision_id,
            policy_hash=policy_hash,
            policy_engine_version=endpoint.egress_policy_version,
            resolver_policy_version=endpoint.resolver_policy_version,
            timeout_seconds=(
                deadline.bounded_timeout(self.connect_timeout_seconds)
                if deadline is not None
                else None
            ),
        )
        if deadline is not None:
            deadline.check_expired()
        return verification
