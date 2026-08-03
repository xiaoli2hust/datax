"""Immutable values used at the ADR-0014 datasource I/O boundary.

The credential service must release product-database locks before it resolves
DNS, acquires egress leases, decrypts a credential, or opens a datasource
connection.  ORM instances are deliberately unsuitable for that hand-off:
they retain a Session relationship and make it too easy to read changed state
after phase A.  The values in this module are plain, frozen snapshots that
make the A/B/C comparison explicit without carrying cleartext credentials.

``CurrentCredentialMaterial`` is intentionally separate from
``DatasourceOperationSnapshot``.  It is created only by the short, current
credential barrier immediately before phase B and its encrypted byte fields
are never rendered by ``repr``.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from uuid import UUID

from datax_studio.credentials.ingress import DatasourceOperationKind


@dataclass(frozen=True)
class FrozenDatasourceRevision:
    """A non-ORM datasource revision safe to use after phase A commits.

    The connection-shaped fields intentionally match ``DatasourceRevisionLike``
    from ``credentials.connectors``.  It also retains the immutable revision
    identifiers and canonical configuration hash needed by phase C.
    """

    id: UUID
    datasource_id: UUID
    revision_no: int
    endpoint_policy_revision_id: UUID
    physical_endpoint_identity_id: UUID
    engine: str
    host: str
    port: int
    database_name: str
    default_schema: str
    username: str
    ssl_mode: str
    config_hash: str


@dataclass(frozen=True)
class FrozenEndpointPolicy:
    """Current endpoint-policy state copied out of a short transaction.

    ``id`` is the immutable endpoint-policy-revision ID so this object can be
    handed directly to ``EndpointPolicyGuard``.  The adjacent policy pointer,
    status, and row version are retained separately so phase C can reject a
    result when the policy was changed, disabled, or repointed while phase B
    was outside the product database.
    """

    id: UUID
    endpoint_policy_id: UUID
    endpoint_policy_current_revision_id: UUID
    endpoint_policy_status: str
    endpoint_policy_row_version: int
    revision_no: int
    engine: str
    host_kind: str
    host_value: str
    allowed_cidrs: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    tls_required: bool
    dns_ttl_ceiling_seconds: int
    resolver_policy_version: str
    egress_policy_version: str
    policy_hash: str

    def __post_init__(self) -> None:
        # Callers often receive JSON-backed ORM lists.  Copy them to tuples so
        # a detached snapshot cannot be mutated after phase A commits.
        object.__setattr__(self, "allowed_cidrs", tuple(self.allowed_cidrs))
        object.__setattr__(self, "allowed_ports", tuple(self.allowed_ports))


@dataclass(frozen=True)
class FrozenCredentialBinding:
    """Non-secret pointer and status material for an active credential.

    This type deliberately has no ciphertext, nonce, wrapped DEK, or password
    field.  It is durable enough for phase C to prove that the datasource still
    points at the same active secret, envelope, and KEK metadata, but cannot be
    used to decrypt anything by itself.
    """

    datasource_id: UUID
    secret_id: UUID
    secret_version: int
    secret_status: str
    envelope_id: UUID
    envelope_version: int
    envelope_status: str
    kek_version: str
    kek_status: str
    kek_fingerprint_sha256: str
    kek_wrapping_algorithm: str
    data_algorithm: str
    aad_schema_version: str


@dataclass(frozen=True)
class FrozenActorAuthorization:
    """Authorization facts that phase C must re-authorize and compare.

    ``authorization_mode`` is intentionally a simple durable label such as
    ``ORGANIZATION_ADMIN`` or ``PROJECT_DEVELOPER``.  The service remains the
    authority for interpreting it; this DTO only freezes the exact membership,
    role-assignment, and optional usage-grant pointers observed in phase A.
    """

    actor_id: UUID
    actor_user_status: str
    actor_user_row_version: int
    session_id: UUID
    organization_id: UUID
    project_id: UUID
    organization_member_id: UUID | None
    organization_member_status: str | None
    actor_must_change_password: bool
    authorization_mode: str
    role_assignment_id: UUID | None
    usage: str | None
    usage_grant_id: UUID | None
    usage_grant_status: str | None
    usage_grant_row_version: int | None


@dataclass(frozen=True)
class DatasourceOperationSnapshot:
    """The immutable phase-A hand-off for one datasource external operation.

    ``datasource_id`` is optional only for the create probe, which cannot have
    a durable datasource/secret/revision binding yet.  All existing-datasource
    operations retain both mutable datasource pointers and the corresponding
    immutable frozen records so phase C can fail closed on every drift.

    Metadata values are decoded/validated in phase A and copied here rather
    than re-reading request objects after outbound work starts.  The signed raw
    cursor is retained only to preserve request intent and is hidden from
    ``repr``; phase B uses ``metadata_after`` instead.
    """

    operation_kind: DatasourceOperationKind
    operation_id: UUID
    organization_id: UUID
    organization_status: str
    organization_row_version: int
    project_id: UUID
    project_status: str
    project_row_version: int
    datasource_id: UUID | None
    datasource_status: str | None
    datasource_row_version: int | None
    datasource_current_revision_id: UUID | None
    datasource_current_secret_id: UUID | None
    datasource_revision: FrozenDatasourceRevision | None
    endpoint_policy: FrozenEndpointPolicy | None
    credential_binding: FrozenCredentialBinding | None
    actor_authorization: FrozenActorAuthorization
    candidate_config_hash: str | None = None
    request_hash: str | None = None
    metadata_usage: str | None = None
    metadata_schema_name: str | None = None
    metadata_table_name: str | None = None
    metadata_limit: int | None = None
    metadata_cursor_scope: str | None = None
    metadata_after: tuple[str, str] | None = None
    metadata_cursor: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.actor_authorization.organization_id != self.organization_id:
            raise ValueError("snapshot actor organization does not match")
        if self.actor_authorization.project_id != self.project_id:
            raise ValueError("snapshot actor project does not match")
        if self.datasource_revision is not None:
            if self.datasource_id != self.datasource_revision.datasource_id:
                raise ValueError("snapshot datasource revision does not match")
            if self.datasource_current_revision_id != self.datasource_revision.id:
                raise ValueError("snapshot current revision pointer does not match")
        if self.credential_binding is not None:
            if self.datasource_id != self.credential_binding.datasource_id:
                raise ValueError("snapshot credential datasource does not match")
            if self.datasource_current_secret_id != self.credential_binding.secret_id:
                raise ValueError("snapshot current secret pointer does not match")
        if (
            self.endpoint_policy is not None
            and self.datasource_revision is not None
            and self.endpoint_policy.id != self.datasource_revision.endpoint_policy_revision_id
        ):
            raise ValueError("snapshot policy revision does not match")
        if self.metadata_after is not None:
            object.__setattr__(self, "metadata_after", tuple(self.metadata_after))


@dataclass(frozen=True)
class CurrentCredentialMaterial:
    """Encrypted material copied by the strict current-credential barrier.

    All encrypted byte values use ``repr=False``.  This is not a serializable
    response model and callers must limit its lifetime to password decryption
    immediately before the outbound connection.
    """

    binding: FrozenCredentialBinding
    ciphertext: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    encrypted_dek: bytes = field(repr=False)

    def __post_init__(self) -> None:
        # A byte copy prevents a caller retaining a mutable bytearray object
        # that could otherwise change beneath the barrier result.
        object.__setattr__(self, "ciphertext", bytes(self.ciphertext))
        object.__setattr__(self, "nonce", bytes(self.nonce))
        object.__setattr__(self, "encrypted_dek", bytes(self.encrypted_dek))


class OperationDeadlineExpired(RuntimeError):
    """Raised when an ADR-0014 external operation has no budget remaining."""


@dataclass(frozen=True)
class OperationDeadline:
    """One fixed total deadline measured by an injectable monotonic clock.

    Connector and resolver timeouts must be capped at ``remaining_seconds()``;
    callers use ``check_expired()`` before each external stage and schema page.
    The deadline never resets as individual phases finish.
    """

    total_seconds: float
    monotonic_clock: Callable[[], float] = time.monotonic
    started_at: float = field(init=False)
    expires_at: float = field(init=False)

    def __post_init__(self) -> None:
        if not math.isfinite(self.total_seconds) or self.total_seconds <= 0:
            raise ValueError("total_seconds must be finite and positive")
        started_at = self._read_clock()
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "expires_at", started_at + self.total_seconds)

    def remaining_seconds(self) -> float:
        """Return the non-negative budget remaining from the original start."""

        remaining = self.expires_at - self._read_clock()
        return max(0.0, remaining)

    def check_expired(self) -> float:
        """Return remaining budget or fail closed once it is exhausted."""

        remaining = self.remaining_seconds()
        if remaining <= 0.0:
            raise OperationDeadlineExpired("DATASOURCE_OPERATION_DEADLINE_EXCEEDED")
        return remaining

    def bounded_timeout(self, configured_seconds: float) -> float:
        """Clamp one external-stage timeout to the remaining total budget."""

        if not math.isfinite(configured_seconds) or configured_seconds <= 0:
            raise ValueError("configured_seconds must be finite and positive")
        return min(float(configured_seconds), self.check_expired())

    def _read_clock(self) -> float:
        now = self.monotonic_clock()
        if not math.isfinite(now):
            raise ValueError("monotonic_clock must return a finite value")
        return now
