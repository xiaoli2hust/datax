from __future__ import annotations

import math
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from uuid import UUID


class DatasourceOperationKind(StrEnum):
    """The external datasource operations governed by ADR-0014.

    These names intentionally describe work categories only.  Admission must
    never retain an actor, request address, hostname, password, or connection
    string as a bucket key.
    """

    CREATE = "CREATE"
    UPDATE = "UPDATE"
    TEST = "TEST"
    METADATA = "METADATA"
    JOB_VALIDATION = "JOB_VALIDATION"


@dataclass(frozen=True)
class DatasourceOperationAdmissionRejection:
    """An opaque, process-local admission rejection.

    The fixed retry value deliberately does not disclose whether the global,
    organization, datasource, retained-state, or TEST cooldown limit caused
    the rejection.
    """

    retry_after_seconds: int


@dataclass(frozen=True)
class DatasourceOperationRetention:
    """Identifier-free retained-state counts for bounded-memory monitoring."""

    organizations: int
    datasources: int


@dataclass
class _OrganizationState:
    in_flight: int
    last_touched_at: float


@dataclass
class _DatasourceState:
    in_flight: int
    next_test_allowed_at: float
    last_touched_at: float


class DatasourceOperationAdmissionLease:
    """Owns one atomic global/organization/datasource operation permit.

    A caller must release the lease in every success, error, timeout, and
    cancellation path.  It also implements a context manager to make that
    discipline straightforward at integration points.
    """

    def __init__(
        self,
        guard: DatasourceOperationAdmissionGuard,
        *,
        organization_id: UUID,
        datasource_ids: tuple[UUID, ...],
    ) -> None:
        self._guard = guard
        self.organization_id = organization_id
        self.datasource_ids = datasource_ids
        self._released = False

    def __enter__(self) -> DatasourceOperationAdmissionLease:
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()

    def release(self) -> None:
        """Release once; repeated cleanup calls are intentionally harmless."""

        if self._released:
            return
        self._released = True
        self._guard._release(
            organization_id=self.organization_id,
            datasource_ids=self.datasource_ids,
        )

    def covers(
        self,
        *,
        organization_id: UUID,
        datasource_ids: Iterable[UUID],
    ) -> bool:
        """Return whether this live lease covers a nested metadata operation.

        Composite callers (job validation and transfer-policy scope discovery)
        acquire every durable datasource atomically before any external work.
        The nested connector call may then reuse that lease, but must never use
        a lease from another organization or a lease that omits its datasource.
        """

        return (
            not self._released
            and self.organization_id == organization_id
            and set(datasource_ids).issubset(self.datasource_ids)
        )


class DatasourceOperationAdmissionGuard:
    """Non-blocking, process-local admission for expensive datasource I/O.

    The guard acquires all scopes atomically under a short in-process lock:
    one global permit, one organization permit, and one permit for every
    deduplicated datasource.  It never waits, opens a database session, or
    stores user/IP/host/credential material.  V1 has one API process, so this
    is intentionally not a distributed or multi-worker coordination scheme.
    """

    # Keeping the response fixed prevents callers from learning which quota,
    # retained-state cap, or TEST cooldown was reached.
    RETRY_AFTER_SECONDS = 60

    def __init__(
        self,
        *,
        max_global_in_flight: int,
        max_organization_in_flight: int,
        max_datasource_in_flight: int,
        test_cooldown_seconds: float,
        retention_seconds: float,
        max_retained_organizations: int,
        max_retained_datasources: int,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._require_positive("max_global_in_flight", max_global_in_flight)
        self._require_exactly_one("max_organization_in_flight", max_organization_in_flight)
        self._require_exactly_one("max_datasource_in_flight", max_datasource_in_flight)
        self._require_non_negative("test_cooldown_seconds", test_cooldown_seconds)
        self._require_non_negative("retention_seconds", retention_seconds)
        self._require_positive("max_retained_organizations", max_retained_organizations)
        self._require_positive("max_retained_datasources", max_retained_datasources)

        self._max_global_in_flight = max_global_in_flight
        self._max_organization_in_flight = max_organization_in_flight
        self._max_datasource_in_flight = max_datasource_in_flight
        self._test_cooldown_seconds = test_cooldown_seconds
        self._retention_seconds = retention_seconds
        self._max_retained_organizations = max_retained_organizations
        self._max_retained_datasources = max_retained_datasources
        self._monotonic_clock = monotonic_clock
        self._lock = Lock()
        self._in_flight = 0
        self._organizations: dict[UUID, _OrganizationState] = {}
        self._datasources: dict[UUID, _DatasourceState] = {}

    def try_acquire(
        self,
        *,
        organization_id: UUID,
        datasource_ids: Iterable[UUID],
        operation_kind: DatasourceOperationKind | str,
    ) -> DatasourceOperationAdmissionLease | DatasourceOperationAdmissionRejection:
        """Return immediately with all requested scopes or with no scopes.

        Empty datasource IDs are valid for a creation probe before a durable
        Datasource exists.  For job validation, callers pass both source and
        target IDs in one invocation; this method sorts and deduplicates them
        before doing any quota mutation, so it cannot partially hold a source
        while waiting for a target.
        """

        if not isinstance(organization_id, UUID):
            raise TypeError("organization_id must be a UUID")
        normalized_ids = self._normalize_datasource_ids(datasource_ids)
        normalized_kind = self._normalize_operation_kind(operation_kind)

        with self._lock:
            now = self._now()
            self._cleanup_locked(now)

            if self._in_flight >= self._max_global_in_flight:
                return self._reject()

            organization = self._organizations.get(organization_id)
            if (
                organization is not None
                and organization.in_flight >= self._max_organization_in_flight
            ):
                return self._reject()

            datasource_states = tuple(
                (datasource_id, self._datasources.get(datasource_id))
                for datasource_id in normalized_ids
            )
            if any(
                state is not None and state.in_flight >= self._max_datasource_in_flight
                for _, state in datasource_states
            ):
                return self._reject()
            if normalized_kind is DatasourceOperationKind.TEST and any(
                state is not None and now < state.next_test_allowed_at
                for _, state in datasource_states
            ):
                return self._reject()

            new_organization = organization is None
            new_datasource_count = sum(state is None for _, state in datasource_states)
            if new_organization and len(self._organizations) >= self._max_retained_organizations:
                return self._reject()
            if len(self._datasources) + new_datasource_count > self._max_retained_datasources:
                return self._reject()

            if organization is None:
                organization = _OrganizationState(in_flight=0, last_touched_at=now)
                self._organizations[organization_id] = organization
            organization.in_flight += 1
            organization.last_touched_at = max(organization.last_touched_at, now)

            for datasource_id, state in datasource_states:
                if state is None:
                    state = _DatasourceState(
                        in_flight=0,
                        next_test_allowed_at=0.0,
                        last_touched_at=now,
                    )
                    self._datasources[datasource_id] = state
                state.in_flight += 1
                state.last_touched_at = max(state.last_touched_at, now)
                if normalized_kind is DatasourceOperationKind.TEST:
                    state.next_test_allowed_at = max(
                        state.next_test_allowed_at,
                        now + self._test_cooldown_seconds,
                    )

            self._in_flight += 1
            return DatasourceOperationAdmissionLease(
                self,
                organization_id=organization_id,
                datasource_ids=normalized_ids,
            )

    def cleanup(self) -> DatasourceOperationRetention:
        """Discard idle, expired scope records and return identifier-free counts."""

        with self._lock:
            self._cleanup_locked(self._now())
            return DatasourceOperationRetention(
                organizations=len(self._organizations),
                datasources=len(self._datasources),
            )

    def retained_scope_counts(self) -> DatasourceOperationRetention:
        """Run cleanup and expose only bounded state cardinality, never keys."""

        return self.cleanup()

    def _release(
        self,
        *,
        organization_id: UUID,
        datasource_ids: tuple[UUID, ...],
    ) -> None:
        with self._lock:
            organization = self._organizations.get(organization_id)
            if organization is None or organization.in_flight < 1:
                raise RuntimeError("datasource admission organization lease underflow")
            states = tuple(
                (datasource_id, self._datasources.get(datasource_id))
                for datasource_id in datasource_ids
            )
            if any(state is None or state.in_flight < 1 for _, state in states):
                raise RuntimeError("datasource admission datasource lease underflow")
            if self._in_flight < 1:
                raise RuntimeError("datasource admission global lease underflow")

            now = self._now()
            self._in_flight -= 1
            organization.in_flight -= 1
            organization.last_touched_at = max(organization.last_touched_at, now)
            for _, state in states:
                assert state is not None
                state.in_flight -= 1
                state.last_touched_at = max(state.last_touched_at, now)
            self._cleanup_locked(now)

    def _cleanup_locked(self, now: float) -> None:
        cutoff = now - self._retention_seconds
        for organization_id, state in tuple(self._organizations.items()):
            if state.in_flight == 0 and state.last_touched_at <= cutoff:
                del self._organizations[organization_id]
        for datasource_id, state in tuple(self._datasources.items()):
            if (
                state.in_flight == 0
                and state.next_test_allowed_at <= now
                and state.last_touched_at <= cutoff
            ):
                del self._datasources[datasource_id]

    @classmethod
    def _reject(cls) -> DatasourceOperationAdmissionRejection:
        return DatasourceOperationAdmissionRejection(retry_after_seconds=cls.RETRY_AFTER_SECONDS)

    def _now(self) -> float:
        now = self._monotonic_clock()
        if not math.isfinite(now):
            raise ValueError("monotonic_clock must return a finite value")
        return now

    @staticmethod
    def _normalize_datasource_ids(datasource_ids: Iterable[UUID]) -> tuple[UUID, ...]:
        normalized = set(datasource_ids)
        if not all(isinstance(datasource_id, UUID) for datasource_id in normalized):
            raise TypeError("datasource_ids must contain only UUID values")
        return tuple(sorted(normalized, key=lambda datasource_id: datasource_id.bytes))

    @staticmethod
    def _normalize_operation_kind(
        operation_kind: DatasourceOperationKind | str,
    ) -> DatasourceOperationKind:
        if isinstance(operation_kind, DatasourceOperationKind):
            return operation_kind
        try:
            return DatasourceOperationKind(operation_kind)
        except ValueError as exc:
            raise ValueError("unsupported datasource operation kind") from exc

    @staticmethod
    def _require_positive(name: str, value: int) -> None:
        if value < 1:
            raise ValueError(f"{name} must be positive")

    @staticmethod
    def _require_exactly_one(name: str, value: int) -> None:
        if value != 1:
            raise ValueError(f"{name} is fixed at 1 by ADR-0014")

    @staticmethod
    def _require_non_negative(name: str, value: float) -> None:
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{name} must be finite and non-negative")
