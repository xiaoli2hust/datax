from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from datax_studio.credentials.ingress import (
    DatasourceOperationAdmissionGuard,
    DatasourceOperationAdmissionRejection,
    DatasourceOperationKind,
)
from datax_studio.settings import Settings


@dataclass
class _Clock:
    value: float = 0.0

    def __call__(self) -> float:
        return self.value


def _guard(
    clock: _Clock,
    *,
    max_global_in_flight: int = 4,
    max_organization_in_flight: int = 1,
    max_datasource_in_flight: int = 1,
    test_cooldown_seconds: float = 10,
    retention_seconds: float = 30,
    max_retained_organizations: int = 16,
    max_retained_datasources: int = 16,
) -> DatasourceOperationAdmissionGuard:
    return DatasourceOperationAdmissionGuard(
        max_global_in_flight=max_global_in_flight,
        max_organization_in_flight=max_organization_in_flight,
        max_datasource_in_flight=max_datasource_in_flight,
        test_cooldown_seconds=test_cooldown_seconds,
        retention_seconds=retention_seconds,
        max_retained_organizations=max_retained_organizations,
        max_retained_datasources=max_retained_datasources,
        monotonic_clock=clock,
    )


def _acquire(
    guard: DatasourceOperationAdmissionGuard,
    *,
    organization_id: UUID,
    datasource_ids: tuple[UUID, ...],
    operation_kind: DatasourceOperationKind = DatasourceOperationKind.METADATA,
):
    return guard.try_acquire(
        organization_id=organization_id,
        datasource_ids=datasource_ids,
        operation_kind=operation_kind,
    )


def test_global_organization_and_datasource_permits_are_all_nonblocking() -> None:
    clock = _Clock()
    guard = _guard(
        clock,
        max_global_in_flight=2,
        max_organization_in_flight=1,
        max_datasource_in_flight=1,
    )
    organization_one = uuid4()
    organization_two = uuid4()
    organization_three = uuid4()
    datasource_one = uuid4()
    datasource_two = uuid4()
    datasource_three = uuid4()

    first = _acquire(
        guard,
        organization_id=organization_one,
        datasource_ids=(datasource_one,),
    )
    assert not isinstance(first, DatasourceOperationAdmissionRejection)

    same_organization = _acquire(
        guard,
        organization_id=organization_one,
        datasource_ids=(datasource_two,),
    )
    assert isinstance(same_organization, DatasourceOperationAdmissionRejection)

    same_datasource = _acquire(
        guard,
        organization_id=organization_two,
        datasource_ids=(datasource_one,),
    )
    assert isinstance(same_datasource, DatasourceOperationAdmissionRejection)

    second = _acquire(
        guard,
        organization_id=organization_two,
        datasource_ids=(datasource_two,),
    )
    assert not isinstance(second, DatasourceOperationAdmissionRejection)

    global_limited = _acquire(
        guard,
        organization_id=organization_three,
        datasource_ids=(datasource_three,),
    )
    assert isinstance(global_limited, DatasourceOperationAdmissionRejection)
    assert global_limited.retry_after_seconds == 60
    assert global_limited.__dict__ == {"retry_after_seconds": 60}

    first.release()
    second.release()
    recovered = _acquire(
        guard,
        organization_id=organization_three,
        datasource_ids=(datasource_three,),
    )
    assert not isinstance(recovered, DatasourceOperationAdmissionRejection)
    recovered.release()


def test_multi_datasource_acquisition_is_sorted_deduplicated_and_atomic() -> None:
    clock = _Clock()
    guard = _guard(clock, max_global_in_flight=3)
    organization_one = uuid4()
    organization_two = uuid4()
    datasource_one = uuid4()
    datasource_two = uuid4()
    datasource_three = uuid4()

    holder = _acquire(
        guard,
        organization_id=organization_two,
        datasource_ids=(datasource_two,),
    )
    assert not isinstance(holder, DatasourceOperationAdmissionRejection)

    rejected = _acquire(
        guard,
        organization_id=organization_one,
        datasource_ids=(datasource_three, datasource_one, datasource_two),
        operation_kind=DatasourceOperationKind.JOB_VALIDATION,
    )
    assert isinstance(rejected, DatasourceOperationAdmissionRejection)

    # The failed multi-acquire must not retain a partial permit for datasource_one.
    independent = _acquire(
        guard,
        organization_id=organization_one,
        datasource_ids=(datasource_one,),
    )
    assert not isinstance(independent, DatasourceOperationAdmissionRejection)
    independent.release()
    holder.release()

    ordered = _acquire(
        guard,
        organization_id=organization_one,
        datasource_ids=(datasource_three, datasource_one, datasource_three),
        operation_kind=DatasourceOperationKind.JOB_VALIDATION,
    )
    assert not isinstance(ordered, DatasourceOperationAdmissionRejection)
    assert ordered.datasource_ids == tuple(
        sorted({datasource_one, datasource_three}, key=lambda value: value.bytes)
    )
    ordered.release()
    ordered.release()


def test_only_test_operations_consume_the_datasource_cooldown() -> None:
    clock = _Clock()
    guard = _guard(clock, test_cooldown_seconds=10)
    organization_id = uuid4()
    datasource_id = uuid4()

    test_lease = _acquire(
        guard,
        organization_id=organization_id,
        datasource_ids=(datasource_id,),
        operation_kind=DatasourceOperationKind.TEST,
    )
    assert not isinstance(test_lease, DatasourceOperationAdmissionRejection)
    test_lease.release()

    immediate_test = _acquire(
        guard,
        organization_id=organization_id,
        datasource_ids=(datasource_id,),
        operation_kind=DatasourceOperationKind.TEST,
    )
    assert isinstance(immediate_test, DatasourceOperationAdmissionRejection)
    assert immediate_test.retry_after_seconds == 60

    metadata = _acquire(
        guard,
        organization_id=organization_id,
        datasource_ids=(datasource_id,),
        operation_kind=DatasourceOperationKind.METADATA,
    )
    assert not isinstance(metadata, DatasourceOperationAdmissionRejection)
    metadata.release()

    clock.value = 10
    next_test = _acquire(
        guard,
        organization_id=organization_id,
        datasource_ids=(datasource_id,),
        operation_kind=DatasourceOperationKind.TEST,
    )
    assert not isinstance(next_test, DatasourceOperationAdmissionRejection)
    next_test.release()


def test_retention_keeps_active_test_cooldown_then_reclaims_expired_idle_scopes() -> None:
    clock = _Clock()
    guard = _guard(
        clock,
        test_cooldown_seconds=10,
        retention_seconds=5,
    )
    organization_id = uuid4()
    datasource_id = uuid4()

    lease = _acquire(
        guard,
        organization_id=organization_id,
        datasource_ids=(datasource_id,),
        operation_kind=DatasourceOperationKind.TEST,
    )
    assert not isinstance(lease, DatasourceOperationAdmissionRejection)
    lease.release()

    clock.value = 5
    assert guard.cleanup().organizations == 0
    assert guard.retained_scope_counts().datasources == 1

    clock.value = 15
    assert guard.cleanup().organizations == 0
    assert guard.retained_scope_counts().datasources == 0


def test_retained_scope_caps_reject_without_retaining_unbounded_new_identifiers() -> None:
    clock = _Clock()
    guard = _guard(
        clock,
        max_retained_organizations=1,
        max_retained_datasources=1,
        retention_seconds=5,
        test_cooldown_seconds=0,
    )
    organization_id = uuid4()
    first_datasource_id = uuid4()
    second_datasource_id = uuid4()

    first = _acquire(
        guard,
        organization_id=organization_id,
        datasource_ids=(first_datasource_id,),
    )
    assert not isinstance(first, DatasourceOperationAdmissionRejection)
    first.release()

    capped = _acquire(
        guard,
        organization_id=organization_id,
        datasource_ids=(second_datasource_id,),
    )
    assert isinstance(capped, DatasourceOperationAdmissionRejection)
    assert capped.retry_after_seconds == 60
    assert guard.retained_scope_counts().datasources == 1

    clock.value = 5
    assert guard.cleanup().datasources == 0
    recovered = _acquire(
        guard,
        organization_id=organization_id,
        datasource_ids=(second_datasource_id,),
    )
    assert not isinstance(recovered, DatasourceOperationAdmissionRejection)
    recovered.release()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_global_in_flight": 0}, "max_global_in_flight must be positive"),
        ({"max_organization_in_flight": 0}, "max_organization_in_flight is fixed"),
        ({"max_organization_in_flight": 2}, "max_organization_in_flight is fixed"),
        ({"max_datasource_in_flight": 0}, "max_datasource_in_flight is fixed"),
        ({"max_datasource_in_flight": 2}, "max_datasource_in_flight is fixed"),
        ({"test_cooldown_seconds": -1}, "test_cooldown_seconds must be finite"),
        ({"retention_seconds": -1}, "retention_seconds must be finite"),
    ],
)
def test_admission_configuration_fails_closed(
    kwargs: dict[str, float | int],
    message: str,
) -> None:
    clock = _Clock()
    with pytest.raises(ValueError, match=message):
        _guard(clock, **kwargs)


def test_guard_rejects_non_uuid_scope_keys_without_storing_them() -> None:
    guard = _guard(_Clock())
    with pytest.raises(TypeError, match="organization_id"):
        guard.try_acquire(
            organization_id="not-a-uuid",  # type: ignore[arg-type]
            datasource_ids=(),
            operation_kind=DatasourceOperationKind.CREATE,
        )
    with pytest.raises(TypeError, match="datasource_ids"):
        guard.try_acquire(
            organization_id=uuid4(),
            datasource_ids=("not-a-uuid",),  # type: ignore[arg-type]
            operation_kind=DatasourceOperationKind.CREATE,
        )
    assert guard.retained_scope_counts().organizations == 0
    assert guard.retained_scope_counts().datasources == 0


def test_v1_settings_keep_datasource_operation_capacity_bounded() -> None:
    settings = Settings()

    assert settings.datasource_operation_max_global_in_flight == 4
    assert settings.datasource_operation_max_organization_in_flight == 1
    assert settings.datasource_operation_max_datasource_in_flight == 1
    assert settings.datasource_operation_test_cooldown_seconds == 60
    assert settings.datasource_operation_deadline_seconds == 30
    assert settings.datasource_operation_retention_seconds == 300
    assert settings.datasource_operation_max_retained_organizations == 64
    assert settings.datasource_operation_max_retained_datasources == 256

    with pytest.raises(ValidationError):
        Settings(datasource_operation_max_global_in_flight=17)
    with pytest.raises(ValidationError):
        Settings(datasource_operation_max_organization_in_flight=2)
    with pytest.raises(ValidationError):
        Settings(datasource_operation_max_datasource_in_flight=2)
    with pytest.raises(ValidationError):
        Settings(datasource_operation_deadline_seconds=121)
