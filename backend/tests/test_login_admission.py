from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from threading import Event

import pytest
from pydantic import ValidationError

from datax_studio.auth.ingress import (
    LoginAdmissionGuard,
    LoginAdmissionRejection,
)
from datax_studio.settings import Settings


@dataclass
class _Clock:
    value: float = 0.0

    def __call__(self) -> float:
        return self.value


def test_login_admission_is_global_and_nonblocking() -> None:
    clock = _Clock()
    guard = LoginAdmissionGuard(
        burst=1,
        rate_per_minute=5,
        max_in_flight=1,
        monotonic_clock=clock,
    )

    lease = guard.try_acquire()
    assert not isinstance(lease, LoginAdmissionRejection)

    concurrent = guard.try_acquire()
    assert isinstance(concurrent, LoginAdmissionRejection)
    assert concurrent.retry_after_seconds == 60
    assert "email" not in concurrent.__dict__
    assert "password" not in concurrent.__dict__

    token_limited = guard.try_acquire()
    assert isinstance(token_limited, LoginAdmissionRejection)

    lease.release()
    clock.value = 12.0
    next_lease = guard.try_acquire()
    assert not isinstance(next_lease, LoginAdmissionRejection)

    clock.value = 60.0
    next_window = guard.try_acquire()
    assert isinstance(next_window, LoginAdmissionRejection)
    next_lease.release()


def test_login_admission_releases_the_slot_after_concurrent_rejection() -> None:
    """A rejected contender must not strand the one verification slot."""

    guard = LoginAdmissionGuard(
        burst=3,
        rate_per_minute=1,
        max_in_flight=1,
    )
    holder_entered = Event()
    allow_holder_to_release = Event()

    def acquire_and_hold() -> None:
        lease = guard.try_acquire()
        assert not isinstance(lease, LoginAdmissionRejection)
        holder_entered.set()
        assert allow_holder_to_release.wait(timeout=5)
        lease.release()

    with ThreadPoolExecutor(max_workers=1) as executor:
        holder = executor.submit(acquire_and_hold)
        assert holder_entered.wait(timeout=5)

        rejected = guard.try_acquire()
        assert isinstance(rejected, LoginAdmissionRejection)
        assert rejected.retry_after_seconds == 60

        allow_holder_to_release.set()
        holder.result(timeout=5)

    recovered = guard.try_acquire()
    assert not isinstance(recovered, LoginAdmissionRejection)
    recovered.release()
    recovered.release()


def test_v1_login_admission_cannot_expand_password_verification_slots() -> None:
    with pytest.raises(ValidationError):
        Settings(login_admission_max_in_flight=2)
