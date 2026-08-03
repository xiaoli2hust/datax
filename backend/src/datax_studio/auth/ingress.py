from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock


@dataclass(frozen=True)
class LoginAdmissionRejection:
    """A deliberately account-agnostic admission rejection.

    No email, client header, password, or source address is retained here.  A
    loopback HTTP request cannot reliably identify the Windows process or user
    that initiated it, so using any of those values as the primary bucket key
    would be an easily bypassed and potentially enumerating control.
    """

    retry_after_seconds: int


class LoginAdmissionLease:
    """Owns one bounded login verification slot until explicitly released."""

    def __init__(self, guard: LoginAdmissionGuard) -> None:
        self._guard = guard
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._guard._release()


class LoginAdmissionGuard:
    """Global, process-local admission for the public local login route.

    The V1 deployment has exactly one API process.  This guard is therefore a
    real ingress control, not a best-effort per-worker hint: it has a global
    token bucket and a non-blocking verification slot before a route may open a
    database session, take an Organization row lock, run Argon2id, or append an
    audit event.  A Docker/API restart intentionally resets it; Docker access
    itself remains an administrator-equivalent local trust boundary.
    """

    # A fixed response avoids exposing whether the global bucket was empty or
    # its single verification slot was occupied.  It is deliberately more
    # conservative than the nominal token refill interval.
    RETRY_AFTER_SECONDS = 60

    def __init__(
        self,
        *,
        burst: int,
        rate_per_minute: int,
        max_in_flight: int,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if burst < 1:
            raise ValueError("login admission burst must be positive")
        if rate_per_minute < 1:
            raise ValueError("login admission rate must be positive")
        if max_in_flight < 1:
            raise ValueError("login admission max_in_flight must be positive")
        self._burst = burst
        self._rate_per_second = rate_per_minute / 60.0
        self._max_in_flight = max_in_flight
        self._monotonic_clock = monotonic_clock
        self._lock = Lock()
        self._tokens = float(burst)
        self._last_refill = monotonic_clock()
        self._in_flight = 0

    def try_acquire(self) -> LoginAdmissionLease | LoginAdmissionRejection:
        """Return immediately; rejected callers must not wait for Argon2/DB."""

        with self._lock:
            now = self._monotonic_clock()
            elapsed = max(0.0, now - self._last_refill)
            self._tokens = min(
                float(self._burst),
                self._tokens + elapsed * self._rate_per_second,
            )
            self._last_refill = now
            if self._in_flight >= self._max_in_flight:
                return self._reject()
            if self._tokens < 1.0:
                return self._reject()
            self._tokens -= 1.0
            self._in_flight += 1
            return LoginAdmissionLease(self)

    def _reject(self) -> LoginAdmissionRejection:
        return LoginAdmissionRejection(retry_after_seconds=self.RETRY_AFTER_SECONDS)

    def _release(self) -> None:
        with self._lock:
            if self._in_flight < 1:
                raise RuntimeError("login admission lease released too many times")
            self._in_flight -= 1
