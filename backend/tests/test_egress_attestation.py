from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from email.message import Message
from uuid import uuid4

import pytest

from datax_studio.egress_attestation import (
    POLICY_ENGINE_VERSION,
    RESOLVER_POLICY_VERSION,
    EgressAttestationError,
    LoopbackEgressAttestationClient,
    compute_policy_set_hash,
)


class _Response:
    status = 200

    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload).encode("utf-8")
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self._body[:limit]


class _Opener:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def open(self, *_args: object, **_kwargs: object) -> _Response:
        return _Response(self.payload)


class _LeaseResponse:
    def __init__(
        self,
        *,
        status: int,
        payload: dict[str, object] | None,
    ) -> None:
        self.status = status
        self._body = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else b""
        )
        self.headers = Message()
        if payload is not None:
            self.headers["Content-Type"] = "application/json"

    def __enter__(self) -> _LeaseResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self._body[:limit]


class _LeaseOpener:
    def __init__(self, *responses: _LeaseResponse) -> None:
        self.responses = list(responses)
        self.requests: list[object] = []

    def open(self, request: object, **_kwargs: object) -> _LeaseResponse:
        self.requests.append(request)
        return self.responses.pop(0)


def _payload(
    *,
    revision_id: str,
    policy_hash: str,
    now: datetime,
) -> dict[str, object]:
    policies = {revision_id: policy_hash}
    return {
        "schema_version": "1.0",
        "status": "VERIFIED",
        "policy_engine_version": POLICY_ENGINE_VERSION,
        "resolver_policy_version": RESOLVER_POLICY_VERSION,
        "network_namespace_id": "net:[1234]",
        "policy_set_hash": compute_policy_set_hash(policies),
        "policies": policies,
        "ruleset_hash": "b" * 64,
        "applied_at": (now - timedelta(seconds=1)).isoformat(),
        "checked_at": now.isoformat(),
    }


def _client(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
) -> LoopbackEgressAttestationClient:
    monkeypatch.setattr(
        "datax_studio.egress_attestation.current_network_namespace_id",
        lambda: "net:[1234]",
    )
    client = LoopbackEgressAttestationClient(
        url="http://127.0.0.1:17990/v1/attestation",
        timeout_seconds=0.5,
        max_age_seconds=5,
    )
    client._opener = _Opener(payload)  # type: ignore[assignment]
    return client


def test_loopback_attestation_verifies_exact_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revision_id = uuid4()
    policy_hash = "c" * 64
    now = datetime.now(UTC)
    client = _client(
        monkeypatch,
        _payload(
            revision_id=str(revision_id),
            policy_hash=policy_hash,
            now=now,
        ),
    )

    verification = client.verify_policy(
        revision_id=revision_id,
        policy_hash=policy_hash,
        policy_engine_version=POLICY_ENGINE_VERSION,
        resolver_policy_version=RESOLVER_POLICY_VERSION,
    )

    assert verification.network_namespace_id == "net:[1234]"
    assert len(verification.evidence_hash) == 64


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (
            lambda payload: payload.update(status="UNVERIFIED"),
            "EGRESS_ATTESTATION_UNVERIFIED",
        ),
        (
            lambda payload: payload.update(network_namespace_id="net:[4321]"),
            "EGRESS_NETWORK_NAMESPACE_MISMATCH",
        ),
        (
            lambda payload: payload.update(
                checked_at=(datetime.now(UTC) - timedelta(seconds=30)).isoformat()
            ),
            "EGRESS_ATTESTATION_STALE",
        ),
        (
            lambda payload: payload.update(
                policies={},
                policy_set_hash=compute_policy_set_hash({}),
            ),
            "EGRESS_POLICY_NOT_APPLIED",
        ),
        (
            lambda payload: payload.update(policy_set_hash="f" * 64),
            "EGRESS_POLICY_SET_HASH_MISMATCH",
        ),
    ],
)
def test_loopback_attestation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutation: object,
    expected_code: str,
) -> None:
    revision_id = uuid4()
    policy_hash = "d" * 64
    payload = _payload(
        revision_id=str(revision_id),
        policy_hash=policy_hash,
        now=datetime.now(UTC),
    )
    assert callable(mutation)
    mutation(payload)
    client = _client(monkeypatch, payload)

    with pytest.raises(EgressAttestationError, match=expected_code):
        client.verify_policy(
            revision_id=revision_id,
            policy_hash=policy_hash,
            policy_engine_version=POLICY_ENGINE_VERSION,
            resolver_policy_version=RESOLVER_POLICY_VERSION,
        )


def test_client_rejects_non_loopback_attestation_endpoint() -> None:
    with pytest.raises(ValueError, match="exact 127.0.0.1"):
        LoopbackEgressAttestationClient(
            url="https://guard.example/v1/attestation",
            timeout_seconds=0.5,
            max_age_seconds=5,
        )


def test_attestation_rejects_noncanonical_policy_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revision_id = uuid4()
    policy_hash = "e" * 64
    payload = _payload(
        revision_id=str(revision_id).upper(),
        policy_hash=policy_hash,
        now=datetime.now(UTC),
    )
    client = _client(monkeypatch, payload)

    with pytest.raises(EgressAttestationError, match="EGRESS_ATTESTATION_INVALID"):
        client.verify_runtime()


def _lease_payload(
    *,
    status: str,
    lease_id: str,
    revision_id: str,
    policy_hash: str,
    selected_ip: str,
    port: int,
    include_token: bool,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "status": status,
        "lease_id": lease_id,
        "revision_id": revision_id,
        "policy_hash": policy_hash,
        "selected_ip": selected_ip,
        "port": port,
        "expires_at": (datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        "renew_after_seconds": 5,
        "kernel_timeout_seconds": 15,
        "ruleset_hash": "a" * 64,
    }
    if include_token:
        payload["bearer_token"] = "T" * 43
    return payload


def test_loopback_lease_create_renew_release_is_exact_and_token_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revision_id = uuid4()
    lease_id = uuid4()
    policy_hash = "f" * 64
    client = _client(
        monkeypatch,
        _payload(
            revision_id=str(revision_id),
            policy_hash=policy_hash,
            now=datetime.now(UTC),
        ),
    )
    opener = _LeaseOpener(
        _LeaseResponse(
            status=201,
            payload=_lease_payload(
                status="GRANTED",
                lease_id=str(lease_id),
                revision_id=str(revision_id),
                policy_hash=policy_hash,
                selected_ip="10.20.30.40",
                port=5432,
                include_token=True,
            ),
        ),
        _LeaseResponse(
            status=200,
            payload=_lease_payload(
                status="RENEWED",
                lease_id=str(lease_id),
                revision_id=str(revision_id),
                policy_hash=policy_hash,
                selected_ip="10.20.30.40",
                port=5432,
                include_token=False,
            ),
        ),
        _LeaseResponse(status=204, payload=None),
    )
    client._opener = opener  # type: ignore[assignment]

    lease = client.create_lease(
        revision_id=revision_id,
        policy_hash=policy_hash,
        selected_ip="10.20.30.40",
        port=5432,
    )
    renewed = client.renew_lease(lease)
    client.release_lease(renewed)

    assert "T" * 43 not in repr(lease)
    assert lease.evidence_hash != renewed.evidence_hash
    create_request, renew_request, release_request = opener.requests
    assert create_request.get_method() == "POST"
    assert create_request.full_url.endswith("/v1/leases")
    assert json.loads(create_request.data) == {
        "schema_version": "1.0",
        "revision_id": str(revision_id),
        "policy_hash": policy_hash,
        "selected_ip": "10.20.30.40",
        "port": 5432,
    }
    assert create_request.get_header("Content-type") == "application/json"
    assert renew_request.get_method() == "PUT"
    assert renew_request.data == b""
    assert renew_request.get_header("Authorization") == f"Bearer {'T' * 43}"
    assert release_request.get_method() == "DELETE"
    assert release_request.data == b""
    assert release_request.get_header("Authorization") == f"Bearer {'T' * 43}"


def test_loopback_lease_rejects_echo_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revision_id = uuid4()
    policy_hash = "9" * 64
    client = _client(
        monkeypatch,
        _payload(
            revision_id=str(revision_id),
            policy_hash=policy_hash,
            now=datetime.now(UTC),
        ),
    )
    client._opener = _LeaseOpener(  # type: ignore[assignment]
        _LeaseResponse(
            status=201,
            payload=_lease_payload(
                status="GRANTED",
                lease_id=str(uuid4()),
                revision_id=str(revision_id),
                policy_hash=policy_hash,
                selected_ip="10.20.30.41",
                port=5432,
                include_token=True,
            ),
        )
    )

    with pytest.raises(EgressAttestationError, match="EGRESS_LEASE_RESPONSE_INVALID"):
        client.create_lease(
            revision_id=revision_id,
            policy_hash=policy_hash,
            selected_ip="10.20.30.40",
            port=5432,
        )
