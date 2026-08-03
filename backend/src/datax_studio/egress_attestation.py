from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID

POLICY_ENGINE_VERSION = "des-nftables-egress-v1"
RESOLVER_POLICY_VERSION = "des-system-dns-v1"
ATTESTATION_SCHEMA_VERSION = "1.0"
_HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_NETWORK_NAMESPACE_PATTERN = re.compile(r"^net:\[[0-9]+\]$")
_BEARER_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_LEASE_CREATION_CAPABILITY_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_LEASE_CREATION_CAPABILITY_HEADER = "X-DataX-Egress-Lease-Capability"
_LEASE_CREATION_CAPABILITY_PATH = Path(
    "/run/secrets/egress_lease_creation_capability"
)
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_LEASE_RESPONSE_BYTES = 16 * 1024
_LEASE_ERROR_CODES = frozenset(
    {
        "LEASE_REQUEST_INVALID",
        "LEASE_AUTH_INVALID",
        "LEASE_CREATION_AUTH_INVALID",
        "LEASE_NOT_FOUND",
        "LEASE_POLICY_NOT_ACTIVE",
        "LEASE_LIMIT_REACHED",
        "LEASE_GUARD_BLOCKED",
        "LEASE_POLICY_SET_CHANGED",
        "NFT_COMMAND_FAILED",
        "NFT_RULESET_DRIFT",
        "NFT_RULESET_INVALID",
        "POLICY_DATABASE_UNAVAILABLE",
        "POLICY_DOCUMENT_INVALID",
        "POLICY_REVISION_DUPLICATE",
        "POLICY_RULE_LIMIT_EXCEEDED",
    }
)


class EgressAttestationError(ValueError):
    """Fail-closed egress attestation error with a stable public code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class EgressVerification:
    policy_engine_version: str
    resolver_policy_version: str
    network_namespace_id: str
    policy_set_hash: str
    ruleset_hash: str
    checked_at: datetime

    @property
    def evidence_hash(self) -> str:
        material = (
            "DXEGRESSATTESTATIONv1\n"
            f"{self.policy_engine_version}\n"
            f"{self.resolver_policy_version}\n"
            f"{self.network_namespace_id}\n"
            f"{self.policy_set_hash}\n"
            f"{self.ruleset_hash}\n"
            f"{self.checked_at.isoformat()}\n"
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EgressLease:
    lease_id: UUID
    revision_id: UUID
    policy_hash: str
    selected_ip: str
    port: int
    expires_at: datetime
    renew_after_seconds: int
    kernel_timeout_seconds: int
    ruleset_hash: str
    bearer_token: str = field(repr=False, compare=False)

    @property
    def evidence_hash(self) -> str:
        material = (
            "DXEGRESSLEASEv1\n"
            f"{self.lease_id}\n"
            f"{self.revision_id}\n"
            f"{self.policy_hash}\n"
            f"{self.selected_ip}\n"
            f"{self.port}\n"
            f"{self.expires_at.isoformat()}\n"
            f"{self.renew_after_seconds}\n"
            f"{self.kernel_timeout_seconds}\n"
            f"{self.ruleset_hash}\n"
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


class EgressVerifier(Protocol):
    def verify_runtime(self) -> EgressVerification: ...

    def verify_policy(
        self,
        *,
        revision_id: UUID,
        policy_hash: str,
        policy_engine_version: str,
        resolver_policy_version: str,
        timeout_seconds: float | None = None,
    ) -> EgressVerification: ...


class EgressLeaseClient(Protocol):
    def create_lease(
        self,
        *,
        revision_id: UUID,
        policy_hash: str,
        selected_ip: str,
        port: int,
        timeout_seconds: float | None = None,
    ) -> EgressLease: ...

    def renew_lease(
        self,
        lease: EgressLease,
        *,
        timeout_seconds: float | None = None,
    ) -> EgressLease: ...

    def release_lease(
        self,
        lease: EgressLease,
        *,
        timeout_seconds: float | None = None,
    ) -> None: ...


def current_network_namespace_id() -> str:
    try:
        namespace_id = os.readlink("/proc/self/ns/net")
    except OSError as exc:
        raise EgressAttestationError("EGRESS_NETWORK_NAMESPACE_UNAVAILABLE") from exc
    if _NETWORK_NAMESPACE_PATTERN.fullmatch(namespace_id) is None:
        raise EgressAttestationError("EGRESS_NETWORK_NAMESPACE_INVALID")
    return namespace_id


def _parse_timestamp(value: object, *, code: str) -> datetime:
    if not isinstance(value, str):
        raise EgressAttestationError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EgressAttestationError(code) from exc
    if parsed.tzinfo is None:
        raise EgressAttestationError(code)
    return parsed.astimezone(UTC)


def compute_policy_set_hash(policies: dict[str, str]) -> str:
    ordered = [
        {"revision_id": revision_id, "policy_hash": policies[revision_id]}
        for revision_id in sorted(policies)
    ]
    payload = json.dumps(
        ordered,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"DXEGRESSPOLICYSETv1\n" + payload).hexdigest()


class LoopbackEgressAttestationClient:
    """Verify the privileged guard through the shared loopback namespace."""

    def __init__(
        self,
        *,
        url: str,
        timeout_seconds: float,
        max_age_seconds: float,
        policy_engine_version: str = POLICY_ENGINE_VERSION,
        resolver_policy_version: str = RESOLVER_POLICY_VERSION,
        lease_creation_capability_file: Path = _LEASE_CREATION_CAPABILITY_PATH,
    ) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/v1/attestation"
            or parsed.port is None
        ):
            raise ValueError(
                "egress attestation URL must be an exact 127.0.0.1 HTTP endpoint"
            )
        if timeout_seconds <= 0 or timeout_seconds > 5:
            raise ValueError("egress attestation timeout must be in (0, 5]")
        if max_age_seconds <= 0 or max_age_seconds > 30:
            raise ValueError("egress attestation max age must be in (0, 30]")
        self.url = url
        self.timeout_seconds = timeout_seconds
        self.max_age_seconds = max_age_seconds
        self.policy_engine_version = policy_engine_version
        self.resolver_policy_version = resolver_policy_version
        self.lease_creation_capability_file = lease_creation_capability_file
        self._lease_collection_url = (
            f"http://127.0.0.1:{parsed.port}/v1/leases"
        )
        # Never honor HTTP(S)_PROXY for a security decision bound to loopback.
        self._opener = build_opener(ProxyHandler({}))

    def _effective_timeout(self, timeout_seconds: float | None) -> float:
        """Clamp one guard HTTP request to an enclosing operation budget."""

        if timeout_seconds is None:
            return self.timeout_seconds
        if timeout_seconds <= 0:
            raise EgressAttestationError("EGRESS_OPERATION_DEADLINE_EXCEEDED")
        return min(self.timeout_seconds, timeout_seconds)

    def _fetch(
        self,
        *,
        timeout_seconds: float | None = None,
    ) -> tuple[EgressVerification, dict[str, str]]:
        request = Request(
            self.url,
            headers={"Accept": "application/json"},
            method="GET",
        )
        try:
            with self._opener.open(
                request,
                timeout=self._effective_timeout(timeout_seconds),
            ) as response:
                if response.status != 200:
                    raise EgressAttestationError("EGRESS_ATTESTATION_UNAVAILABLE")
                content_type = response.headers.get_content_type()
                if content_type != "application/json":
                    raise EgressAttestationError("EGRESS_ATTESTATION_INVALID")
                payload_bytes = response.read(_MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise EgressAttestationError("EGRESS_ATTESTATION_UNAVAILABLE") from exc
        if len(payload_bytes) > _MAX_RESPONSE_BYTES:
            raise EgressAttestationError("EGRESS_ATTESTATION_INVALID")
        try:
            payload = json.loads(payload_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EgressAttestationError("EGRESS_ATTESTATION_INVALID") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "status",
            "policy_engine_version",
            "resolver_policy_version",
            "network_namespace_id",
            "policy_set_hash",
            "policies",
            "ruleset_hash",
            "applied_at",
            "checked_at",
        }:
            raise EgressAttestationError("EGRESS_ATTESTATION_INVALID")
        if (
            payload["schema_version"] != ATTESTATION_SCHEMA_VERSION
            or payload["status"] != "VERIFIED"
            or payload["policy_engine_version"] != self.policy_engine_version
            or payload["resolver_policy_version"] != self.resolver_policy_version
        ):
            raise EgressAttestationError("EGRESS_ATTESTATION_UNVERIFIED")
        namespace_id = payload["network_namespace_id"]
        if (
            not isinstance(namespace_id, str)
            or _NETWORK_NAMESPACE_PATTERN.fullmatch(namespace_id) is None
            or namespace_id != current_network_namespace_id()
        ):
            raise EgressAttestationError("EGRESS_NETWORK_NAMESPACE_MISMATCH")
        policy_set_hash = payload["policy_set_hash"]
        ruleset_hash = payload["ruleset_hash"]
        if (
            not isinstance(policy_set_hash, str)
            or _HASH_PATTERN.fullmatch(policy_set_hash) is None
            or not isinstance(ruleset_hash, str)
            or _HASH_PATTERN.fullmatch(ruleset_hash) is None
        ):
            raise EgressAttestationError("EGRESS_ATTESTATION_INVALID")
        policies = payload["policies"]
        if not isinstance(policies, dict) or len(policies) > 10_000:
            raise EgressAttestationError("EGRESS_ATTESTATION_INVALID")
        normalized_policies: dict[str, str] = {}
        for raw_revision_id, raw_policy_hash in policies.items():
            try:
                revision_id = str(UUID(str(raw_revision_id)))
            except ValueError as exc:
                raise EgressAttestationError("EGRESS_ATTESTATION_INVALID") from exc
            if (
                raw_revision_id != revision_id
                or not isinstance(raw_policy_hash, str)
                or _HASH_PATTERN.fullmatch(raw_policy_hash) is None
            ):
                raise EgressAttestationError("EGRESS_ATTESTATION_INVALID")
            normalized_policies[revision_id] = raw_policy_hash
        if list(normalized_policies) != sorted(normalized_policies):
            raise EgressAttestationError("EGRESS_ATTESTATION_INVALID")
        if compute_policy_set_hash(normalized_policies) != policy_set_hash:
            raise EgressAttestationError("EGRESS_POLICY_SET_HASH_MISMATCH")
        applied_at = _parse_timestamp(
            payload["applied_at"],
            code="EGRESS_ATTESTATION_INVALID",
        )
        checked_at = _parse_timestamp(
            payload["checked_at"],
            code="EGRESS_ATTESTATION_INVALID",
        )
        now = datetime.now(UTC)
        if (
            checked_at < applied_at
            or (now - checked_at).total_seconds() > self.max_age_seconds
            or (checked_at - now).total_seconds() > 2
        ):
            raise EgressAttestationError("EGRESS_ATTESTATION_STALE")
        return (
            EgressVerification(
                policy_engine_version=self.policy_engine_version,
                resolver_policy_version=self.resolver_policy_version,
                network_namespace_id=namespace_id,
                policy_set_hash=policy_set_hash,
                ruleset_hash=ruleset_hash,
                checked_at=checked_at,
            ),
            normalized_policies,
        )

    def verify_runtime(self) -> EgressVerification:
        verification, _ = self._fetch()
        return verification

    def verify_policy(
        self,
        *,
        revision_id: UUID,
        policy_hash: str,
        policy_engine_version: str,
        resolver_policy_version: str,
        timeout_seconds: float | None = None,
    ) -> EgressVerification:
        if (
            policy_engine_version != self.policy_engine_version
            or resolver_policy_version != self.resolver_policy_version
            or _HASH_PATTERN.fullmatch(policy_hash) is None
        ):
            raise EgressAttestationError("EGRESS_POLICY_VERSION_MISMATCH")
        verification, policies = self._fetch(timeout_seconds=timeout_seconds)
        if policies.get(str(revision_id)) != policy_hash:
            raise EgressAttestationError("EGRESS_POLICY_NOT_APPLIED")
        return verification

    def create_lease(
        self,
        *,
        revision_id: UUID,
        policy_hash: str,
        selected_ip: str,
        port: int,
        timeout_seconds: float | None = None,
    ) -> EgressLease:
        document = {
            "schema_version": ATTESTATION_SCHEMA_VERSION,
            "revision_id": str(revision_id),
            "policy_hash": policy_hash,
            "selected_ip": selected_ip,
            "port": port,
        }
        response = self._lease_request(
            self._lease_collection_url,
            method="POST",
            body=json.dumps(
                document,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii"),
            expected_status=201,
            bearer_token=None,
            lease_creation_capability=self._read_lease_creation_capability(),
            timeout_seconds=timeout_seconds,
        )
        return self._parse_lease_response(
            response,
            expected_status="GRANTED",
            expected_revision_id=revision_id,
            expected_policy_hash=policy_hash,
            expected_selected_ip=selected_ip,
            expected_port=port,
            existing_token=None,
        )

    def renew_lease(
        self,
        lease: EgressLease,
        *,
        timeout_seconds: float | None = None,
    ) -> EgressLease:
        response = self._lease_request(
            f"{self._lease_collection_url}/{lease.lease_id}",
            method="PUT",
            body=b"",
            expected_status=200,
            bearer_token=lease.bearer_token,
            lease_creation_capability=None,
            timeout_seconds=timeout_seconds,
        )
        renewed = self._parse_lease_response(
            response,
            expected_status="RENEWED",
            expected_revision_id=lease.revision_id,
            expected_policy_hash=lease.policy_hash,
            expected_selected_ip=lease.selected_ip,
            expected_port=lease.port,
            existing_token=lease.bearer_token,
        )
        if renewed.lease_id != lease.lease_id:
            raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID")
        return renewed

    def release_lease(
        self,
        lease: EgressLease,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        response = self._lease_request(
            f"{self._lease_collection_url}/{lease.lease_id}",
            method="DELETE",
            body=b"",
            expected_status=204,
            bearer_token=lease.bearer_token,
            lease_creation_capability=None,
            expect_json=False,
            timeout_seconds=timeout_seconds,
        )
        if response is not None:
            raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID")

    def _lease_request(
        self,
        url: str,
        *,
        method: str,
        body: bytes,
        expected_status: int,
        bearer_token: str | None,
        lease_creation_capability: str | None,
        expect_json: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict[str, object] | None:
        headers = {
            "Accept": "application/json",
            "Cache-Control": "no-store",
        }
        if method == "POST":
            headers["Content-Type"] = "application/json"
            if (
                lease_creation_capability is None
                or _LEASE_CREATION_CAPABILITY_PATTERN.fullmatch(
                    lease_creation_capability
                )
                is None
            ):
                raise EgressAttestationError(
                    "EGRESS_LEASE_CREATION_CAPABILITY_UNAVAILABLE"
                )
            headers[_LEASE_CREATION_CAPABILITY_HEADER] = lease_creation_capability
        if bearer_token is not None:
            if _BEARER_TOKEN_PATTERN.fullmatch(bearer_token) is None:
                raise EgressAttestationError("EGRESS_LEASE_AUTH_INVALID")
            headers["Authorization"] = f"Bearer {bearer_token}"
        request = Request(
            url,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(
                request,
                timeout=self._effective_timeout(timeout_seconds),
            ) as response:
                if response.status != expected_status:
                    raise EgressAttestationError("EGRESS_LEASE_UNAVAILABLE")
                payload_bytes = response.read(_MAX_LEASE_RESPONSE_BYTES + 1)
                if len(payload_bytes) > _MAX_LEASE_RESPONSE_BYTES:
                    raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID")
                if not expect_json:
                    if payload_bytes:
                        raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID")
                    return None
                if response.headers.get_content_type() != "application/json":
                    raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID")
        except HTTPError as exc:
            raise EgressAttestationError(self._lease_http_error_code(exc)) from exc
        except EgressAttestationError:
            raise
        except (URLError, TimeoutError, OSError) as exc:
            raise EgressAttestationError("EGRESS_LEASE_UNAVAILABLE") from exc
        try:
            payload = json.loads(payload_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID") from exc
        if not isinstance(payload, dict):
            raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID")
        return payload

    def _read_lease_creation_capability(self) -> str:
        """Read the Launcher-managed lease control secret only for POST.

        The secret never becomes part of a DataX job or child process
        environment.  This is caller authentication inside the shared
        loopback namespace, not a hostile same-UID process boundary.
        """

        path = self.lease_creation_capability_file
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise EgressAttestationError(
                "EGRESS_LEASE_CREATION_CAPABILITY_UNAVAILABLE"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_size != 64
        ):
            raise EgressAttestationError("EGRESS_LEASE_CREATION_CAPABILITY_UNAVAILABLE")

        raw: bytearray | None = None
        try:
            raw = bytearray(path.read_bytes())
            value = raw.decode("ascii")
            if (
                len(raw) != 64
                or _LEASE_CREATION_CAPABILITY_PATTERN.fullmatch(value) is None
            ):
                raise EgressAttestationError(
                    "EGRESS_LEASE_CREATION_CAPABILITY_UNAVAILABLE"
                )
            return value
        except (OSError, UnicodeDecodeError) as exc:
            raise EgressAttestationError(
                "EGRESS_LEASE_CREATION_CAPABILITY_UNAVAILABLE"
            ) from exc
        finally:
            if raw is not None:
                raw[:] = b"\x00" * len(raw)

    @staticmethod
    def _lease_http_error_code(error: HTTPError) -> str:
        try:
            body = error.read(_MAX_LEASE_RESPONSE_BYTES + 1)
            document = json.loads(body)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return "EGRESS_LEASE_UNAVAILABLE"
        if (
            len(body) > _MAX_LEASE_RESPONSE_BYTES
            or not isinstance(document, dict)
            or set(document) != {"code"}
            or document["code"] not in _LEASE_ERROR_CODES
        ):
            return "EGRESS_LEASE_UNAVAILABLE"
        return str(document["code"])

    @staticmethod
    def _parse_lease_response(
        payload: dict[str, object],
        *,
        expected_status: str,
        expected_revision_id: UUID,
        expected_policy_hash: str,
        expected_selected_ip: str,
        expected_port: int,
        existing_token: str | None,
    ) -> EgressLease:
        expected_fields = {
            "schema_version",
            "status",
            "lease_id",
            "revision_id",
            "policy_hash",
            "selected_ip",
            "port",
            "expires_at",
            "renew_after_seconds",
            "kernel_timeout_seconds",
            "ruleset_hash",
        }
        if existing_token is None:
            expected_fields.add("bearer_token")
        if set(payload) != expected_fields:
            raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID")
        try:
            lease_id = UUID(str(payload["lease_id"]))
            revision_id = UUID(str(payload["revision_id"]))
        except ValueError as exc:
            raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID") from exc
        if (
            payload["schema_version"] != ATTESTATION_SCHEMA_VERSION
            or payload["status"] != expected_status
            or str(lease_id) != payload["lease_id"]
            or str(revision_id) != payload["revision_id"]
            or revision_id != expected_revision_id
            or payload["policy_hash"] != expected_policy_hash
            or payload["selected_ip"] != expected_selected_ip
            or payload["port"] != expected_port
            or payload["renew_after_seconds"] != 5
            or payload["kernel_timeout_seconds"] != 15
            or not isinstance(payload["ruleset_hash"], str)
            or _HASH_PATTERN.fullmatch(payload["ruleset_hash"]) is None
        ):
            raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID")
        expires_at = _parse_timestamp(
            payload["expires_at"],
            code="EGRESS_LEASE_RESPONSE_INVALID",
        )
        now = datetime.now(UTC)
        if expires_at <= now or (expires_at - now).total_seconds() > 60:
            raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID")
        token = existing_token if existing_token is not None else payload["bearer_token"]
        if (
            not isinstance(token, str)
            or _BEARER_TOKEN_PATTERN.fullmatch(token) is None
        ):
            raise EgressAttestationError("EGRESS_LEASE_RESPONSE_INVALID")
        return EgressLease(
            lease_id=lease_id,
            revision_id=revision_id,
            policy_hash=expected_policy_hash,
            selected_ip=expected_selected_ip,
            port=expected_port,
            expires_at=expires_at,
            renew_after_seconds=5,
            kernel_timeout_seconds=15,
            ruleset_hash=str(payload["ruleset_hash"]),
            bearer_token=token,
        )


class UnavailableEgressVerifier:
    """Development default that can never authorize an outbound connection."""

    def verify_runtime(self) -> EgressVerification:
        raise EgressAttestationError("EGRESS_ATTESTATION_UNAVAILABLE")

    def verify_policy(
        self,
        *,
        revision_id: UUID,
        policy_hash: str,
        policy_engine_version: str,
        resolver_policy_version: str,
        timeout_seconds: float | None = None,
    ) -> EgressVerification:
        del (
            revision_id,
            policy_hash,
            policy_engine_version,
            resolver_policy_version,
            timeout_seconds,
        )
        raise EgressAttestationError("EGRESS_ATTESTATION_UNAVAILABLE")


class UnavailableEgressLeaseClient:
    """Development default that can never create an outbound allowance."""

    def create_lease(self, **_kwargs: object) -> EgressLease:
        raise EgressAttestationError("EGRESS_LEASE_UNAVAILABLE")

    def renew_lease(
        self,
        lease: EgressLease,
        *,
        timeout_seconds: float | None = None,
    ) -> EgressLease:
        del lease, timeout_seconds
        raise EgressAttestationError("EGRESS_LEASE_UNAVAILABLE")

    def release_lease(
        self,
        lease: EgressLease,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        del lease, timeout_seconds
        raise EgressAttestationError("EGRESS_LEASE_UNAVAILABLE")


def attestation_payload_hash(payload: dict[str, Any]) -> str:
    """Stable helper used by guard-side contract tests."""

    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
