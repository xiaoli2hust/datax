from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_REFRESH_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def normalize_email(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    if (
        len(normalized) > 254
        or normalized.count("@") != 1
        or normalized.startswith("@")
        or normalized.endswith("@")
        or any(character.isspace() for character in normalized)
    ):
        raise ValueError("invalid email")
    return normalized


class Argon2idPasswordHasher:
    def __init__(
        self,
        *,
        time_cost: int = 3,
        memory_cost: int = 65_536,
        parallelism: int = 4,
    ) -> None:
        self._hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(32))

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerificationError, InvalidHashError):
            return False

    def verify_dummy(self, password: str) -> None:
        self.verify(self._dummy_hash, password)

    def needs_rehash(self, password_hash: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True


@dataclass(frozen=True)
class AccessClaims:
    user_id: UUID
    organization_id: UUID
    session_id: UUID
    issued_at: datetime
    expires_at: datetime
    token_id: UUID


class TokenManager:
    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
        refresh_hmac_key: bytes,
        issuer: str,
        audience: str,
        access_token_seconds: int = 900,
    ) -> None:
        if len(refresh_hmac_key) < 32:
            raise ValueError("refresh token HMAC key must contain at least 32 bytes")
        private_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        configured_public = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if not hmac.compare_digest(private_public, configured_public):
            raise ValueError("JWT Ed25519 private and public keys do not match")
        self._private_key = private_key
        self._public_key = public_key
        self._refresh_hmac_key = refresh_hmac_key
        self.issuer = issuer
        self.audience = audience
        self.access_token_seconds = access_token_seconds

    @classmethod
    def from_files(
        cls,
        *,
        private_key_file: Path,
        public_key_file: Path,
        refresh_hmac_key_file: Path,
        issuer: str,
        audience: str,
        access_token_seconds: int,
    ) -> TokenManager:
        private_key = serialization.load_pem_private_key(
            private_key_file.read_bytes(),
            password=None,
        )
        public_key = serialization.load_pem_public_key(public_key_file.read_bytes())
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("JWT private key must be Ed25519")
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("JWT public key must be Ed25519")
        return cls(
            private_key=private_key,
            public_key=public_key,
            refresh_hmac_key=refresh_hmac_key_file.read_bytes(),
            issuer=issuer,
            audience=audience,
            access_token_seconds=access_token_seconds,
        )

    def issue_access(
        self,
        *,
        user_id: UUID,
        organization_id: UUID,
        session_id: UUID,
        now: datetime | None = None,
    ) -> tuple[str, AccessClaims]:
        issued_at = ensure_aware(now or utc_now())
        expires_at = issued_at + timedelta(seconds=self.access_token_seconds)
        token_id = uuid4()
        claims = {
            "sub": str(user_id),
            "org_id": str(organization_id),
            "session_id": str(session_id),
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": str(token_id),
            "iss": self.issuer,
            "aud": self.audience,
        }
        encoded = jwt.encode(claims, self._private_key, algorithm="EdDSA")
        return encoded, AccessClaims(
            user_id=user_id,
            organization_id=organization_id,
            session_id=session_id,
            issued_at=issued_at,
            expires_at=expires_at,
            token_id=token_id,
        )

    def decode_access(self, token: str) -> AccessClaims:
        return self._decode_access(token, verify_expiration=True)

    def decode_access_for_logout(self, token: str) -> AccessClaims:
        """Verify a bearer token while allowing an expired session to be revoked."""
        return self._decode_access(token, verify_expiration=False)

    def _decode_access(
        self,
        token: str,
        *,
        verify_expiration: bool,
    ) -> AccessClaims:
        claims = jwt.decode(
            token,
            self._public_key,
            algorithms=["EdDSA"],
            audience=self.audience,
            issuer=self.issuer,
            options={
                "require": ["sub", "org_id", "session_id", "iat", "exp", "jti"],
                "verify_exp": verify_expiration,
            },
        )
        return AccessClaims(
            user_id=UUID(claims["sub"]),
            organization_id=UUID(claims["org_id"]),
            session_id=UUID(claims["session_id"]),
            issued_at=datetime.fromtimestamp(int(claims["iat"]), UTC),
            expires_at=datetime.fromtimestamp(int(claims["exp"]), UTC),
            token_id=UUID(claims["jti"]),
        )

    @staticmethod
    def new_refresh_token() -> str:
        return secrets.token_urlsafe(48)

    @staticmethod
    def is_valid_refresh_token(token: str | None) -> bool:
        return token is not None and _REFRESH_TOKEN_PATTERN.fullmatch(token) is not None

    def hash_refresh_token(self, token: str) -> bytes:
        if not self.is_valid_refresh_token(token):
            raise ValueError("invalid refresh token")
        return hmac.new(
            self._refresh_hmac_key,
            token.encode("ascii"),
            hashlib.sha256,
        ).digest()

    def hash_ip(self, source_ip: str | None) -> bytes | None:
        if source_ip is None:
            return None
        return hmac.new(
            self._refresh_hmac_key,
            source_ip.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    def encode_cursor(
        self,
        *,
        created_at: datetime,
        user_id: UUID,
        actor_id: UUID,
        status: str | None,
    ) -> str:
        payload = json.dumps(
            {
                "v": 1,
                "created_at": ensure_aware(created_at).isoformat(),
                "user_id": str(user_id),
                "actor_id": str(actor_id),
                "status": status,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        signature = hmac.new(self._refresh_hmac_key, payload, hashlib.sha256).digest()
        return f"{_base64url(payload)}.{_base64url(signature)}"

    def decode_cursor(
        self,
        token: str,
        *,
        actor_id: UUID,
        status: str | None,
    ) -> tuple[datetime, UUID]:
        try:
            encoded_payload, encoded_signature = token.split(".", 1)
            payload = _base64url_decode(encoded_payload)
            signature = _base64url_decode(encoded_signature)
            expected = hmac.new(self._refresh_hmac_key, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("invalid cursor signature")
            decoded: dict[str, Any] = json.loads(payload)
            if (
                decoded.get("v") != 1
                or decoded.get("actor_id") != str(actor_id)
                or decoded.get("status") != status
            ):
                raise ValueError("cursor scope mismatch")
            created_at = datetime.fromisoformat(decoded["created_at"])
            return ensure_aware(created_at), UUID(decoded["user_id"])
        except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError("invalid cursor") from exc


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
