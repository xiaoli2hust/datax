from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from datax_studio.auth.security import Argon2idPasswordHasher, TokenManager


def test_argon2id_hash_is_salted_and_verifiable() -> None:
    hasher = Argon2idPasswordHasher(
        time_cost=1,
        memory_cost=8_192,
        parallelism=1,
    )
    first = hasher.hash("A-strong-password-123!")
    second = hasher.hash("A-strong-password-123!")

    assert first.startswith("$argon2id$")
    assert second.startswith("$argon2id$")
    assert first != second
    assert hasher.verify(first, "A-strong-password-123!")
    assert not hasher.verify(first, "Wrong-password-123!")


def test_ed25519_access_token_has_required_short_lived_claims() -> None:
    private_key = Ed25519PrivateKey.generate()
    manager = TokenManager(
        private_key=private_key,
        public_key=private_key.public_key(),
        refresh_hmac_key=b"k" * 32,
        issuer="issuer",
        audience="audience",
        access_token_seconds=900,
    )
    now = datetime.now(UTC).replace(microsecond=0)
    token, issued = manager.issue_access(
        user_id=uuid4(),
        organization_id=uuid4(),
        session_id=uuid4(),
        now=now,
    )

    header = jwt.get_unverified_header(token)
    decoded = manager.decode_access(token)
    assert header["alg"] == "EdDSA"
    assert decoded.user_id == issued.user_id
    assert decoded.organization_id == issued.organization_id
    assert decoded.session_id == issued.session_id
    assert decoded.expires_at - decoded.issued_at == timedelta(seconds=900)

    other_private_key = Ed25519PrivateKey.generate()
    wrong_manager = TokenManager(
        private_key=other_private_key,
        public_key=other_private_key.public_key(),
        refresh_hmac_key=b"k" * 32,
        issuer="issuer",
        audience="audience",
        access_token_seconds=900,
    )
    with pytest.raises(jwt.InvalidSignatureError):
        wrong_manager.decode_access(token)


def test_ed25519_key_pair_mismatch_fails_closed_at_startup() -> None:
    private_key = Ed25519PrivateKey.generate()
    unrelated_public_key = Ed25519PrivateKey.generate().public_key()

    with pytest.raises(ValueError, match="do not match"):
        TokenManager(
            private_key=private_key,
            public_key=unrelated_public_key,
            refresh_hmac_key=b"k" * 32,
            issuer="issuer",
            audience="audience",
        )


def test_refresh_hash_uses_secret_hmac_key() -> None:
    private_key = Ed25519PrivateKey.generate()
    token = TokenManager.new_refresh_token()
    first = TokenManager(
        private_key=private_key,
        public_key=private_key.public_key(),
        refresh_hmac_key=b"a" * 32,
        issuer="issuer",
        audience="audience",
    )
    second = TokenManager(
        private_key=private_key,
        public_key=private_key.public_key(),
        refresh_hmac_key=b"b" * 32,
        issuer="issuer",
        audience="audience",
    )

    assert first.hash_refresh_token(token) != second.hash_refresh_token(token)
    assert len(first.hash_refresh_token(token)) == 32
    assert first.is_valid_refresh_token(token)
    assert not first.is_valid_refresh_token("not-valid*refresh")
    with pytest.raises(ValueError, match="invalid refresh token"):
        first.hash_refresh_token("not-valid*refresh")
