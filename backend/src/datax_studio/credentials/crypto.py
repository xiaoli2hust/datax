from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import (
    aes_key_unwrap_with_padding,
    aes_key_wrap_with_padding,
)

from datax_studio.credentials.keyring import zeroize

DATA_ALGORITHM = "AES-256-GCM"
WRAPPING_ALGORITHM = "AES-256-KWP"
AAD_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class EncryptedCredential:
    ciphertext: bytes
    nonce: bytes
    encrypted_dek: bytes
    wrapped_dek_sha256: str


def build_credential_aad(
    *,
    organization_id: UUID,
    project_id: UUID,
    datasource_id: UUID,
    credential_secret_id: UUID,
    secret_version: int,
) -> bytes:
    if secret_version < 1:
        raise ValueError("secret_version must be positive")
    return (
        "DXCREDENTIALv1\n"
        f"{str(organization_id).lower()}\n"
        f"{str(project_id).lower()}\n"
        f"{str(datasource_id).lower()}\n"
        f"{str(credential_secret_id).lower()}\n"
        f"{secret_version}\n"
        f"{AAD_SCHEMA_VERSION}\n"
        f"{DATA_ALGORITHM}"
    ).encode()


def encrypt_credential(
    plaintext: bytearray,
    *,
    aad: bytes,
    kek: bytearray,
) -> EncryptedCredential:
    if not plaintext:
        raise ValueError("credential must not be empty")
    if len(kek) != 32:
        raise ValueError("KEK must contain exactly 32 bytes")
    dek = bytearray(os.urandom(32))
    nonce = os.urandom(12)
    try:
        ciphertext = AESGCM(bytes(dek)).encrypt(nonce, plaintext, aad)
        encrypted_dek = aes_key_wrap_with_padding(kek, dek)
        return EncryptedCredential(
            ciphertext=ciphertext,
            nonce=nonce,
            encrypted_dek=encrypted_dek,
            wrapped_dek_sha256=hashlib.sha256(encrypted_dek).hexdigest(),
        )
    finally:
        zeroize(dek)


def decrypt_credential(
    *,
    ciphertext: bytes,
    nonce: bytes,
    encrypted_dek: bytes,
    aad: bytes,
    kek: bytearray,
) -> bytearray:
    if len(kek) != 32:
        raise ValueError("KEK must contain exactly 32 bytes")
    dek_bytes = aes_key_unwrap_with_padding(kek, encrypted_dek)
    dek = bytearray(dek_bytes)
    try:
        plaintext = AESGCM(bytes(dek)).decrypt(nonce, ciphertext, aad)
        return bytearray(plaintext)
    finally:
        zeroize(dek)
