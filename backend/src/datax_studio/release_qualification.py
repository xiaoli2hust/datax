"""Fail-closed parsing and verification primitives for ADR-0011 Phase A.

This module intentionally has no Settings, Compose, API, Worker, or plugin-certification
integration.  It only lets a protected qualification harness verify a short-lived HQA-signed
permission for an independently pinned immutable release payload.  It cannot create E3/E4
facts, change ordinary-user execution, or supply a production certification source.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

_PAYLOAD_ROOT_DOMAIN = b"DES-RELEASE-PAYLOAD-v1\n"
_HARNESS_QUALIFICATION_DOMAIN = b"DES-HARNESS-QUALIFICATION-v1\n"
_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_JSON_NESTING = 64
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_IMAGE_ROLES = ("api", "egress_guard", "postgres", "web", "worker")
_PLUGIN_NAMES = ("mysqlreader", "mysqlwriter", "postgresqlreader", "postgresqlwriter")
_PAYLOAD_PROVENANCE = object()


class QualificationVerificationError(ValueError):
    """A stable, intentionally non-secret reason why a qualification was rejected."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _DuplicateJsonKey(ValueError):
    pass


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _ArtifactModel(_StrictModel):
    path: str = Field(
        min_length=1,
        max_length=512,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$",
    )
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("path")
    @classmethod
    def _safe_relative_path(cls, value: str) -> str:
        if value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/")):
            raise ValueError("unsafe artifact path")
        return value


class _IdentityModel(_StrictModel):
    repository: Literal["xiaoli2hust/datax"]
    source_ref: str = Field(
        pattern=(
            r"^refs/(heads/main|tags/v(0|[1-9][0-9]*)\."
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))$"
        )
    )
    commit_sha: str = Field(pattern=r"^[a-f0-9]{40}$")
    product_version: str = Field(pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
    release_candidate: str = Field(
        pattern=(
            r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\."
            r"(0|[1-9][0-9]*)-[0-9a-f]{12}$"
        )
    )

    @model_validator(mode="after")
    def _candidate_matches_identity(self) -> _IdentityModel:
        if self.release_candidate != f"{self.product_version}-{self.commit_sha[:12]}":
            raise ValueError("release candidate does not bind its commit")
        if self.source_ref.startswith("refs/tags/"):
            expected_tag = f"refs/tags/v{self.product_version}"
            if self.source_ref != expected_tag:
                raise ValueError("tag does not bind product version")
        return self


class _TargetPlatformsModel(_StrictModel):
    windows_host: Literal["windows-x64"]
    linux_runtime: Literal["linux-amd64"]


class _ImageModel(_StrictModel):
    role: Literal["api", "egress_guard", "postgres", "web", "worker"]
    reference: str = Field(
        pattern=r"^[a-z0-9][a-z0-9._/-]{0,254}@sha256:[a-f0-9]{64}$"
    )


class _UpstreamModel(_StrictModel):
    repository: Literal["https://github.com/alibaba/DataX.git"]
    commit_sha: str = Field(pattern=r"^[a-f0-9]{40}$")
    module_path: str = Field(
        min_length=1,
        max_length=512,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$",
    )

    @field_validator("module_path")
    @classmethod
    def _safe_module_path(cls, value: str) -> str:
        if value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/")):
            raise ValueError("unsafe upstream module path")
        return value


class _PluginModel(_StrictModel):
    name: Literal["mysqlreader", "mysqlwriter", "postgresqlreader", "postgresqlwriter"]
    jar: _ArtifactModel
    upstream: _UpstreamModel
    parameter_boundary_contract_version: str = Field(pattern=r"^[1-9][0-9]*\.[0-9]+$")
    dependency_inventory: _ArtifactModel
    license_review: _ArtifactModel


class _WorkerRuntimeModel(_StrictModel):
    datax_release: Literal["datax_v202309"]
    jdk_version: str = Field(min_length=1, max_length=120, pattern=r"^[^\x00-\x1f\x7f]+$")
    runtime_manifest: _ArtifactModel
    runtime_tree_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    plugins: list[_PluginModel]

    @model_validator(mode="after")
    def _exact_plugins(self) -> _WorkerRuntimeModel:
        if tuple(plugin.name for plugin in self.plugins) != _PLUGIN_NAMES:
            raise ValueError("worker runtime plugins must be the exact ordered V1 set")
        return self


class _HqaKeyModel(_StrictModel):
    key_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    algorithm: Literal["Ed25519"]
    public_key_base64: str = Field(pattern=r"^[A-Za-z0-9+/]{43}=$")
    not_before: str = Field(pattern=r"Z$")
    valid_until: str = Field(pattern=r"Z$")


class _HqaKeyringModel(_StrictModel):
    keyring_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    keys: list[_HqaKeyModel] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def _ordered_unique_keys(self) -> _HqaKeyringModel:
        key_ids = tuple(key.key_id for key in self.keys)
        if not key_ids or key_ids != tuple(sorted(key_ids)) or len(key_ids) != len(set(key_ids)):
            raise ValueError("HQA keys must be sorted and unique")
        return self


class _ImageSbomModel(_StrictModel):
    role: Literal["api", "egress_guard", "postgres", "web", "worker"]
    artifact: _ArtifactModel


class _ArtifactsModel(_StrictModel):
    build_identity: _ArtifactModel
    image_lock: _ArtifactModel
    source_sbom: _ArtifactModel
    image_sboms: list[_ImageSbomModel]
    license_inventory: _ArtifactModel

    @model_validator(mode="after")
    def _exact_image_sboms(self) -> _ArtifactsModel:
        if tuple(item.role for item in self.image_sboms) != _IMAGE_ROLES:
            raise ValueError("image SBOMs must be the exact ordered image set")
        return self


class _ReleasePayloadDocument(_StrictModel):
    schema_version: Literal["1.0"]
    artifact_kind: Literal["RELEASE_PAYLOAD"]
    identity: _IdentityModel
    target_platforms: _TargetPlatformsModel
    images: list[_ImageModel]
    worker_runtime: _WorkerRuntimeModel
    hqa_keyring: _HqaKeyringModel
    artifacts: _ArtifactsModel
    payload_root_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def _exact_images(self) -> _ReleasePayloadDocument:
        if tuple(image.role for image in self.images) != _IMAGE_ROLES:
            raise ValueError("images must be the exact ordered release set")
        return self


class _PayloadBindingModel(_StrictModel):
    payload_root_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    identity: _IdentityModel
    target_platforms: _TargetPlatformsModel
    images: list[_ImageModel]
    worker_runtime: _WorkerRuntimeModel
    artifacts: _ArtifactsModel

    @model_validator(mode="after")
    def _exact_images(self) -> _PayloadBindingModel:
        if tuple(image.role for image in self.images) != _IMAGE_ROLES:
            raise ValueError("images must be the exact ordered release set")
        return self


class _HarnessModel(_StrictModel):
    identity: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    environment_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    environment_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    harness_version: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._+-]+$",
    )


class _SignatureModel(_StrictModel):
    algorithm: Literal["Ed25519"]
    value_base64: str = Field(pattern=r"^[A-Za-z0-9+/]{86}==$")


class _HarnessQualificationDocument(_StrictModel):
    schema_version: Literal["1.0"]
    artifact_kind: Literal["HARNESS_QUALIFICATION"]
    qualification_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    purpose: Literal["QUALIFICATION_HARNESS"]
    issuer_key_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    issued_at: str = Field(pattern=r"Z$")
    not_before: str = Field(pattern=r"Z$")
    valid_until: str = Field(pattern=r"Z$")
    nonce: str = Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    payload_binding: _PayloadBindingModel
    harness: _HarnessModel
    signature: _SignatureModel


@dataclass(frozen=True)
class HqaPublicKey:
    key_id: str
    public_key: bytes = field(repr=False)
    not_before: datetime
    valid_until: datetime


@dataclass(frozen=True)
class ReleasePayload:
    """A P whose raw document and caller-supplied expected root were both verified."""

    payload_root_sha256: str
    _expected_payload_root_sha256: str = field(repr=False)
    _canonical_without_root: bytes = field(repr=False)
    _binding_canonical: bytes = field(repr=False)
    _hqa_keys: tuple[HqaPublicKey, ...] = field(repr=False)
    _provenance: object = field(repr=False, compare=False)


@dataclass(frozen=True)
class ExpectedHarness:
    """Identity independently fixed by the protected harness, never by QH input."""

    identity: str
    environment_id: str
    environment_manifest_sha256: str
    harness_version: str


@dataclass(frozen=True)
class QualificationNonceUse:
    """Data needed by a durable, atomic HQA nonce ledger.

    The ledger must make ``(issuer_key_id, nonce)`` globally unique until at least
    ``valid_until``.  It must not scope uniqueness by payload root or qualification ID:
    doing so would let the same signed nonce authorize more than one qualification.
    """

    payload_root_sha256: str
    issuer_key_id: str
    qualification_id: str
    nonce: str
    valid_until: datetime


@dataclass(frozen=True)
class VerifiedHarnessQualification:
    """Successful Phase-A authorization metadata, not an E3/E4 conclusion."""

    qualification_id: str
    payload_root_sha256: str
    issuer_key_id: str
    valid_until: datetime


@dataclass(frozen=True)
class _ParsedHarnessQualification:
    qualification_id: str
    issuer_key_id: str
    issued_at: datetime
    not_before: datetime
    valid_until: datetime
    nonce: str
    payload_binding_canonical: bytes
    harness: ExpectedHarness
    signature: bytes = field(repr=False)
    signature_input: bytes = field(repr=False)


def parse_release_payload(
    raw: bytes,
    *,
    expected_payload_root_sha256: str,
) -> ReleasePayload:
    """Parse P as strict JCS and bind it to a protected harness's expected root.

    The caller must obtain ``expected_payload_root_sha256`` from a protected build handoff;
    accepting a self-asserted root from the same untrusted file would make the P keyring
    self-authorizing.
    """

    if not isinstance(expected_payload_root_sha256, str) or not _SHA256.fullmatch(
        expected_payload_root_sha256
    ):
        raise QualificationVerificationError("EXPECTED_PAYLOAD_ROOT_INVALID")
    document = _load_canonical_json(raw, kind="RELEASE_PAYLOAD")
    try:
        parsed = _ReleasePayloadDocument.model_validate(document)
    except ValidationError as error:
        raise QualificationVerificationError("RELEASE_PAYLOAD_FORMAT_INVALID") from error

    payload_without_root = dict(document)
    payload_without_root.pop("payload_root_sha256", None)
    canonical_without_root = _canonicalize(
        payload_without_root,
        code="RELEASE_PAYLOAD_CANONICAL_INVALID",
    )
    computed_root = hashlib.sha256(_PAYLOAD_ROOT_DOMAIN + canonical_without_root).hexdigest()
    if computed_root != parsed.payload_root_sha256:
        raise QualificationVerificationError("RELEASE_PAYLOAD_ROOT_MISMATCH")
    if parsed.payload_root_sha256 != expected_payload_root_sha256:
        raise QualificationVerificationError("RELEASE_PAYLOAD_EXPECTED_ROOT_MISMATCH")

    binding = _payload_binding(parsed)
    return ReleasePayload(
        payload_root_sha256=parsed.payload_root_sha256,
        _expected_payload_root_sha256=expected_payload_root_sha256,
        _canonical_without_root=canonical_without_root,
        _binding_canonical=_canonicalize(binding, code="RELEASE_PAYLOAD_CANONICAL_INVALID"),
        _hqa_keys=_hqa_keys(parsed.hqa_keyring),
        _provenance=_PAYLOAD_PROVENANCE,
    )


def verify_harness_qualification(
    raw: bytes,
    *,
    release_payload: ReleasePayload,
    expected_harness: ExpectedHarness,
    now: datetime,
    consume_nonce: Callable[[QualificationNonceUse], bool],
) -> VerifiedHarnessQualification:
    """Verify one QH against an already independently pinned P.

    ``consume_nonce`` must be a durable, atomic protected-harness operation.  It has no
    default and is called only after all P-root, cryptographic, identity, and time checks
    have succeeded.  A false return or ledger failure always rejects the QH.
    """

    _verify_release_payload_provenance(release_payload)
    _verify_expected_harness(expected_harness)
    current_time = _normalise_now(now)
    qualification = _parse_harness_qualification(raw)

    key = next(
        (item for item in release_payload._hqa_keys if item.key_id == qualification.issuer_key_id),
        None,
    )
    if key is None:
        raise QualificationVerificationError("QH_ISSUER_KEY_UNKNOWN")
    if not (key.not_before <= qualification.issued_at <= qualification.not_before):
        raise QualificationVerificationError("QH_ISSUER_KEY_TIME_INVALID")
    if qualification.valid_until > key.valid_until:
        raise QualificationVerificationError("QH_ISSUER_KEY_TIME_INVALID")
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(
            qualification.signature,
            qualification.signature_input,
        )
    except (InvalidSignature, ValueError):
        raise QualificationVerificationError("QH_SIGNATURE_INVALID") from None

    if qualification.payload_binding_canonical != release_payload._binding_canonical:
        raise QualificationVerificationError("QH_PAYLOAD_BINDING_MISMATCH")
    if qualification.harness != expected_harness:
        raise QualificationVerificationError("QH_HARNESS_IDENTITY_MISMATCH")
    if not (qualification.not_before <= current_time < qualification.valid_until):
        raise QualificationVerificationError("QH_NOT_CURRENTLY_VALID")

    nonce_use = QualificationNonceUse(
        payload_root_sha256=release_payload.payload_root_sha256,
        issuer_key_id=qualification.issuer_key_id,
        qualification_id=qualification.qualification_id,
        nonce=qualification.nonce,
        valid_until=qualification.valid_until,
    )
    try:
        consumed = consume_nonce(nonce_use)
    except Exception:
        raise QualificationVerificationError("QH_NONCE_LEDGER_UNAVAILABLE") from None
    if consumed is not True:
        raise QualificationVerificationError("QH_NONCE_REPLAYED")
    return VerifiedHarnessQualification(
        qualification_id=qualification.qualification_id,
        payload_root_sha256=release_payload.payload_root_sha256,
        issuer_key_id=qualification.issuer_key_id,
        valid_until=qualification.valid_until,
    )


def _payload_binding(document: _ReleasePayloadDocument) -> dict[str, Any]:
    return {
        "payload_root_sha256": document.payload_root_sha256,
        "identity": document.identity.model_dump(mode="json"),
        "target_platforms": document.target_platforms.model_dump(mode="json"),
        "images": [item.model_dump(mode="json") for item in document.images],
        "worker_runtime": document.worker_runtime.model_dump(mode="json"),
        "artifacts": document.artifacts.model_dump(mode="json"),
    }


def _hqa_keys(keyring: _HqaKeyringModel) -> tuple[HqaPublicKey, ...]:
    parsed_keys: list[HqaPublicKey] = []
    for key in keyring.keys:
        not_before = _parse_utc_timestamp(key.not_before, code="RELEASE_PAYLOAD_KEY_TIME_INVALID")
        valid_until = _parse_utc_timestamp(key.valid_until, code="RELEASE_PAYLOAD_KEY_TIME_INVALID")
        if not_before >= valid_until:
            raise QualificationVerificationError("RELEASE_PAYLOAD_KEY_TIME_INVALID")
        try:
            material = base64.b64decode(key.public_key_base64, validate=True)
        except (binascii.Error, ValueError):
            raise QualificationVerificationError("RELEASE_PAYLOAD_KEY_MATERIAL_INVALID") from None
        if len(material) != 32:
            raise QualificationVerificationError("RELEASE_PAYLOAD_KEY_MATERIAL_INVALID")
        parsed_keys.append(
            HqaPublicKey(
                key_id=key.key_id,
                public_key=material,
                not_before=not_before,
                valid_until=valid_until,
            )
        )
    return tuple(parsed_keys)


def _parse_harness_qualification(raw: bytes) -> _ParsedHarnessQualification:
    document = _load_canonical_json(raw, kind="HARNESS_QUALIFICATION")
    try:
        parsed = _HarnessQualificationDocument.model_validate(document)
    except ValidationError as error:
        raise QualificationVerificationError("QH_FORMAT_INVALID") from error
    if (
        _NONCE.fullmatch(parsed.nonce) is None
        or _IDENTIFIER.fullmatch(parsed.qualification_id) is None
    ):
        raise QualificationVerificationError("QH_FORMAT_INVALID")

    issued_at = _parse_utc_timestamp(parsed.issued_at, code="QH_TIMESTAMP_INVALID")
    not_before = _parse_utc_timestamp(parsed.not_before, code="QH_TIMESTAMP_INVALID")
    valid_until = _parse_utc_timestamp(parsed.valid_until, code="QH_TIMESTAMP_INVALID")
    if issued_at > not_before or not_before >= valid_until:
        raise QualificationVerificationError("QH_VALIDITY_WINDOW_INVALID")
    if valid_until - issued_at > timedelta(hours=24):
        raise QualificationVerificationError("QH_VALIDITY_WINDOW_TOO_LONG")
    try:
        signature = base64.b64decode(parsed.signature.value_base64, validate=True)
    except (binascii.Error, ValueError):
        raise QualificationVerificationError("QH_SIGNATURE_FORMAT_INVALID") from None
    if len(signature) != 64:
        raise QualificationVerificationError("QH_SIGNATURE_FORMAT_INVALID")

    unsigned = dict(document)
    unsigned.pop("signature", None)
    return _ParsedHarnessQualification(
        qualification_id=parsed.qualification_id,
        issuer_key_id=parsed.issuer_key_id,
        issued_at=issued_at,
        not_before=not_before,
        valid_until=valid_until,
        nonce=parsed.nonce,
        payload_binding_canonical=_canonicalize(
            parsed.payload_binding.model_dump(mode="json"),
            code="QH_PAYLOAD_BINDING_INVALID",
        ),
        harness=ExpectedHarness(
            identity=parsed.harness.identity,
            environment_id=parsed.harness.environment_id,
            environment_manifest_sha256=parsed.harness.environment_manifest_sha256,
            harness_version=parsed.harness.harness_version,
        ),
        signature=signature,
        signature_input=_HARNESS_QUALIFICATION_DOMAIN
        + _canonicalize(unsigned, code="QH_CANONICAL_INVALID"),
    )


def _verify_release_payload_provenance(payload: ReleasePayload) -> None:
    if not isinstance(payload, ReleasePayload) or payload._provenance is not _PAYLOAD_PROVENANCE:
        raise QualificationVerificationError("RELEASE_PAYLOAD_NOT_VERIFIED")
    computed_root = hashlib.sha256(
        _PAYLOAD_ROOT_DOMAIN + payload._canonical_without_root
    ).hexdigest()
    if computed_root != payload.payload_root_sha256:
        raise QualificationVerificationError("RELEASE_PAYLOAD_ROOT_MISMATCH")
    if payload.payload_root_sha256 != payload._expected_payload_root_sha256:
        raise QualificationVerificationError("RELEASE_PAYLOAD_EXPECTED_ROOT_MISMATCH")


def _verify_expected_harness(expected: ExpectedHarness) -> None:
    if not isinstance(expected, ExpectedHarness):
        raise QualificationVerificationError("QH_EXPECTED_HARNESS_INVALID")
    if (
        _IDENTIFIER.fullmatch(expected.identity) is None
        or _IDENTIFIER.fullmatch(expected.environment_id) is None
        or not isinstance(expected.environment_manifest_sha256, str)
        or _SHA256.fullmatch(expected.environment_manifest_sha256) is None
        or not isinstance(expected.harness_version, str)
        or not re.fullmatch(r"^[A-Za-z0-9._+-]{1,128}$", expected.harness_version)
    ):
        raise QualificationVerificationError("QH_EXPECTED_HARNESS_INVALID")


def _normalise_now(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise QualificationVerificationError("QH_CURRENT_TIME_INVALID")
    return value.astimezone(UTC)


def _parse_utc_timestamp(value: str, *, code: str) -> datetime:
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        raise QualificationVerificationError(code)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        raise QualificationVerificationError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QualificationVerificationError(code)
    return parsed.astimezone(UTC)


def _load_canonical_json(raw: bytes, *, kind: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_DOCUMENT_BYTES:
        raise QualificationVerificationError(f"{kind}_JSON_INVALID")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise QualificationVerificationError(f"{kind}_CANONICAL_JSON_REQUIRED")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise QualificationVerificationError(f"{kind}_UTF8_REQUIRED") from None
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except _DuplicateJsonKey:
        raise QualificationVerificationError(f"{kind}_DUPLICATE_JSON_KEY") from None
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise QualificationVerificationError(f"{kind}_JSON_INVALID") from None
    if not isinstance(document, dict):
        raise QualificationVerificationError(f"{kind}_JSON_INVALID")
    _reject_excessive_json_nesting(document, kind=kind)
    if _canonicalize(document, code=f"{kind}_CANONICAL_JSON_REQUIRED") != raw:
        raise QualificationVerificationError(f"{kind}_CANONICAL_JSON_REQUIRED")
    return document


def _canonicalize(value: Any, *, code: str) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise QualificationVerificationError(code) from None


def _reject_excessive_json_nesting(value: object, *, kind: str) -> None:
    """Reject deeply nested input before Pydantic or RFC 8785 can recurse on it."""

    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > _MAX_JSON_NESTING:
            raise QualificationVerificationError(f"{kind}_JSON_INVALID")
        if isinstance(current, dict):
            pending.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            pending.extend((child, depth + 1) for child in current)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey()
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    del value
    raise ValueError("non-finite JSON number")
