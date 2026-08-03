"""Fail-closed parsing and verification primitives for ADR-0011 qualification.

This module intentionally has no Settings, Compose, API, Worker, or plugin-certification
integration.  It only lets a protected qualification harness verify a short-lived HQA-signed
Phase-A permission or a RQA-signed private Phase-B qualification for an independently pinned
immutable release payload.  It cannot create E3/E4 facts, change ordinary-user execution, or
supply a production certification source.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, NamedTuple

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

_PAYLOAD_ROOT_DOMAIN = b"DES-RELEASE-PAYLOAD-v1\n"
_HARNESS_QUALIFICATION_DOMAIN = b"DES-HARNESS-QUALIFICATION-v1\n"
_RELEASE_QUALIFICATION_DOMAIN = b"DES-RELEASE-QUALIFICATION-v1\n"
_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_JSON_NESTING = 64
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_IMAGE_ROLES = ("api", "egress_guard", "postgres", "web", "worker")
_PLUGIN_NAMES = ("mysqlreader", "mysqlwriter", "postgresqlreader", "postgresqlwriter")
_PAYLOAD_PROVENANCE = object()
_RELEASE_PAYLOAD_INTEGRITY_KEY = secrets.token_bytes(32)


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


class _RqaKeyModel(_StrictModel):
    key_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    algorithm: Literal["Ed25519"]
    public_key_base64: str = Field(pattern=r"^[A-Za-z0-9+/]{43}=$")
    not_before: str = Field(pattern=r"Z$")
    valid_until: str = Field(pattern=r"Z$")


class _RqaKeyringModel(_StrictModel):
    keyring_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    keys: list[_RqaKeyModel] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def _ordered_unique_keys(self) -> _RqaKeyringModel:
        key_ids = tuple(key.key_id for key in self.keys)
        if not key_ids or key_ids != tuple(sorted(key_ids)) or len(key_ids) != len(set(key_ids)):
            raise ValueError("RQA keys must be sorted and unique")
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
    rqa_keyring: _RqaKeyringModel
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


class _ReleaseBindingPluginModel(_StrictModel):
    name: Literal["mysqlreader", "mysqlwriter", "postgresqlreader", "postgresqlwriter"]
    jar_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    parameter_boundary_contract_version: str = Field(pattern=r"^[1-9][0-9]*\.[0-9]+$")
    dependency_inventory_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    license_review_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class _ReleaseBindingModel(_StrictModel):
    payload_root_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload_binding_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    commit_sha: str = Field(pattern=r"^[a-f0-9]{40}$")
    release_candidate: str = Field(
        pattern=(
            r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\."
            r"(0|[1-9][0-9]*)-[0-9a-f]{12}$"
        )
    )
    build_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    image_lock_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    worker_image_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    runtime_tree_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    plugins: list[_ReleaseBindingPluginModel]

    @model_validator(mode="after")
    def _exact_plugins(self) -> _ReleaseBindingModel:
        if tuple(plugin.name for plugin in self.plugins) != _PLUGIN_NAMES:
            raise ValueError("release binding plugins must be the exact ordered V1 set")
        return self


class _EvidenceDescriptorModel(_StrictModel):
    evidence_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    description: str = Field(min_length=1, max_length=240, pattern=r"^[^\x00-\x1f\x7f]+$")
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("description")
    @classmethod
    def _trimmed_description(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("evidence description must be trimmed")
        return value


class _QualificationPluginModel(_StrictModel):
    name: Literal["mysqlreader", "postgresqlreader", "mysqlwriter", "postgresqlwriter"]
    jar_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    parameter_boundary_contract_version: str = Field(pattern=r"^[1-9][0-9]*\.[0-9]+$")


class _QualificationEvidenceModel(_StrictModel):
    phase_a_e3_evidence: _EvidenceDescriptorModel
    phase_a_private_windows_evidence: _EvidenceDescriptorModel
    payload_qualification_evidence: _EvidenceDescriptorModel

    @model_validator(mode="after")
    def _unique_evidence_ids(self) -> _QualificationEvidenceModel:
        evidence_ids = (
            self.phase_a_e3_evidence.evidence_id,
            self.phase_a_private_windows_evidence.evidence_id,
            self.payload_qualification_evidence.evidence_id,
        )
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("qualification evidence IDs must be unique")
        return self


class _PluginQualificationRowModel(_StrictModel):
    reader: _QualificationPluginModel
    writer: _QualificationPluginModel
    evidence: _QualificationEvidenceModel

    @model_validator(mode="after")
    def _reader_writer_roles(self) -> _PluginQualificationRowModel:
        if not self.reader.name.endswith("reader") or not self.writer.name.endswith("writer"):
            raise ValueError("qualification row must bind one reader and one writer")
        return self


class _ImageSbomHashModel(_StrictModel):
    role: Literal["api", "egress_guard", "postgres", "web", "worker"]
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class _DependencyLicenseReviewModel(_StrictModel):
    source_sbom_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    image_sboms: list[_ImageSbomHashModel]
    license_inventory_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    conclusion: Literal["ACCEPTED_FOR_PRIVATE_PHASE_B"]

    @model_validator(mode="after")
    def _exact_image_sboms(self) -> _DependencyLicenseReviewModel:
        if tuple(item.role for item in self.image_sboms) != _IMAGE_ROLES:
            raise ValueError("dependency/license image SBOMs must be the exact ordered image set")
        return self


class _ReleaseQualificationDocument(_StrictModel):
    schema_version: Literal["1.0"]
    artifact_kind: Literal["RELEASE_QUALIFICATION"]
    authorization_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    purpose: Literal["PRIVATE_PHASE_B_QUALIFICATION"]
    issuer_key_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    issued_at: str = Field(pattern=r"Z$")
    not_before: str = Field(pattern=r"Z$")
    valid_until: str = Field(pattern=r"Z$")
    release_binding: _ReleaseBindingModel
    dependency_license_review: _DependencyLicenseReviewModel
    qualification_rows: list[_PluginQualificationRowModel] = Field(min_length=1, max_length=4)
    signature: _SignatureModel

    @model_validator(mode="after")
    def _ordered_unique_pairs(self) -> _ReleaseQualificationDocument:
        pairs = tuple((row.reader.name, row.writer.name) for row in self.qualification_rows)
        if pairs != tuple(sorted(pairs)) or len(pairs) != len(set(pairs)):
            raise ValueError("qualification rows must be sorted and unique")
        return self


@dataclass(frozen=True)
class HqaPublicKey:
    key_id: str
    public_key: bytes = field(repr=False)
    not_before: datetime
    valid_until: datetime


@dataclass(frozen=True)
class RqaPublicKey:
    """A Release Qualification Authority public key pinned by verified P."""

    key_id: str
    public_key: bytes = field(repr=False)
    not_before: datetime
    valid_until: datetime


@dataclass(frozen=True)
class PayloadBinding:
    """Non-secret P facts needed to bind a protected Phase-A runtime.

    This value only becomes available through :func:`payload_binding`, which
    first rechecks the provenance sentinel and canonical P root.  It is not a
    release certification record and it cannot authorize an ordinary user.
    """

    payload_root_sha256: str
    payload_binding_sha256: str
    commit_sha: str
    worker_image_digest: str
    datax_release: str
    runtime_sha256: str
    plugin_sha256s: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ReleasePayload:
    """A P whose raw document and caller-supplied expected root were both verified.

    Derived binding/keyring data is rebuilt from canonical P at each use and a
    process-local integrity tag rejects accidental dataclass field replacement.
    This remains an in-process safeguard, not a protected trust boundary.
    """

    payload_root_sha256: str
    _expected_payload_root_sha256: str = field(repr=False)
    _canonical_without_root: bytes = field(repr=False)
    _provenance: object = field(repr=False, compare=False)
    _integrity_tag: str = field(repr=False, compare=False)


class ExpectedHarness(NamedTuple):
    """Identity independently fixed by the protected harness, never by QH input."""

    identity: str
    environment_id: str
    environment_manifest_sha256: str
    harness_version: str


class ExpectedPluginPair(NamedTuple):
    """One exact Reader/Writer pair independently selected by a private Phase-B reader."""

    reader_name: str
    writer_name: str


@dataclass(frozen=True)
class VerifiedReleaseQualification:
    """A private Phase-B test authorization, explicitly not E4 or public release approval."""

    authorization_id: str
    payload_root_sha256: str
    issuer_key_id: str
    reader_name: str
    writer_name: str
    issued_at: datetime
    not_before: datetime
    valid_until: datetime


class QualificationNonceUse(NamedTuple):
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
    issued_at: datetime
    not_before: datetime
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


@dataclass(frozen=True)
class _ParsedPluginQualificationRow:
    reader_name: str
    reader_binding: tuple[str, str]
    writer_name: str
    writer_binding: tuple[str, str]


@dataclass(frozen=True)
class _ParsedReleaseQualification:
    authorization_id: str
    issuer_key_id: str
    issued_at: datetime
    not_before: datetime
    valid_until: datetime
    release_binding_canonical: bytes = field(repr=False)
    dependency_license_review_canonical: bytes = field(repr=False)
    rows: tuple[_ParsedPluginQualificationRow, ...]
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

    if type(expected_payload_root_sha256) is not str or not _SHA256.fullmatch(
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
    # Validate all derived P facts now, but do not retain a replaceable copy of
    # them in ReleasePayload. Consumers rebuild them from canonical P below.
    binding = _payload_binding(parsed)
    _public_payload_binding(
        parsed,
        binding_sha256=hashlib.sha256(
            _canonicalize(binding, code="RELEASE_PAYLOAD_CANONICAL_INVALID")
        ).hexdigest(),
    )
    _assert_distinct_authority_keyrings(
        _hqa_keys(parsed.hqa_keyring),
        _rqa_keys(parsed.rqa_keyring),
    )

    payload = ReleasePayload(
        payload_root_sha256=parsed.payload_root_sha256,
        _expected_payload_root_sha256=expected_payload_root_sha256,
        _canonical_without_root=canonical_without_root,
        _provenance=_PAYLOAD_PROVENANCE,
        _integrity_tag="",
    )
    return replace(payload, _integrity_tag=_release_payload_integrity_tag(payload))


def payload_binding(payload: ReleasePayload) -> PayloadBinding:
    """Return immutable non-secret runtime binding facts from a verified P.

    A caller cannot use an arbitrary similarly-shaped dataclass: this function
    repeats the same provenance/root checks used before QH verification.
    """

    document = _verify_release_payload_provenance(payload)
    binding = _payload_binding(document)
    return _public_payload_binding(
        document,
        binding_sha256=hashlib.sha256(
            _canonicalize(binding, code="RELEASE_PAYLOAD_CANONICAL_INVALID")
        ).hexdigest(),
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

    verified, nonce_use = _verified_harness_qualification_facts(
        raw,
        release_payload=release_payload,
        expected_harness=expected_harness,
        now=now,
    )
    try:
        consumed = consume_nonce(nonce_use)
    except Exception:
        raise QualificationVerificationError("QH_NONCE_LEDGER_UNAVAILABLE") from None
    if consumed is not True:
        raise QualificationVerificationError("QH_NONCE_REPLAYED")
    return verified


def inspect_harness_qualification_evidence(
    raw: bytes,
    *,
    release_payload: ReleasePayload,
    expected_harness: ExpectedHarness,
    now: datetime,
) -> VerifiedHarnessQualification:
    """Inspect a QH without consuming its nonce or granting any capability.

    This is deliberately narrower than :func:`verify_harness_qualification`:
    it is only for a protected private filesystem loader to reject malformed,
    stale, wrongly signed, or wrongly bound evidence before the future issuer
    has begun its one atomic nonce-and-grant transaction.  The returned value
    deliberately has no raw nonce and is not an authorization, a durable
    record, an E3/E4 result, or an ordinary-user execution capability.

    A future issuer must re-read and re-verify the exact QH while atomically
    consuming its nonce and writing its PAG.  It must never treat this
    inspection as a substitute for that transaction.
    """

    verified, _nonce_use = _verified_harness_qualification_facts(
        raw,
        release_payload=release_payload,
        expected_harness=expected_harness,
        now=now,
    )
    return verified


def verify_release_qualification(
    raw: bytes,
    *,
    release_payload: ReleasePayload,
    expected_pair: ExpectedPluginPair,
    now: datetime,
) -> VerifiedReleaseQualification:
    """Verify a RQA-signed QR for one protected private Phase-B pair.

    This is a parser/verification primitive only.  It neither starts DataX nor
    changes a plugin manifest, derives E4, grants ordinary-user execution, or
    reads a configurable filesystem path.  A future protected Phase-B reader
    must independently pin the QR resource through the final release manifest
    before calling this function.
    """

    payload_document = _verify_release_payload_provenance(release_payload)
    pair = _verified_plugin_pair(expected_pair)
    current_time = _normalise_release_qualification_now(now)
    qualification = _parse_release_qualification(raw)

    key = next(
        (
            item
            for item in _rqa_keys(payload_document.rqa_keyring)
            if item.key_id == qualification.issuer_key_id
        ),
        None,
    )
    if key is None:
        raise QualificationVerificationError("QR_ISSUER_KEY_UNKNOWN")
    if not (key.not_before <= qualification.issued_at <= qualification.not_before):
        raise QualificationVerificationError("QR_ISSUER_KEY_TIME_INVALID")
    if qualification.valid_until > key.valid_until:
        raise QualificationVerificationError("QR_ISSUER_KEY_TIME_INVALID")
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(
            qualification.signature,
            qualification.signature_input,
        )
    except (InvalidSignature, ValueError):
        raise QualificationVerificationError("QR_SIGNATURE_INVALID") from None

    expected_binding = _release_qualification_binding(payload_document)
    if qualification.release_binding_canonical != _canonicalize(
        expected_binding,
        code="RELEASE_PAYLOAD_CANONICAL_INVALID",
    ):
        raise QualificationVerificationError("QR_RELEASE_BINDING_MISMATCH")
    if qualification.dependency_license_review_canonical != _canonicalize(
        _dependency_license_review(payload_document),
        code="RELEASE_PAYLOAD_CANONICAL_INVALID",
    ):
        raise QualificationVerificationError("QR_DEPENDENCY_LICENSE_MISMATCH")
    row = next(
        (
            item
            for item in qualification.rows
            if (item.reader_name, item.writer_name) == pair
        ),
        None,
    )
    if row is None:
        raise QualificationVerificationError("QR_PLUGIN_PAIR_NOT_QUALIFIED")
    expected_plugins = {
        plugin.name: (
            plugin.jar.sha256,
            plugin.parameter_boundary_contract_version,
        )
        for plugin in payload_document.worker_runtime.plugins
    }
    if (
        expected_plugins.get(row.reader_name) != row.reader_binding
        or expected_plugins.get(row.writer_name) != row.writer_binding
    ):
        raise QualificationVerificationError("QR_PLUGIN_BINDING_MISMATCH")
    if not (qualification.not_before <= current_time < qualification.valid_until):
        raise QualificationVerificationError("QR_NOT_CURRENTLY_VALID")

    return VerifiedReleaseQualification(
        authorization_id=qualification.authorization_id,
        payload_root_sha256=release_payload.payload_root_sha256,
        issuer_key_id=qualification.issuer_key_id,
        reader_name=row.reader_name,
        writer_name=row.writer_name,
        issued_at=qualification.issued_at,
        not_before=qualification.not_before,
        valid_until=qualification.valid_until,
    )


def verify_harness_qualification_with_recorder[RecordedQualification](
    raw: bytes,
    *,
    release_payload: ReleasePayload,
    expected_harness: ExpectedHarness,
    now: datetime,
    record_verified: Callable[
        [VerifiedHarnessQualification, QualificationNonceUse],
        RecordedQualification,
    ],
) -> RecordedQualification:
    """Verify QH, then make one caller-owned atomic durable recording attempt.

    This private primitive exists for the future protected Phase-A issuer.  It
    deliberately does *not* call a generic nonce callback before the caller
    has prepared its exact reader/writer binding: a nonce-only write followed
    by a separate grant insert creates a crash window in which the QH is spent
    without a corresponding PAG.  The supplied recorder must therefore make
    nonce consumption and grant persistence one database transaction.

    The recorder is intentionally not wrapped or retried here.  In particular,
    an ambiguous database commit must remain visible to the protected caller;
    silently retrying could turn an uncertain issuance into a replay decision.
    No standard API, Worker, Settings, or plugin-certification path imports
    this function.
    """

    verified, nonce_use = _verified_harness_qualification_facts(
        raw,
        release_payload=release_payload,
        expected_harness=expected_harness,
        now=now,
    )
    return record_verified(verified, nonce_use)


def _verified_harness_qualification_facts(
    raw: bytes,
    *,
    release_payload: ReleasePayload,
    expected_harness: ExpectedHarness,
    now: datetime,
) -> tuple[VerifiedHarnessQualification, QualificationNonceUse]:
    """Return verified QH facts without touching a nonce ledger."""

    payload_document = _verify_release_payload_provenance(release_payload)
    expected_harness_fields = _verified_harness_fields(expected_harness)
    current_time = _normalise_now(now)
    qualification = _parse_harness_qualification(raw)

    expected_binding_canonical = _canonicalize(
        _payload_binding(payload_document),
        code="RELEASE_PAYLOAD_CANONICAL_INVALID",
    )
    hqa_keys = _hqa_keys(payload_document.hqa_keyring)

    key = next(
        (item for item in hqa_keys if item.key_id == qualification.issuer_key_id),
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

    if qualification.payload_binding_canonical != expected_binding_canonical:
        raise QualificationVerificationError("QH_PAYLOAD_BINDING_MISMATCH")
    if _verified_harness_fields(qualification.harness) != expected_harness_fields:
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
    return (
        VerifiedHarnessQualification(
        qualification_id=qualification.qualification_id,
        payload_root_sha256=release_payload.payload_root_sha256,
        issuer_key_id=qualification.issuer_key_id,
        issued_at=qualification.issued_at,
        not_before=qualification.not_before,
        valid_until=qualification.valid_until,
        ),
        nonce_use,
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


def _public_payload_binding(
    document: _ReleasePayloadDocument,
    *,
    binding_sha256: str,
) -> PayloadBinding:
    worker_reference = next(
        (image.reference for image in document.images if image.role == "worker"),
        None,
    )
    if worker_reference is None:
        # The strict model already makes this unreachable, but do not construct
        # a partial Phase-A binding if a future model changes unexpectedly.
        raise QualificationVerificationError("RELEASE_PAYLOAD_FORMAT_INVALID")
    _repository, separator, worker_digest = worker_reference.partition("@")
    if separator != "@" or not re.fullmatch(r"sha256:[a-f0-9]{64}", worker_digest):
        raise QualificationVerificationError("RELEASE_PAYLOAD_FORMAT_INVALID")
    plugins = tuple(
        (plugin.name, plugin.jar.sha256)
        for plugin in document.worker_runtime.plugins
    )
    if tuple(name for name, _digest in plugins) != _PLUGIN_NAMES:
        raise QualificationVerificationError("RELEASE_PAYLOAD_FORMAT_INVALID")
    return PayloadBinding(
        payload_root_sha256=document.payload_root_sha256,
        payload_binding_sha256=binding_sha256,
        commit_sha=document.identity.commit_sha,
        worker_image_digest=worker_digest,
        datax_release=document.worker_runtime.datax_release,
        runtime_sha256=document.worker_runtime.runtime_tree_sha256,
        plugin_sha256s=plugins,
    )


def _release_qualification_binding(document: _ReleasePayloadDocument) -> dict[str, Any]:
    """Return the complete non-secret P facts that QR must repeat exactly."""

    public_binding = _public_payload_binding(
        document,
        binding_sha256=hashlib.sha256(
            _canonicalize(_payload_binding(document), code="RELEASE_PAYLOAD_CANONICAL_INVALID")
        ).hexdigest(),
    )
    return {
        "payload_root_sha256": document.payload_root_sha256,
        "payload_binding_sha256": public_binding.payload_binding_sha256,
        "commit_sha": document.identity.commit_sha,
        "release_candidate": document.identity.release_candidate,
        "build_identity_sha256": document.artifacts.build_identity.sha256,
        "image_lock_sha256": document.artifacts.image_lock.sha256,
        "worker_image_digest": public_binding.worker_image_digest,
        "runtime_tree_sha256": document.worker_runtime.runtime_tree_sha256,
        "plugins": [
            {
                "name": plugin.name,
                "jar_sha256": plugin.jar.sha256,
                "parameter_boundary_contract_version": plugin.parameter_boundary_contract_version,
                "dependency_inventory_sha256": plugin.dependency_inventory.sha256,
                "license_review_sha256": plugin.license_review.sha256,
            }
            for plugin in document.worker_runtime.plugins
        ],
    }


def _dependency_license_review(document: _ReleasePayloadDocument) -> dict[str, Any]:
    """Return the P-bound dependency and licence facts QR must not self-assert."""

    return {
        "source_sbom_sha256": document.artifacts.source_sbom.sha256,
        "image_sboms": [
            {"role": item.role, "sha256": item.artifact.sha256}
            for item in document.artifacts.image_sboms
        ],
        "license_inventory_sha256": document.artifacts.license_inventory.sha256,
        "conclusion": "ACCEPTED_FOR_PRIVATE_PHASE_B",
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


def _rqa_keys(keyring: _RqaKeyringModel) -> tuple[RqaPublicKey, ...]:
    parsed_keys: list[RqaPublicKey] = []
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
            RqaPublicKey(
                key_id=key.key_id,
                public_key=material,
                not_before=not_before,
                valid_until=valid_until,
            )
        )
    return tuple(parsed_keys)


def _assert_distinct_authority_keyrings(
    hqa_keys: tuple[HqaPublicKey, ...],
    rqa_keys: tuple[RqaPublicKey, ...],
) -> None:
    """Reject a payload that silently makes the HQA and RQA the same authority."""

    if (
        {key.key_id for key in hqa_keys} & {key.key_id for key in rqa_keys}
        or {key.public_key for key in hqa_keys} & {key.public_key for key in rqa_keys}
    ):
        raise QualificationVerificationError("RELEASE_PAYLOAD_KEYRING_SEPARATION_INVALID")


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


def _parse_release_qualification(raw: bytes) -> _ParsedReleaseQualification:
    document = _load_canonical_json(raw, kind="RELEASE_QUALIFICATION")
    try:
        parsed = _ReleaseQualificationDocument.model_validate(document)
    except ValidationError as error:
        raise QualificationVerificationError("QR_FORMAT_INVALID") from error
    if _IDENTIFIER.fullmatch(parsed.authorization_id) is None:
        raise QualificationVerificationError("QR_FORMAT_INVALID")

    issued_at = _parse_utc_timestamp(parsed.issued_at, code="QR_TIMESTAMP_INVALID")
    not_before = _parse_utc_timestamp(parsed.not_before, code="QR_TIMESTAMP_INVALID")
    valid_until = _parse_utc_timestamp(parsed.valid_until, code="QR_TIMESTAMP_INVALID")
    if issued_at > not_before or not_before >= valid_until:
        raise QualificationVerificationError("QR_VALIDITY_WINDOW_INVALID")
    if valid_until - issued_at > timedelta(days=30):
        raise QualificationVerificationError("QR_VALIDITY_WINDOW_TOO_LONG")
    try:
        signature = base64.b64decode(parsed.signature.value_base64, validate=True)
    except (binascii.Error, ValueError):
        raise QualificationVerificationError("QR_SIGNATURE_FORMAT_INVALID") from None
    if len(signature) != 64:
        raise QualificationVerificationError("QR_SIGNATURE_FORMAT_INVALID")

    unsigned = dict(document)
    unsigned.pop("signature", None)
    return _ParsedReleaseQualification(
        authorization_id=parsed.authorization_id,
        issuer_key_id=parsed.issuer_key_id,
        issued_at=issued_at,
        not_before=not_before,
        valid_until=valid_until,
        release_binding_canonical=_canonicalize(
            parsed.release_binding.model_dump(mode="json"),
            code="QR_RELEASE_BINDING_INVALID",
        ),
        dependency_license_review_canonical=_canonicalize(
            parsed.dependency_license_review.model_dump(mode="json"),
            code="QR_DEPENDENCY_LICENSE_INVALID",
        ),
        rows=tuple(
            _ParsedPluginQualificationRow(
                reader_name=row.reader.name,
                reader_binding=(
                    row.reader.jar_sha256,
                    row.reader.parameter_boundary_contract_version,
                ),
                writer_name=row.writer.name,
                writer_binding=(
                    row.writer.jar_sha256,
                    row.writer.parameter_boundary_contract_version,
                ),
            )
            for row in parsed.qualification_rows
        ),
        signature=signature,
        signature_input=_RELEASE_QUALIFICATION_DOMAIN
        + _canonicalize(unsigned, code="QR_CANONICAL_INVALID"),
    )


def _verify_release_payload_provenance(payload: ReleasePayload) -> _ReleasePayloadDocument:
    if type(payload) is not ReleasePayload or payload._provenance is not _PAYLOAD_PROVENANCE:
        raise QualificationVerificationError("RELEASE_PAYLOAD_NOT_VERIFIED")
    if (
        not isinstance(payload._canonical_without_root, bytes)
        or type(payload.payload_root_sha256) is not str
        or _SHA256.fullmatch(payload.payload_root_sha256) is None
        or type(payload._expected_payload_root_sha256) is not str
        or _SHA256.fullmatch(payload._expected_payload_root_sha256) is None
    ):
        raise QualificationVerificationError("RELEASE_PAYLOAD_NOT_VERIFIED")
    if not isinstance(payload._integrity_tag, str) or not hmac.compare_digest(
        payload._integrity_tag,
        _release_payload_integrity_tag(payload),
    ):
        raise QualificationVerificationError("RELEASE_PAYLOAD_NOT_VERIFIED")
    computed_root = hashlib.sha256(
        _PAYLOAD_ROOT_DOMAIN + payload._canonical_without_root
    ).hexdigest()
    if computed_root != payload.payload_root_sha256:
        raise QualificationVerificationError("RELEASE_PAYLOAD_ROOT_MISMATCH")
    if payload.payload_root_sha256 != payload._expected_payload_root_sha256:
        raise QualificationVerificationError("RELEASE_PAYLOAD_EXPECTED_ROOT_MISMATCH")
    try:
        document_without_root = json.loads(
            payload._canonical_without_root.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (
        _DuplicateJsonKey,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ):
        raise QualificationVerificationError("RELEASE_PAYLOAD_NOT_VERIFIED") from None
    if not isinstance(document_without_root, dict):
        raise QualificationVerificationError("RELEASE_PAYLOAD_NOT_VERIFIED")
    _reject_excessive_json_nesting(document_without_root, kind="RELEASE_PAYLOAD")
    if (
        _canonicalize(
            document_without_root,
            code="RELEASE_PAYLOAD_NOT_VERIFIED",
        )
        != payload._canonical_without_root
    ):
        raise QualificationVerificationError("RELEASE_PAYLOAD_NOT_VERIFIED")
    try:
        document = _ReleasePayloadDocument.model_validate(
            {
                **document_without_root,
                "payload_root_sha256": payload.payload_root_sha256,
            }
        )
    except ValidationError:
        raise QualificationVerificationError("RELEASE_PAYLOAD_NOT_VERIFIED") from None
    if document.payload_root_sha256 != payload.payload_root_sha256:
        raise QualificationVerificationError("RELEASE_PAYLOAD_NOT_VERIFIED")
    try:
        _assert_distinct_authority_keyrings(
            _hqa_keys(document.hqa_keyring),
            _rqa_keys(document.rqa_keyring),
        )
    except QualificationVerificationError:
        raise QualificationVerificationError("RELEASE_PAYLOAD_NOT_VERIFIED") from None
    return document


def _release_payload_integrity_tag(payload: ReleasePayload) -> str:
    canonical = payload._canonical_without_root
    if (
        not isinstance(canonical, bytes)
        or type(payload.payload_root_sha256) is not str
        or type(payload._expected_payload_root_sha256) is not str
    ):
        return ""
    try:
        payload_root = payload.payload_root_sha256.encode("ascii")
        expected_root = payload._expected_payload_root_sha256.encode("ascii")
    except UnicodeEncodeError:
        return ""
    message = b"".join(
        (
            b"DES-RELEASE-PAYLOAD-IN-PROCESS-v1\n",
            payload_root,
            b"\n",
            expected_root,
            b"\n",
            len(canonical).to_bytes(8, "big"),
            canonical,
        )
    )
    return hmac.new(
        _RELEASE_PAYLOAD_INTEGRITY_KEY,
        message,
        hashlib.sha256,
    ).hexdigest()


def _verified_harness_fields(expected: ExpectedHarness) -> tuple[str, str, str, str]:
    if type(expected) is not ExpectedHarness:
        raise QualificationVerificationError("QH_EXPECTED_HARNESS_INVALID")
    if (
        type(expected.identity) is not str
        or _IDENTIFIER.fullmatch(expected.identity) is None
        or type(expected.environment_id) is not str
        or _IDENTIFIER.fullmatch(expected.environment_id) is None
        or type(expected.environment_manifest_sha256) is not str
        or _SHA256.fullmatch(expected.environment_manifest_sha256) is None
        or type(expected.harness_version) is not str
        or not re.fullmatch(r"^[A-Za-z0-9._+-]{1,128}$", expected.harness_version)
    ):
        raise QualificationVerificationError("QH_EXPECTED_HARNESS_INVALID")
    return (
        expected.identity,
        expected.environment_id,
        expected.environment_manifest_sha256,
        expected.harness_version,
    )


def _verified_plugin_pair(expected: ExpectedPluginPair) -> tuple[str, str]:
    if type(expected) is not ExpectedPluginPair:
        raise QualificationVerificationError("QR_EXPECTED_PLUGIN_PAIR_INVALID")
    if (
        type(expected.reader_name) is not str
        or expected.reader_name not in {"mysqlreader", "postgresqlreader"}
        or type(expected.writer_name) is not str
        or expected.writer_name not in {"mysqlwriter", "postgresqlwriter"}
    ):
        raise QualificationVerificationError("QR_EXPECTED_PLUGIN_PAIR_INVALID")
    return (expected.reader_name, expected.writer_name)


def _normalise_now(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise QualificationVerificationError("QH_CURRENT_TIME_INVALID")
    return value.astimezone(UTC)


def _normalise_release_qualification_now(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise QualificationVerificationError("QR_CURRENT_TIME_INVALID")
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
