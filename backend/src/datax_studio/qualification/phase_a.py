"""Fail-closed Phase-A payload, harness, and job-version binding primitives.

This module deliberately does *not* implement ``PluginCertificationSource``.
It cannot create a ``WINDOWS_E4_CERTIFIED`` record, list a public plugin
capability, or alter the ordinary API/Worker/recovery gates.  A future private
Phase-A API and Worker must use these values together with the durable database
grant ledger described by ADR-0011.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Protocol

from datax_studio.release_qualification import (
    ExpectedHarness,
    PayloadBinding,
    QualificationNonceUse,
    ReleasePayload,
    VerifiedHarnessQualification,
    payload_binding,
    verify_harness_qualification,
)

_IMAGE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_HARNESS_VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
_READER_PLUGIN_NAMES = frozenset({"mysqlreader", "postgresqlreader"})
_WRITER_PLUGIN_NAMES = frozenset({"mysqlwriter", "postgresqlwriter"})
_PLUGIN_NAMES = _READER_PLUGIN_NAMES | _WRITER_PLUGIN_NAMES
_AUTHORIZATION_PROVENANCE = object()
_EXECUTION_BINDING_PROVENANCE = object()
# Deliberately process-local: persistence must be revalidated by the future
# protected ledger reader, rather than deserializing an in-process authority.
_IN_PROCESS_INTEGRITY_KEY = secrets.token_bytes(32)


class PhaseAAuthorizationError(ValueError):
    """Stable, non-secret reason why a private Phase-A gate rejected input."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class JobVersionBinding(Protocol):
    """The immutable JobVersion facts that a private grant must bind."""

    datax_release: str
    runtime_sha256: str
    reader_plugin_name: str
    reader_plugin_sha256: str
    writer_plugin_name: str
    writer_plugin_sha256: str


@dataclass(frozen=True)
class PhaseARuntimeIdentity:
    """Runtime facts measured by the private API/Worker, never taken from QH."""

    worker_image_digest: str
    datax_release: str
    runtime_sha256: str
    plugin_sha256s: Mapping[str, str]


@dataclass(frozen=True)
class PhaseAHarnessAuthorization:
    """A consumed QH bound to a verified immutable payload, not a release fact.

    Its private provenance marker plus process-local integrity tag reject
    accidental construction or field replacement outside this module. They
    are not a substitute for the future protected issuer and durable-ledger
    read boundary: Python process memory is not a trust domain.
    """

    payload_root_sha256: str
    payload_binding_sha256: str
    payload_commit_sha: str
    worker_image_digest: str
    datax_release: str
    runtime_sha256: str
    plugin_sha256s: tuple[tuple[str, str], ...]
    harness: ExpectedHarness
    qualification_id: str
    issuer_key_id: str
    nonce_sha256: str
    qh_document_sha256: str
    issued_at: datetime
    not_before: datetime
    valid_until: datetime
    _provenance: object = field(repr=False, compare=False)
    _integrity_tag: str = field(repr=False, compare=False)

    def plugin_sha256(self, plugin_name: str) -> str | None:
        return dict(self.plugin_sha256s).get(plugin_name)


@dataclass(frozen=True)
class PhaseAExecutionBinding:
    """The non-secret, immutable fields a durable private execution grant stores.

    The private provenance marker plus integrity tag only protect this
    in-process handoff. A future cross-process consumer must reconstruct an
    equivalent value from a protected durable grant lookup, not deserialize
    caller-controlled fields.
    """

    payload_root_sha256: str
    payload_binding_sha256: str
    payload_commit_sha: str
    worker_image_digest: str
    datax_release: str
    runtime_sha256: str
    reader_plugin_name: str
    reader_plugin_sha256: str
    writer_plugin_name: str
    writer_plugin_sha256: str
    harness: ExpectedHarness
    qualification_id: str
    issuer_key_id: str
    nonce_sha256: str
    qh_document_sha256: str
    issued_at: datetime
    not_before: datetime
    valid_until: datetime
    _provenance: object = field(repr=False, compare=False)
    _integrity_tag: str = field(repr=False, compare=False)


def activate_harness_authorization(
    *,
    raw_qualification: bytes,
    release_payload: ReleasePayload,
    expected_harness: ExpectedHarness,
    current_runtime: PhaseARuntimeIdentity,
    now: datetime,
    consume_nonce: Callable[[QualificationNonceUse], bool],
) -> PhaseAHarnessAuthorization:
    """Consume a QH only after binding P to the actual protected runtime.

    ``consume_nonce`` must be a durable, atomic operation.  It is intentionally
    supplied by the future protected authority rather than by Settings or a
    request body.  Standard application components must never call this
    function.
    """

    binding = payload_binding(release_payload)
    _assert_runtime_matches_payload(current_runtime=current_runtime, binding=binding)
    captured_nonce: list[QualificationNonceUse] = []

    def consume_and_capture(nonce_use: QualificationNonceUse) -> bool:
        captured_nonce.append(nonce_use)
        return consume_nonce(nonce_use)

    verified = verify_harness_qualification(
        raw_qualification,
        release_payload=release_payload,
        expected_harness=expected_harness,
        now=now,
        consume_nonce=consume_and_capture,
    )
    if len(captured_nonce) != 1:
        raise PhaseAAuthorizationError("PHASE_A_NONCE_CONSUMPTION_INVALID")
    nonce_use = captured_nonce[0]
    _assert_verified_qualification(
        verified=verified,
        nonce_use=nonce_use,
        expected_payload_root=binding.payload_root_sha256,
    )
    normalized_now = _normalise_now(now)
    if not (nonce_use.valid_until > normalized_now):
        raise PhaseAAuthorizationError("PHASE_A_QUALIFICATION_EXPIRED")
    authorization = PhaseAHarnessAuthorization(
        payload_root_sha256=binding.payload_root_sha256,
        payload_binding_sha256=binding.payload_binding_sha256,
        payload_commit_sha=binding.commit_sha,
        worker_image_digest=binding.worker_image_digest,
        datax_release=binding.datax_release,
        runtime_sha256=binding.runtime_sha256,
        plugin_sha256s=binding.plugin_sha256s,
        harness=expected_harness,
        qualification_id=verified.qualification_id,
        issuer_key_id=verified.issuer_key_id,
        nonce_sha256=_nonce_sha256(nonce_use.nonce),
        qh_document_sha256=hashlib.sha256(raw_qualification).hexdigest(),
        issued_at=verified.issued_at,
        not_before=verified.not_before,
        valid_until=nonce_use.valid_until,
        _provenance=_AUTHORIZATION_PROVENANCE,
        _integrity_tag="",
    )
    return replace(
        authorization,
        _integrity_tag=_authorization_integrity_tag(authorization),
    )


def bind_execution(
    *,
    authorization: PhaseAHarnessAuthorization,
    version: JobVersionBinding,
    current_runtime: PhaseARuntimeIdentity,
    now: datetime,
) -> PhaseAExecutionBinding:
    """Bind one private execution to the already-consumed Phase-A authority.

    The caller must persist this exact result in a private companion grant
    table.  It never mutates ``JobVersion``, public plugin records, or normal
    execution authorization.
    """

    _assert_active_authorization(authorization=authorization, now=now)
    _assert_runtime_matches_authorization(
        current_runtime=current_runtime,
        authorization=authorization,
    )
    _assert_version_matches_authorization(version=version, authorization=authorization)
    binding = PhaseAExecutionBinding(
        payload_root_sha256=authorization.payload_root_sha256,
        payload_binding_sha256=authorization.payload_binding_sha256,
        payload_commit_sha=authorization.payload_commit_sha,
        worker_image_digest=authorization.worker_image_digest,
        datax_release=authorization.datax_release,
        runtime_sha256=authorization.runtime_sha256,
        reader_plugin_name=version.reader_plugin_name,
        reader_plugin_sha256=version.reader_plugin_sha256,
        writer_plugin_name=version.writer_plugin_name,
        writer_plugin_sha256=version.writer_plugin_sha256,
        harness=authorization.harness,
        qualification_id=authorization.qualification_id,
        issuer_key_id=authorization.issuer_key_id,
        nonce_sha256=authorization.nonce_sha256,
        qh_document_sha256=authorization.qh_document_sha256,
        issued_at=authorization.issued_at,
        not_before=authorization.not_before,
        valid_until=authorization.valid_until,
        _provenance=_EXECUTION_BINDING_PROVENANCE,
        _integrity_tag="",
    )
    return replace(binding, _integrity_tag=_execution_binding_integrity_tag(binding))


def assert_execution_binding(
    *,
    binding: PhaseAExecutionBinding,
    version: JobVersionBinding,
    current_runtime: PhaseARuntimeIdentity,
    expected_harness: ExpectedHarness,
    now: datetime,
) -> None:
    """Revalidate a persisted grant before private claim/start/Popen steps."""

    _assert_binding_shape(binding)
    normalized_now = _normalise_now(now)
    if normalized_now < binding.not_before:
        raise PhaseAAuthorizationError("PHASE_A_GRANT_NOT_YET_VALID")
    if binding.valid_until <= normalized_now:
        raise PhaseAAuthorizationError("PHASE_A_GRANT_EXPIRED")
    if not _is_valid_harness(expected_harness):
        raise PhaseAAuthorizationError("PHASE_A_EXPECTED_HARNESS_INVALID")
    if _harness_integrity_fields(binding.harness) != _harness_integrity_fields(expected_harness):
        raise PhaseAAuthorizationError("PHASE_A_GRANT_HARNESS_MISMATCH")
    _assert_runtime_matches_binding(current_runtime=current_runtime, binding=binding)
    _assert_version_matches_binding(version=version, binding=binding)


def _assert_version_matches_binding(
    *, version: JobVersionBinding, binding: PhaseAExecutionBinding
) -> None:
    (
        datax_release,
        runtime_sha256,
        reader_plugin_name,
        reader_plugin_sha256,
        writer_plugin_name,
        writer_plugin_sha256,
    ) = _validated_version_fields(
        version,
        invalid_code="PHASE_A_GRANT_JOB_VERSION_INVALID",
    )
    if (
        reader_plugin_name not in _READER_PLUGIN_NAMES
        or writer_plugin_name not in _WRITER_PLUGIN_NAMES
        or datax_release != binding.datax_release
        or runtime_sha256 != binding.runtime_sha256
        or reader_plugin_name != binding.reader_plugin_name
        or reader_plugin_sha256 != binding.reader_plugin_sha256
        or writer_plugin_name != binding.writer_plugin_name
        or writer_plugin_sha256 != binding.writer_plugin_sha256
    ):
        raise PhaseAAuthorizationError("PHASE_A_GRANT_JOB_VERSION_MISMATCH")


def _assert_runtime_matches_payload(
    *,
    current_runtime: PhaseARuntimeIdentity,
    binding: object,
) -> None:
    if type(binding) is not PayloadBinding:
        raise PhaseAAuthorizationError("PHASE_A_PAYLOAD_BINDING_INVALID")
    _assert_runtime_facts(
        current_runtime=current_runtime,
        worker_image_digest=binding.worker_image_digest,
        datax_release=binding.datax_release,
        runtime_sha256=binding.runtime_sha256,
        plugin_sha256s=binding.plugin_sha256s,
        mismatch_code="PHASE_A_RUNTIME_PAYLOAD_MISMATCH",
    )


def _assert_runtime_matches_authorization(
    *, current_runtime: PhaseARuntimeIdentity, authorization: PhaseAHarnessAuthorization
) -> None:
    _assert_runtime_facts(
        current_runtime=current_runtime,
        worker_image_digest=authorization.worker_image_digest,
        datax_release=authorization.datax_release,
        runtime_sha256=authorization.runtime_sha256,
        plugin_sha256s=authorization.plugin_sha256s,
        mismatch_code="PHASE_A_RUNTIME_AUTHORIZATION_MISMATCH",
    )


def _assert_runtime_matches_binding(
    *, current_runtime: PhaseARuntimeIdentity, binding: PhaseAExecutionBinding
) -> None:
    expected_plugins = (
        (binding.reader_plugin_name, binding.reader_plugin_sha256),
        (binding.writer_plugin_name, binding.writer_plugin_sha256),
    )
    _assert_runtime_facts(
        current_runtime=current_runtime,
        worker_image_digest=binding.worker_image_digest,
        datax_release=binding.datax_release,
        runtime_sha256=binding.runtime_sha256,
        plugin_sha256s=expected_plugins,
        mismatch_code="PHASE_A_RUNTIME_GRANT_MISMATCH",
    )


def _assert_runtime_facts(
    *,
    current_runtime: PhaseARuntimeIdentity,
    worker_image_digest: str,
    datax_release: str,
    runtime_sha256: str,
    plugin_sha256s: tuple[tuple[str, str], ...],
    mismatch_code: str,
) -> None:
    if type(current_runtime) is not PhaseARuntimeIdentity:
        raise PhaseAAuthorizationError("PHASE_A_RUNTIME_IDENTITY_INVALID")
    if (
        type(current_runtime.worker_image_digest) is not str
        or _IMAGE_DIGEST.fullmatch(current_runtime.worker_image_digest) is None
        or type(current_runtime.runtime_sha256) is not str
        or _SHA256.fullmatch(current_runtime.runtime_sha256) is None
        or type(current_runtime.datax_release) is not str
        or type(current_runtime.plugin_sha256s) is not dict
    ):
        raise PhaseAAuthorizationError("PHASE_A_RUNTIME_IDENTITY_INVALID")
    runtime_plugins = tuple(current_runtime.plugin_sha256s.items())
    if (
        len(runtime_plugins) != len(_PLUGIN_NAMES)
        or any(
            type(name) is not str
            or name not in _PLUGIN_NAMES
            or type(value) is not str
            or _SHA256.fullmatch(value) is None
            for name, value in runtime_plugins
        )
        or {name for name, _value in runtime_plugins} != _PLUGIN_NAMES
    ):
        raise PhaseAAuthorizationError("PHASE_A_RUNTIME_IDENTITY_INVALID")
    runtime_plugins_by_name = dict(runtime_plugins)
    if (
        current_runtime.worker_image_digest != worker_image_digest
        or current_runtime.datax_release != datax_release
        or current_runtime.runtime_sha256 != runtime_sha256
        or any(
            runtime_plugins_by_name.get(name) != digest
            for name, digest in plugin_sha256s
        )
    ):
        raise PhaseAAuthorizationError(mismatch_code)


def _assert_version_matches_authorization(
    *, version: JobVersionBinding, authorization: PhaseAHarnessAuthorization
) -> None:
    (
        datax_release,
        runtime_sha256,
        reader_plugin_name,
        reader_plugin_sha256,
        writer_plugin_name,
        writer_plugin_sha256,
    ) = _validated_version_fields(version, invalid_code="PHASE_A_JOB_VERSION_INVALID")
    plugins = dict(authorization.plugin_sha256s)
    if (
        datax_release != authorization.datax_release
        or runtime_sha256 != authorization.runtime_sha256
        or reader_plugin_name not in _READER_PLUGIN_NAMES
        or writer_plugin_name not in _WRITER_PLUGIN_NAMES
        or reader_plugin_sha256 != plugins.get(reader_plugin_name)
        or writer_plugin_sha256 != plugins.get(writer_plugin_name)
    ):
        raise PhaseAAuthorizationError("PHASE_A_JOB_VERSION_MISMATCH")


def _validated_version_fields(
    version: JobVersionBinding,
    *,
    invalid_code: str,
) -> tuple[str, str, str, str, str, str]:
    """Read the untrusted JobVersion view once and require exact builtin facts."""

    try:
        fields = (
            version.datax_release,
            version.runtime_sha256,
            version.reader_plugin_name,
            version.reader_plugin_sha256,
            version.writer_plugin_name,
            version.writer_plugin_sha256,
        )
    except Exception as error:
        raise PhaseAAuthorizationError(invalid_code) from error
    if any(type(value) is not str for value in fields):
        raise PhaseAAuthorizationError(invalid_code)
    return fields


def _assert_active_authorization(
    *, authorization: PhaseAHarnessAuthorization, now: datetime
) -> None:
    _assert_binding_shape(authorization)
    normalized_now = _normalise_now(now)
    if normalized_now < authorization.not_before:
        raise PhaseAAuthorizationError("PHASE_A_QUALIFICATION_NOT_YET_VALID")
    if authorization.valid_until <= normalized_now:
        raise PhaseAAuthorizationError("PHASE_A_QUALIFICATION_EXPIRED")


def _assert_binding_shape(value: object) -> None:
    if type(value) is PhaseAHarnessAuthorization:
        if value._provenance is not _AUTHORIZATION_PROVENANCE:
            raise PhaseAAuthorizationError("PHASE_A_GRANT_INVALID")
        plugin_sha256s = value.plugin_sha256s
        nonce_sha256 = value.nonce_sha256
        qh_document_sha256 = value.qh_document_sha256
        root = value.payload_root_sha256
        payload_binding_sha256 = value.payload_binding_sha256
        commit = value.payload_commit_sha
        digest = value.worker_image_digest
        runtime_sha256 = value.runtime_sha256
        datax_release = value.datax_release
        harness = value.harness
        qualification_id = value.qualification_id
        issuer_key_id = value.issuer_key_id
        issued_at = value.issued_at
        not_before = value.not_before
        valid_until = value.valid_until
    elif type(value) is PhaseAExecutionBinding:
        if value._provenance is not _EXECUTION_BINDING_PROVENANCE:
            raise PhaseAAuthorizationError("PHASE_A_GRANT_INVALID")
        plugin_sha256s = (
            (value.reader_plugin_name, value.reader_plugin_sha256),
            (value.writer_plugin_name, value.writer_plugin_sha256),
        )
        nonce_sha256 = value.nonce_sha256
        qh_document_sha256 = value.qh_document_sha256
        root = value.payload_root_sha256
        payload_binding_sha256 = value.payload_binding_sha256
        commit = value.payload_commit_sha
        digest = value.worker_image_digest
        runtime_sha256 = value.runtime_sha256
        datax_release = value.datax_release
        harness = value.harness
        qualification_id = value.qualification_id
        issuer_key_id = value.issuer_key_id
        issued_at = value.issued_at
        not_before = value.not_before
        valid_until = value.valid_until
    else:
        raise PhaseAAuthorizationError("PHASE_A_GRANT_INVALID")
    if (
        type(root) is not str
        or _SHA256.fullmatch(root) is None
        or type(payload_binding_sha256) is not str
        or _SHA256.fullmatch(payload_binding_sha256) is None
        or type(commit) is not str
        or not re.fullmatch(r"[a-f0-9]{40}", commit)
        or type(digest) is not str
        or _IMAGE_DIGEST.fullmatch(digest) is None
        or type(runtime_sha256) is not str
        or _SHA256.fullmatch(runtime_sha256) is None
        or type(nonce_sha256) is not str
        or _SHA256.fullmatch(nonce_sha256) is None
        or type(qh_document_sha256) is not str
        or _SHA256.fullmatch(qh_document_sha256) is None
        or datax_release != "datax_v202309"
        or not _is_valid_harness(harness)
        or type(qualification_id) is not str
        or _IDENTIFIER.fullmatch(qualification_id) is None
        or type(issuer_key_id) is not str
        or _IDENTIFIER.fullmatch(issuer_key_id) is None
        or type(issued_at) is not datetime
        or issued_at.tzinfo is None
        or issued_at.utcoffset() is None
        or type(not_before) is not datetime
        or not_before.tzinfo is None
        or not_before.utcoffset() is None
        or type(valid_until) is not datetime
        or valid_until.tzinfo is None
        or valid_until.utcoffset() is None
        or issued_at > not_before
        or not_before >= valid_until
        or not isinstance(plugin_sha256s, tuple)
        or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or type(item[0]) is not str
            or item[0] not in _PLUGIN_NAMES
            or type(item[1]) is not str
            or _SHA256.fullmatch(item[1]) is None
            for item in plugin_sha256s
        )
    ):
        raise PhaseAAuthorizationError("PHASE_A_GRANT_INVALID")
    if type(value) is PhaseAExecutionBinding and (
        value.reader_plugin_name not in _READER_PLUGIN_NAMES
        or value.writer_plugin_name not in _WRITER_PLUGIN_NAMES
    ):
        raise PhaseAAuthorizationError("PHASE_A_GRANT_INVALID")
    expected_integrity_tag = (
        _authorization_integrity_tag(value)
        if type(value) is PhaseAHarnessAuthorization
        else _execution_binding_integrity_tag(value)
    )
    if not isinstance(value._integrity_tag, str) or not hmac.compare_digest(
        value._integrity_tag,
        expected_integrity_tag,
    ):
        raise PhaseAAuthorizationError("PHASE_A_GRANT_INVALID")


def _authorization_integrity_tag(value: PhaseAHarnessAuthorization) -> str:
    return _integrity_tag(
        {
            "kind": "authorization",
            "payload_root_sha256": value.payload_root_sha256,
            "payload_binding_sha256": value.payload_binding_sha256,
            "payload_commit_sha": value.payload_commit_sha,
            "worker_image_digest": value.worker_image_digest,
            "datax_release": value.datax_release,
            "runtime_sha256": value.runtime_sha256,
            "plugin_sha256s": list(value.plugin_sha256s),
            "harness": _harness_integrity_fields(value.harness),
            "qualification_id": value.qualification_id,
            "issuer_key_id": value.issuer_key_id,
            "nonce_sha256": value.nonce_sha256,
            "qh_document_sha256": value.qh_document_sha256,
            "issued_at": _utc_integrity_timestamp(value.issued_at),
            "not_before": _utc_integrity_timestamp(value.not_before),
            "valid_until": _utc_integrity_timestamp(value.valid_until),
        }
    )


def _execution_binding_integrity_tag(value: PhaseAExecutionBinding) -> str:
    return _integrity_tag(
        {
            "kind": "execution-binding",
            "payload_root_sha256": value.payload_root_sha256,
            "payload_binding_sha256": value.payload_binding_sha256,
            "payload_commit_sha": value.payload_commit_sha,
            "worker_image_digest": value.worker_image_digest,
            "datax_release": value.datax_release,
            "runtime_sha256": value.runtime_sha256,
            "reader_plugin_name": value.reader_plugin_name,
            "reader_plugin_sha256": value.reader_plugin_sha256,
            "writer_plugin_name": value.writer_plugin_name,
            "writer_plugin_sha256": value.writer_plugin_sha256,
            "harness": _harness_integrity_fields(value.harness),
            "qualification_id": value.qualification_id,
            "issuer_key_id": value.issuer_key_id,
            "nonce_sha256": value.nonce_sha256,
            "qh_document_sha256": value.qh_document_sha256,
            "issued_at": _utc_integrity_timestamp(value.issued_at),
            "not_before": _utc_integrity_timestamp(value.not_before),
            "valid_until": _utc_integrity_timestamp(value.valid_until),
        }
    )


def _integrity_tag(value: dict[str, object]) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hmac.new(_IN_PROCESS_INTEGRITY_KEY, canonical, hashlib.sha256).hexdigest()


def _harness_integrity_fields(value: ExpectedHarness) -> dict[str, str]:
    return {
        "identity": value.identity,
        "environment_id": value.environment_id,
        "environment_manifest_sha256": value.environment_manifest_sha256,
        "harness_version": value.harness_version,
    }


def _is_valid_harness(value: object) -> bool:
    return (
        type(value) is ExpectedHarness
        and type(value.identity) is str
        and _IDENTIFIER.fullmatch(value.identity) is not None
        and type(value.environment_id) is str
        and _IDENTIFIER.fullmatch(value.environment_id) is not None
        and type(value.environment_manifest_sha256) is str
        and _SHA256.fullmatch(value.environment_manifest_sha256) is not None
        and type(value.harness_version) is str
        and _HARNESS_VERSION.fullmatch(value.harness_version) is not None
    )


def _utc_integrity_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        return "INVALID"
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _assert_verified_qualification(
    *,
    verified: VerifiedHarnessQualification,
    nonce_use: QualificationNonceUse,
    expected_payload_root: str,
) -> None:
    if (
        verified.payload_root_sha256 != expected_payload_root
        or nonce_use.payload_root_sha256 != expected_payload_root
        or verified.qualification_id != nonce_use.qualification_id
        or verified.issuer_key_id != nonce_use.issuer_key_id
        or verified.issued_at > verified.not_before
        or verified.valid_until != nonce_use.valid_until
    ):
        raise PhaseAAuthorizationError("PHASE_A_QUALIFICATION_BINDING_INVALID")


def _normalise_now(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise PhaseAAuthorizationError("PHASE_A_CURRENT_TIME_INVALID")
    return value.astimezone(UTC)


def _nonce_sha256(nonce: str) -> str:
    if type(nonce) is not str or not nonce.isascii():
        raise PhaseAAuthorizationError("PHASE_A_NONCE_INVALID")
    return hashlib.sha256(nonce.encode("ascii")).hexdigest()
