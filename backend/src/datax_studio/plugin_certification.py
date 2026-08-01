from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Literal, Protocol

from datax_studio.api.problems import ProblemException

PluginName = Literal[
    "mysqlreader",
    "mysqlwriter",
    "postgresqlreader",
    "postgresqlwriter",
]
CertificationState = Literal[
    "SOURCE_PRESENT",
    "BUILD_VERIFIED",
    "PACKAGED",
    "CONTRACTED",
    "E3_CERTIFIED",
    "WINDOWS_E4_CERTIFIED",
    "BLOCKED",
]
EvidenceSource = Literal[
    "TRUSTED_RELEASE_ATTESTATION",
    "TEST_INJECTION",
]

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_CANDIDATE_ID = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_EVIDENCE_REF = re.compile(r"^[A-Za-z0-9._/:-]{1,300}$")
_DEPENDENCY_VALUE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
_LICENSE_PATH = re.compile(r"^[A-Za-z0-9_./-]{1,300}$")


@dataclass(frozen=True)
class CertifiedDependency:
    name: str
    version: str
    license_expression: str
    license_file: str
    redistribution_status: Literal["DOCUMENTED"] = "DOCUMENTED"


@dataclass(frozen=True)
class PluginCertificationRecord:
    """Candidate-bound evidence; a record is not trusted merely because it exists."""

    plugin_name: PluginName
    certification_state: CertificationState
    ordinary_user_executable: bool
    source: EvidenceSource
    candidate_id: str | None
    candidate_commit: str | None
    worker_image_digest: str | None
    runtime_sha256: str
    plugin_sha256: str
    e3_evidence_ref: str | None
    windows_e4_evidence_ref: str | None
    dependency_inventory_ref: str | None
    license_review_ref: str | None
    dependencies: tuple[CertifiedDependency, ...]
    valid_until: datetime | None


class JobVersionBinding(Protocol):
    datax_release: str
    runtime_sha256: str
    reader_plugin_name: str
    reader_plugin_sha256: str
    writer_plugin_name: str
    writer_plugin_sha256: str


class PluginCertificationSource(Protocol):
    current_candidate_id: str | None
    current_candidate_commit: str | None
    current_worker_image_digest: str | None

    def get_record(self, plugin_name: str) -> PluginCertificationRecord | None: ...

    def require_job_version(
        self,
        *,
        version: JobVersionBinding,
        now: datetime,
    ) -> tuple[PluginCertificationRecord, PluginCertificationRecord]: ...


class DenyAllPluginCertificationSource:
    """Production default until a trusted, signed release-attestation reader exists."""

    current_candidate_id: str | None = None
    current_candidate_commit: str | None = None
    current_worker_image_digest: str | None = None

    def get_record(self, plugin_name: str) -> PluginCertificationRecord | None:
        del plugin_name
        return None

    def require_job_version(
        self,
        *,
        version: JobVersionBinding,
        now: datetime,
    ) -> tuple[PluginCertificationRecord, PluginCertificationRecord]:
        del version, now
        raise _certification_problem(["WINDOWS_E4_EVIDENCE_MISSING"])


class ExplicitTestPluginCertificationSource:
    """Test-only dependency injection; it is never constructed from settings or env vars."""

    def __init__(
        self,
        *,
        current_candidate_id: str,
        current_candidate_commit: str,
        current_worker_image_digest: str,
        records: Mapping[str, PluginCertificationRecord],
    ) -> None:
        self.current_candidate_id = current_candidate_id
        self.current_candidate_commit = current_candidate_commit
        self.current_worker_image_digest = current_worker_image_digest
        self._records = MappingProxyType(dict(records))
        if any(record.source != "TEST_INJECTION" for record in self._records.values()):
            raise ValueError("explicit test certification accepts TEST_INJECTION evidence only")

    def get_record(self, plugin_name: str) -> PluginCertificationRecord | None:
        return self._records.get(plugin_name)

    def require_job_version(
        self,
        *,
        version: JobVersionBinding,
        now: datetime,
    ) -> tuple[PluginCertificationRecord, PluginCertificationRecord]:
        if version.datax_release != "datax_v202309":
            raise _certification_problem(["DATAX_RELEASE_MISMATCH"])
        reader = self.get_record(version.reader_plugin_name)
        writer = self.get_record(version.writer_plugin_name)
        reasons: list[str] = []
        if reader is None:
            reasons.append("READER_CERTIFICATION_MISSING")
        else:
            reasons.extend(
                certification_block_reasons(
                    reader,
                    expected_plugin_name=version.reader_plugin_name,
                    expected_plugin_sha256=version.reader_plugin_sha256,
                    expected_runtime_sha256=version.runtime_sha256,
                    current_candidate_id=self.current_candidate_id,
                    current_candidate_commit=self.current_candidate_commit,
                    current_worker_image_digest=self.current_worker_image_digest,
                    now=now,
                )
            )
        if writer is None:
            reasons.append("WRITER_CERTIFICATION_MISSING")
        else:
            reasons.extend(
                certification_block_reasons(
                    writer,
                    expected_plugin_name=version.writer_plugin_name,
                    expected_plugin_sha256=version.writer_plugin_sha256,
                    expected_runtime_sha256=version.runtime_sha256,
                    current_candidate_id=self.current_candidate_id,
                    current_candidate_commit=self.current_candidate_commit,
                    current_worker_image_digest=self.current_worker_image_digest,
                    now=now,
                )
            )
        if reader is not None and writer is not None:
            if reader.candidate_id != writer.candidate_id:
                reasons.append("PAIR_CANDIDATE_ID_MISMATCH")
            if reader.candidate_commit != writer.candidate_commit:
                reasons.append("PAIR_CANDIDATE_COMMIT_MISMATCH")
            if reader.worker_image_digest != writer.worker_image_digest:
                reasons.append("PAIR_WORKER_IMAGE_MISMATCH")
        if reasons:
            raise _certification_problem(reasons)
        assert reader is not None and writer is not None
        return reader, writer


def certification_block_reasons(
    record: PluginCertificationRecord,
    *,
    expected_plugin_name: str,
    expected_plugin_sha256: str,
    expected_runtime_sha256: str,
    current_candidate_id: str | None,
    current_candidate_commit: str | None,
    current_worker_image_digest: str | None,
    now: datetime,
) -> list[str]:
    reasons: list[str] = []
    if record.certification_state != "WINDOWS_E4_CERTIFIED":
        reasons.append("NOT_WINDOWS_E4_CERTIFIED")
    if not record.ordinary_user_executable:
        reasons.append("ORDINARY_USER_EXECUTION_NOT_APPROVED")
    if record.plugin_name != expected_plugin_name:
        reasons.append("PLUGIN_NAME_MISMATCH")
    if not _SHA256.fullmatch(record.plugin_sha256):
        reasons.append("PLUGIN_HASH_INVALID")
    elif record.plugin_sha256 != expected_plugin_sha256:
        reasons.append("PLUGIN_HASH_MISMATCH")
    if not _SHA256.fullmatch(record.runtime_sha256):
        reasons.append("RUNTIME_HASH_INVALID")
    elif record.runtime_sha256 != expected_runtime_sha256:
        reasons.append("RUNTIME_HASH_MISMATCH")
    if record.candidate_id is None or not _CANDIDATE_ID.fullmatch(record.candidate_id):
        reasons.append("CANDIDATE_ID_INVALID")
    elif record.candidate_id != current_candidate_id:
        reasons.append("CANDIDATE_ID_NOT_CURRENT")
    if record.candidate_commit is None or not _COMMIT.fullmatch(record.candidate_commit):
        reasons.append("CANDIDATE_COMMIT_INVALID")
    elif record.candidate_commit != current_candidate_commit:
        reasons.append("CANDIDATE_COMMIT_NOT_CURRENT")
    if record.worker_image_digest is None or not _IMAGE_DIGEST.fullmatch(
        record.worker_image_digest
    ):
        reasons.append("WORKER_IMAGE_DIGEST_INVALID")
    elif record.worker_image_digest != current_worker_image_digest:
        reasons.append("WORKER_IMAGE_NOT_CURRENT")
    if not record.e3_evidence_ref:
        reasons.append("E3_EVIDENCE_MISSING")
    elif not _EVIDENCE_REF.fullmatch(record.e3_evidence_ref):
        reasons.append("E3_EVIDENCE_REF_INVALID")
    if not record.windows_e4_evidence_ref:
        reasons.append("WINDOWS_E4_EVIDENCE_MISSING")
    elif not _EVIDENCE_REF.fullmatch(record.windows_e4_evidence_ref):
        reasons.append("WINDOWS_E4_EVIDENCE_REF_INVALID")
    if not record.dependency_inventory_ref or not record.dependencies:
        reasons.append("DEPENDENCY_INVENTORY_INCOMPLETE")
    elif not _EVIDENCE_REF.fullmatch(record.dependency_inventory_ref):
        reasons.append("DEPENDENCY_INVENTORY_REF_INVALID")
    if not record.license_review_ref:
        reasons.append("LICENSE_REVIEW_REQUIRED")
    elif not _EVIDENCE_REF.fullmatch(record.license_review_ref):
        reasons.append("LICENSE_REVIEW_REF_INVALID")
    dependency_keys: set[tuple[str, str]] = set()
    for dependency in record.dependencies:
        if (
            not _DEPENDENCY_VALUE.fullmatch(dependency.name)
            or not _DEPENDENCY_VALUE.fullmatch(dependency.version)
            or len(dependency.version) > 64
            or not _DEPENDENCY_VALUE.fullmatch(dependency.license_expression)
            or len(dependency.license_expression) > 128
        ):
            reasons.append("DEPENDENCY_RECORD_INVALID")
        if dependency.redistribution_status != "DOCUMENTED":
            reasons.append("DEPENDENCY_REDISTRIBUTION_NOT_DOCUMENTED")
        if (
            not _LICENSE_PATH.fullmatch(dependency.license_file)
            or dependency.license_file.startswith("/")
            or ".." in dependency.license_file.split("/")
        ):
            reasons.append("DEPENDENCY_LICENSE_PATH_INVALID")
        key = (dependency.name, dependency.version)
        if key in dependency_keys:
            reasons.append("DEPENDENCY_RECORD_DUPLICATED")
        dependency_keys.add(key)
    if record.valid_until is None:
        reasons.append("EVIDENCE_EXPIRY_MISSING")
    else:
        try:
            if _aware_utc(record.valid_until) <= _aware_utc(now):
                reasons.append("EVIDENCE_EXPIRED")
        except (AttributeError, TypeError, ValueError):
            reasons.append("EVIDENCE_TIMESTAMP_INVALID")
    return list(dict.fromkeys(reasons))


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("certification timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _certification_problem(reasons: list[str]) -> ProblemException:
    return ProblemException(
        status=409,
        code="PLUGIN_WINDOWS_E4_CERTIFICATION_REQUIRED",
        title="DataX 执行能力尚未通过 Windows E4 认证",
        detail=(
            "当前 JobVersion 的 Reader/Writer 没有与当前候选制品绑定的"
            "、在有效期内的 Windows E4 证据，系统拒绝创建或启动执行。"
        ),
        details={"block_reasons": list(dict.fromkeys(reasons))},
    )
