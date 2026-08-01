from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProjectStatus(StrEnum):
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class ProjectCreate(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    slug: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]{2,63}$",
    )
    description: str | None = Field(default=None, max_length=1000)


class ProjectPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    status: Literal[ProjectStatus.ARCHIVED] | None = None

    @model_validator(mode="after")
    def require_change(self) -> ProjectPatch:
        if not self.model_fields_set:
            raise ValueError("at least one field is required")
        return self


class ProjectResponse(StrictModel):
    id: UUID
    organization_id: UUID
    name: str
    slug: str
    description: str | None
    status: ProjectStatus
    row_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime


class ProjectPage(StrictModel):
    items: list[ProjectResponse]
    next_cursor: str | None
    has_more: bool


ProcessStateValue = Literal[
    "QUEUED",
    "STARTING",
    "RUNNING",
    "VERIFYING",
    "CANCEL_REQUESTED",
    "SUCCEEDED",
    "FAILED",
    "TIMED_OUT",
    "CANCELED",
    "LOST",
]
VerificationStateValue = Literal[
    "NOT_STARTED",
    "VERIFYING",
    "PASSED",
    "FAILED",
    "INCONCLUSIVE",
]
DataEffectValue = Literal["NONE", "POSSIBLE", "CONFIRMED", "UNKNOWN"]


class DashboardWindow(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_: datetime = Field(alias="from")
    to: datetime


class DashboardJobCounts(StrictModel):
    total: int = Field(ge=0)
    draft: int = Field(ge=0)
    valid: int = Field(ge=0)
    published: int = Field(ge=0)
    archived: int = Field(ge=0)
    executable: int = Field(ge=0)


class DashboardExecutionCounts(StrictModel):
    QUEUED: int = Field(ge=0)
    STARTING: int = Field(ge=0)
    RUNNING: int = Field(ge=0)
    VERIFYING: int = Field(ge=0)
    CANCEL_REQUESTED: int = Field(ge=0)
    SUCCEEDED: int = Field(ge=0)
    FAILED: int = Field(ge=0)
    TIMED_OUT: int = Field(ge=0)
    CANCELED: int = Field(ge=0)
    LOST: int = Field(ge=0)


class DashboardVerificationCounts(StrictModel):
    NOT_STARTED: int = Field(ge=0)
    VERIFYING: int = Field(ge=0)
    PASSED: int = Field(ge=0)
    FAILED: int = Field(ge=0)
    INCONCLUSIVE: int = Field(ge=0)


class DashboardDataEffectCounts(StrictModel):
    NONE: int = Field(ge=0)
    POSSIBLE: int = Field(ge=0)
    CONFIRMED: int = Field(ge=0)
    UNKNOWN: int = Field(ge=0)


class DashboardSuccessRate(StrictModel):
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    ratio: float | None = Field(default=None, ge=0, le=1)


class DashboardVerifiedRecords(StrictModel):
    value: int = Field(ge=0)
    complete: bool
    missing_verification_count: int = Field(ge=0)


class DashboardExecutionItem(StrictModel):
    execution_id: UUID
    job_id: UUID
    job_version_id: UUID
    job_name: str = Field(min_length=1, max_length=128)
    process_state: ProcessStateValue
    data_effect: DataEffectValue
    verification_state: VerificationStateValue
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    failure_code: str | None = Field(default=None, max_length=64)


class DashboardTrendBucket(StrictModel):
    bucket_start: datetime
    bucket_end: datetime
    process_counts: DashboardExecutionCounts
    verification_counts: DashboardVerificationCounts


class DashboardRuntime(StrictModel):
    worker_online: bool
    runtime_ready: bool
    oracle_ready: bool
    datax_release: Literal["datax_v202309"] | None
    version_match: bool


class DashboardDrilldownFilters(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_: datetime | None = Field(alias="from")
    to: datetime | None
    process_states: list[ProcessStateValue] = Field(max_length=10)
    verification_states: list[VerificationStateValue] = Field(max_length=5)
    data_effects: list[DataEffectValue] = Field(max_length=4)
    exclude_job_status: Literal["DRAFT", "VALID", "PUBLISHED", "ARCHIVED"] | None
    has_published_version: bool | None
    unresolved_failure: bool | None


class DashboardDrilldown(StrictModel):
    metric_key: Literal[
        "executable_jobs",
        "all_executions",
        "queued",
        "running",
        "succeeded",
        "failed",
        "timed_out",
        "lost",
        "canceled",
        "unresolved_failures",
    ]
    resource: Literal["JOBS", "EXECUTIONS"]
    path: str = Field(
        pattern=r"^/api/v1/projects/[0-9a-fA-F-]+/(jobs|executions)$"
    )
    filters: DashboardDrilldownFilters


class DashboardResponse(StrictModel):
    project_id: UUID
    window: DashboardWindow
    job_counts: DashboardJobCounts
    execution_total: int = Field(ge=0)
    execution_state_counts: DashboardExecutionCounts
    verification_state_counts: DashboardVerificationCounts
    data_effect_counts: DashboardDataEffectCounts
    success_rate: DashboardSuccessRate
    unresolved_failure_count: int = Field(ge=0)
    verified_records: DashboardVerifiedRecords
    recent_executions: list[DashboardExecutionItem] = Field(max_length=10)
    recent_failures: list[DashboardExecutionItem] = Field(max_length=10)
    trend: list[DashboardTrendBucket] = Field(max_length=31)
    runtime: DashboardRuntime
    drilldowns: list[DashboardDrilldown] = Field(min_length=1)
    generated_at: datetime


class Engine(StrEnum):
    MYSQL_8 = "MYSQL_8"
    POSTGRESQL_15 = "POSTGRESQL_15"


_PLUGIN_MANIFEST_IDENTITIES: dict[
    tuple[str, str],
    tuple[str, str, str, str],
] = {
    ("MYSQL_8", "READER"): (
        "mysqlreader",
        "datax/plugin/reader/mysqlreader/mysqlreader-0.0.1-SNAPSHOT.jar",
        "c4ffc40c90af4068999178ac7297bb2066de59b8dccfa6e8e956b48327487206",
        "86ef9813bfc558048a99e32ffaf4889a48f2f082b0f692dc73770f5385161e8f",
    ),
    ("MYSQL_8", "WRITER"): (
        "mysqlwriter",
        "datax/plugin/writer/mysqlwriter/mysqlwriter-0.0.1-SNAPSHOT.jar",
        "b83fe2a8eb0d1e535b84914e5fa169722bd085686eb11d63841e92a6d7cf1b2c",
        "2c5914e3625f3c32e79d661407ec4644e94905037c78e1aa21391e0174c2d3ed",
    ),
    ("POSTGRESQL_15", "READER"): (
        "postgresqlreader",
        "datax/plugin/reader/postgresqlreader/postgresqlreader-0.0.1-SNAPSHOT.jar",
        "f14129fe23f6ca90bfc36b3c3bf64ff8d53288053af26e666411dde47211a835",
        "5f298fb97165625ae5de9c32cb8454128feaa9c7ef8856f943f7683191291b32",
    ),
    ("POSTGRESQL_15", "WRITER"): (
        "postgresqlwriter",
        "datax/plugin/writer/postgresqlwriter/postgresqlwriter-0.0.1-SNAPSHOT.jar",
        "d29dcd149b37c269e8e741184172a69ce80cd6ffc69503440fdd9d4afe49e4c4",
        "1ea3e7ef4deebb90b36e4c7b1cb1e91852abbe9d6db0d52eee7a42fa037589f6",
    ),
}


class HostKind(StrEnum):
    EXACT_FQDN = "EXACT_FQDN"
    EXACT_IP = "EXACT_IP"


class EndpointPolicyCreate(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    engine: Engine
    host_kind: HostKind
    host_value: str = Field(min_length=1, max_length=253)
    allowed_cidrs: list[str] = Field(min_length=1, max_length=64)
    allowed_ports: list[int] = Field(min_length=1, max_length=64)
    tls_required: bool
    dns_ttl_ceiling_seconds: int = Field(ge=1, le=3600)


class EndpointPolicyRevisionResponse(StrictModel):
    id: UUID
    endpoint_policy_id: UUID
    revision_no: int = Field(ge=1)
    engine: Engine
    host_kind: HostKind
    host_value: str
    allowed_cidrs: list[str]
    allowed_ports: list[int]
    tls_required: bool
    dns_ttl_ceiling_seconds: int
    resolver_policy_version: str
    egress_policy_version: str
    policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_by: UUID
    created_at: datetime


class EndpointPolicyResponse(StrictModel):
    id: UUID
    organization_id: UUID
    name: str
    current_revision_id: UUID
    current_revision_no: int
    current_revision: EndpointPolicyRevisionResponse
    status: Literal["ACTIVE", "DISABLED"]
    row_version: int = Field(ge=1)


class EndpointPolicyPage(StrictModel):
    items: list[EndpointPolicyResponse]
    next_cursor: str | None
    has_more: bool


class PluginArtifact(StrictModel):
    relative_path: str = Field(
        min_length=1,
        max_length=300,
        pattern=r"^[A-Za-z0-9_./-]+\.jar$",
    )
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("relative_path")
    @classmethod
    def require_contained_relative_path(cls, value: str) -> str:
        if value.startswith("/") or ".." in value.split("/"):
            raise ValueError("plugin artifact must be a contained relative path")
        return value


class PluginRuntime(StrictModel):
    jdk_major: Literal[8]
    python_major: Literal[3]


class PluginUpstream(StrictModel):
    repository: Literal["https://github.com/alibaba/DataX.git"]
    tag: Literal["datax_v202309"]
    commit: Literal["9a1f88751e24314b083a74f1b83ef56d69ce98bd"]
    tree: Literal["534508f96331c4b9f3737ea4e8294cc56aedc67d"]
    module: Literal[
        "mysqlreader",
        "mysqlwriter",
        "postgresqlreader",
        "postgresqlwriter",
    ]
    module_pom_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    plugin_json_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class PluginDependency(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    license_expression: str = Field(min_length=1, max_length=128)
    license_file: str = Field(
        min_length=1,
        max_length=300,
        pattern=r"^[A-Za-z0-9_./-]+$",
    )
    redistribution_status: Literal[
        "DOCUMENTED",
        "REVIEW_REQUIRED",
        "BLOCKED",
    ]

    @field_validator("license_file")
    @classmethod
    def require_contained_license_path(cls, value: str) -> str:
        if value.startswith("/") or ".." in value.split("/"):
            raise ValueError(
                "dependency license_file must be a contained relative path"
            )
        return value


class PluginSupplyChain(StrictModel):
    dependency_inventory_status: Literal["COMPLETE", "INCOMPLETE", "BLOCKED"]
    license_review_status: Literal["CLEARED", "REVIEW_REQUIRED", "BLOCKED"]
    dependency_inventory_ref: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9._/:-]{1,300}$",
    )
    license_review_ref: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9._/:-]{1,300}$",
    )
    dependencies: list[PluginDependency] = Field(default_factory=list, max_length=64)


class PluginAccess(StrictModel):
    network_scope: Literal["APPROVED_DATABASE_ENDPOINT_ONLY"]
    filesystem_scope: Literal["PRIVATE_RUNTIME_ONLY"]
    allows_arbitrary_sql: Literal[False]
    allows_host_paths: Literal[False]
    allows_shell: Literal[False]
    allows_user_plugins: Literal[False]


class PluginOracle(StrictModel):
    kind: Literal["RELATIONAL_MULTISET_V1"]
    schema_version: Literal["1.0"]
    required_for_e3: Literal[True]


class PluginEvidence(StrictModel):
    source: Literal[
        "CURRENT_RUNTIME_ATTESTATION",
        "TRUSTED_RELEASE_ATTESTATION",
    ]
    candidate_id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9._-]{8,128}$",
    )
    candidate_commit: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{40}$",
    )
    worker_image_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    runtime_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    e3_evidence_ref: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9._/:-]{1,300}$",
    )
    windows_e4_evidence_ref: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9._/:-]{1,300}$",
    )
    valid_until: datetime | None = None

    @field_validator("valid_until")
    @classmethod
    def require_aware_valid_until(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("plugin evidence valid_until must be timezone-aware")
        return value


class PluginFieldConstraints(StrictModel):
    minimum: int | None = None
    maximum: int | None = None
    min_length: int | None = Field(default=None, ge=0)
    max_length: int | None = Field(default=None, ge=1)
    pattern: str | None = Field(default=None, max_length=256)


class PluginConnectionField(StrictModel):
    key: Literal[
        "host",
        "port",
        "database_name",
        "default_schema",
        "username",
        "password",
        "ssl_mode",
    ]
    label: str = Field(min_length=1, max_length=64)
    value_type: Literal["STRING", "INTEGER", "SECRET", "ENUM"]
    required: bool
    sensitive: bool
    default: str | int | bool | None = None
    enum_values: list[str] = Field(default_factory=list, max_length=16)
    constraints: PluginFieldConstraints = Field(
        default_factory=PluginFieldConstraints,
    )


class PluginCapabilities(StrictModel):
    schema_introspection: Literal[True]
    full_table_selection: Literal[True]
    column_selection: Literal[True]
    direct_mapping_only: Literal[True]
    target_table_must_exist: Literal[True]
    write_modes: list[Literal["INSERT"]] = Field(max_length=1)
    supports_free_sql: Literal[False]
    supports_pre_sql: Literal[False]
    supports_post_sql: Literal[False]
    supports_transformer: Literal[False]
    supports_custom_parameters: Literal[False]


class PluginManifest(StrictModel):
    schema_version: Literal["2.0"]
    name: str = Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")
    display_name: str = Field(min_length=1, max_length=128)
    engine: Engine
    direction: Literal["READER", "WRITER"]
    datax_plugin_name: Literal[
        "mysqlreader",
        "mysqlwriter",
        "postgresqlreader",
        "postgresqlwriter",
    ]
    datax_release: Literal["datax_v202309"]
    upstream: PluginUpstream
    artifact: PluginArtifact
    runtime: PluginRuntime
    supply_chain: PluginSupplyChain
    connection_fields: list[PluginConnectionField] = Field(
        min_length=6,
        max_length=8,
    )
    capabilities: PluginCapabilities
    access: PluginAccess
    oracle: PluginOracle
    certification_state: Literal[
        "SOURCE_PRESENT",
        "BUILD_VERIFIED",
        "PACKAGED",
        "CONTRACTED",
        "E3_CERTIFIED",
        "WINDOWS_E4_CERTIFIED",
        "BLOCKED",
    ]
    ordinary_user_executable: bool
    evidence: PluginEvidence
    block_reasons: list[str] = Field(max_length=32)

    @model_validator(mode="after")
    def require_honest_certification_state(self) -> PluginManifest:
        (
            expected_name,
            expected_artifact_path,
            expected_pom_sha256,
            expected_plugin_json_sha256,
        ) = _PLUGIN_MANIFEST_IDENTITIES[(self.engine.value, self.direction)]
        if (
            self.name,
            self.datax_plugin_name,
            self.upstream.module,
            self.artifact.relative_path,
            self.upstream.module_pom_sha256,
            self.upstream.plugin_json_sha256,
        ) != (
            expected_name,
            expected_name,
            expected_name,
            expected_artifact_path,
            expected_pom_sha256,
            expected_plugin_json_sha256,
        ):
            raise ValueError(
                "plugin identity must match the locked engine/direction upstream mapping"
            )
        if self.certification_state == "WINDOWS_E4_CERTIFIED":
            if not self.ordinary_user_executable or self.block_reasons:
                raise ValueError(
                    "Windows E4 capability must be executable and unblocked"
                )
            if (
                self.supply_chain.dependency_inventory_status != "COMPLETE"
                or self.supply_chain.license_review_status != "CLEARED"
                or self.supply_chain.dependency_inventory_ref is None
                or self.supply_chain.license_review_ref is None
                or not self.supply_chain.dependencies
                or any(
                    dependency.redistribution_status != "DOCUMENTED"
                    for dependency in self.supply_chain.dependencies
                )
            ):
                raise ValueError(
                    "Windows E4 capability requires cleared supply-chain review"
                )
            if (
                self.evidence.source != "TRUSTED_RELEASE_ATTESTATION"
                or self.evidence.candidate_id is None
                or self.evidence.candidate_commit is None
                or self.evidence.worker_image_digest is None
                or self.evidence.e3_evidence_ref is None
                or self.evidence.windows_e4_evidence_ref is None
                or self.evidence.valid_until is None
            ):
                raise ValueError(
                    "Windows E4 capability requires complete candidate evidence"
                )
        elif self.ordinary_user_executable or not self.block_reasons:
            raise ValueError("non-E4 capability must be blocked for ordinary users")
        if any(
            not re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", item)
            for item in self.block_reasons
        ):
            raise ValueError("plugin block reasons must be stable uppercase codes")
        return self


class PluginPage(StrictModel):
    items: list[PluginManifest] = Field(min_length=4, max_length=4)


class TableReference(StrictModel):
    schema_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[^\x00-\x1f\x7f/\\]+$",
    )
    table_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[^\x00-\x1f\x7f/\\]+$",
    )


class JobEndpoint(StrictModel):
    datasource_id: UUID
    datasource_revision_id: UUID
    plugin_name: Literal[
        "mysqlreader",
        "postgresqlreader",
        "mysqlwriter",
        "postgresqlwriter",
    ]
    table: TableReference


class ColumnMapping(StrictModel):
    source_column: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[^\x00-\x1f\x7f/\\]+$",
    )
    source_ordinal: int = Field(ge=1, le=65535)
    source_type: str = Field(min_length=1, max_length=128)
    source_nullable: bool
    target_column: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[^\x00-\x1f\x7f/\\]+$",
    )
    target_ordinal: int = Field(ge=1, le=65535)
    target_type: str = Field(min_length=1, max_length=128)
    target_nullable: bool
    compatibility: Literal["EXACT", "WIDENING"]
    oracle_logical_type: Literal[
        "INTEGER",
        "DECIMAL",
        "TEXT",
        "BOOLEAN",
        "DATE",
        "TIME",
        "TIMESTAMP",
        "BINARY",
    ]


class DirtyDataLimit(StrictModel):
    record_count: Literal[0]
    percentage: Literal[0]


class WritePolicy(StrictModel):
    mode: Literal["INSERT"]
    target_table_must_exist: Literal[True]
    target_table_must_be_empty: Literal[True]
    platform_may_mutate_target_before_run: Literal[False]


class ExecutionPolicy(StrictModel):
    channel: int = Field(default=1, ge=1, le=16)
    timeout_seconds: int = Field(default=3600, ge=60, le=604_800)
    dirty_data_limit: DirtyDataLimit


class JobSpecV1(StrictModel):
    schema_version: Literal["1.0"]
    source: JobEndpoint
    target: JobEndpoint
    selection_mode: Literal["ALL_COLUMNS", "SELECTED_COLUMNS"]
    mappings: list[ColumnMapping] = Field(min_length=1, max_length=2048)
    source_consistency_mode: Literal["OPERATOR_QUIESCED"]
    target_precondition: Literal["EMPTY_AND_VERIFIABLE"]
    write_semantics: Literal["INSERT_ONLY_ONCE"]
    duplicate_policy: Literal["REJECT_NONEMPTY_TARGET"]
    partial_write_policy: Literal["MANUAL_REMEDIATE"]
    write_policy: WritePolicy
    execution_policy: ExecutionPolicy

    @model_validator(mode="after")
    def validate_v1_shape(self) -> JobSpecV1:
        if self.source.plugin_name not in {"mysqlreader", "postgresqlreader"}:
            raise ValueError("source plugin must be a certified reader")
        if self.target.plugin_name not in {"mysqlwriter", "postgresqlwriter"}:
            raise ValueError("target plugin must be a certified writer")
        source_columns = [item.source_column for item in self.mappings]
        target_columns = [item.target_column for item in self.mappings]
        if len(set(source_columns)) != len(source_columns):
            raise ValueError("source columns must be unique")
        if len(set(target_columns)) != len(target_columns):
            raise ValueError("target columns must be unique")
        if any(item.source_nullable and not item.target_nullable for item in self.mappings):
            raise ValueError("nullable source cannot map to non-nullable target")
        return self


class JobCreate(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    draft_spec: JobSpecV1


class JobPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    draft_spec: JobSpecV1 | None = None
    status: Literal["ARCHIVED"] | None = None

    @model_validator(mode="after")
    def require_change(self) -> JobPatch:
        if not self.model_fields_set:
            raise ValueError("at least one field is required")
        return self


class JobResponse(StrictModel):
    id: UUID
    project_id: UUID
    name: str
    description: str | None
    status: Literal["DRAFT", "VALID", "PUBLISHED", "ARCHIVED"]
    draft_spec: JobSpecV1
    draft_spec_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    validated_spec_hash: str | None
    latest_published_version_id: UUID | None
    latest_published_version_no: int | None = Field(default=None, ge=1)
    latest_published_reader_plugin: Literal[
        "mysqlreader", "postgresqlreader"
    ] | None
    latest_published_writer_plugin: Literal[
        "mysqlwriter", "postgresqlwriter"
    ] | None
    latest_execution_process_state: ProcessStateValue | None
    latest_execution_at: datetime | None
    row_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime


class JobPage(StrictModel):
    items: list[JobResponse]
    next_cursor: str | None
    has_more: bool


class ValidationIssue(StrictModel):
    code: Literal[
        "JOB_SPEC_INVALID",
        "SOURCE_TARGET_SAME_TABLE",
        "DATASOURCE_DISABLED",
        "TARGET_TABLE_NOT_FOUND",
        "COLUMN_NOT_FOUND",
        "TYPE_MAPPING_UNSUPPORTED",
        "NULLABILITY_UNSAFE",
        "SCHEMA_DRIFT_DETECTED",
    ]
    path: str = Field(max_length=500)
    message: str = Field(max_length=1000)


class ValidationReport(StrictModel):
    valid: bool
    draft_spec_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_schema_hash: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    target_schema_hash: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    errors: list[ValidationIssue]
    warnings: list[ValidationIssue]


class JobPreview(StrictModel):
    draft_spec_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    redacted_datax_json: dict[str, object]
    executable: Literal[False]
    warnings: list[ValidationIssue]


class PublishRequest(StrictModel):
    expected_draft_spec_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class JobVersionResponse(StrictModel):
    id: UUID
    job_id: UUID
    version_no: int = Field(ge=1)
    spec: JobSpecV1
    spec_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    version_artifact_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_datasource_revision_id: UUID
    target_datasource_revision_id: UUID
    source_endpoint_policy_revision_id: UUID
    target_endpoint_policy_revision_id: UUID
    source_physical_table_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_namespace_id: UUID
    transfer_policy_id: UUID
    transfer_policy_scope_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_schema_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_schema_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    datax_release: Literal["datax_v202309"]
    runtime_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reader_plugin: Literal["mysqlreader", "postgresqlreader"]
    reader_plugin_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    writer_plugin: Literal["mysqlwriter", "postgresqlwriter"]
    writer_plugin_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    published_by: UUID
    published_at: datetime


class JobVersionPage(StrictModel):
    items: list[JobVersionResponse]
    next_cursor: str | None
    has_more: bool


class SourceQuiescenceConfirmation(StrictModel):
    confirmed: Literal[True]
    confirmed_at: datetime
    note: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def normalize_time(self) -> SourceQuiescenceConfirmation:
        _require_aware(self.confirmed_at, "confirmed_at")
        return self


class TargetExclusivityConfirmation(StrictModel):
    statement_version: Literal["1.0"]
    confirmed: Literal[True]
    confirmed_at: datetime
    valid_until: datetime
    responsible_party: Literal["OPERATOR", "DBA"]
    note: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def validate_window(self) -> TargetExclusivityConfirmation:
        confirmed_at = _require_aware(self.confirmed_at, "confirmed_at")
        valid_until = _require_aware(self.valid_until, "valid_until")
        if valid_until <= confirmed_at:
            raise ValueError("valid_until must be later than confirmed_at")
        return self


class ExecutionCreate(StrictModel):
    job_version_id: UUID
    source_quiescence_confirmation: SourceQuiescenceConfirmation
    target_exclusivity_confirmation: TargetExclusivityConfirmation


class TargetExclusivityRevocationRequest(StrictModel):
    statement_version: Literal["1.0"]
    responsible_party: Literal["OPERATOR", "DBA"]
    reason: Literal[
        "OPERATOR_REVOKED",
        "DBA_REVOKED",
        "EXTERNAL_DML_DDL_REPORTED",
        "CHANGE_FREEZE_BROKEN",
    ]
    reported_at: datetime
    note: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def normalize_time(self) -> TargetExclusivityRevocationRequest:
        _require_aware(self.reported_at, "reported_at")
        return self


class CancelExecutionRequest(StrictModel):
    reason: str | None = Field(default=None, min_length=1, max_length=500)


class CancelRequestResponse(StrictModel):
    id: UUID
    execution_id: UUID
    status: Literal["PENDING", "ACKNOWLEDGED", "COMPLETED", "REJECTED"]
    requested_at: datetime


class TargetCopyLockSummary(StrictModel):
    target_namespace_id: UUID
    state: Literal["RESERVED", "ACTIVE", "RECOVERY_REQUIRED", "RELEASED"]
    reserved_at: datetime
    activated_at: datetime | None
    released_at: datetime | None
    fence_epoch: int | None = Field(default=None, ge=1)


class TargetNamespaceSnapshot(StrictModel):
    target_namespace_id: UUID
    physical_endpoint_identity_id: UUID
    engine: Engine
    normalized_catalog_name: str = Field(min_length=1, max_length=128)
    normalized_schema_name: str = Field(max_length=128)
    normalized_table_name: str = Field(min_length=1, max_length=128)
    normalization_version: Literal["1.0"]
    physical_table_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class PhysicalEndpointIdentityResponse(StrictModel):
    id: UUID
    organization_id: UUID
    engine: Engine
    identity_scheme: Literal[
        "MYSQL_SERVER_UUID",
        "POSTGRES_SYSTEM_IDENTIFIER",
    ]
    server_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    verification_evidence_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_by: UUID
    created_at: datetime


class AuditPage(StrictModel):
    items: list[dict[str, object]]
    next_cursor: str | None
    has_more: bool


class TargetEmptyEvidence(StrictModel):
    result: Literal["EMPTY"]
    checked_at: datetime
    observed_row_count: Literal[0]
    target_datasource_revision_id: UUID
    target_endpoint_policy_revision_id: UUID
    target_namespace_id: UUID
    physical_table_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    connection_evidence_id: UUID
    evidence_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def normalize_time(self) -> TargetEmptyEvidence:
        _require_aware(self.checked_at, "checked_at")
        return self


class RuntimePreflight(StrictModel):
    datax_release: Literal["datax_v202309"]
    runtime_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reader_plugin_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    writer_plugin_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    resolved_config_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_connection_evidence_id: UUID
    target_connection_evidence_id: UUID
    target_empty_evidence: TargetEmptyEvidence


class ExecutionRuntimeSnapshot(StrictModel):
    job_spec_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_schema_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_schema_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_datasource_revision_id: UUID
    target_datasource_revision_id: UUID
    source_endpoint_policy_revision_id: UUID
    target_endpoint_policy_revision_id: UUID
    source_physical_endpoint_identity_id: UUID
    target_namespace: TargetNamespaceSnapshot
    transfer_policy_scope_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_secret_version: int = Field(ge=1)
    target_secret_version: int = Field(ge=1)
    source_secret_envelope_id: UUID
    target_secret_envelope_id: UUID
    datax_release: Literal["datax_v202309"]
    runtime_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reader_plugin: Literal["mysqlreader", "postgresqlreader"]
    reader_plugin_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    writer_plugin: Literal["mysqlwriter", "postgresqlwriter"]
    writer_plugin_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_consistency_mode: Literal["OPERATOR_QUIESCED"]
    target_precondition: Literal["EMPTY_AND_VERIFIABLE"]
    write_semantics: Literal["INSERT_ONLY_ONCE"]
    duplicate_policy: Literal["REJECT_NONEMPTY_TARGET"]
    partial_write_policy: Literal["MANUAL_REMEDIATE"]
    source_quiescence_confirmed_by: UUID
    source_quiescence_accepted_at: datetime
    target_exclusivity_confirmed_by: UUID
    target_exclusivity_responsible_party: Literal["OPERATOR", "DBA"]
    target_exclusivity_accepted_at: datetime
    target_exclusivity_statement_version: Literal["1.0"]
    target_exclusivity_valid_until: datetime
    target_exclusivity_confirmation_sha256: str = Field(
        pattern=r"^[a-f0-9]{64}$"
    )
    target_empty_evidence: TargetEmptyEvidence
    target_lock_key_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_fence_epoch: int = Field(ge=1)
    verification_oracle_schema_version: Literal["1.0"]


class VerificationSummary(StrictModel):
    oracle_version: str = Field(pattern=r"^oracle-v1\.[0-9]+$")
    result: Literal["PASSED", "FAILED", "INCONCLUSIVE"]
    inconclusive_reason: Literal[
        "SOURCE_QUIESCENCE_BROKEN",
        "TARGET_LOCK_LOST",
        "TARGET_EXCLUSIVITY_BROKEN",
        "TARGET_SNAPSHOT_INVALID",
        "SOURCE_READ_FAILED",
        "TARGET_READ_FAILED",
        "NORMALIZATION_FAILED",
        "ORACLE_INTERNAL_ERROR",
    ] | None
    source_row_count: int | None = Field(ge=0)
    target_row_count: int | None = Field(ge=0)
    missing_row_count: int | None = Field(ge=0)
    unexpected_row_count: int | None = Field(ge=0)
    row_count_equal: bool | None
    multiset_sha256_equal: bool | None
    target_exclusivity_valid: bool | None
    target_snapshot_id: str | None = Field(min_length=1, max_length=256)
    target_snapshot_started_at: datetime | None
    target_snapshot_finished_at: datetime | None
    source_multiset_sha256: str | None = Field(pattern=r"^[a-f0-9]{64}$")
    target_multiset_sha256: str | None = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    finished_at: datetime


class RunSummary(StrictModel):
    records_read: int = Field(ge=0)
    records_written: int = Field(ge=0)
    records_failed: int = Field(ge=0)
    bytes_read: int = Field(ge=0)
    average_bytes_per_second: float = Field(ge=0)
    average_records_per_second: float = Field(ge=0)


class ExecutionResponse(StrictModel):
    id: UUID
    project_id: UUID
    job_id: UUID
    job_version_id: UUID
    rerun_of_execution_id: UUID | None
    trigger_type: Literal["MANUAL"]
    requested_by: UUID
    process_state: Literal[
        "QUEUED",
        "STARTING",
        "RUNNING",
        "VERIFYING",
        "SUCCEEDED",
        "FAILED",
        "TIMED_OUT",
        "CANCEL_REQUESTED",
        "CANCELED",
        "LOST",
    ]
    data_effect: Literal["NONE", "POSSIBLE", "CONFIRMED", "UNKNOWN"]
    verification_state: Literal[
        "NOT_STARTED",
        "VERIFYING",
        "PASSED",
        "FAILED",
        "INCONCLUSIVE",
    ]
    target_exclusivity_confirmation: TargetExclusivityConfirmation
    target_exclusivity_status: Literal["ACTIVE", "REVOKED", "EXPIRED"]
    target_exclusivity_revoked_at: datetime | None
    target_exclusivity_revocation_reason: str | None
    source_datasource_revision_id: UUID
    target_datasource_revision_id: UUID
    source_endpoint_policy_revision_id: UUID
    target_endpoint_policy_revision_id: UUID
    target_namespace_id: UUID
    target_copy_lock: TargetCopyLockSummary
    source_secret_version: int | None = Field(default=None, ge=1)
    target_secret_version: int | None = Field(default=None, ge=1)
    source_secret_envelope_id: UUID | None
    target_secret_envelope_id: UUID | None
    source_connection_evidence_id: UUID | None
    target_connection_evidence_id: UUID | None
    capacity_profile: Literal["LIGHTWEIGHT", "LARGE"]
    service_reservation_seconds: Literal[360, 3600]
    queue_eligibility_state: Literal["ELIGIBLE", "BLOCKED"]
    queue_block_reason: str | None
    queue_state_changed_at: datetime
    eligible_wait_milliseconds: int = Field(ge=0)
    log_incomplete: bool
    log_raw_received_bytes: int = Field(ge=0)
    log_redacted_received_bytes: int = Field(ge=0)
    log_stored_bytes: int = Field(ge=0)
    log_dropped_bytes: int = Field(ge=0)
    resolved_config_hash: str | None
    runtime_snapshot: ExecutionRuntimeSnapshot | None
    verification_summary: VerificationSummary | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    exit_code: int | None
    failure_code: str | None
    failure_message: str | None
    summary_parse_status: Literal["PENDING", "SUCCEEDED", "FAILED"]
    run_summary: RunSummary | None


class ExecutionPage(StrictModel):
    items: list[ExecutionResponse]
    next_cursor: str | None
    has_more: bool


class CredentialBinding(StrictModel):
    source_secret_id: UUID
    target_secret_id: UUID
    source_secret_envelope_id: UUID
    target_secret_envelope_id: UUID
    source_secret_version: int = Field(ge=1)
    target_secret_version: int = Field(ge=1)


class ClaimedExecution(StrictModel):
    execution_id: UUID
    attempt_id: UUID
    fence_epoch: int = Field(ge=1)
    lease_token: str = Field(min_length=32)


def _require_aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must include a UTC offset")
    return value.astimezone(UTC)
