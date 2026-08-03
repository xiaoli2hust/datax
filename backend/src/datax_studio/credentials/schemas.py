from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Engine(StrEnum):
    MYSQL_8 = "MYSQL_8"
    POSTGRESQL_15 = "POSTGRESQL_15"


class SslMode(StrEnum):
    DISABLE = "DISABLE"
    REQUIRE = "REQUIRE"
    VERIFY_CA = "VERIFY_CA"
    VERIFY_FULL = "VERIFY_FULL"


class EndpointPolicyPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    host_kind: Literal["EXACT_FQDN", "EXACT_IP"] | None = None
    host_value: str | None = Field(default=None, min_length=1, max_length=253)
    allowed_cidrs: list[
        Annotated[str, Field(min_length=3, max_length=49)]
    ] | None = Field(
        default=None,
        min_length=1,
        max_length=64,
    )
    allowed_ports: list[
        Annotated[int, Field(ge=1, le=65535)]
    ] | None = Field(
        default=None,
        min_length=1,
        max_length=16,
    )
    tls_required: bool | None = None
    dns_ttl_ceiling_seconds: int | None = Field(default=None, ge=1, le=3600)
    status: Literal["ACTIVE", "DISABLED"] | None = None

    @model_validator(mode="after")
    def validate_patch(self) -> EndpointPolicyPatch:
        if not self.model_fields_set:
            raise ValueError("at least one field is required")
        for field_name in self.model_fields_set:
            if getattr(self, field_name) is None:
                raise ValueError(f"{field_name} must not be null")
        if self.name is not None and not self.name.strip():
            raise ValueError("name must not be blank")
        if (
            self.allowed_cidrs is not None
            and len(set(self.allowed_cidrs)) != len(self.allowed_cidrs)
        ):
            raise ValueError("allowed_cidrs must contain unique items")
        if (
            self.allowed_ports is not None
            and len(set(self.allowed_ports)) != len(self.allowed_ports)
        ):
            raise ValueError("allowed_ports must contain unique items")
        return self


class DatasourceCreate(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    endpoint_policy_id: UUID
    engine: Engine
    host: str = Field(min_length=1, max_length=253, pattern=r"^[^:/\\\s]+$")
    port: int = Field(ge=1, le=65535)
    database_name: str = Field(min_length=1, max_length=128)
    default_schema: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=512)
    ssl_mode: SslMode


class DatasourcePatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    endpoint_policy_id: UUID | None = None
    engine: Engine | None = None
    host: str | None = Field(
        default=None,
        min_length=1,
        max_length=253,
        pattern=r"^[^:/\\\s]+$",
    )
    port: int | None = Field(default=None, ge=1, le=65535)
    database_name: str | None = Field(default=None, min_length=1, max_length=128)
    default_schema: str | None = Field(default=None, min_length=1, max_length=128)
    username: str | None = Field(default=None, min_length=1, max_length=128)
    ssl_mode: SslMode | None = None
    status: Literal["ACTIVE", "DISABLED"] | None = None
    password: SecretStr | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def validate_patch(self) -> DatasourcePatch:
        if not self.model_fields_set:
            raise ValueError("at least one field is required")
        if "name" in self.model_fields_set and (
            self.name is None or not self.name.strip()
        ):
            raise ValueError("name must not be null or blank")
        if (
            "password" in self.model_fields_set
            and (self.password is None or not self.password.get_secret_value())
        ):
            raise ValueError("password must be omitted to retain the current credential")
        for field_name in (
            "endpoint_policy_id",
            "engine",
            "host",
            "port",
            "database_name",
            "default_schema",
            "username",
            "ssl_mode",
            "status",
        ):
            if field_name in self.model_fields_set and getattr(self, field_name) is None:
                raise ValueError(f"{field_name} must not be null")
        return self


class CredentialSecretStatusChange(StrictModel):
    status: Literal["RETIRED", "REVOKED", "COMPROMISED"]
    reason_code: str = Field(pattern=r"^[A-Z0-9_]+$", min_length=1, max_length=64)


class CredentialSecretEnvelopeSummary(StrictModel):
    envelope_version: int = Field(ge=1)
    kek_version: str = Field(min_length=1, max_length=64)
    wrapping_algorithm: Literal["AES-256-KWP"]
    status: Literal["ACTIVE", "SUPERSEDED"]
    wrapped_dek_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime


class CredentialSecretSummary(StrictModel):
    secret_version: int = Field(ge=1)
    status: Literal["ACTIVE", "RETIRED", "REVOKED", "COMPROMISED"]
    status_reason_code: str | None
    status_changed_at: datetime
    created_at: datetime
    active_envelope: CredentialSecretEnvelopeSummary | None


class CredentialSecretPage(StrictModel):
    items: list[CredentialSecretSummary]


class DatasourceRevisionAdminDetail(StrictModel):
    id: UUID
    datasource_id: UUID
    revision_no: int = Field(ge=1)
    endpoint_policy_revision_id: UUID
    physical_endpoint_identity_id: UUID
    engine: Engine
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    database_name: str = Field(min_length=1, max_length=128)
    default_schema: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    ssl_mode: SslMode
    connection_options: dict[str, object]
    config_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_by: UUID
    created_at: datetime

    @model_validator(mode="after")
    def require_empty_connection_options(
        self,
    ) -> DatasourceRevisionAdminDetail:
        if self.connection_options:
            raise ValueError(
                "V1 connection_options must be an empty object"
            )
        return self


class DatasourceAdminDetail(StrictModel):
    id: UUID
    project_id: UUID
    name: str
    description: str | None
    engine: Engine
    current_revision: DatasourceRevisionAdminDetail
    current_secret: CredentialSecretSummary
    status: Literal["ACTIVE", "DISABLED", "DELETED"]
    row_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime


class DatasourceRedactedSummary(StrictModel):
    id: UUID
    project_id: UUID
    name: str
    description: str | None
    engine: Engine
    endpoint_redacted: Literal["REDACTED"] = "REDACTED"
    credential_configured: bool
    current_revision_id: UUID
    current_revision_no: int = Field(ge=1)
    credential_status: Literal["READY", "UNAVAILABLE"]
    last_test_status: Literal["SUCCEEDED", "FAILED"] | None
    last_tested_at: datetime | None
    last_test_error_code: str | None
    status: Literal["ACTIVE", "DISABLED", "DELETED"]
    row_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime


class DatasourcePage(StrictModel):
    items: list[DatasourceRedactedSummary]
    next_cursor: str | None
    has_more: bool


class DatasourceTestResult(StrictModel):
    status: Literal["SUCCEEDED", "FAILED"]
    tested_at: datetime
    latency_ms: int = Field(ge=0)
    server_version: str | None = Field(default=None, max_length=128)
    error_code: str | None = Field(default=None, max_length=64)
    message: str = Field(max_length=500)
    request_id: UUID


class EndpointConnectionEvidenceResponse(StrictModel):
    id: UUID
    operation_kind: Literal[
        "TEST",
        "METADATA",
        "PREFLIGHT",
        "DATAX",
        "ORACLE",
        "RECOVERY_PROBE",
    ]
    datasource_revision_id: UUID
    endpoint_policy_revision_id: UUID
    resolver_policy_version: str = Field(min_length=1, max_length=64)
    resolved_ips: list[str] = Field(min_length=1, max_length=64)
    selected_ip: str = Field(min_length=2, max_length=45)
    peer_observation_status: Literal["OBSERVED", "ENFORCED_NOT_OBSERVED"]
    peer_ip: str | None = Field(default=None, min_length=2, max_length=45)
    egress_policy_version: str = Field(min_length=1, max_length=64)
    egress_evidence_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: Literal["ALLOWED", "DENIED"]
    evidence_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime

    @model_validator(mode="after")
    def validate_ip_evidence(
        self,
    ) -> EndpointConnectionEvidenceResponse:
        if len(set(self.resolved_ips)) != len(self.resolved_ips):
            raise ValueError("resolved_ips must contain unique items")
        try:
            for value in (*self.resolved_ips, self.selected_ip):
                ipaddress.ip_address(value)
            if self.peer_ip is not None:
                ipaddress.ip_address(self.peer_ip)
        except ValueError as exc:
            raise ValueError(
                "connection evidence must contain valid IP addresses"
            ) from exc
        if self.peer_observation_status == "OBSERVED":
            if self.peer_ip is None or self.peer_ip != self.selected_ip:
                raise ValueError("observed peer_ip must equal selected_ip")
        elif self.operation_kind != "DATAX" or self.peer_ip is not None:
            raise ValueError(
                "only DATAX may record an enforced but unobserved peer"
            )
        return self


class DatasourceUsageGrantResponse(StrictModel):
    id: UUID
    datasource_id: UUID
    organization_member_id: UUID
    usage: Literal["SOURCE_USE", "TARGET_USE"]
    status: Literal["ACTIVE", "REVOKED"]
    granted_by: UUID
    granted_at: datetime


class DatasourceUsageGrantReplace(StrictModel):
    usages: list[Literal["SOURCE_USE", "TARGET_USE"]] = Field(max_length=2)

    @model_validator(mode="after")
    def validate_usages(self) -> DatasourceUsageGrantReplace:
        if len(set(self.usages)) != len(self.usages):
            raise ValueError("usages must contain unique items")
        return self


class DatasourceUsageGrantPage(StrictModel):
    items: list[DatasourceUsageGrantResponse]
    next_cursor: str | None
    has_more: bool


class ColumnSchema(StrictModel):
    name: str
    ordinal: int = Field(ge=1)
    native_type: str
    logical_type: Literal[
        "INTEGER",
        "DECIMAL",
        "TEXT",
        "BOOLEAN",
        "DATE",
        "TIME",
        "TIMESTAMP",
        "BINARY",
    ] | None
    nullable: bool
    primary_key: bool
    generated: bool
    identity: bool
    character_maximum_length: int | None = Field(default=None, ge=1)
    numeric_precision: int | None = Field(default=None, ge=1)
    numeric_scale: int | None = Field(default=None, ge=0)
    datetime_precision: int | None = Field(default=None, ge=0)
    oracle_supported: bool
    unsupported_reason: Literal[
        "BINARY_FLOAT_UNSUPPORTED",
        "NATIVE_TYPE_UNSUPPORTED",
        "GENERATED_COLUMN_UNSUPPORTED",
    ] | None


class TableSchema(StrictModel):
    schema_name: str = Field(min_length=1, max_length=128)
    table_name: str = Field(min_length=1, max_length=128)
    physical_table_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    columns: list[ColumnSchema]
    schema_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    oracle_compatible: bool
    target_insert_compatible: bool
    incompatibility_reasons: list[
        Literal[
            "UNSUPPORTED_COLUMN_TYPE",
            "GENERATED_COLUMN_PRESENT",
            "ENABLED_TRIGGER_PRESENT",
            "PARTITIONED_TABLE_UNSUPPORTED",
            "ROW_SECURITY_ENABLED",
        ]
    ]
    captured_at: datetime


class TableSchemaPage(StrictModel):
    items: list[TableSchema]
    next_cursor: str | None
    has_more: bool
