from __future__ import annotations

import hashlib
from typing import Literal
from uuid import UUID

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_SNAPSHOT_HASH_DOMAIN = b"DXSCHEMASNAPSHOTv1\n"
_EVENT_ORDER = ("INSERT", "UPDATE", "DELETE", "TRUNCATE")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SchemaColumn(_StrictModel):
    ordinal_position: int = Field(ge=1, le=65535)
    name: str = Field(min_length=1, max_length=128)
    native_type: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9_ (),]+$",
    )
    logical_type: Literal[
        "INTEGER",
        "DECIMAL",
        "TEXT",
        "BOOLEAN",
        "DATE",
        "TIME",
        "TIMESTAMP",
        "BINARY",
    ]
    nullable: bool
    unsigned: bool
    generated: bool
    identity: bool
    character_maximum_length: int | None = Field(default=None, ge=1)
    numeric_precision: int | None = Field(default=None, ge=1)
    numeric_scale: int | None = Field(default=None, ge=0)
    datetime_precision: int | None = Field(default=None, ge=0)
    character_set_name: str | None = Field(default=None, max_length=128)
    collation_name: str | None = Field(default=None, max_length=128)
    default_present: bool
    default_expression_sha256: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )

    @model_validator(mode="after")
    def validate_default_hash(self) -> SchemaColumn:
        if self.default_present != (self.default_expression_sha256 is not None):
            raise ValueError(
                "default_expression_sha256 must be present exactly when a default exists"
            )
        return self


class SchemaConstraint(_StrictModel):
    kind: Literal["PRIMARY_KEY", "UNIQUE", "FOREIGN_KEY", "CHECK"]
    columns: list[str] = Field(min_length=1, max_length=2048)
    enforced: bool
    definition_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    referenced_physical_table_identity_hash: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )

    @model_validator(mode="after")
    def validate_reference(self) -> SchemaConstraint:
        if len(set(self.columns)) != len(self.columns):
            raise ValueError("constraint columns must be unique")
        if (self.kind == "FOREIGN_KEY") != (
            self.referenced_physical_table_identity_hash is not None
        ):
            raise ValueError(
                "only FOREIGN_KEY constraints have a referenced table identity"
            )
        return self


class SchemaTrigger(_StrictModel):
    name_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    timing: Literal["BEFORE", "AFTER", "INSTEAD_OF"]
    events: list[Literal["INSERT", "UPDATE", "DELETE", "TRUNCATE"]] = Field(
        min_length=1,
        max_length=4,
    )
    orientation: Literal["ROW", "STATEMENT"]
    enabled: bool
    definition_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_events(self) -> SchemaTrigger:
        expected = [event for event in _EVENT_ORDER if event in self.events]
        if self.events != expected:
            raise ValueError("trigger events must be unique and in canonical order")
        return self


class SchemaTableOptions(_StrictModel):
    partitioned: bool
    row_security_enabled: bool | None


class SchemaSnapshot(_StrictModel):
    schema_version: Literal["1.0"]
    normalization_version: Literal["1.0"]
    engine: Literal["MYSQL_8", "POSTGRESQL_15"]
    physical_endpoint_identity_id: UUID
    physical_table_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    identifier_case_mode: Literal[
        "MYSQL_LOWER_CASE_TABLE_NAMES_0",
        "MYSQL_LOWER_CASE_TABLE_NAMES_1",
        "MYSQL_LOWER_CASE_TABLE_NAMES_2",
        "POSTGRESQL_FOLDED_OR_QUOTED",
    ]
    catalog_name: str = Field(min_length=1, max_length=128)
    schema_name: str = Field(max_length=128)
    table_name: str = Field(min_length=1, max_length=128)
    table_kind: Literal["BASE_TABLE"]
    columns: list[SchemaColumn] = Field(min_length=1, max_length=2048)
    constraints: list[SchemaConstraint] = Field(max_length=4096)
    triggers: list[SchemaTrigger] = Field(max_length=4096)
    table_options: SchemaTableOptions

    @model_validator(mode="after")
    def validate_semantics(self) -> SchemaSnapshot:
        expected_ordinals = list(range(1, len(self.columns) + 1))
        if [column.ordinal_position for column in self.columns] != expected_ordinals:
            raise ValueError("column ordinals must be contiguous and ordered")
        column_names = [column.name for column in self.columns]
        if len(set(column_names)) != len(column_names):
            raise ValueError("column names must be unique")
        available = set(column_names)
        if any(not set(item.columns) <= available for item in self.constraints):
            raise ValueError("constraint refers to an unknown column")
        if self.constraints != sorted(
            self.constraints,
            key=lambda item: rfc8785.dumps(item.model_dump(mode="json")),
        ):
            raise ValueError("constraints must be in canonical order")
        if self.triggers != sorted(
            self.triggers,
            key=lambda item: rfc8785.dumps(item.model_dump(mode="json")),
        ):
            raise ValueError("triggers must be in canonical order")
        if self.engine == "MYSQL_8":
            if not self.identifier_case_mode.startswith("MYSQL_"):
                raise ValueError("MySQL identifier case mode is invalid")
            if self.table_options.row_security_enabled is not None:
                raise ValueError("MySQL row_security_enabled must be null")
        else:
            if self.identifier_case_mode != "POSTGRESQL_FOLDED_OR_QUOTED":
                raise ValueError("PostgreSQL identifier case mode is invalid")
            if self.table_options.row_security_enabled is None:
                raise ValueError("PostgreSQL row_security_enabled must be boolean")
        return self


def validate_schema_snapshot(value: dict[str, object]) -> SchemaSnapshot:
    return SchemaSnapshot.model_validate(value)


def schema_snapshot_hash(value: SchemaSnapshot | dict[str, object]) -> str:
    snapshot = (
        value
        if isinstance(value, SchemaSnapshot)
        else validate_schema_snapshot(value)
    )
    canonical = rfc8785.dumps(snapshot.model_dump(mode="json"))
    return hashlib.sha256(SCHEMA_SNAPSHOT_HASH_DOMAIN + canonical).hexdigest()
