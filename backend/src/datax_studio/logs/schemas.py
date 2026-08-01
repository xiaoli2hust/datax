from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LogLine(StrictModel):
    sequence: int = Field(ge=1)
    timestamp: datetime
    stream: Literal["STDOUT", "STDERR", "SYSTEM"]
    level: Literal["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "UNKNOWN"]
    message: str = Field(max_length=16384)
    line_truncated: bool
    raw_received_bytes: int = Field(ge=0)
    redacted_received_bytes: int = Field(ge=0)
    stored_bytes: int = Field(ge=0)
    dropped_bytes: int = Field(ge=0)


class LogGap(StrictModel):
    gap_no: int = Field(ge=1)
    reason: Literal[
        "LINE_LIMIT",
        "EXECUTION_LIMIT",
        "RING_EVICTION",
        "SOURCE_READ_ERROR",
        "DECODE_ERROR",
        "REDACTION_FAILURE",
        "STORAGE_FAILURE",
        "FENCE_LOST",
    ]
    after_sequence: int | None = Field(default=None, ge=1)
    before_sequence: int | None = Field(default=None, ge=1)
    raw_received_bytes: int = Field(ge=0)
    redacted_received_bytes: int = Field(ge=0)
    stored_bytes: int = Field(ge=0)
    dropped_bytes: int = Field(ge=0)
    detected_at: datetime
    evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class LogPage(StrictModel):
    items: list[LogLine] = Field(max_length=1000)
    next_cursor: str = Field(min_length=1)
    eof: bool
    redaction_rules_version: str = Field(max_length=32)
    truncated: bool
    incomplete: bool
    raw_received_bytes: int = Field(ge=0)
    redacted_received_bytes: int = Field(ge=0)
    stored_bytes: int = Field(ge=0)
    reason: Literal[
        "NONE",
        "EXECUTION_LIMIT",
        "LINE_LIMIT",
        "RING_EVICTION",
    ]
    dropped_bytes: int = Field(ge=0)
    first_truncated_sequence: int | None = Field(default=None, ge=1)
    gap_count: int = Field(ge=0)
    gaps: list[LogGap] = Field(max_length=1000)
    expires_at: datetime


class LogDownload(StrictModel):
    content: bytes
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    redaction_rules_version: str = Field(max_length=32)
    truncated: bool
    incomplete: bool
    raw_received_bytes: int = Field(ge=0)
    redacted_received_bytes: int = Field(ge=0)
    stored_bytes: int = Field(ge=0)
    dropped_bytes: int = Field(ge=0)
    gap_count: int = Field(ge=0)
    truncation_reason: Literal[
        "NONE",
        "EXECUTION_LIMIT",
        "LINE_LIMIT",
        "RING_EVICTION",
    ]
