from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from datax_studio.core.schemas import (
    SourceQuiescenceConfirmation,
    StrictModel,
    TargetEmptyEvidence,
    TargetExclusivityConfirmation,
)


class RemediationConfirmation(StrictModel):
    action: Literal[
        "CLEANED_TARGET",
        "RECREATED_TARGET",
        "NO_CLEANUP_REQUIRED",
        "OTHER_EXTERNAL_ACTION",
    ]
    cleanup_performed: bool
    reason: str = Field(min_length=1, max_length=1000)
    confirmed_at: datetime

    @model_validator(mode="after")
    def validate_action(self) -> RemediationConfirmation:
        if self.confirmed_at.tzinfo is None:
            raise ValueError("confirmed_at must include an offset")
        if self.action in {"CLEANED_TARGET", "RECREATED_TARGET"}:
            if not self.cleanup_performed:
                raise ValueError("cleanup_performed must be true for cleanup actions")
        elif self.action == "NO_CLEANUP_REQUIRED" and self.cleanup_performed:
            raise ValueError("cleanup_performed must be false when no cleanup was required")
        return self


class ExecutionRerunCreate(StrictModel):
    source_quiescence_confirmation: SourceQuiescenceConfirmation
    target_exclusivity_confirmation: TargetExclusivityConfirmation
    recovery_gate_id: UUID


class RecoveryGateResponse(StrictModel):
    id: UUID
    execution_id: UUID
    target_namespace_id: UUID
    status: Literal["OPEN", "REMEDIATION_SUBMITTED", "VERIFIED", "REJECTED"]
    data_effect_at_open: Literal["NONE", "POSSIBLE", "CONFIRMED", "UNKNOWN"]
    remediation_confirmation: RemediationConfirmation | None
    target_empty_evidence: TargetEmptyEvidence | None
    latest_recovery_probe_id: UUID | None
    submitted_at: datetime | None
    verified_at: datetime | None
    reason_code: str | None = Field(default=None, max_length=64)


class RecoveryProbeAttemptResponse(StrictModel):
    id: UUID
    recovery_probe_id: UUID
    attempt_no: int = Field(ge=1)
    fence_epoch: int = Field(ge=1)
    started_at: datetime | None
    finished_at: datetime | None
    termination_reason: str | None = Field(default=None, max_length=64)


class RecoveryProbeResponse(StrictModel):
    id: UUID
    project_id: UUID
    recovery_gate_id: UUID
    target_namespace_id: UUID
    target_datasource_revision_id: UUID
    target_endpoint_policy_revision_id: UUID | None
    process_state: Literal[
        "QUEUED",
        "STARTING",
        "RUNNING",
        "SUCCEEDED",
        "FAILED",
        "CANCELED",
        "LOST",
    ]
    result: Literal["NOT_STARTED", "EMPTY", "NONEMPTY", "INCONCLUSIVE"]
    fence_epoch: int = Field(ge=0)
    active_attempt: RecoveryProbeAttemptResponse | None
    service_reservation_seconds: int = Field(ge=1)
    queue_eligibility_state: Literal["ELIGIBLE", "BLOCKED"]
    queue_block_reason: str | None = Field(default=None, max_length=64)
    queue_state_changed_at: datetime
    eligible_wait_milliseconds: int = Field(ge=0)
    queued_at: datetime
    finished_at: datetime | None
    target_connection_evidence_id: UUID | None
    target_empty_evidence: TargetEmptyEvidence | None
    failure_code: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def enforce_success_result(self) -> RecoveryProbeResponse:
        if self.process_state == "SUCCEEDED" and self.result != "EMPTY":
            raise ValueError("a successful recovery probe must prove EMPTY")
        return self


class RecoverySubmissionResponse(StrictModel):
    recovery_gate: RecoveryGateResponse
    recovery_probe: RecoveryProbeResponse
