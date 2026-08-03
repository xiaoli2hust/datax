from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from datax_studio.core.db import Execution
from datax_studio.recovery.db import RecoveryGate


def ensure_recovery_gate(
    session: Session,
    *,
    execution: Execution,
    now: datetime,
) -> RecoveryGate | None:
    """Create the recovery fact in the caller's terminal-state transaction.

    A claimed execution must never commit RECOVERY_REQUIRED without the gate
    that makes operator remediation reachable. Keeping this helper free of
    ControlService dependencies lets both the execution state machine and the
    recovery application service use the same idempotent rule without a
    circular service import.
    """

    if execution.attempt_count < 1 or execution.process_state not in {
        "FAILED",
        "TIMED_OUT",
        "CANCELED",
        "LOST",
    }:
        return None
    gate = session.scalar(
        select(RecoveryGate)
        .where(RecoveryGate.execution_id == execution.id)
        .with_for_update()
    )
    if gate is None:
        gate = RecoveryGate(
            id=uuid4(),
            execution_id=execution.id,
            project_id=execution.project_id,
            target_namespace_id=execution.target_namespace_id,
            status="OPEN",
            data_effect_at_open=execution.data_effect,
            remediation_confirmation=None,
            target_empty_evidence=None,
            latest_recovery_probe_id=None,
            submitted_at=None,
            verified_at=None,
            reason_code=execution.failure_code,
            created_at=now,
        )
        session.add(gate)
        session.flush()
    return gate
