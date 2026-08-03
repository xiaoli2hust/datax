from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from datax_studio.auth.db import AuditChainWatermark, AuditEvent


def advance_audit_chain_watermark(
    session: Session,
    *,
    organization_id: UUID,
    previous_sequence: int,
    previous_hash: str | None,
    sequence: int,
    event_hash: str,
    updated_at: datetime,
) -> None:
    """Advance the durable audit head in the same transaction as its event.

    All application writers already serialize an organization's append chain on
    its Organization row (the credentials writer is brought into that rule by
    this change).  The watermark comparison turns a missing/backfilled state or
    an out-of-band tail into a transaction failure instead of silently making a
    readiness cache look current.  The unique ``audit_events`` sequence
    constraint remains the SQLite backstop where ``FOR UPDATE`` is not a real
    row lock.
    """

    if sequence != previous_sequence + 1:
        raise RuntimeError("audit watermark sequence is not contiguous")
    actual_tail = session.scalar(
        select(AuditEvent)
        .where(AuditEvent.organization_id == organization_id)
        .order_by(AuditEvent.organization_sequence.desc())
        .limit(1)
    )
    actual_sequence = actual_tail.organization_sequence if actual_tail else 0
    actual_hash = actual_tail.event_hash if actual_tail else None
    if actual_sequence != previous_sequence or actual_hash != previous_hash:
        raise RuntimeError("audit append tail does not match the database")

    watermark = session.scalar(
        select(AuditChainWatermark)
        .where(AuditChainWatermark.organization_id == organization_id)
        .with_for_update()
    )
    if watermark is None:
        if previous_sequence != 0 or previous_hash is not None:
            raise RuntimeError("audit watermark is missing for an existing chain")
        watermark = AuditChainWatermark(
            organization_id=organization_id,
            head_sequence=sequence,
            head_hash=event_hash,
            verified_sequence=0,
            verified_hash=None,
            full_replay_sequence=0,
            full_replay_hash=None,
            full_replay_finished_at=None,
            integrity_status="PENDING",
            failure_code=None,
            failure_sequence=None,
            mutation_epoch=1,
            updated_at=updated_at,
        )
        session.add(watermark)
        return
    old_epoch = watermark.mutation_epoch
    values: dict[str, object] = {
        "head_sequence": sequence,
        "head_hash": event_hash,
        "mutation_epoch": old_epoch + 1,
        "updated_at": updated_at,
    }
    # A failed replay is intentionally sticky.  Appending a new event cannot
    # repair an earlier malformed/tampered record, and silently clearing the
    # failure here would let a suffix-only verification hide that condition.
    if watermark.integrity_status != "FAILED":
        values.update(
            {
                "integrity_status": "PENDING",
                "failure_code": None,
                "failure_sequence": None,
            }
        )
    result = session.execute(
        update(AuditChainWatermark)
        .where(
            AuditChainWatermark.organization_id == organization_id,
            AuditChainWatermark.head_sequence == previous_sequence,
            AuditChainWatermark.head_hash.is_not_distinct_from(previous_hash),
            AuditChainWatermark.mutation_epoch == old_epoch,
        )
        .values(**values)
    )
    if result.rowcount != 1:
        raise RuntimeError("audit watermark compare-and-set failed")
