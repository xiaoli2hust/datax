"""enforce append-only audit events in PostgreSQL

Revision ID: 20260730_0007
Revises: 20260730_0006
Create Date: 2026-07-30
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260730_0007"
down_revision: str | Sequence[str] | None = "20260730_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION des_reject_audit_event_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION
                USING
                    ERRCODE = '55000',
                    MESSAGE = 'audit_events is append-only';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_append_only_row
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW
        EXECUTE FUNCTION des_reject_audit_event_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_append_only_truncate
        BEFORE TRUNCATE ON audit_events
        FOR EACH STATEMENT
        EXECUTE FUNCTION des_reject_audit_event_mutation()
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS audit_events_append_only_truncate ON audit_events"
    )
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only_row ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS des_reject_audit_event_mutation()")
