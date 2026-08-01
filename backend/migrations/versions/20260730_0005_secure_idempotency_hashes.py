"""replace unkeyed idempotency hashes with a keyed scheme

Revision ID: 20260730_0005
Revises: 20260730_0004
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260730_0005"
down_revision: str | Sequence[str] | None = "20260730_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Idempotency rows expire after 24 hours and are not business records. Purging
    # them removes legacy unkeyed hashes that could disclose low-entropy temporary
    # passwords to a database/backup reader.
    op.execute("DELETE FROM idempotency_records")
    op.add_column(
        "idempotency_records",
        sa.Column("request_hash_scheme", sa.String(length=32), nullable=True),
    )
    op.alter_column(
        "idempotency_records",
        "request_hash_scheme",
        nullable=False,
    )
    op.create_check_constraint(
        "ck_idempotency_request_hash_scheme",
        "idempotency_records",
        "request_hash_scheme = 'HMAC-SHA256-v1'",
    )


def downgrade() -> None:
    # Rows using the keyed format cannot be represented safely by the legacy
    # schema, so discard only the short-lived idempotency cache on downgrade.
    op.execute("DELETE FROM idempotency_records")
    op.drop_constraint(
        "ck_idempotency_request_hash_scheme",
        "idempotency_records",
        type_="check",
    )
    op.drop_column("idempotency_records", "request_hash_scheme")
