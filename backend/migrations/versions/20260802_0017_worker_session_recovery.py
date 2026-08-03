"""expire abandoned Worker database sessions

Revision ID: 20260802_0017
Revises: 20260802_0016
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0017"
down_revision: str | Sequence[str] | None = "20260802_0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_WORKER_ROLE = "datax_worker"
_IDLE_SESSION_TIMEOUT = "30s"
_IDLE_IN_TRANSACTION_SESSION_TIMEOUT = "15s"


def _quoted_worker_role(bind: sa.engine.Connection) -> str:
    return bind.dialect.identifier_preparer.quote(_WORKER_ROLE)


def _worker_role(bind: sa.engine.Connection) -> str:
    if bind.dialect.name != "postgresql":
        raise RuntimeError("worker session recovery requires PostgreSQL")
    return _quoted_worker_role(bind)


def upgrade() -> None:
    """Bound abnormal Worker restart residue at the PostgreSQL server."""

    bind = op.get_bind()
    role = _worker_role(bind)
    op.execute(f"ALTER ROLE {role} SET idle_session_timeout TO '{_IDLE_SESSION_TIMEOUT}'")
    op.execute(
        "ALTER ROLE "
        f"{role} SET idle_in_transaction_session_timeout "
        f"TO '{_IDLE_IN_TRANSACTION_SESSION_TIMEOUT}'"
    )


def downgrade() -> None:
    bind = op.get_bind()
    role = _worker_role(bind)
    op.execute(f"ALTER ROLE {role} RESET idle_session_timeout")
    op.execute(f"ALTER ROLE {role} RESET idle_in_transaction_session_timeout")
