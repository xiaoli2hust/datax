"""bound the Worker database connection budget across restart generations

Revision ID: 20260802_0016
Revises: 20260802_0015
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0016"
down_revision: str | Sequence[str] | None = "20260802_0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_WORKER_ROLE = "datax_worker"
_PREVIOUS_CONNECTION_LIMIT = 8
_WORKER_CONNECTION_LIMIT = 12


def _quoted_worker_role(bind: sa.engine.Connection) -> str:
    return bind.dialect.identifier_preparer.quote(_WORKER_ROLE)


def _set_worker_connection_limit(limit: int) -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("worker connection budget requires PostgreSQL")
    op.execute(
        f"ALTER ROLE {_quoted_worker_role(bind)} CONNECTION LIMIT {limit}"
    )


def upgrade() -> None:
    """Allow one bounded Worker plus two stale restart generations."""

    _set_worker_connection_limit(_WORKER_CONNECTION_LIMIT)


def downgrade() -> None:
    _set_worker_connection_limit(_PREVIOUS_CONNECTION_LIMIT)
