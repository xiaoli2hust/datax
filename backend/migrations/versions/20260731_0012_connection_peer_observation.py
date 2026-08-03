"""distinguish enforced DataX destinations from observed socket peers

Revision ID: 20260731_0012
Revises: 20260730_0011
Create Date: 2026-07-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260731_0012"
down_revision: str | Sequence[str] | None = "20260730_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "endpoint_connection_evidences",
        sa.Column(
            "peer_observation_status",
            sa.String(length=32),
            nullable=False,
            server_default="OBSERVED",
        ),
    )
    op.alter_column(
        "endpoint_connection_evidences",
        "peer_ip",
        existing_type=postgresql.INET(),
        nullable=True,
    )
    op.create_check_constraint(
        "ck_endpoint_connection_evidence_peer_observation",
        "endpoint_connection_evidences",
        "("
        "peer_observation_status = 'OBSERVED' AND peer_ip IS NOT NULL"
        ") OR ("
        "operation_kind = 'DATAX' AND "
        "peer_observation_status = 'ENFORCED_NOT_OBSERVED' AND "
        "peer_ip IS NULL"
        ")",
    )
    op.alter_column(
        "endpoint_connection_evidences",
        "peer_observation_status",
        server_default=None,
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM endpoint_connection_evidences
                WHERE peer_observation_status = 'ENFORCED_NOT_OBSERVED'
                   OR peer_ip IS NULL
            ) THEN
                RAISE EXCEPTION
                    'cannot downgrade while unobserved DataX peer evidence exists';
            END IF;
        END
        $$;
        """
    )
    op.drop_constraint(
        "ck_endpoint_connection_evidence_peer_observation",
        "endpoint_connection_evidences",
        type_="check",
    )
    op.alter_column(
        "endpoint_connection_evidences",
        "peer_ip",
        existing_type=postgresql.INET(),
        nullable=False,
    )
    op.drop_column(
        "endpoint_connection_evidences",
        "peer_observation_status",
    )
