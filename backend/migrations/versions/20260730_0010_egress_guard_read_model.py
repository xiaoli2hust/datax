"""add the least-privilege egress guard read model

Revision ID: 20260730_0010
Revises: 20260730_0009
Create Date: 2026-07-30
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import op

revision: str = "20260730_0010"
down_revision: str | Sequence[str] | None = "20260730_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE = "datax_egress_guard"
_PASSWORD_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def _guard_password() -> str:
    raw_path = os.getenv("DES_EGRESS_GUARD_DATABASE_PASSWORD_FILE")
    if not raw_path:
        raise RuntimeError(
            "DES_EGRESS_GUARD_DATABASE_PASSWORD_FILE is required for migration 0010"
        )
    path = Path(raw_path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise RuntimeError("egress guard database password path is unsafe")
    try:
        raw_password = path.read_bytes()
        password = raw_password.decode("ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError("egress guard database password is unreadable") from exc
    if len(raw_password) != 64:
        raise RuntimeError(
            "egress guard database password must be exactly 64 bytes without a newline"
        )
    if _PASSWORD_PATTERN.fullmatch(password) is None:
        raise RuntimeError(
            "egress guard database password must be 32 random bytes encoded as lowercase hex"
        )
    return password


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("egress guard read model requires PostgreSQL")
    password = _guard_password()
    database_name = bind.execute(sa.text("SELECT current_database()")).scalar_one()
    quoted_database = bind.dialect.identifier_preparer.quote(database_name)

    op.execute(
        """
        CREATE VIEW des_egress_guard_active_rules_v1
        WITH (security_barrier = true)
        AS
        SELECT
            revision.id AS revision_id,
            revision.policy_hash,
            revision.resolver_policy_version,
            revision.egress_policy_version,
            revision.allowed_cidrs,
            revision.allowed_ports
        FROM endpoint_policies AS policy
        JOIN endpoint_policy_revisions AS revision
          ON revision.id = policy.current_revision_id
         AND revision.endpoint_policy_id = policy.id
        WHERE policy.status = 'ACTIVE'
        """
    )
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = '{_ROLE}'
            ) THEN
                CREATE ROLE {_ROLE}
                    LOGIN
                    NOSUPERUSER
                    NOCREATEDB
                    NOCREATEROLE
                    NOINHERIT
                    NOREPLICATION
                    CONNECTION LIMIT 2
                    PASSWORD '{password}';
            ELSE
                ALTER ROLE {_ROLE}
                    WITH LOGIN
                    NOSUPERUSER
                    NOCREATEDB
                    NOCREATEROLE
                    NOINHERIT
                    NOREPLICATION
                    CONNECTION LIMIT 2
                    PASSWORD '{password}';
            END IF;
        END
        $$;
        """
    )
    op.execute(f"REVOKE ALL ON SCHEMA public FROM {_ROLE}")
    op.execute(
        f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {_ROLE}"
    )
    op.execute(f"GRANT CONNECT ON DATABASE {quoted_database} TO {_ROLE}")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {_ROLE}")
    op.execute(
        f"GRANT SELECT ON TABLE des_egress_guard_active_rules_v1 TO {_ROLE}"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"REVOKE ALL ON TABLES FROM {_ROLE}"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("egress guard read model requires PostgreSQL")
    database_name = bind.execute(sa.text("SELECT current_database()")).scalar_one()
    quoted_database = bind.dialect.identifier_preparer.quote(database_name)
    op.execute(f"REVOKE CONNECT ON DATABASE {quoted_database} FROM {_ROLE}")
    op.execute(f"DROP OWNED BY {_ROLE}")
    op.execute("DROP VIEW des_egress_guard_active_rules_v1")
    op.execute(f"DROP ROLE {_ROLE}")
