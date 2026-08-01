"""separate runtime database login roles from the migration owner

Revision ID: 20260731_0013
Revises: 20260731_0012
Create Date: 2026-07-31
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import op

revision: str = "20260731_0013"
down_revision: str | Sequence[str] | None = "20260731_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_API_ROLE = "datax_api"
_WORKER_ROLE = "datax_worker"
_RUNTIME_ROLES = {
    _API_ROLE: ("DES_API_DATABASE_PASSWORD_FILE", 24),
    _WORKER_ROLE: ("DES_WORKER_DATABASE_PASSWORD_FILE", 8),
}
_RELATED_SECRET_ENVIRONMENTS = (
    "DES_DATABASE_PASSWORD_FILE",
    "DES_EGRESS_GUARD_DATABASE_PASSWORD_FILE",
)
_PASSWORD_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def _read_password(environment_name: str) -> str:
    raw_path = os.getenv(environment_name)
    if not raw_path:
        raise RuntimeError(f"{environment_name} is required for migration 0013")
    path = Path(raw_path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{environment_name} path is unsafe")
    try:
        raw_password = path.read_bytes()
        password = raw_password.decode("ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"{environment_name} is unreadable") from exc
    if len(raw_password) != 64 or _PASSWORD_PATTERN.fullmatch(password) is None:
        raise RuntimeError(
            f"{environment_name} must contain exactly 32 random bytes "
            "encoded as lowercase hex without a newline"
        )
    return password


def _runtime_passwords() -> dict[str, str]:
    passwords = {
        role: _read_password(environment_name)
        for role, (environment_name, _limit) in _RUNTIME_ROLES.items()
    }
    related = [
        _read_password(environment_name)
        for environment_name in _RELATED_SECRET_ENVIRONMENTS
    ]
    all_passwords = [*passwords.values(), *related]
    if len(set(all_passwords)) != len(all_passwords):
        raise RuntimeError(
            "migration owner, API, Worker, and egress guard database "
            "passwords must all be independent"
        )
    return passwords


def _quoted_identifier(bind: sa.engine.Connection, value: str) -> str:
    return bind.dialect.identifier_preparer.quote(value)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("runtime database roles require PostgreSQL")
    passwords = _runtime_passwords()
    database_name = bind.execute(sa.text("SELECT current_database()")).scalar_one()
    migration_owner = bind.execute(sa.text("SELECT current_user")).scalar_one()
    quoted_database = _quoted_identifier(bind, database_name)
    quoted_owner = _quoted_identifier(bind, migration_owner)

    op.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    op.execute(
        f"REVOKE CONNECT, TEMPORARY ON DATABASE {quoted_database} FROM PUBLIC"
    )
    for role, (_environment_name, connection_limit) in _RUNTIME_ROLES.items():
        password = passwords[role]
        op.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = '{role}'
                ) THEN
                    CREATE ROLE {role}
                        LOGIN
                        NOSUPERUSER
                        NOCREATEDB
                        NOCREATEROLE
                        NOINHERIT
                        NOREPLICATION
                        CONNECTION LIMIT {connection_limit}
                        PASSWORD '{password}';
                ELSE
                    ALTER ROLE {role}
                        WITH LOGIN
                        NOSUPERUSER
                        NOCREATEDB
                        NOCREATEROLE
                        NOINHERIT
                        NOREPLICATION
                        CONNECTION LIMIT {connection_limit}
                        PASSWORD '{password}';
                END IF;
            END
            $$;
            """
        )
        op.execute(f"REVOKE ALL ON DATABASE {quoted_database} FROM {role}")
        op.execute(f"REVOKE ALL ON SCHEMA public FROM {role}")
        op.execute(
            f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {role}"
        )
        op.execute(
            f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {role}"
        )
        op.execute(f"GRANT CONNECT ON DATABASE {quoted_database} TO {role}")
        op.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
        op.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE "
            f"ON ALL TABLES IN SCHEMA public TO {role}"
        )
        op.execute(
            f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner} "
            f"IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE "
            f"ON TABLES TO {role}"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner} "
            f"IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {role}"
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("runtime database roles require PostgreSQL")
    database_name = bind.execute(sa.text("SELECT current_database()")).scalar_one()
    migration_owner = bind.execute(sa.text("SELECT current_user")).scalar_one()
    quoted_database = _quoted_identifier(bind, database_name)
    quoted_owner = _quoted_identifier(bind, migration_owner)

    for role in _RUNTIME_ROLES:
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner} "
            f"IN SCHEMA public REVOKE ALL ON TABLES FROM {role}"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner} "
            f"IN SCHEMA public REVOKE ALL ON SEQUENCES FROM {role}"
        )
        op.execute(f"REVOKE CONNECT ON DATABASE {quoted_database} FROM {role}")
        op.execute(f"DROP OWNED BY {role}")
        op.execute(f"DROP ROLE {role}")
