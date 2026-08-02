from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

OWNER_URL_ENV = "DATAX_MIGRATION_POSTGRES_TEST_URL"
GUARD_URL_ENV = "DATAX_EGRESS_GUARD_POSTGRES_TEST_URL"


def test_egress_guard_role_can_only_read_the_security_barrier_view() -> None:
    owner_url = os.getenv(OWNER_URL_ENV)
    guard_url = os.getenv(GUARD_URL_ENV)
    if not owner_url or not guard_url:
        pytest.skip(f"{OWNER_URL_ENV} and {GUARD_URL_ENV} are required")

    owner = create_engine(owner_url, pool_pre_ping=True)
    guard = create_engine(
        guard_url,
        pool_pre_ping=True,
        isolation_level="AUTOCOMMIT",
    )
    try:
        with owner.connect() as connection:
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == "20260802_0019"
            reloptions = connection.execute(
                text(
                    "SELECT reloptions FROM pg_class "
                    "WHERE relname = 'des_egress_guard_active_rules_v1'"
                )
            ).scalar_one()
            assert "security_barrier=true" in reloptions

        with guard.connect() as connection:
            assert connection.execute(text("SELECT current_user")).scalar_one() == (
                "datax_egress_guard"
            )
            assert connection.execute(
                text("SELECT count(*) FROM des_egress_guard_active_rules_v1")
            ).scalar_one() == 0
            for statement in (
                "SELECT count(*) FROM endpoint_policies",
                "CREATE TABLE guard_must_not_create(id integer)",
                "INSERT INTO endpoint_policies DEFAULT VALUES",
            ):
                with pytest.raises(DBAPIError) as failure:
                    connection.execute(text(statement))
                assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    finally:
        guard.dispose()
        owner.dispose()
