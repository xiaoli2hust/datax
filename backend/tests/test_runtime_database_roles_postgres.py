from __future__ import annotations

import os
import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

OWNER_URL_ENV = "DATAX_MIGRATION_POSTGRES_TEST_URL"
API_URL_ENV = "DATAX_API_POSTGRES_TEST_URL"
WORKER_URL_ENV = "DATAX_WORKER_POSTGRES_TEST_URL"


def test_runtime_database_roles_have_dml_but_no_ddl_authority() -> None:
    owner_url = os.getenv(OWNER_URL_ENV)
    api_url = os.getenv(API_URL_ENV)
    worker_url = os.getenv(WORKER_URL_ENV)
    if not owner_url or not api_url or not worker_url:
        pytest.skip(
            f"{OWNER_URL_ENV}, {API_URL_ENV}, and {WORKER_URL_ENV} are required"
        )

    owner = create_engine(owner_url, pool_pre_ping=True)
    runtime_engines = {
        "datax_api": create_engine(
            api_url,
            pool_pre_ping=True,
            isolation_level="AUTOCOMMIT",
        ),
        "datax_worker": create_engine(
            worker_url,
            pool_pre_ping=True,
            isolation_level="AUTOCOMMIT",
        ),
    }
    try:
        with owner.connect() as connection:
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == "20260802_0018"
            roles = {
                row.rolname: row
                for row in connection.execute(
                    text(
                        "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, "
                        "rolinherit, rolreplication, rolconnlimit "
                        "FROM pg_roles "
                        "WHERE rolname IN ('datax_api', 'datax_worker')"
                    )
                )
            }
            assert set(roles) == set(runtime_engines)
            assert roles["datax_worker"].rolconnlimit == 12
            for row in roles.values():
                assert row.rolsuper is False
                assert row.rolcreatedb is False
                assert row.rolcreaterole is False
                assert row.rolinherit is False
                assert row.rolreplication is False
            for role in runtime_engines:
                assert connection.execute(
                    text(
                        "SELECT has_database_privilege("
                        ":role, current_database(), 'TEMP')"
                    ),
                    {"role": role},
                ).scalar_one() is False

        for role, engine in runtime_engines.items():
            with engine.connect() as connection:
                assert connection.execute(text("SELECT current_user")).scalar_one() == role
                if role == "datax_worker":
                    assert connection.execute(
                        text("SHOW idle_session_timeout")
                    ).scalar_one() == "30s"
                    assert connection.execute(
                        text("SHOW idle_in_transaction_session_timeout")
                    ).scalar_one() == "15s"
                assert connection.execute(
                    text("SELECT count(*) FROM system_control")
                ).scalar_one() == 1
                for statement in (
                    f"CREATE TABLE {role}_must_not_create(id integer)",
                    f"CREATE TEMP TABLE {role}_must_not_create_temp(id integer)",
                    "ALTER TABLE system_control ADD COLUMN must_not_add integer",
                    f"CREATE ROLE {role}_must_not_create_role",
                ):
                    with pytest.raises(DBAPIError) as failure:
                        connection.execute(text(statement))
                    assert getattr(failure.value.orig, "sqlstate", None) == "42501"
    finally:
        for engine in runtime_engines.values():
            engine.dispose()
        owner.dispose()


def test_worker_role_reclaims_abandoned_sessions() -> None:
    owner_url = os.getenv(OWNER_URL_ENV)
    worker_url = os.getenv(WORKER_URL_ENV)
    if not owner_url or not worker_url:
        pytest.skip(f"{OWNER_URL_ENV} and {WORKER_URL_ENV} are required")

    owner = create_engine(owner_url, pool_pre_ping=True)
    worker = create_engine(worker_url, pool_pre_ping=True)
    try:
        # Use a short test-only role default to prove that the PostgreSQL
        # server—not a process-local finalizer—reclaims an abandoned session.
        with owner.begin() as connection:
            connection.execute(
                text("ALTER ROLE datax_worker SET idle_session_timeout TO '1s'")
            )
            connection.execute(
                text(
                    "ALTER ROLE datax_worker "
                    "SET idle_in_transaction_session_timeout TO '15s'"
                )
            )
        with worker.connect() as connection:
            assert connection.execute(
                text("SHOW idle_session_timeout")
            ).scalar_one() == "1s"
            # SQLAlchemy autobegins for SHOW. End that transaction so the
            # server is specifically testing idle_session_timeout.
            connection.commit()
            time.sleep(2)
            with pytest.raises(DBAPIError):
                connection.execute(text("SELECT 1"))

        with owner.begin() as connection:
            connection.execute(
                text("ALTER ROLE datax_worker SET idle_session_timeout TO '30s'")
            )
            connection.execute(
                text(
                    "ALTER ROLE datax_worker "
                    "SET idle_in_transaction_session_timeout TO '1s'"
                )
            )
        with worker.connect() as connection:
            assert connection.execute(
                text("SHOW idle_in_transaction_session_timeout")
            ).scalar_one() == "1s"
            # Keep SQLAlchemy's implicit transaction open this time.
            time.sleep(2)
            with pytest.raises(DBAPIError):
                connection.execute(text("SELECT 1"))
    finally:
        with owner.begin() as connection:
            connection.execute(
                text("ALTER ROLE datax_worker SET idle_session_timeout TO '30s'")
            )
            connection.execute(
                text(
                    "ALTER ROLE datax_worker "
                    "SET idle_in_transaction_session_timeout TO '15s'"
                )
            )
        worker.dispose()
        owner.dispose()
