from __future__ import annotations

import os
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import DBAPIError

POSTGRES_URL = os.getenv("DATAX_MIGRATION_POSTGRES_TEST_URL")
API_POSTGRES_URL = os.getenv("DATAX_API_POSTGRES_TEST_URL")
WORKER_POSTGRES_URL = os.getenv("DATAX_WORKER_POSTGRES_TEST_URL")
_RUNTIME_ROLES = ("datax_api", "datax_worker")
_LEDGER_SCHEMA = "des_phase_a_qualification"
_LEDGER_TABLES = (
    "phase_a_qualification_nonces",
    "phase_a_qualification_grants",
)
_TABLE_PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="DATAX_MIGRATION_POSTGRES_TEST_URL is not configured",
)


def _assert_sqlstate(error: DBAPIError, expected: str) -> None:
    assert getattr(error.orig, "sqlstate", None) == expected


def _assert_runtime_roles_have_no_ledger_table_privileges(
    connection: Connection,
) -> None:
    roles = set(
        connection.execute(
            text(
                "SELECT rolname FROM pg_roles "
                "WHERE rolname IN ('datax_api', 'datax_worker')"
            )
        ).scalars()
    )
    assert roles == set(_RUNTIME_ROLES)

    for role in _RUNTIME_ROLES:
        for privilege in ("USAGE", "CREATE"):
            assert connection.execute(
                text("SELECT has_schema_privilege(:role, :schema_name, :privilege)"),
                {
                    "role": role,
                    "schema_name": _LEDGER_SCHEMA,
                    "privilege": privilege,
                },
            ).scalar_one() is False
        for table_name in _LEDGER_TABLES:
            for privilege in _TABLE_PRIVILEGES:
                assert connection.execute(
                    text(
                        "SELECT has_table_privilege("
                        ":role, :table_name, :privilege)"
                    ),
                    {
                        "role": role,
                        "table_name": f"{_LEDGER_SCHEMA}.{table_name}",
                        "privilege": privilege,
                    },
                ).scalar_one() is False


def _insert_nonce(
    connection: Connection,
    *,
    nonce_id: UUID,
    issuer_key_id: str,
    nonce_sha256: str,
    qualification_id: str,
    payload_root_sha256: str,
) -> dict[str, object]:
    return dict(
        connection.execute(
            text(
                """
                WITH database_clock AS (
                    SELECT clock_timestamp() AS now
                )
                INSERT INTO des_phase_a_qualification.phase_a_qualification_nonces
                    (
                        id, issuer_key_id, nonce_sha256, qualification_id,
                        payload_root_sha256, valid_until, consumed_at, created_at
                    )
                SELECT
                    :nonce_id, :issuer_key_id, :nonce_sha256, :qualification_id,
                    :payload_root_sha256,
                    database_clock.now + INTERVAL '15 minutes',
                    database_clock.now - INTERVAL '1 second',
                    database_clock.now - INTERVAL '1 second'
                FROM database_clock
                RETURNING id, created_at, consumed_at, valid_until
                """
            ),
            {
                "nonce_id": nonce_id,
                "issuer_key_id": issuer_key_id,
                "nonce_sha256": nonce_sha256,
                "qualification_id": qualification_id,
                "payload_root_sha256": payload_root_sha256,
            },
        )
        .mappings()
        .one()
    )


def _insert_grant(
    connection: Connection,
    *,
    grant_id: UUID,
    nonce_id: UUID,
) -> dict[str, object]:
    return dict(
        connection.execute(
            text(
                    """
                    WITH database_clock AS (
                        SELECT clock_timestamp() AS now
                    )
                INSERT INTO des_phase_a_qualification.phase_a_qualification_grants
                    (
                        id, nonce_id, payload_binding_sha256,
                        payload_root_sha256, candidate_commit, worker_image_digest,
                        datax_release, runtime_sha256, reader_plugin_name,
                        reader_plugin_sha256, writer_plugin_name, writer_plugin_sha256,
                        harness_identity, harness_environment_id,
                        harness_environment_manifest_sha256, harness_version,
                        qh_document_sha256, qh_qualification_id, qh_issuer_key_id,
                        qh_issued_at, qh_not_before, qh_valid_until, state,
                        created_at, revoked_at, revocation_reason, expired_at
                    )
                    SELECT
                    :grant_id, nonce.id, :payload_binding_sha256,
                    nonce.payload_root_sha256, :candidate_commit,
                    :worker_image_digest, 'datax_v202309', :runtime_sha256,
                    'mysqlreader', :reader_plugin_sha256,
                    'postgresqlwriter', :writer_plugin_sha256,
                    'phase-a-e2-harness', 'phase-a-e2-environment',
                    :harness_environment_manifest_sha256, '1.0.0+e2',
                    :qh_document_sha256, nonce.qualification_id,
                    nonce.issuer_key_id,
                    database_clock.now - INTERVAL '1 minute',
                    database_clock.now - INTERVAL '30 seconds', nonce.valid_until,
                    'ACTIVE', database_clock.now, NULL, NULL, NULL
                FROM des_phase_a_qualification.phase_a_qualification_nonces AS nonce
                CROSS JOIN database_clock
                WHERE nonce.id = :nonce_id
                RETURNING id, nonce_id, state, created_at, qh_valid_until
                """
            ),
            {
                "grant_id": grant_id,
                "nonce_id": nonce_id,
                "payload_binding_sha256": "b" * 64,
                "candidate_commit": "c" * 40,
                "worker_image_digest": f"sha256:{'d' * 64}",
                "runtime_sha256": "e" * 64,
                "reader_plugin_sha256": "f" * 64,
                "writer_plugin_sha256": "a" * 64,
                "harness_environment_manifest_sha256": "b" * 64,
                "qh_document_sha256": "c" * 64,
            },
        )
        .mappings()
        .one()
    )


def _assert_runtime_login_is_denied_ledger_dml(url: str) -> None:
    engine = create_engine(url, pool_pre_ping=True)
    try:
        for table_name in _LEDGER_TABLES:
            qualified_table = f"{_LEDGER_SCHEMA}.{table_name}"
            for statement in (
                f"SELECT * FROM {qualified_table} LIMIT 1",
                f"INSERT INTO {qualified_table} DEFAULT VALUES",
                f"UPDATE {qualified_table} SET id = id WHERE FALSE",
                f"DELETE FROM {qualified_table} WHERE FALSE",
                f"TRUNCATE {qualified_table}",
            ):
                with engine.connect() as connection:
                    with pytest.raises(DBAPIError) as failure:
                        connection.execute(text(statement))
                    _assert_sqlstate(failure.value, "42501")
    finally:
        engine.dispose()


@pytest.mark.skipif(
    not API_POSTGRES_URL or not WORKER_POSTGRES_URL,
    reason="runtime PostgreSQL role URLs are not configured",
)
def test_runtime_role_logins_cannot_read_or_mutate_private_phase_a_ledger() -> None:
    assert API_POSTGRES_URL is not None
    assert WORKER_POSTGRES_URL is not None
    _assert_runtime_login_is_denied_ledger_dml(API_POSTGRES_URL)
    _assert_runtime_login_is_denied_ledger_dml(WORKER_POSTGRES_URL)


def test_phase_a_qualification_ledger_enforces_real_postgresql_guards() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    nonce_id = uuid4()
    grant_id = uuid4()
    issuer_key_id = "hqa-e2-key-0001"
    qualification_id = "qh-e2-qualification-0001"
    nonce_sha256 = "a" * 64
    payload_root_sha256 = "b" * 64

    try:
        with engine.begin() as connection:
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == "20260802_0020"
            _assert_runtime_roles_have_no_ledger_table_privileges(connection)

            nonce = _insert_nonce(
                connection,
                nonce_id=nonce_id,
                issuer_key_id=issuer_key_id,
                nonce_sha256=nonce_sha256,
                qualification_id=qualification_id,
                payload_root_sha256=payload_root_sha256,
            )
            assert nonce["id"] == nonce_id
            assert nonce["created_at"] <= nonce["consumed_at"] < nonce["valid_until"]

            grant = _insert_grant(connection, grant_id=grant_id, nonce_id=nonce_id)
            assert grant["id"] == grant_id
            assert grant["nonce_id"] == nonce_id
            assert grant["state"] == "ACTIVE"
            assert grant["created_at"] < grant["qh_valid_until"]

        with (
            pytest.raises(DBAPIError, match="nonce ledger is append-only") as failure,
            engine.begin() as connection,
        ):
            connection.execute(
                text(
                    "UPDATE des_phase_a_qualification.phase_a_qualification_nonces "
                    "SET qualification_id = 'qh-e2-mutated-0001' "
                    "WHERE id = :nonce_id"
                ),
                {"nonce_id": nonce_id},
            )
        _assert_sqlstate(failure.value, "55000")

        with pytest.raises(DBAPIError) as failure, engine.begin() as connection:
            _insert_nonce(
                connection,
                nonce_id=uuid4(),
                issuer_key_id=issuer_key_id,
                nonce_sha256=nonce_sha256,
                qualification_id="qh-e2-replay-0001",
                payload_root_sha256=payload_root_sha256,
            )
        _assert_sqlstate(failure.value, "23505")
        assert "uq_phase_a_qualification_nonces_issuer_nonce" in str(failure.value)

        with (
            pytest.raises(
                DBAPIError,
                match="qualification bindings are immutable",
            ) as failure,
            engine.begin() as connection,
        ):
            connection.execute(
                text(
                    "UPDATE des_phase_a_qualification.phase_a_qualification_grants "
                    "SET reader_plugin_name = 'postgresqlreader' "
                    "WHERE id = :grant_id"
                ),
                {"grant_id": grant_id},
            )
        _assert_sqlstate(failure.value, "55000")

        with engine.begin() as connection:
            revoked = connection.execute(
                text(
                    """
                    UPDATE des_phase_a_qualification.phase_a_qualification_grants
                    SET state = 'REVOKED',
                        revoked_at = clock_timestamp(),
                        revocation_reason = 'TEST_REVOKED'
                    WHERE id = :grant_id
                    RETURNING state, revoked_at, revocation_reason, qh_valid_until
                    """
                ),
                {"grant_id": grant_id},
            ).mappings().one()
            assert revoked["state"] == "REVOKED"
            assert revoked["revocation_reason"] == "TEST_REVOKED"
            assert revoked["revoked_at"] < revoked["qh_valid_until"]
    finally:
        engine.dispose()
