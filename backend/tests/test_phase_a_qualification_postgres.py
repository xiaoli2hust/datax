from __future__ import annotations

import os
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import DBAPIError

POSTGRES_URL = os.getenv("DATAX_MIGRATION_POSTGRES_TEST_URL")
API_POSTGRES_URL = os.getenv("DATAX_API_POSTGRES_TEST_URL")
WORKER_POSTGRES_URL = os.getenv("DATAX_WORKER_POSTGRES_TEST_URL")
ISSUER_POSTGRES_URL = os.getenv("DATAX_PHASE_A_ISSUER_POSTGRES_TEST_URL")
CONSUMER_POSTGRES_URL = os.getenv("DATAX_PHASE_A_CONSUMER_POSTGRES_TEST_URL")
_RUNTIME_ROLES = ("datax_api", "datax_worker")
_PRIVATE_ROLES = (
    "datax_phase_a_ledger_owner",
    "datax_phase_a_issuer",
    "datax_phase_a_consumer",
)
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
_FUNCTION_SIGNATURES = {
    "issue": (
        "des_phase_a_qualification.des_issue_phase_a_qualification_grant("
        "uuid,uuid,text,text,text,text,text,text,text,text,text,text,text,text,"
        "text,text,text,text,text,timestamp with time zone,timestamp with time zone,"
        "timestamp with time zone)"
    ),
    "revoke": "des_phase_a_qualification.des_revoke_phase_a_qualification_grant(uuid,text)",
    "read": "des_phase_a_qualification.des_read_active_phase_a_qualification_grant(uuid)",
}

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


def _assert_private_roles_and_functions_are_narrowly_granted(
    connection: Connection,
) -> None:
    roles = {
        row.rolname: row
        for row in connection.execute(
            text(
                "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolinherit, "
                "rolreplication, rolbypassrls, rolconnlimit "
                "FROM pg_roles WHERE rolname = ANY(:roles)"
            ),
            {"roles": list(_PRIVATE_ROLES)},
        )
    }
    assert set(roles) == set(_PRIVATE_ROLES)
    for role in roles.values():
        assert role.rolsuper is False
        assert role.rolcreatedb is False
        assert role.rolcreaterole is False
        assert role.rolinherit is False
        assert role.rolreplication is False
        assert role.rolbypassrls is False
        assert role.rolconnlimit == 1

    memberships = set(
        connection.execute(
            text(
                "SELECT member_role.rolname, parent_role.rolname "
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS member_role ON member_role.oid = membership.member "
                "JOIN pg_roles AS parent_role ON parent_role.oid = membership.roleid "
                "WHERE member_role.rolname = ANY(:roles) "
                "OR parent_role.rolname = ANY(:roles)"
            ),
            {"roles": list(_PRIVATE_ROLES)},
        )
    )
    assert memberships == set()

    functions = {
        row.proname: row
        for row in connection.execute(
            text(
                "SELECT procedure.proname, procedure.prosecdef, owner_role.rolname AS owner, "
                "procedure.proconfig "
                "FROM pg_proc AS procedure "
                "JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace "
                "JOIN pg_roles AS owner_role ON owner_role.oid = procedure.proowner "
                "WHERE namespace.nspname = :schema_name "
                "AND procedure.proname = ANY(:names)"
            ),
            {
                "schema_name": _LEDGER_SCHEMA,
                "names": [
                    "des_issue_phase_a_qualification_grant",
                    "des_revoke_phase_a_qualification_grant",
                    "des_read_active_phase_a_qualification_grant",
                ],
            },
        )
    }
    assert set(functions) == {
        "des_issue_phase_a_qualification_grant",
        "des_revoke_phase_a_qualification_grant",
        "des_read_active_phase_a_qualification_grant",
    }
    for function in functions.values():
        assert function.prosecdef is True
        assert function.owner == "datax_phase_a_ledger_owner"
        assert "search_path=pg_catalog, pg_temp" in str(function.proconfig)

    expected_function_privileges = {
        "datax_phase_a_issuer": {"issue", "revoke"},
        "datax_phase_a_consumer": {"read"},
        "datax_api": set(),
        "datax_worker": set(),
        "datax_egress_guard": set(),
    }
    for role, allowed in expected_function_privileges.items():
        for operation, signature in _FUNCTION_SIGNATURES.items():
            assert connection.execute(
                text(
                    "SELECT has_function_privilege("
                    ":role, to_regprocedure(:signature), 'EXECUTE')"
                ),
                {"role": role, "signature": signature},
            ).scalar_one() is (operation in allowed)


def _assert_ledger_owner_future_function_is_not_public(connection: Connection) -> None:
    """Prove the owner-wide default ACL beats PostgreSQL's PUBLIC EXECUTE default."""

    probe = "des_phase_a_qualification.des_phase_a_default_privilege_probe"
    connection.execute(text("SET LOCAL ROLE datax_phase_a_ledger_owner"))
    connection.execute(
        text(
            f"""
            CREATE FUNCTION {probe}()
            RETURNS boolean
            LANGUAGE sql
            AS $$ SELECT true $$
            """
        )
    )
    connection.execute(text("RESET ROLE"))
    assert connection.execute(
        text(
            "SELECT NOT EXISTS ("
            "SELECT 1 FROM pg_proc AS procedure "
            "CROSS JOIN LATERAL aclexplode("
            "COALESCE(procedure.proacl, acldefault('f', procedure.proowner))"
            ") AS privilege "
            "WHERE procedure.oid = to_regprocedure(:signature) "
            "AND privilege.grantee = 0 "
            "AND privilege.privilege_type = 'EXECUTE'"
            ")"
        ),
        {"signature": f"{probe}()"},
    ).scalar_one() is True
    connection.execute(text(f"DROP FUNCTION {probe}()"))


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


def _assert_login_is_denied_ledger_dml(url: str) -> None:
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


def _assert_login_is_denied_function(url: str, statement: str) -> None:
    engine = create_engine(url, pool_pre_ping=True)
    try:
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
    _assert_login_is_denied_ledger_dml(API_POSTGRES_URL)
    _assert_login_is_denied_ledger_dml(WORKER_POSTGRES_URL)
    _assert_login_is_denied_function(
        API_POSTGRES_URL,
        "SELECT * FROM des_phase_a_qualification."
        "des_read_active_phase_a_qualification_grant(NULL::uuid)",
    )
    _assert_login_is_denied_function(
        WORKER_POSTGRES_URL,
        "SELECT * FROM des_phase_a_qualification."
        "des_read_active_phase_a_qualification_grant(NULL::uuid)",
    )


@pytest.mark.skipif(
    not ISSUER_POSTGRES_URL or not CONSUMER_POSTGRES_URL,
    reason="private Phase-A issuer and consumer PostgreSQL role URLs are not configured",
)
def test_private_phase_a_role_logins_only_issue_revoke_or_read_via_exact_functions() -> None:
    assert POSTGRES_URL is not None
    assert ISSUER_POSTGRES_URL is not None
    assert CONSUMER_POSTGRES_URL is not None
    owner = create_engine(POSTGRES_URL, pool_pre_ping=True)
    issuer = create_engine(ISSUER_POSTGRES_URL, pool_pre_ping=True)
    consumer = create_engine(CONSUMER_POSTGRES_URL, pool_pre_ping=True)
    grant_id = uuid4()
    replay_grant_id = uuid4()
    nonce_id = uuid4()
    try:
        with owner.connect() as connection:
            _assert_private_roles_and_functions_are_narrowly_granted(connection)
        with owner.begin() as connection:
            _assert_ledger_owner_future_function_is_not_public(connection)

        _assert_login_is_denied_ledger_dml(ISSUER_POSTGRES_URL)
        _assert_login_is_denied_ledger_dml(CONSUMER_POSTGRES_URL)
        _assert_login_is_denied_function(
            ISSUER_POSTGRES_URL,
            "SELECT * FROM des_phase_a_qualification."
            "des_read_active_phase_a_qualification_grant(NULL::uuid)",
        )
        _assert_login_is_denied_function(
            CONSUMER_POSTGRES_URL,
            "SELECT des_phase_a_qualification."
            "des_revoke_phase_a_qualification_grant(NULL::uuid, 'TEST_REVOKED')",
        )
        with issuer.connect() as connection:
            with pytest.raises(DBAPIError) as failure:
                connection.execute(text("SET ROLE datax_phase_a_ledger_owner"))
            _assert_sqlstate(failure.value, "42501")

        issue_statement = text(
            """
            SELECT des_phase_a_qualification.des_issue_phase_a_qualification_grant(
                :grant_id, :nonce_id, :nonce_sha256, :payload_binding_sha256,
                :payload_root_sha256, :candidate_commit, :worker_image_digest,
                :runtime_sha256, 'mysqlreader', :reader_plugin_sha256,
                'postgresqlwriter', :writer_plugin_sha256, 'phase-a-e2-harness',
                'phase-a-e2-environment', :harness_environment_manifest_sha256,
                '1.0.0+e2', :qh_document_sha256, 'qh-e2-qualification-issuer-0001',
                'hqa-e2-key-issuer-0001', clock_timestamp() - INTERVAL '2 minutes',
                clock_timestamp() - INTERVAL '1 minute',
                clock_timestamp() + INTERVAL '15 minutes'
            )
            """
        )
        parameters = {
            "grant_id": grant_id,
            "nonce_id": nonce_id,
            "nonce_sha256": "1" * 64,
            "payload_binding_sha256": "2" * 64,
            "payload_root_sha256": "3" * 64,
            "candidate_commit": "4" * 40,
            "worker_image_digest": f"sha256:{'5' * 64}",
            "runtime_sha256": "6" * 64,
            "reader_plugin_sha256": "7" * 64,
            "writer_plugin_sha256": "8" * 64,
            "harness_environment_manifest_sha256": "9" * 64,
            "qh_document_sha256": "a" * 64,
        }
        with issuer.begin() as connection:
            assert connection.execute(issue_statement, parameters).scalar_one() == grant_id

        with consumer.begin() as connection:
            row = connection.execute(
                text(
                    "SELECT * FROM des_phase_a_qualification."
                    "des_read_active_phase_a_qualification_grant(:grant_id)"
                ),
                {"grant_id": grant_id},
            ).mappings().one()
            assert row["grant_id"] == grant_id
            assert row["nonce_sha256"] == parameters["nonce_sha256"]
            assert row["qh_qualification_id"] == "qh-e2-qualification-issuer-0001"

        with pytest.raises(DBAPIError) as failure, issuer.begin() as connection:
            connection.execute(
                issue_statement,
                {**parameters, "grant_id": replay_grant_id},
            )
        _assert_sqlstate(failure.value, "P0001")
        with owner.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT count(*) FROM des_phase_a_qualification."
                    "phase_a_qualification_nonces WHERE id = :nonce_id"
                ),
                {"nonce_id": nonce_id},
            ).scalar_one() == 1
            assert connection.execute(
                text(
                    "SELECT count(*) FROM des_phase_a_qualification."
                    "phase_a_qualification_grants WHERE id = ANY(:grant_ids)"
                ),
                {"grant_ids": [grant_id, replay_grant_id]},
            ).scalar_one() == 1

        with issuer.begin() as connection:
            assert connection.execute(
                text(
                    "SELECT des_phase_a_qualification."
                    "des_revoke_phase_a_qualification_grant(:grant_id, 'TEST_REVOKED')"
                ),
                {"grant_id": grant_id},
            ).scalar_one() is True
        with consumer.begin() as connection:
            assert connection.execute(
                text(
                    "SELECT * FROM des_phase_a_qualification."
                    "des_read_active_phase_a_qualification_grant(:grant_id)"
                ),
                {"grant_id": grant_id},
            ).mappings().one_or_none() is None
    finally:
        issuer.dispose()
        consumer.dispose()
        owner.dispose()


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
            ).scalar_one() == "20260802_0022"
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
