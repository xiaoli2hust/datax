"""establish the protected Phase-A ledger role/function boundary

Revision ID: 20260802_0021
Revises: 20260802_0020
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260802_0021"
down_revision: str | Sequence[str] | None = "20260802_0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRIVATE_SCHEMA = "des_phase_a_qualification"
_NONCE_TABLE = f"{_PRIVATE_SCHEMA}.phase_a_qualification_nonces"
_GRANT_TABLE = f"{_PRIVATE_SCHEMA}.phase_a_qualification_grants"
_LEDGER_OWNER_ROLE = "datax_phase_a_ledger_owner"
_ISSUER_ROLE = "datax_phase_a_issuer"
_CONSUMER_ROLE = "datax_phase_a_consumer"
_RUNTIME_ROLES = ("datax_api", "datax_worker", "datax_egress_guard")

_NONCE_GUARD_FUNCTION = f"{_PRIVATE_SCHEMA}.des_phase_a_qualification_nonce_guard"
_TRUNCATE_GUARD_FUNCTION = f"{_PRIVATE_SCHEMA}.des_reject_phase_a_qualification_truncate"
_GRANT_GUARD_FUNCTION = f"{_PRIVATE_SCHEMA}.des_phase_a_qualification_grant_guard"
_ISSUE_FUNCTION = f"{_PRIVATE_SCHEMA}.des_issue_phase_a_qualification_grant"
_REVOKE_FUNCTION = f"{_PRIVATE_SCHEMA}.des_revoke_phase_a_qualification_grant"
_READ_FUNCTION = f"{_PRIVATE_SCHEMA}.des_read_active_phase_a_qualification_grant"

_ISSUE_SIGNATURE = (
    "uuid, uuid, text, text, text, text, text, text, text, text, text, text, "
    "text, text, text, text, text, text, text, timestamptz, timestamptz, timestamptz"
)
_REVOKE_SIGNATURE = "uuid, text"
_READ_SIGNATURE = "uuid"


def _require_postgresql() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("Phase-A ledger roles require PostgreSQL")


def _create_no_login_role(role: str) -> None:
    op.execute(
        f"""
        CREATE ROLE {role}
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOREPLICATION
            NOBYPASSRLS
            CONNECTION LIMIT 1;
        """
    )


def upgrade() -> None:
    _require_postgresql()
    # Object ownership moves to a role that the migration owner must never
    # inherit. PostgreSQL requires superuser authority for that transfer; fail
    # before any DDL rather than creating a half-protected ledger.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A ledger migration requires a PostgreSQL superuser';
            END IF;
        END
        $$;
        """
    )

    # A previously created role with any of these names could carry a hidden
    # membership edge into the private owner.  Do not try to normalize an
    # attacker- or operator-created principal in place: it is impossible to
    # prove its prior grants/defaults/memberships were harmless.  The migration
    # is one-shot and transactional, so an existing name or any membership
    # relation is a safe, actionable hard stop.
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_roles
                WHERE rolname IN ('{_LEDGER_OWNER_ROLE}', '{_ISSUER_ROLE}', '{_CONSUMER_ROLE}')
            ) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A private ledger roles must not pre-exist';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM pg_auth_members AS membership
                JOIN pg_roles AS member_role ON member_role.oid = membership.member
                JOIN pg_roles AS parent_role ON parent_role.oid = membership.roleid
                WHERE member_role.rolname IN (
                    '{_LEDGER_OWNER_ROLE}',
                    '{_ISSUER_ROLE}',
                    '{_CONSUMER_ROLE}'
                )
                   OR parent_role.rolname IN (
                    '{_LEDGER_OWNER_ROLE}',
                    '{_ISSUER_ROLE}',
                    '{_CONSUMER_ROLE}'
                )
            ) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A private ledger role membership is not allowed';
            END IF;
        END
        $$;
        """
    )

    # Standard Compose deliberately has no credential for either caller role.
    # A future protected harness must provision a short-lived login separately;
    # leaving these roles NOLOGIN means a normal desktop start cannot turn this
    # migration into a user-configurable qualification path.
    for role in (_LEDGER_OWNER_ROLE, _ISSUER_ROLE, _CONSUMER_ROLE):
        _create_no_login_role(role)

    # No login role receives membership in this owner, including the migration
    # owner. The superuser-only migration transfers object ownership directly;
    # API, Worker, egress guard, issuer, and consumer cannot SET ROLE into it.
    op.execute(f"ALTER SCHEMA {_PRIVATE_SCHEMA} OWNER TO {_LEDGER_OWNER_ROLE}")
    for table in (_NONCE_TABLE, _GRANT_TABLE):
        op.execute(f"ALTER TABLE {table} OWNER TO {_LEDGER_OWNER_ROLE}")
    for function in (
        _NONCE_GUARD_FUNCTION,
        _TRUNCATE_GUARD_FUNCTION,
        _GRANT_GUARD_FUNCTION,
    ):
        op.execute(f"ALTER FUNCTION {function}() OWNER TO {_LEDGER_OWNER_ROLE}")

    # PostgreSQL grants PUBLIC EXECUTE on newly created functions by default.
    # Close that global default before creating Security Definer entry points.
    # A per-schema default ACL cannot override the built-in global PUBLIC
    # EXECUTE default, so this role-wide revoke is required for any later
    # protected-ledger maintenance as well.
    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {_LEDGER_OWNER_ROLE} "
        "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
    )
    for privilege_kind in ("TABLES", "SEQUENCES", "FUNCTIONS"):
        for role in ("PUBLIC", *_RUNTIME_ROLES, _ISSUER_ROLE, _CONSUMER_ROLE):
            op.execute(
                f"ALTER DEFAULT PRIVILEGES FOR ROLE {_LEDGER_OWNER_ROLE} "
                f"IN SCHEMA {_PRIVATE_SCHEMA} REVOKE ALL ON {privilege_kind} FROM {role}"
            )
    for role in ("PUBLIC", *_RUNTIME_ROLES, _ISSUER_ROLE, _CONSUMER_ROLE):
        op.execute(f"REVOKE ALL ON SCHEMA {_PRIVATE_SCHEMA} FROM {role}")
        op.execute(f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA {_PRIVATE_SCHEMA} FROM {role}")
        op.execute(
            f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA {_PRIVATE_SCHEMA} FROM {role}"
        )
        op.execute(
            f"REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA {_PRIVATE_SCHEMA} FROM {role}"
        )

    op.execute(
        f"""
        CREATE FUNCTION {_ISSUE_FUNCTION}(
            p_grant_id uuid,
            p_nonce_id uuid,
            p_nonce_sha256 text,
            p_payload_binding_sha256 text,
            p_payload_root_sha256 text,
            p_candidate_commit text,
            p_worker_image_digest text,
            p_runtime_sha256 text,
            p_reader_plugin_name text,
            p_reader_plugin_sha256 text,
            p_writer_plugin_name text,
            p_writer_plugin_sha256 text,
            p_harness_identity text,
            p_harness_environment_id text,
            p_harness_environment_manifest_sha256 text,
            p_harness_version text,
            p_qh_document_sha256 text,
            p_qh_qualification_id text,
            p_qh_issuer_key_id text,
            p_qh_issued_at timestamptz,
            p_qh_not_before timestamptz,
            p_qh_valid_until timestamptz
        )
        RETURNS uuid
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            v_now timestamptz := clock_timestamp();
            v_nonce_id uuid;
        BEGIN
            IF session_user <> '{_ISSUER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A issuer role is required';
            END IF;
            IF p_grant_id IS NULL OR p_nonce_id IS NULL
               OR p_qh_issued_at IS NULL OR p_qh_not_before IS NULL
               OR p_qh_valid_until IS NULL THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A grant input is incomplete';
            END IF;
            IF p_nonce_sha256 !~ '^[a-f0-9]{{64}}$'
               OR p_payload_binding_sha256 !~ '^[a-f0-9]{{64}}$'
               OR p_payload_root_sha256 !~ '^[a-f0-9]{{64}}$'
               OR p_runtime_sha256 !~ '^[a-f0-9]{{64}}$'
               OR p_reader_plugin_sha256 !~ '^[a-f0-9]{{64}}$'
               OR p_writer_plugin_sha256 !~ '^[a-f0-9]{{64}}$'
               OR p_harness_environment_manifest_sha256 !~ '^[a-f0-9]{{64}}$'
               OR p_qh_document_sha256 !~ '^[a-f0-9]{{64}}$'
               OR p_candidate_commit !~ '^[a-f0-9]{{40}}$'
               OR p_worker_image_digest !~ '^sha256:[a-f0-9]{{64}}$'
               OR p_reader_plugin_name NOT IN ('mysqlreader', 'postgresqlreader')
               OR p_writer_plugin_name NOT IN ('mysqlwriter', 'postgresqlwriter')
               OR p_harness_identity !~ '^[A-Za-z0-9._-]{{8,128}}$'
               OR p_harness_environment_id !~ '^[A-Za-z0-9._-]{{8,128}}$'
               OR p_harness_version !~ '^[A-Za-z0-9._+-]{{1,128}}$'
               OR p_qh_qualification_id !~ '^[A-Za-z0-9._-]{{8,128}}$'
               OR p_qh_issuer_key_id !~ '^[A-Za-z0-9._-]{{8,128}}$' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A grant binding is invalid';
            END IF;
            IF p_qh_issued_at > p_qh_not_before
               OR p_qh_not_before > v_now
               OR p_qh_valid_until <= v_now
               OR p_qh_not_before >= p_qh_valid_until
               OR p_qh_valid_until > p_qh_issued_at + INTERVAL '24 hours' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A grant QH window is invalid';
            END IF;

            INSERT INTO {_NONCE_TABLE}
                (
                    id, issuer_key_id, nonce_sha256, qualification_id,
                    payload_root_sha256, valid_until, consumed_at, created_at
                )
            VALUES
                (
                    p_nonce_id, p_qh_issuer_key_id, p_nonce_sha256,
                    p_qh_qualification_id, p_payload_root_sha256,
                    p_qh_valid_until, v_now, v_now
                )
            ON CONFLICT DO NOTHING
            RETURNING id INTO v_nonce_id;
            IF v_nonce_id IS NULL THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A QH nonce was already consumed';
            END IF;

            INSERT INTO {_GRANT_TABLE}
                (
                    id, nonce_id, payload_binding_sha256, payload_root_sha256,
                    candidate_commit, worker_image_digest, datax_release,
                    runtime_sha256, reader_plugin_name, reader_plugin_sha256,
                    writer_plugin_name, writer_plugin_sha256, harness_identity,
                    harness_environment_id, harness_environment_manifest_sha256,
                    harness_version, qh_document_sha256, qh_qualification_id,
                    qh_issuer_key_id, qh_issued_at, qh_not_before, qh_valid_until,
                    state, created_at, revoked_at, revocation_reason, expired_at
                )
            VALUES
                (
                    p_grant_id, v_nonce_id, p_payload_binding_sha256,
                    p_payload_root_sha256, p_candidate_commit,
                    p_worker_image_digest, 'datax_v202309', p_runtime_sha256,
                    p_reader_plugin_name, p_reader_plugin_sha256,
                    p_writer_plugin_name, p_writer_plugin_sha256,
                    p_harness_identity, p_harness_environment_id,
                    p_harness_environment_manifest_sha256, p_harness_version,
                    p_qh_document_sha256, p_qh_qualification_id,
                    p_qh_issuer_key_id, p_qh_issued_at, p_qh_not_before,
                    p_qh_valid_until, 'ACTIVE', v_now, NULL, NULL, NULL
                );
            RETURN p_grant_id;
        END;
        $$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION {_REVOKE_FUNCTION}(
            p_grant_id uuid,
            p_reason text
        )
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            v_now timestamptz := clock_timestamp();
            v_rows integer := 0;
        BEGIN
            IF session_user <> '{_ISSUER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A issuer role is required';
            END IF;
            IF p_grant_id IS NULL OR p_reason !~ '^[A-Z][A-Z0-9_]{{2,63}}$' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A grant revocation input is invalid';
            END IF;
            UPDATE {_GRANT_TABLE} AS grant_row
            SET state = 'EXPIRED', expired_at = v_now
            WHERE grant_row.id = p_grant_id
              AND grant_row.state = 'ACTIVE'
              AND grant_row.qh_valid_until <= v_now;
            UPDATE {_GRANT_TABLE}
            SET state = 'REVOKED', revoked_at = v_now, revocation_reason = p_reason
            WHERE id = p_grant_id
              AND state = 'ACTIVE'
              AND qh_valid_until > v_now;
            GET DIAGNOSTICS v_rows = ROW_COUNT;
            RETURN v_rows = 1;
        END;
        $$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION {_READ_FUNCTION}(
            p_grant_id uuid
        )
        RETURNS TABLE (
            grant_id uuid,
            nonce_sha256 text,
            payload_binding_sha256 text,
            payload_root_sha256 text,
            candidate_commit text,
            worker_image_digest text,
            datax_release text,
            runtime_sha256 text,
            reader_plugin_name text,
            reader_plugin_sha256 text,
            writer_plugin_name text,
            writer_plugin_sha256 text,
            harness_identity text,
            harness_environment_id text,
            harness_environment_manifest_sha256 text,
            harness_version text,
            qh_document_sha256 text,
            qh_qualification_id text,
            qh_issuer_key_id text,
            qh_issued_at timestamptz,
            qh_not_before timestamptz,
            qh_valid_until timestamptz
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            v_now timestamptz := clock_timestamp();
        BEGIN
            IF session_user <> '{_CONSUMER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A consumer role is required';
            END IF;
            -- A reader may only observe an active, current grant. The lifecycle
            -- update is intentionally atomic with the lookup so an expired grant
            -- cannot stay externally indistinguishable from ACTIVE forever.
            UPDATE {_GRANT_TABLE} AS grant_row
            SET state = 'EXPIRED', expired_at = v_now
            WHERE grant_row.id = p_grant_id
              AND grant_row.state = 'ACTIVE'
              AND grant_row.qh_valid_until <= v_now;

            RETURN QUERY
            SELECT
                grant_row.id,
                nonce_row.nonce_sha256::text,
                grant_row.payload_binding_sha256::text,
                grant_row.payload_root_sha256::text,
                grant_row.candidate_commit::text,
                grant_row.worker_image_digest::text,
                grant_row.datax_release::text,
                grant_row.runtime_sha256::text,
                grant_row.reader_plugin_name::text,
                grant_row.reader_plugin_sha256::text,
                grant_row.writer_plugin_name::text,
                grant_row.writer_plugin_sha256::text,
                grant_row.harness_identity::text,
                grant_row.harness_environment_id::text,
                grant_row.harness_environment_manifest_sha256::text,
                grant_row.harness_version::text,
                grant_row.qh_document_sha256::text,
                grant_row.qh_qualification_id::text,
                grant_row.qh_issuer_key_id::text,
                grant_row.qh_issued_at,
                grant_row.qh_not_before,
                grant_row.qh_valid_until
            FROM {_GRANT_TABLE} AS grant_row
            JOIN {_NONCE_TABLE} AS nonce_row ON nonce_row.id = grant_row.nonce_id
            WHERE grant_row.id = p_grant_id
              AND grant_row.state = 'ACTIVE'
              AND grant_row.qh_not_before <= v_now
              AND grant_row.qh_valid_until > v_now
            FOR UPDATE OF grant_row;
        END;
        $$;
        """
    )

    for function, signature in (
        (_ISSUE_FUNCTION, _ISSUE_SIGNATURE),
        (_REVOKE_FUNCTION, _REVOKE_SIGNATURE),
        (_READ_FUNCTION, _READ_SIGNATURE),
    ):
        op.execute(f"ALTER FUNCTION {function}({signature}) OWNER TO {_LEDGER_OWNER_ROLE}")
        for role in ("PUBLIC", *_RUNTIME_ROLES, _ISSUER_ROLE, _CONSUMER_ROLE):
            op.execute(f"REVOKE ALL PRIVILEGES ON FUNCTION {function}({signature}) FROM {role}")

    for role in (_ISSUER_ROLE, _CONSUMER_ROLE):
        op.execute(
            f"""
            DO $$
            BEGIN
                EXECUTE format(
                    'GRANT CONNECT ON DATABASE %I TO %I',
                    current_database(),
                    '{role}'
                );
            END
            $$;
            """
        )
    op.execute(f"GRANT USAGE ON SCHEMA {_PRIVATE_SCHEMA} TO {_ISSUER_ROLE}")
    op.execute(f"GRANT USAGE ON SCHEMA {_PRIVATE_SCHEMA} TO {_CONSUMER_ROLE}")
    op.execute(
        f"GRANT EXECUTE ON FUNCTION {_ISSUE_FUNCTION}({_ISSUE_SIGNATURE}) TO {_ISSUER_ROLE}"
    )
    op.execute(
        f"GRANT EXECUTE ON FUNCTION {_REVOKE_FUNCTION}({_REVOKE_SIGNATURE}) TO {_ISSUER_ROLE}"
    )
    op.execute(
        f"GRANT EXECUTE ON FUNCTION {_READ_FUNCTION}({_READ_SIGNATURE}) TO {_CONSUMER_ROLE}"
    )


def downgrade() -> None:
    _require_postgresql()
    for function, signature in (
        (_READ_FUNCTION, _READ_SIGNATURE),
        (_REVOKE_FUNCTION, _REVOKE_SIGNATURE),
        (_ISSUE_FUNCTION, _ISSUE_SIGNATURE),
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {function}({signature})")

    # Return the existing 0020 objects to the migration owner before dropping
    # the non-login owner. Migration 0020's downgrade then owns its normal
    # trigger/table/schema teardown again.
    for function in (
        _NONCE_GUARD_FUNCTION,
        _TRUNCATE_GUARD_FUNCTION,
        _GRANT_GUARD_FUNCTION,
    ):
        op.execute(f"ALTER FUNCTION {function}() OWNER TO CURRENT_USER")
    for table in (_NONCE_TABLE, _GRANT_TABLE):
        op.execute(f"ALTER TABLE {table} OWNER TO CURRENT_USER")
    op.execute(f"ALTER SCHEMA {_PRIVATE_SCHEMA} OWNER TO CURRENT_USER")

    # The owner-wide default-function ACL introduced by this revision is a
    # dependency of the owner role even after every ledger object is returned
    # above. ``DROP OWNED`` removes that ACL and any revision-owned grants;
    # subsequent migrations must already be downgraded before this one, so it
    # cannot silently erase a newer protected-ledger object.
    op.execute(f"DROP OWNED BY {_LEDGER_OWNER_ROLE}")

    for role in (_ISSUER_ROLE, _CONSUMER_ROLE):
        op.execute(
            f"""
            DO $$
            BEGIN
                EXECUTE format(
                    'REVOKE ALL ON DATABASE %I FROM %I',
                    current_database(),
                    '{role}'
                );
            END
            $$;
            """
        )
        op.execute(f"DROP OWNED BY {role}")
        op.execute(f"DROP ROLE {role}")
    op.execute(f"DROP ROLE {_LEDGER_OWNER_ROLE}")
