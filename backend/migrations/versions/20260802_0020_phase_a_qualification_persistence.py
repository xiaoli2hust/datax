"""persist protected Phase-A QH replay and grant facts

Revision ID: 20260802_0020
Revises: 20260802_0019
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0020"
down_revision: str | Sequence[str] | None = "20260802_0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_API_ROLE = "datax_api"
_WORKER_ROLE = "datax_worker"
_PRIVATE_SCHEMA = "des_phase_a_qualification"
_NONCE_TABLE = "phase_a_qualification_nonces"
_GRANT_TABLE = "phase_a_qualification_grants"
_NONCE_GUARD_FUNCTION = f"{_PRIVATE_SCHEMA}.des_phase_a_qualification_nonce_guard"
_TRUNCATE_GUARD_FUNCTION = f"{_PRIVATE_SCHEMA}.des_reject_phase_a_qualification_truncate"
_GRANT_GUARD_FUNCTION = f"{_PRIVATE_SCHEMA}.des_phase_a_qualification_grant_guard"


def _qualified(table_name: str) -> str:
    return f"{_PRIVATE_SCHEMA}.{table_name}"


def _require_postgresql() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("Phase-A qualification persistence requires PostgreSQL")


def upgrade() -> None:
    _require_postgresql()
    # This ledger is intentionally not part of public application state. A
    # schema-level boundary makes default privileges closed and lets standard
    # backup exclude table rows, trigger functions, and schema metadata as one
    # fixed unit. The migration owner remains the only current owner; no
    # issuer/consumer role is introduced by this E1 foundation.
    op.execute(f"CREATE SCHEMA {_PRIVATE_SCHEMA} AUTHORIZATION CURRENT_USER")
    op.execute(f"REVOKE ALL ON SCHEMA {_PRIVATE_SCHEMA} FROM PUBLIC")
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {_PRIVATE_SCHEMA} "
        "REVOKE ALL ON TABLES FROM PUBLIC"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {_PRIVATE_SCHEMA} "
        "REVOKE ALL ON SEQUENCES FROM PUBLIC"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {_PRIVATE_SCHEMA} "
        "REVOKE ALL ON FUNCTIONS FROM PUBLIC"
    )
    for role in (_API_ROLE, _WORKER_ROLE):
        op.execute(f"REVOKE ALL ON SCHEMA {_PRIVATE_SCHEMA} FROM {role}")
    op.create_table(
        _NONCE_TABLE,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("issuer_key_id", sa.String(length=128), nullable=False),
        # The raw QH nonce must never cross this boundary. This is its lowercase
        # hexadecimal SHA-256 digest, and the issuer/hash pair is durable.
        sa.Column("nonce_sha256", sa.String(length=64), nullable=False),
        sa.Column("qualification_id", sa.String(length=128), nullable=False),
        sa.Column("payload_root_sha256", sa.String(length=64), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "issuer_key_id",
            "nonce_sha256",
            name="uq_phase_a_qualification_nonces_issuer_nonce",
        ),
        sa.UniqueConstraint(
            "issuer_key_id",
            "qualification_id",
            name="uq_phase_a_qualification_nonces_issuer_qualification",
        ),
        sa.CheckConstraint(
            "issuer_key_id ~ '^[A-Za-z0-9._-]{8,128}$'",
            name="ck_phase_a_qualification_nonces_issuer",
        ),
        sa.CheckConstraint(
            "qualification_id ~ '^[A-Za-z0-9._-]{8,128}$'",
            name="ck_phase_a_qualification_nonces_qualification",
        ),
        sa.CheckConstraint(
            "nonce_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_phase_a_qualification_nonces_nonce_hash",
        ),
        sa.CheckConstraint(
            "payload_root_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_phase_a_qualification_nonces_payload_root",
        ),
        sa.CheckConstraint(
            "consumed_at >= created_at AND consumed_at < valid_until",
            name="ck_phase_a_qualification_nonces_timestamps",
        ),
        schema=_PRIVATE_SCHEMA,
    )
    op.create_index(
        "ix_phase_a_qualification_nonces_valid_until",
        _NONCE_TABLE,
        ["valid_until", "id"],
        schema=_PRIVATE_SCHEMA,
    )

    op.create_table(
        _GRANT_TABLE,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "nonce_id",
            sa.Uuid(),
            sa.ForeignKey(f"{_qualified(_NONCE_TABLE)}.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("payload_binding_sha256", sa.String(length=64), nullable=False),
        sa.Column("payload_root_sha256", sa.String(length=64), nullable=False),
        sa.Column("candidate_commit", sa.String(length=40), nullable=False),
        sa.Column("worker_image_digest", sa.String(length=71), nullable=False),
        sa.Column("datax_release", sa.String(length=32), nullable=False),
        sa.Column("runtime_sha256", sa.String(length=64), nullable=False),
        sa.Column("reader_plugin_name", sa.String(length=64), nullable=False),
        sa.Column("reader_plugin_sha256", sa.String(length=64), nullable=False),
        sa.Column("writer_plugin_name", sa.String(length=64), nullable=False),
        sa.Column("writer_plugin_sha256", sa.String(length=64), nullable=False),
        sa.Column("harness_identity", sa.String(length=128), nullable=False),
        sa.Column("harness_environment_id", sa.String(length=128), nullable=False),
        sa.Column(
            "harness_environment_manifest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("harness_version", sa.String(length=128), nullable=False),
        # Hash of canonical, signed QH only. Never retain the document's raw nonce.
        sa.Column("qh_document_sha256", sa.String(length=64), nullable=False),
        sa.Column("qh_qualification_id", sa.String(length=128), nullable=False),
        sa.Column("qh_issuer_key_id", sa.String(length=128), nullable=False),
        sa.Column("qh_issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("qh_not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("qh_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=64), nullable=True),
        sa.Column("expired_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("nonce_id", name="uq_phase_a_qualification_grants_nonce"),
        sa.UniqueConstraint(
            "qh_issuer_key_id",
            "qh_qualification_id",
            name="uq_phase_a_qualification_grants_issuer_qualification",
        ),
        sa.CheckConstraint(
            "state IN ('ACTIVE', 'REVOKED', 'EXPIRED')",
            name="ck_phase_a_qualification_grants_state",
        ),
        sa.CheckConstraint(
            "(state = 'ACTIVE' AND revoked_at IS NULL AND revocation_reason IS NULL "
            "AND expired_at IS NULL) OR "
            "(state = 'REVOKED' AND revoked_at IS NOT NULL "
            "AND revocation_reason IS NOT NULL AND expired_at IS NULL) OR "
            "(state = 'EXPIRED' AND revoked_at IS NULL AND revocation_reason IS NULL "
            "AND expired_at IS NOT NULL)",
            name="ck_phase_a_qualification_grants_lifecycle",
        ),
        sa.CheckConstraint(
            "qh_issued_at <= qh_not_before AND qh_not_before < qh_valid_until "
            "AND qh_valid_until <= qh_issued_at + INTERVAL '24 hours' "
            "AND created_at >= qh_not_before AND created_at < qh_valid_until",
            name="ck_phase_a_qualification_grants_qh_window",
        ),
        sa.CheckConstraint(
            "state <> 'REVOKED' OR (revoked_at >= created_at AND revoked_at < qh_valid_until)",
            name="ck_phase_a_qualification_grants_revoked_at",
        ),
        sa.CheckConstraint(
            "state <> 'EXPIRED' OR (expired_at >= created_at AND expired_at >= qh_valid_until)",
            name="ck_phase_a_qualification_grants_expired_at",
        ),
        sa.CheckConstraint(
            "payload_binding_sha256 ~ '^[a-f0-9]{64}$' "
            "AND payload_root_sha256 ~ '^[a-f0-9]{64}$' "
            "AND runtime_sha256 ~ '^[a-f0-9]{64}$' "
            "AND reader_plugin_sha256 ~ '^[a-f0-9]{64}$' "
            "AND writer_plugin_sha256 ~ '^[a-f0-9]{64}$' "
            "AND harness_environment_manifest_sha256 ~ '^[a-f0-9]{64}$' "
            "AND qh_document_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_phase_a_qualification_grants_hashes",
        ),
        sa.CheckConstraint(
            "candidate_commit ~ '^[a-f0-9]{40}$'",
            name="ck_phase_a_qualification_grants_identity",
        ),
        sa.CheckConstraint(
            "worker_image_digest ~ '^sha256:[a-f0-9]{64}$' AND datax_release = 'datax_v202309'",
            name="ck_phase_a_qualification_grants_runtime",
        ),
        sa.CheckConstraint(
            "reader_plugin_name IN ('mysqlreader', 'postgresqlreader') "
            "AND writer_plugin_name IN ('mysqlwriter', 'postgresqlwriter')",
            name="ck_phase_a_qualification_grants_plugins",
        ),
        sa.CheckConstraint(
            "harness_identity ~ '^[A-Za-z0-9._-]{8,128}$' "
            "AND harness_environment_id ~ '^[A-Za-z0-9._-]{8,128}$' "
            "AND harness_version ~ '^[A-Za-z0-9._+-]{1,128}$'",
            name="ck_phase_a_qualification_grants_harness",
        ),
        sa.CheckConstraint(
            "qh_qualification_id ~ '^[A-Za-z0-9._-]{8,128}$' "
            "AND qh_issuer_key_id ~ '^[A-Za-z0-9._-]{8,128}$' "
            "AND (revocation_reason IS NULL "
            "OR revocation_reason ~ '^[A-Z][A-Z0-9_]{2,63}$')",
            name="ck_phase_a_qualification_grants_qh_identifiers",
        ),
        schema=_PRIVATE_SCHEMA,
    )
    op.create_index(
        "ix_phase_a_qualification_grants_state_valid_until",
        _GRANT_TABLE,
        ["state", "qh_valid_until", "id"],
        schema=_PRIVATE_SCHEMA,
    )

    # 0013 previously granted broad default table privileges to both runtime
    # roles. Revoke those direct grants after creation; only a future protected
    # harness integration may introduce a narrow, separately reviewed path.
    for role in (_API_ROLE, _WORKER_ROLE):
        op.execute(f"REVOKE ALL PRIVILEGES ON TABLE {_qualified(_NONCE_TABLE)} FROM {role}")
        op.execute(f"REVOKE ALL PRIVILEGES ON TABLE {_qualified(_GRANT_TABLE)} FROM {role}")

    op.execute(
        f"""
        CREATE FUNCTION {_NONCE_GUARD_FUNCTION}()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.created_at > clock_timestamp()
                   OR NEW.consumed_at > clock_timestamp()
                   OR NEW.valid_until <= clock_timestamp() THEN
                    RAISE EXCEPTION
                        USING ERRCODE = '22023',
                              MESSAGE = 'Phase-A QH nonce timestamps are not current';
                END IF;
                RETURN NEW;
            END IF;

            RAISE EXCEPTION
                USING ERRCODE = '55000',
                      MESSAGE = 'Phase-A QH nonce ledger is append-only';
        END;
        $$;
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER phase_a_qualification_nonce_immutable
        BEFORE INSERT OR UPDATE OR DELETE ON {_qualified(_NONCE_TABLE)}
        FOR EACH ROW
        EXECUTE FUNCTION {_NONCE_GUARD_FUNCTION}()
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION {_TRUNCATE_GUARD_FUNCTION}()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $$
        BEGIN
            RAISE EXCEPTION
                USING ERRCODE = '55000',
                      MESSAGE = 'Phase-A qualification tables cannot be truncated';
        END;
        $$;
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER phase_a_qualification_nonce_no_truncate
        BEFORE TRUNCATE ON {_qualified(_NONCE_TABLE)}
        FOR EACH STATEMENT
        EXECUTE FUNCTION {_TRUNCATE_GUARD_FUNCTION}()
        """
    )

    op.execute(
        f"""
        CREATE FUNCTION {_GRANT_GUARD_FUNCTION}()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $$
        DECLARE
            nonce_record RECORD;
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.state <> 'ACTIVE'
                   OR NEW.created_at > clock_timestamp()
                   OR NEW.qh_valid_until <= clock_timestamp()
                   OR NEW.qh_issued_at > NEW.qh_not_before
                   OR NEW.qh_not_before > NEW.created_at
                   OR NEW.created_at >= NEW.qh_valid_until THEN
                    RAISE EXCEPTION
                        USING ERRCODE = '22023',
                              MESSAGE = 'Phase-A qualification grant is not currently valid';
                END IF;

                SELECT issuer_key_id, qualification_id, payload_root_sha256,
                       valid_until, consumed_at
                INTO nonce_record
                FROM {_qualified(_NONCE_TABLE)}
                WHERE id = NEW.nonce_id
                FOR KEY SHARE;

                IF NOT FOUND
                   OR nonce_record.issuer_key_id IS DISTINCT FROM NEW.qh_issuer_key_id
                   OR nonce_record.qualification_id IS DISTINCT FROM NEW.qh_qualification_id
                   OR nonce_record.payload_root_sha256 IS DISTINCT FROM NEW.payload_root_sha256
                   OR nonce_record.valid_until IS DISTINCT FROM NEW.qh_valid_until
                   OR nonce_record.consumed_at > NEW.created_at THEN
                    RAISE EXCEPTION
                        USING ERRCODE = '23514',
                              MESSAGE = 'Phase-A grant nonce binding mismatch';
                END IF;
                RETURN NEW;
            END IF;

            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A qualification grants cannot be deleted';
            END IF;

            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.nonce_id IS DISTINCT FROM OLD.nonce_id
               OR NEW.payload_binding_sha256 IS DISTINCT FROM OLD.payload_binding_sha256
               OR NEW.payload_root_sha256 IS DISTINCT FROM OLD.payload_root_sha256
               OR NEW.candidate_commit IS DISTINCT FROM OLD.candidate_commit
               OR NEW.worker_image_digest IS DISTINCT FROM OLD.worker_image_digest
               OR NEW.datax_release IS DISTINCT FROM OLD.datax_release
               OR NEW.runtime_sha256 IS DISTINCT FROM OLD.runtime_sha256
               OR NEW.reader_plugin_name IS DISTINCT FROM OLD.reader_plugin_name
               OR NEW.reader_plugin_sha256 IS DISTINCT FROM OLD.reader_plugin_sha256
               OR NEW.writer_plugin_name IS DISTINCT FROM OLD.writer_plugin_name
               OR NEW.writer_plugin_sha256 IS DISTINCT FROM OLD.writer_plugin_sha256
               OR NEW.harness_identity IS DISTINCT FROM OLD.harness_identity
               OR NEW.harness_environment_id IS DISTINCT FROM OLD.harness_environment_id
               OR NEW.harness_environment_manifest_sha256
                    IS DISTINCT FROM OLD.harness_environment_manifest_sha256
               OR NEW.harness_version IS DISTINCT FROM OLD.harness_version
               OR NEW.qh_document_sha256 IS DISTINCT FROM OLD.qh_document_sha256
               OR NEW.qh_qualification_id IS DISTINCT FROM OLD.qh_qualification_id
               OR NEW.qh_issuer_key_id IS DISTINCT FROM OLD.qh_issuer_key_id
               OR NEW.qh_issued_at IS DISTINCT FROM OLD.qh_issued_at
               OR NEW.qh_not_before IS DISTINCT FROM OLD.qh_not_before
               OR NEW.qh_valid_until IS DISTINCT FROM OLD.qh_valid_until
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A qualification bindings are immutable';
            END IF;

            IF OLD.state <> 'ACTIVE' OR NEW.state NOT IN ('REVOKED', 'EXPIRED') THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A qualification grant lifecycle is terminal';
            END IF;

            IF NEW.state = 'REVOKED' THEN
                IF NEW.revoked_at > clock_timestamp()
                   OR NEW.revoked_at < OLD.created_at
                   OR NEW.revoked_at >= NEW.qh_valid_until THEN
                    RAISE EXCEPTION
                        USING ERRCODE = '22023',
                              MESSAGE = 'Phase-A qualification revocation timestamp is invalid';
                END IF;
            ELSE
                IF NEW.expired_at > clock_timestamp()
                   OR NEW.expired_at < OLD.created_at
                   OR NEW.expired_at < NEW.qh_valid_until THEN
                    RAISE EXCEPTION
                        USING ERRCODE = '22023',
                              MESSAGE = 'Phase-A qualification expiry timestamp is invalid';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER phase_a_qualification_grant_lifecycle
        BEFORE INSERT OR UPDATE OR DELETE ON {_qualified(_GRANT_TABLE)}
        FOR EACH ROW
        EXECUTE FUNCTION {_GRANT_GUARD_FUNCTION}()
        """
    )
    for function in (
        _NONCE_GUARD_FUNCTION,
        _TRUNCATE_GUARD_FUNCTION,
        _GRANT_GUARD_FUNCTION,
    ):
        op.execute(f"REVOKE ALL PRIVILEGES ON FUNCTION {function}() FROM PUBLIC")
        for role in (_API_ROLE, _WORKER_ROLE):
            op.execute(f"REVOKE ALL PRIVILEGES ON FUNCTION {function}() FROM {role}")
    op.execute(
        f"""
        CREATE TRIGGER phase_a_qualification_grant_no_truncate
        BEFORE TRUNCATE ON {_qualified(_GRANT_TABLE)}
        FOR EACH STATEMENT
        EXECUTE FUNCTION {_TRUNCATE_GUARD_FUNCTION}()
        """
    )


def downgrade() -> None:
    _require_postgresql()
    op.execute(
        f"DROP TRIGGER IF EXISTS phase_a_qualification_grant_no_truncate "
        f"ON {_qualified(_GRANT_TABLE)}"
    )
    op.execute(
        f"DROP TRIGGER IF EXISTS phase_a_qualification_grant_lifecycle "
        f"ON {_qualified(_GRANT_TABLE)}"
    )
    op.execute(
        f"DROP TRIGGER IF EXISTS phase_a_qualification_nonce_no_truncate "
        f"ON {_qualified(_NONCE_TABLE)}"
    )
    op.execute(
        f"DROP TRIGGER IF EXISTS phase_a_qualification_nonce_immutable "
        f"ON {_qualified(_NONCE_TABLE)}"
    )
    op.execute(f"DROP FUNCTION IF EXISTS {_GRANT_GUARD_FUNCTION}()")
    op.execute(f"DROP FUNCTION IF EXISTS {_NONCE_GUARD_FUNCTION}()")
    op.execute(f"DROP FUNCTION IF EXISTS {_TRUNCATE_GUARD_FUNCTION}()")
    op.drop_index(
        "ix_phase_a_qualification_grants_state_valid_until",
        table_name=_GRANT_TABLE,
        schema=_PRIVATE_SCHEMA,
    )
    op.drop_table(_GRANT_TABLE, schema=_PRIVATE_SCHEMA)
    op.drop_index(
        "ix_phase_a_qualification_nonces_valid_until",
        table_name=_NONCE_TABLE,
        schema=_PRIVATE_SCHEMA,
    )
    op.drop_table(_NONCE_TABLE, schema=_PRIVATE_SCHEMA)
    op.execute(f"DROP SCHEMA {_PRIVATE_SCHEMA}")
