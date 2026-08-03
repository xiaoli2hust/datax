# ruff: noqa: E501
"""bind a protected Phase-A grant to one immutable execution

Revision ID: 20260802_0022
Revises: 20260802_0021
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0022"
down_revision: str | Sequence[str] | None = "20260802_0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRIVATE_SCHEMA = "des_phase_a_qualification"
_NONCE_TABLE = f"{_PRIVATE_SCHEMA}.phase_a_qualification_nonces"
_GRANT_TABLE = f"{_PRIVATE_SCHEMA}.phase_a_qualification_grants"
_AUTHORIZATION_TABLE_NAME = "phase_a_execution_authorizations"
_AUTHORIZATION_TABLE = f"{_PRIVATE_SCHEMA}.{_AUTHORIZATION_TABLE_NAME}"
_LEDGER_OWNER_ROLE = "datax_phase_a_ledger_owner"
_ISSUER_ROLE = "datax_phase_a_issuer"
_CONSUMER_ROLE = "datax_phase_a_consumer"
_RUNTIME_ROLES = ("datax_api", "datax_worker", "datax_egress_guard")

_AUTHORIZATION_GUARD_FUNCTION = (
    f"{_PRIVATE_SCHEMA}.des_phase_a_execution_authorization_guard"
)
# This trigger function protects a public table and must be included in a
# standard dump.  Keeping it in the excluded private schema would leave a
# dangling trigger after restore.  It is still SECURITY DEFINER, owned by the
# NOLOGIN ledger owner, and revoked from every caller; its location is for
# dump/restore referential integrity, not a relaxation of the role boundary.
_EXECUTION_AUTHORIZATION_MODE_GUARD_FUNCTION = "public.des_phase_a_execution_mode_guard"
_AUTHORIZE_FUNCTION = f"{_PRIVATE_SCHEMA}.des_authorize_phase_a_execution"
_READ_FUNCTION = f"{_PRIVATE_SCHEMA}.des_read_active_phase_a_execution_authorization"
_AUTHORIZE_SIGNATURE = "uuid, uuid, uuid"
_READ_SIGNATURE = "uuid"

_PUBLIC_READ_TABLES = (
    "public.executions",
    "public.sync_jobs",
    "public.projects",
    "public.job_versions",
    "public.datasources",
    "public.datasource_revisions",
    "public.endpoint_policies",
    "public.endpoint_policy_revisions",
    "public.physical_endpoint_identities",
    "public.target_namespaces",
    "public.transfer_policies",
)

# Runtime database credentials are an independently valuable boundary: a
# compromised API/Worker connection must not recover protected-harness facts
# simply by bypassing the Python query filters.  These policies follow every
# public row that can directly or transitively identify an Execution.  They
# intentionally do not create a private runner capability; the Phase-A runner
# remains disabled until it receives its own reviewed role and lifecycle.
_STANDARD_RUNTIME_RLS_POLICIES = (
    ("executions", "authorization_mode = 'STANDARD'"),
    (
        "execution_attempts",
        """
        EXISTS (
            SELECT 1
            FROM public.executions AS parent_execution
            WHERE parent_execution.id = execution_attempts.execution_id
        )
        """,
    ),
    (
        "target_copy_locks",
        """
        EXISTS (
            SELECT 1
            FROM public.executions AS parent_execution
            WHERE parent_execution.id = target_copy_locks.execution_id
        )
        """,
    ),
    (
        "execution_events",
        """
        EXISTS (
            SELECT 1
            FROM public.executions AS parent_execution
            WHERE parent_execution.id = execution_events.execution_id
        )
        """,
    ),
    (
        "execution_cancel_requests",
        """
        EXISTS (
            SELECT 1
            FROM public.executions AS parent_execution
            WHERE parent_execution.id = execution_cancel_requests.execution_id
        )
        """,
    ),
    (
        "execution_log_chunks",
        """
        EXISTS (
            SELECT 1
            FROM public.executions AS parent_execution
            WHERE parent_execution.id = execution_log_chunks.execution_id
        )
        """,
    ),
    (
        "execution_log_gaps",
        """
        EXISTS (
            SELECT 1
            FROM public.executions AS parent_execution
            WHERE parent_execution.id = execution_log_gaps.execution_id
        )
        """,
    ),
    (
        "recovery_gates",
        """
        EXISTS (
            SELECT 1
            FROM public.executions AS parent_execution
            WHERE parent_execution.id = recovery_gates.execution_id
        )
        """,
    ),
    (
        "recovery_probes",
        """
        EXISTS (
            SELECT 1
            FROM public.recovery_gates AS parent_gate
            WHERE parent_gate.id = recovery_probes.recovery_gate_id
        )
        """,
    ),
    (
        "recovery_probe_attempts",
        """
        EXISTS (
            SELECT 1
            FROM public.recovery_probes AS parent_probe
            WHERE parent_probe.id = recovery_probe_attempts.recovery_probe_id
        )
        """,
    ),
    (
        "endpoint_connection_evidences",
        """
        (execution_id IS NULL AND recovery_probe_id IS NULL)
        OR EXISTS (
            SELECT 1
            FROM public.executions AS parent_execution
            WHERE parent_execution.id = endpoint_connection_evidences.execution_id
        )
        OR EXISTS (
            SELECT 1
            FROM public.recovery_probes AS parent_probe
            WHERE parent_probe.id = endpoint_connection_evidences.recovery_probe_id
        )
        """,
    ),
    (
        "work_termination_requests",
        """
        (work_kind = 'EXECUTION' AND EXISTS (
            SELECT 1
            FROM public.executions AS parent_execution
            WHERE parent_execution.id = work_termination_requests.work_id
        ))
        OR (work_kind = 'RECOVERY_PROBE' AND EXISTS (
            SELECT 1
            FROM public.recovery_probes AS parent_probe
            WHERE parent_probe.id = work_termination_requests.work_id
        ))
        """,
    ),
)


def _require_postgresql_superuser() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("Phase-A execution authorizations require PostgreSQL")
    # This migration changes a public-table constraint and transfers private
    # object ownership to a NOLOGIN role.  Failing before DDL is safer than a
    # partially protected authorization boundary.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A execution authorization migration requires a PostgreSQL superuser';
            END IF;
        END
        $$;
        """
    )


def upgrade() -> None:
    _require_postgresql_superuser()

    # A private authorization is never a normal product execution.  Existing
    # rows are conservatively STANDARD; the ordinary Worker query is narrowed
    # in the same release so it cannot claim a future protected-harness row.
    # The private row remains BLOCKED after the authorization record exists:
    # this migration deliberately does not ship a private Worker or an
    # authorization-to-process-state transition.
    op.add_column(
        "executions",
        sa.Column(
            "authorization_mode",
            sa.String(length=24),
            nullable=False,
            server_default="STANDARD",
        ),
    )
    op.create_check_constraint(
        "ck_executions_authorization_mode",
        "executions",
        "authorization_mode IN ('STANDARD','PHASE_A_HARNESS')",
    )
    op.create_index(
        "ix_executions_authorization_queue",
        "executions",
        ["authorization_mode", "process_state", "queue_eligibility_state", "queued_at", "id"],
    )
    # API/Worker database roles currently retain broad public-table DML until
    # the later runtime-role migration.  Guard the new private discriminator
    # at the database boundary now: ordinary roles cannot create, mutate,
    # delete, downgrade, or escalate a Phase-A row even by bypassing Python.
    # A superuser remains deliberately outside this boundary; future private
    # creation must use a separately reviewed SECURITY DEFINER function.
    op.execute(
        f"""
        CREATE FUNCTION {_EXECUTION_AUTHORIZATION_MODE_GUARD_FUNCTION}()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.authorization_mode = 'PHASE_A_HARNESS'
                   AND session_user IN ('datax_api', 'datax_worker', 'datax_egress_guard') THEN
                    RAISE EXCEPTION
                        USING ERRCODE = '42501',
                              MESSAGE = 'standard runtime roles cannot create a Phase-A execution';
                END IF;
                RETURN NEW;
            END IF;
            IF TG_OP = 'DELETE' THEN
                IF OLD.authorization_mode = 'PHASE_A_HARNESS'
                   AND session_user IN ('datax_api', 'datax_worker', 'datax_egress_guard') THEN
                    RAISE EXCEPTION
                        USING ERRCODE = '42501',
                              MESSAGE = 'standard runtime roles cannot delete a Phase-A execution';
                END IF;
                RETURN OLD;
            END IF;
            IF OLD.authorization_mode = 'PHASE_A_HARNESS'
               AND session_user IN ('datax_api', 'datax_worker', 'datax_egress_guard') THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'standard runtime roles cannot mutate a Phase-A execution';
            END IF;
            IF NEW.authorization_mode IS DISTINCT FROM OLD.authorization_mode THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'execution authorization mode is immutable';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER executions_phase_a_authorization_mode_guard
        BEFORE INSERT OR UPDATE OR DELETE ON public.executions
        FOR EACH ROW
        EXECUTE FUNCTION {_EXECUTION_AUTHORIZATION_MODE_GUARD_FUNCTION}()
        """
    )
    # The record copies all non-secret execution, endpoint, policy, runtime,
    # and QH/PAG binding facts at one controlled instant.  It deliberately has
    # no raw qualification, nonce, credential, hostname, connection string, or
    # table name.  PostgreSQL functions below are the only supported insert and
    # read boundary; no ordinary API/Worker role receives table privileges.
    op.create_table(
        _AUTHORIZATION_TABLE_NAME,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "grant_id",
            sa.Uuid(),
            sa.ForeignKey(f"{_GRANT_TABLE}.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("execution_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("job_version_id", sa.Uuid(), nullable=False),
        sa.Column("job_version_artifact_hash", sa.String(length=64), nullable=False),
        sa.Column("job_spec_hash", sa.String(length=64), nullable=False),
        sa.Column("source_datasource_revision_id", sa.Uuid(), nullable=False),
        sa.Column("source_datasource_config_hash", sa.String(length=64), nullable=False),
        sa.Column("target_datasource_revision_id", sa.Uuid(), nullable=False),
        sa.Column("target_datasource_config_hash", sa.String(length=64), nullable=False),
        sa.Column("source_endpoint_policy_revision_id", sa.Uuid(), nullable=False),
        sa.Column("source_endpoint_policy_hash", sa.String(length=64), nullable=False),
        sa.Column("target_endpoint_policy_revision_id", sa.Uuid(), nullable=False),
        sa.Column("target_endpoint_policy_hash", sa.String(length=64), nullable=False),
        sa.Column("source_physical_endpoint_identity_id", sa.Uuid(), nullable=False),
        sa.Column("source_server_identity_hash", sa.String(length=64), nullable=False),
        sa.Column("target_physical_endpoint_identity_id", sa.Uuid(), nullable=False),
        sa.Column("target_server_identity_hash", sa.String(length=64), nullable=False),
        sa.Column("source_physical_table_identity_hash", sa.String(length=64), nullable=False),
        sa.Column("target_namespace_id", sa.Uuid(), nullable=False),
        sa.Column("target_physical_table_identity_hash", sa.String(length=64), nullable=False),
        sa.Column("target_normalization_version", sa.String(length=16), nullable=False),
        sa.Column("transfer_policy_id", sa.Uuid(), nullable=False),
        sa.Column("transfer_policy_scope_hash", sa.String(length=64), nullable=False),
        sa.Column("transfer_policy_row_version", sa.BigInteger(), nullable=False),
        sa.Column("payload_binding_sha256", sa.String(length=64), nullable=False),
        sa.Column("payload_root_sha256", sa.String(length=64), nullable=False),
        # The one-way nonce digest is part of the durable Phase-A binding. It
        # is not the raw QH nonce and cannot be used to replay the QH.
        sa.Column("nonce_sha256", sa.String(length=64), nullable=False),
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
        sa.Column("qh_document_sha256", sa.String(length=64), nullable=False),
        sa.Column("qh_qualification_id", sa.String(length=128), nullable=False),
        sa.Column("qh_issuer_key_id", sa.String(length=128), nullable=False),
        sa.Column("qh_issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("qh_not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("qh_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("grant_id", name="uq_phase_a_execution_authorizations_grant"),
        sa.UniqueConstraint(
            "execution_id",
            name="uq_phase_a_execution_authorizations_execution",
        ),
        sa.CheckConstraint(
            "job_version_artifact_hash ~ '^[a-f0-9]{64}$' "
            "AND job_spec_hash ~ '^[a-f0-9]{64}$' "
            "AND source_datasource_config_hash ~ '^[a-f0-9]{64}$' "
            "AND target_datasource_config_hash ~ '^[a-f0-9]{64}$' "
            "AND source_endpoint_policy_hash ~ '^[a-f0-9]{64}$' "
            "AND target_endpoint_policy_hash ~ '^[a-f0-9]{64}$' "
            "AND source_server_identity_hash ~ '^[a-f0-9]{64}$' "
            "AND target_server_identity_hash ~ '^[a-f0-9]{64}$' "
            "AND source_physical_table_identity_hash ~ '^[a-f0-9]{64}$' "
            "AND target_physical_table_identity_hash ~ '^[a-f0-9]{64}$' "
            "AND transfer_policy_scope_hash ~ '^[a-f0-9]{64}$' "
            "AND payload_binding_sha256 ~ '^[a-f0-9]{64}$' "
            "AND payload_root_sha256 ~ '^[a-f0-9]{64}$' "
            "AND nonce_sha256 ~ '^[a-f0-9]{64}$' "
            "AND runtime_sha256 ~ '^[a-f0-9]{64}$' "
            "AND reader_plugin_sha256 ~ '^[a-f0-9]{64}$' "
            "AND writer_plugin_sha256 ~ '^[a-f0-9]{64}$' "
            "AND harness_environment_manifest_sha256 ~ '^[a-f0-9]{64}$' "
            "AND qh_document_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_phase_a_execution_authorizations_hashes",
        ),
        sa.CheckConstraint(
            "candidate_commit ~ '^[a-f0-9]{40}$' "
            "AND worker_image_digest ~ '^sha256:[a-f0-9]{64}$' "
            "AND datax_release = 'datax_v202309'",
            name="ck_phase_a_execution_authorizations_runtime",
        ),
        sa.CheckConstraint(
            "reader_plugin_name IN ('mysqlreader', 'postgresqlreader') "
            "AND writer_plugin_name IN ('mysqlwriter', 'postgresqlwriter')",
            name="ck_phase_a_execution_authorizations_plugins",
        ),
        sa.CheckConstraint(
            "harness_identity ~ '^[A-Za-z0-9._-]{8,128}$' "
            "AND harness_environment_id ~ '^[A-Za-z0-9._-]{8,128}$' "
            "AND harness_version ~ '^[A-Za-z0-9._+-]{1,128}$' "
            "AND target_normalization_version ~ '^[A-Za-z0-9._+-]{1,16}$'",
            name="ck_phase_a_execution_authorizations_identifiers",
        ),
        sa.CheckConstraint(
            "qh_qualification_id ~ '^[A-Za-z0-9._-]{8,128}$' "
            "AND qh_issuer_key_id ~ '^[A-Za-z0-9._-]{8,128}$' "
            "AND qh_issued_at <= qh_not_before "
            "AND qh_not_before < qh_valid_until "
            "AND created_at >= qh_not_before "
            "AND created_at < qh_valid_until "
            "AND transfer_policy_row_version >= 1",
            name="ck_phase_a_execution_authorizations_lifecycle",
        ),
        schema=_PRIVATE_SCHEMA,
    )
    op.create_index(
        "ix_phase_a_execution_authorizations_execution_created",
        _AUTHORIZATION_TABLE_NAME,
        ["execution_id", "created_at"],
        schema=_PRIVATE_SCHEMA,
    )
    op.execute(f"ALTER TABLE {_AUTHORIZATION_TABLE} OWNER TO {_LEDGER_OWNER_ROLE}")

    op.execute(
        f"""
        CREATE FUNCTION {_AUTHORIZATION_GUARD_FUNCTION}()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.created_at > clock_timestamp()
                   OR NEW.qh_valid_until <= clock_timestamp()
                   OR NEW.qh_not_before > NEW.created_at THEN
                    RAISE EXCEPTION
                        USING ERRCODE = '22023',
                              MESSAGE = 'Phase-A execution authorization is not currently valid';
                END IF;
                RETURN NEW;
            END IF;
            RAISE EXCEPTION
                USING ERRCODE = '55000',
                      MESSAGE = 'Phase-A execution authorizations are append-only';
        END;
        $$;
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER phase_a_execution_authorization_immutable
        BEFORE INSERT OR UPDATE OR DELETE ON {_AUTHORIZATION_TABLE}
        FOR EACH ROW
        EXECUTE FUNCTION {_AUTHORIZATION_GUARD_FUNCTION}()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER phase_a_execution_authorization_no_truncate
        BEFORE TRUNCATE ON {_AUTHORIZATION_TABLE}
        FOR EACH STATEMENT
        EXECUTE FUNCTION {_PRIVATE_SCHEMA}.des_reject_phase_a_qualification_truncate()
        """
    )
    op.execute(f"ALTER FUNCTION {_AUTHORIZATION_GUARD_FUNCTION}() OWNER TO {_LEDGER_OWNER_ROLE}")

    # The owner has no LOGIN and no membership edge.  These narrow grants only
    # make its two Security Definer functions capable of deriving and checking
    # the non-secret public execution snapshot; standard runtime roles do not
    # obtain any additional capability from this migration.
    op.execute(f"GRANT USAGE ON SCHEMA public TO {_LEDGER_OWNER_ROLE}")
    for table in _PUBLIC_READ_TABLES:
        op.execute(f"GRANT SELECT ON TABLE {table} TO {_LEDGER_OWNER_ROLE}")
    op.execute(
        "GRANT UPDATE (queue_eligibility_state, queue_block_reason, "
        f"queue_state_changed_at, state_version) ON TABLE public.executions TO {_LEDGER_OWNER_ROLE}"
    )

    # The ledger-owner security-definer functions must be able to see the
    # protected parent row, while normal runtime roles receive only rows whose
    # parent remains STANDARD.  PostgreSQL applies the parent policy again to
    # every correlated subquery below, so a private parent cannot be recovered
    # through an attempt, log, recovery probe, evidence, or safety-stop row.
    op.execute("ALTER TABLE public.executions ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"""
        CREATE POLICY phase_a_ledger_execution_authorization
        ON public.executions
        FOR ALL TO {_LEDGER_OWNER_ROLE}
        USING (true)
        WITH CHECK (true)
        """
    )
    runtime_roles = ", ".join(_RUNTIME_ROLES)
    for table, predicate in _STANDARD_RUNTIME_RLS_POLICIES:
        policy_name = f"phase_a_standard_runtime_{table}"
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {policy_name}
            ON public.{table}
            FOR ALL TO {runtime_roles}
            USING ({predicate})
            WITH CHECK ({predicate})
            """
        )

    op.execute(
        f"""
        CREATE FUNCTION {_AUTHORIZE_FUNCTION}(
            p_authorization_id uuid,
            p_grant_id uuid,
            p_execution_id uuid
        )
        RETURNS uuid
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            v_now timestamptz := clock_timestamp();
            v_grant RECORD;
            v_execution public.executions%ROWTYPE;
            v_version public.job_versions%ROWTYPE;
            v_job_project_id uuid;
            v_authorization_id uuid;
        BEGIN
            IF session_user <> '{_ISSUER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A issuer role is required';
            END IF;
            IF p_authorization_id IS NULL OR p_grant_id IS NULL OR p_execution_id IS NULL THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution authorization input is incomplete';
            END IF;

            -- Lock the grant first so one QH/PAG cannot race into two
            -- executions. Expiration is persisted before authorization.
            UPDATE {_GRANT_TABLE} AS grant_row
            SET state = 'EXPIRED', expired_at = v_now
            WHERE grant_row.id = p_grant_id
              AND grant_row.state = 'ACTIVE'
              AND grant_row.qh_valid_until <= v_now;
            SELECT * INTO v_grant
            FROM {_GRANT_TABLE}
            WHERE id = p_grant_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A grant is not active';
            END IF;
            IF v_grant.state <> 'ACTIVE'
               OR v_grant.qh_not_before > v_now
               OR v_grant.qh_valid_until <= v_now THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A grant is not active';
            END IF;
            IF EXISTS (
                SELECT 1 FROM {_AUTHORIZATION_TABLE} WHERE grant_id = p_grant_id
            ) THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A grant is already bound to an execution';
            END IF;

            SELECT * INTO v_execution
            FROM public.executions
            WHERE id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution does not exist';
            END IF;
            IF v_execution.authorization_mode <> 'PHASE_A_HARNESS'
               OR v_execution.process_state <> 'QUEUED'
               OR v_execution.active_attempt_id IS NOT NULL
               OR v_execution.attempt_count <> 0
               OR v_execution.queue_eligibility_state <> 'BLOCKED'
               OR v_execution.queue_block_reason <> 'PHASE_A_AUTHORIZATION_PENDING'
               OR v_execution.target_exclusivity_status <> 'ACTIVE'
               OR v_execution.target_exclusivity_revoked_at IS NOT NULL
               OR v_execution.target_exclusivity_revocation_reason IS NOT NULL THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution is not a pending private harness execution';
            END IF;
            IF EXISTS (
                SELECT 1 FROM {_AUTHORIZATION_TABLE} WHERE execution_id = p_execution_id
            ) THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution is already authorized';
            END IF;

            SELECT * INTO v_version
            FROM public.job_versions
            WHERE id = v_execution.job_version_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution version does not exist';
            END IF;
            SELECT project_id INTO v_job_project_id
            FROM public.sync_jobs
            WHERE id = v_execution.job_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution job does not exist';
            END IF;
            IF v_execution.job_id <> v_version.job_id
               OR v_execution.project_id <> v_job_project_id
               OR v_execution.source_datasource_revision_id <> v_version.source_datasource_revision_id
               OR v_execution.target_datasource_revision_id <> v_version.target_datasource_revision_id
               OR v_execution.source_endpoint_policy_revision_id <> v_version.source_endpoint_policy_revision_id
               OR v_execution.target_endpoint_policy_revision_id <> v_version.target_endpoint_policy_revision_id
               OR v_execution.target_namespace_id <> v_version.target_namespace_id
               OR v_grant.datax_release <> v_version.datax_release
               OR v_grant.runtime_sha256 <> v_version.runtime_sha256
               OR v_grant.reader_plugin_name <> v_version.reader_plugin_name
               OR v_grant.reader_plugin_sha256 <> v_version.reader_plugin_sha256
               OR v_grant.writer_plugin_name <> v_version.writer_plugin_name
               OR v_grant.writer_plugin_sha256 <> v_version.writer_plugin_sha256 THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution binding does not match its immutable version or grant';
            END IF;

            INSERT INTO {_AUTHORIZATION_TABLE} (
                id, grant_id, execution_id, project_id, job_id, job_version_id,
                job_version_artifact_hash, job_spec_hash,
                source_datasource_revision_id, source_datasource_config_hash,
                target_datasource_revision_id, target_datasource_config_hash,
                source_endpoint_policy_revision_id, source_endpoint_policy_hash,
                target_endpoint_policy_revision_id, target_endpoint_policy_hash,
                source_physical_endpoint_identity_id, source_server_identity_hash,
                target_physical_endpoint_identity_id, target_server_identity_hash,
                source_physical_table_identity_hash, target_namespace_id,
                target_physical_table_identity_hash, target_normalization_version,
                transfer_policy_id, transfer_policy_scope_hash, transfer_policy_row_version,
                payload_binding_sha256, payload_root_sha256, nonce_sha256, candidate_commit,
                worker_image_digest, datax_release, runtime_sha256,
                reader_plugin_name, reader_plugin_sha256,
                writer_plugin_name, writer_plugin_sha256,
                harness_identity, harness_environment_id,
                harness_environment_manifest_sha256, harness_version,
                qh_document_sha256, qh_qualification_id, qh_issuer_key_id,
                qh_issued_at, qh_not_before, qh_valid_until, created_at
            )
            SELECT
                p_authorization_id, grant_row.id, execution_row.id,
                execution_row.project_id, execution_row.job_id, version_row.id,
                version_row.version_artifact_hash, version_row.spec_hash,
                source_revision.id, source_revision.config_hash,
                target_revision.id, target_revision.config_hash,
                source_policy.id, source_policy.policy_hash,
                target_policy.id, target_policy.policy_hash,
                source_identity.id, source_identity.server_identity_hash,
                target_identity.id, target_identity.server_identity_hash,
                version_row.source_physical_table_identity_hash,
                target_namespace.id, target_namespace.physical_table_identity_hash,
                target_namespace.normalization_version,
                transfer_policy.id, transfer_policy.scope_hash, transfer_policy.row_version,
                grant_row.payload_binding_sha256, grant_row.payload_root_sha256,
                nonce_row.nonce_sha256,
                grant_row.candidate_commit, grant_row.worker_image_digest,
                grant_row.datax_release, grant_row.runtime_sha256,
                grant_row.reader_plugin_name, grant_row.reader_plugin_sha256,
                grant_row.writer_plugin_name, grant_row.writer_plugin_sha256,
                grant_row.harness_identity, grant_row.harness_environment_id,
                grant_row.harness_environment_manifest_sha256, grant_row.harness_version,
                grant_row.qh_document_sha256, grant_row.qh_qualification_id,
                grant_row.qh_issuer_key_id, grant_row.qh_issued_at,
                grant_row.qh_not_before, grant_row.qh_valid_until, v_now
            FROM {_GRANT_TABLE} AS grant_row
            JOIN {_NONCE_TABLE} AS nonce_row ON nonce_row.id = grant_row.nonce_id
            JOIN public.executions AS execution_row ON execution_row.id = p_execution_id
            JOIN public.sync_jobs AS job_row ON job_row.id = execution_row.job_id
            JOIN public.projects AS project_row
              ON project_row.id = execution_row.project_id
             AND project_row.id = job_row.project_id
             AND project_row.status = 'ACTIVE'
            JOIN public.job_versions AS version_row
              ON version_row.id = execution_row.job_version_id
             AND version_row.job_id = job_row.id
            JOIN public.datasource_revisions AS source_revision
              ON source_revision.id = execution_row.source_datasource_revision_id
             AND source_revision.id = version_row.source_datasource_revision_id
            JOIN public.datasources AS source_datasource
              ON source_datasource.id = source_revision.datasource_id
             AND source_datasource.project_id = project_row.id
             AND source_datasource.current_revision_id = source_revision.id
             AND source_datasource.status = 'ACTIVE'
            JOIN public.datasource_revisions AS target_revision
              ON target_revision.id = execution_row.target_datasource_revision_id
             AND target_revision.id = version_row.target_datasource_revision_id
            JOIN public.datasources AS target_datasource
              ON target_datasource.id = target_revision.datasource_id
             AND target_datasource.project_id = project_row.id
             AND target_datasource.current_revision_id = target_revision.id
             AND target_datasource.status = 'ACTIVE'
            JOIN public.endpoint_policy_revisions AS source_policy
              ON source_policy.id = execution_row.source_endpoint_policy_revision_id
             AND source_policy.id = version_row.source_endpoint_policy_revision_id
             AND source_policy.id = source_revision.endpoint_policy_revision_id
            JOIN public.endpoint_policies AS source_endpoint_policy
              ON source_endpoint_policy.id = source_policy.endpoint_policy_id
             AND source_endpoint_policy.organization_id = project_row.organization_id
             AND source_endpoint_policy.current_revision_id = source_policy.id
             AND source_endpoint_policy.status = 'ACTIVE'
            JOIN public.endpoint_policy_revisions AS target_policy
              ON target_policy.id = execution_row.target_endpoint_policy_revision_id
             AND target_policy.id = version_row.target_endpoint_policy_revision_id
             AND target_policy.id = target_revision.endpoint_policy_revision_id
            JOIN public.endpoint_policies AS target_endpoint_policy
              ON target_endpoint_policy.id = target_policy.endpoint_policy_id
             AND target_endpoint_policy.organization_id = project_row.organization_id
             AND target_endpoint_policy.current_revision_id = target_policy.id
             AND target_endpoint_policy.status = 'ACTIVE'
            JOIN public.physical_endpoint_identities AS source_identity
              ON source_identity.id = source_revision.physical_endpoint_identity_id
             AND source_identity.organization_id = project_row.organization_id
             AND source_identity.engine = source_revision.engine
             AND source_policy.engine = source_revision.engine
            JOIN public.physical_endpoint_identities AS target_identity
              ON target_identity.id = target_revision.physical_endpoint_identity_id
             AND target_identity.organization_id = project_row.organization_id
             AND target_identity.engine = target_revision.engine
             AND target_policy.engine = target_revision.engine
            JOIN public.target_namespaces AS target_namespace
              ON target_namespace.id = execution_row.target_namespace_id
             AND target_namespace.id = version_row.target_namespace_id
             AND target_namespace.physical_endpoint_identity_id = target_identity.id
             AND target_namespace.engine = target_revision.engine
            JOIN public.transfer_policies AS transfer_policy
              ON transfer_policy.id = version_row.transfer_policy_id
             AND transfer_policy.project_id = execution_row.project_id
             AND transfer_policy.source_datasource_revision_id = source_revision.id
             AND transfer_policy.target_datasource_revision_id = target_revision.id
             AND transfer_policy.source_physical_endpoint_identity_id = source_identity.id
             AND transfer_policy.target_physical_endpoint_identity_id = target_identity.id
             AND transfer_policy.scope_hash = version_row.transfer_policy_scope_hash
             AND transfer_policy.status = 'ACTIVE'
            WHERE grant_row.id = p_grant_id
              AND grant_row.state = 'ACTIVE'
              AND grant_row.qh_not_before <= v_now
              AND grant_row.qh_valid_until > v_now
              AND job_row.status = 'PUBLISHED'
              AND grant_row.datax_release = version_row.datax_release
              AND grant_row.runtime_sha256 = version_row.runtime_sha256
              AND grant_row.reader_plugin_name = version_row.reader_plugin_name
              AND grant_row.reader_plugin_sha256 = version_row.reader_plugin_sha256
              AND grant_row.writer_plugin_name = version_row.writer_plugin_name
              AND grant_row.writer_plugin_sha256 = version_row.writer_plugin_sha256
              AND (
                    (source_revision.engine = 'MYSQL_8'
                     AND version_row.reader_plugin_name = 'mysqlreader')
                    OR (source_revision.engine = 'POSTGRESQL_15'
                        AND version_row.reader_plugin_name = 'postgresqlreader')
              )
              AND (
                    (target_revision.engine = 'MYSQL_8'
                     AND version_row.writer_plugin_name = 'mysqlwriter')
                    OR (target_revision.engine = 'POSTGRESQL_15'
                        AND version_row.writer_plugin_name = 'postgresqlwriter')
              )
            RETURNING id INTO v_authorization_id;
            IF v_authorization_id IS NULL THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution public binding is incomplete or changed';
            END IF;

            UPDATE public.executions
            SET queue_eligibility_state = 'BLOCKED',
                queue_block_reason = 'PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED',
                queue_state_changed_at = v_now,
                state_version = state_version + 1
            WHERE id = p_execution_id
              AND authorization_mode = 'PHASE_A_HARNESS'
              AND process_state = 'QUEUED'
              AND active_attempt_id IS NULL
              AND attempt_count = 0
              AND queue_eligibility_state = 'BLOCKED'
              AND queue_block_reason = 'PHASE_A_AUTHORIZATION_PENDING';
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A execution changed while authorization was being recorded';
            END IF;
            RETURN v_authorization_id;
        END;
        $$;
        """
    )

    op.execute(
        f"""
        CREATE FUNCTION {_READ_FUNCTION}(
            p_execution_id uuid
        )
        RETURNS TABLE (
            authorization_id uuid,
            grant_id uuid,
            execution_id uuid,
            project_id uuid,
            job_id uuid,
            job_version_id uuid,
            job_version_artifact_hash text,
            job_spec_hash text,
            source_datasource_revision_id uuid,
            source_datasource_config_hash text,
            target_datasource_revision_id uuid,
            target_datasource_config_hash text,
            source_endpoint_policy_revision_id uuid,
            source_endpoint_policy_hash text,
            target_endpoint_policy_revision_id uuid,
            target_endpoint_policy_hash text,
            source_physical_endpoint_identity_id uuid,
            source_server_identity_hash text,
            target_physical_endpoint_identity_id uuid,
            target_server_identity_hash text,
            source_physical_table_identity_hash text,
            target_namespace_id uuid,
            target_physical_table_identity_hash text,
            target_normalization_version text,
            transfer_policy_id uuid,
            transfer_policy_scope_hash text,
            transfer_policy_row_version bigint,
            payload_binding_sha256 text,
            payload_root_sha256 text,
            nonce_sha256 text,
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
            qh_valid_until timestamptz,
            authorized_at timestamptz
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
            IF p_execution_id IS NULL THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution authorization lookup input is incomplete';
            END IF;
            -- Persist the lifecycle transition before return so a stale
            -- ACTIVE grant is never treated as an authorization.
            UPDATE {_GRANT_TABLE} AS grant_row
            SET state = 'EXPIRED', expired_at = v_now
            FROM {_AUTHORIZATION_TABLE} AS authorization_row
            WHERE authorization_row.grant_id = grant_row.id
              AND authorization_row.execution_id = p_execution_id
              AND grant_row.state = 'ACTIVE'
              AND grant_row.qh_valid_until <= v_now;

            RETURN QUERY
            SELECT
                authorization_row.id,
                authorization_row.grant_id,
                authorization_row.execution_id,
                authorization_row.project_id,
                authorization_row.job_id,
                authorization_row.job_version_id,
                authorization_row.job_version_artifact_hash::text,
                authorization_row.job_spec_hash::text,
                authorization_row.source_datasource_revision_id,
                authorization_row.source_datasource_config_hash::text,
                authorization_row.target_datasource_revision_id,
                authorization_row.target_datasource_config_hash::text,
                authorization_row.source_endpoint_policy_revision_id,
                authorization_row.source_endpoint_policy_hash::text,
                authorization_row.target_endpoint_policy_revision_id,
                authorization_row.target_endpoint_policy_hash::text,
                authorization_row.source_physical_endpoint_identity_id,
                authorization_row.source_server_identity_hash::text,
                authorization_row.target_physical_endpoint_identity_id,
                authorization_row.target_server_identity_hash::text,
                authorization_row.source_physical_table_identity_hash::text,
                authorization_row.target_namespace_id,
                authorization_row.target_physical_table_identity_hash::text,
                authorization_row.target_normalization_version::text,
                authorization_row.transfer_policy_id,
                authorization_row.transfer_policy_scope_hash::text,
                authorization_row.transfer_policy_row_version,
                authorization_row.payload_binding_sha256::text,
                authorization_row.payload_root_sha256::text,
                authorization_row.nonce_sha256::text,
                authorization_row.candidate_commit::text,
                authorization_row.worker_image_digest::text,
                authorization_row.datax_release::text,
                authorization_row.runtime_sha256::text,
                authorization_row.reader_plugin_name::text,
                authorization_row.reader_plugin_sha256::text,
                authorization_row.writer_plugin_name::text,
                authorization_row.writer_plugin_sha256::text,
                authorization_row.harness_identity::text,
                authorization_row.harness_environment_id::text,
                authorization_row.harness_environment_manifest_sha256::text,
                authorization_row.harness_version::text,
                authorization_row.qh_document_sha256::text,
                authorization_row.qh_qualification_id::text,
                authorization_row.qh_issuer_key_id::text,
                authorization_row.qh_issued_at,
                authorization_row.qh_not_before,
                authorization_row.qh_valid_until,
                authorization_row.created_at
            FROM {_AUTHORIZATION_TABLE} AS authorization_row
            JOIN {_GRANT_TABLE} AS grant_row ON grant_row.id = authorization_row.grant_id
            JOIN {_NONCE_TABLE} AS nonce_row ON nonce_row.id = grant_row.nonce_id
            JOIN public.executions AS execution_row ON execution_row.id = authorization_row.execution_id
            JOIN public.sync_jobs AS job_row ON job_row.id = execution_row.job_id
            JOIN public.projects AS project_row
              ON project_row.id = execution_row.project_id
             AND project_row.id = job_row.project_id
             AND project_row.status = 'ACTIVE'
            JOIN public.job_versions AS version_row
              ON version_row.id = execution_row.job_version_id
             AND version_row.job_id = job_row.id
            JOIN public.datasource_revisions AS source_revision
              ON source_revision.id = execution_row.source_datasource_revision_id
            JOIN public.datasources AS source_datasource
              ON source_datasource.id = source_revision.datasource_id
             AND source_datasource.project_id = project_row.id
             AND source_datasource.current_revision_id = source_revision.id
             AND source_datasource.status = 'ACTIVE'
            JOIN public.datasource_revisions AS target_revision
              ON target_revision.id = execution_row.target_datasource_revision_id
            JOIN public.datasources AS target_datasource
              ON target_datasource.id = target_revision.datasource_id
             AND target_datasource.project_id = project_row.id
             AND target_datasource.current_revision_id = target_revision.id
             AND target_datasource.status = 'ACTIVE'
            JOIN public.endpoint_policy_revisions AS source_policy
              ON source_policy.id = execution_row.source_endpoint_policy_revision_id
            JOIN public.endpoint_policies AS source_endpoint_policy
              ON source_endpoint_policy.id = source_policy.endpoint_policy_id
             AND source_endpoint_policy.organization_id = project_row.organization_id
             AND source_endpoint_policy.current_revision_id = source_policy.id
             AND source_endpoint_policy.status = 'ACTIVE'
            JOIN public.endpoint_policy_revisions AS target_policy
              ON target_policy.id = execution_row.target_endpoint_policy_revision_id
            JOIN public.endpoint_policies AS target_endpoint_policy
              ON target_endpoint_policy.id = target_policy.endpoint_policy_id
             AND target_endpoint_policy.organization_id = project_row.organization_id
             AND target_endpoint_policy.current_revision_id = target_policy.id
             AND target_endpoint_policy.status = 'ACTIVE'
            JOIN public.physical_endpoint_identities AS source_identity
              ON source_identity.id = source_revision.physical_endpoint_identity_id
             AND source_identity.organization_id = project_row.organization_id
             AND source_identity.engine = source_revision.engine
             AND source_policy.engine = source_revision.engine
            JOIN public.physical_endpoint_identities AS target_identity
              ON target_identity.id = target_revision.physical_endpoint_identity_id
             AND target_identity.organization_id = project_row.organization_id
             AND target_identity.engine = target_revision.engine
             AND target_policy.engine = target_revision.engine
            JOIN public.target_namespaces AS target_namespace
              ON target_namespace.id = execution_row.target_namespace_id
             AND target_namespace.physical_endpoint_identity_id = target_identity.id
             AND target_namespace.engine = target_revision.engine
            JOIN public.transfer_policies AS transfer_policy
              ON transfer_policy.id = version_row.transfer_policy_id
            WHERE authorization_row.execution_id = p_execution_id
              AND grant_row.state = 'ACTIVE'
              AND grant_row.qh_not_before <= v_now
              AND grant_row.qh_valid_until > v_now
              AND execution_row.authorization_mode = 'PHASE_A_HARNESS'
              AND execution_row.target_exclusivity_status = 'ACTIVE'
              AND execution_row.target_exclusivity_revoked_at IS NULL
              AND execution_row.target_exclusivity_revocation_reason IS NULL
              AND execution_row.project_id = authorization_row.project_id
              AND execution_row.job_id = authorization_row.job_id
              AND execution_row.job_version_id = authorization_row.job_version_id
              AND job_row.project_id = execution_row.project_id
              AND job_row.status = 'PUBLISHED'
              AND version_row.job_id = execution_row.job_id
              AND version_row.version_artifact_hash = authorization_row.job_version_artifact_hash
              AND version_row.spec_hash = authorization_row.job_spec_hash
              AND execution_row.source_datasource_revision_id = authorization_row.source_datasource_revision_id
              AND execution_row.target_datasource_revision_id = authorization_row.target_datasource_revision_id
              AND execution_row.source_endpoint_policy_revision_id = authorization_row.source_endpoint_policy_revision_id
              AND execution_row.target_endpoint_policy_revision_id = authorization_row.target_endpoint_policy_revision_id
              AND execution_row.target_namespace_id = authorization_row.target_namespace_id
              AND version_row.source_datasource_revision_id = execution_row.source_datasource_revision_id
              AND version_row.target_datasource_revision_id = execution_row.target_datasource_revision_id
              AND version_row.source_endpoint_policy_revision_id = execution_row.source_endpoint_policy_revision_id
              AND version_row.target_endpoint_policy_revision_id = execution_row.target_endpoint_policy_revision_id
              AND version_row.target_namespace_id = execution_row.target_namespace_id
              AND version_row.source_physical_table_identity_hash = authorization_row.source_physical_table_identity_hash
              AND source_revision.config_hash = authorization_row.source_datasource_config_hash
              AND target_revision.config_hash = authorization_row.target_datasource_config_hash
              AND source_revision.datasource_id = source_datasource.id
              AND target_revision.datasource_id = target_datasource.id
              AND source_revision.endpoint_policy_revision_id = source_policy.id
              AND target_revision.endpoint_policy_revision_id = target_policy.id
              AND source_policy.policy_hash = authorization_row.source_endpoint_policy_hash
              AND target_policy.policy_hash = authorization_row.target_endpoint_policy_hash
              AND source_revision.physical_endpoint_identity_id = source_identity.id
              AND target_revision.physical_endpoint_identity_id = target_identity.id
              AND source_identity.id = authorization_row.source_physical_endpoint_identity_id
              AND source_identity.server_identity_hash = authorization_row.source_server_identity_hash
              AND target_identity.id = authorization_row.target_physical_endpoint_identity_id
              AND target_identity.server_identity_hash = authorization_row.target_server_identity_hash
              AND target_namespace.physical_endpoint_identity_id = target_identity.id
              AND target_namespace.physical_table_identity_hash = authorization_row.target_physical_table_identity_hash
              AND target_namespace.normalization_version = authorization_row.target_normalization_version
              AND transfer_policy.project_id = execution_row.project_id
              AND transfer_policy.source_datasource_revision_id = source_revision.id
              AND transfer_policy.target_datasource_revision_id = target_revision.id
              AND transfer_policy.source_physical_endpoint_identity_id = source_identity.id
              AND transfer_policy.target_physical_endpoint_identity_id = target_identity.id
              AND transfer_policy.scope_hash = version_row.transfer_policy_scope_hash
              AND transfer_policy.id = authorization_row.transfer_policy_id
              AND transfer_policy.scope_hash = authorization_row.transfer_policy_scope_hash
              AND transfer_policy.row_version = authorization_row.transfer_policy_row_version
              AND transfer_policy.status = 'ACTIVE'
              AND grant_row.payload_binding_sha256 = authorization_row.payload_binding_sha256
              AND grant_row.payload_root_sha256 = authorization_row.payload_root_sha256
              AND nonce_row.nonce_sha256 = authorization_row.nonce_sha256
              AND grant_row.candidate_commit = authorization_row.candidate_commit
              AND grant_row.worker_image_digest = authorization_row.worker_image_digest
              AND grant_row.datax_release = authorization_row.datax_release
              AND grant_row.runtime_sha256 = authorization_row.runtime_sha256
              AND grant_row.reader_plugin_name = authorization_row.reader_plugin_name
              AND grant_row.reader_plugin_sha256 = authorization_row.reader_plugin_sha256
              AND grant_row.writer_plugin_name = authorization_row.writer_plugin_name
              AND grant_row.writer_plugin_sha256 = authorization_row.writer_plugin_sha256
              AND grant_row.harness_identity = authorization_row.harness_identity
              AND grant_row.harness_environment_id = authorization_row.harness_environment_id
              AND grant_row.harness_environment_manifest_sha256 = authorization_row.harness_environment_manifest_sha256
              AND grant_row.harness_version = authorization_row.harness_version
              AND grant_row.qh_document_sha256 = authorization_row.qh_document_sha256
              AND grant_row.qh_qualification_id = authorization_row.qh_qualification_id
              AND grant_row.qh_issuer_key_id = authorization_row.qh_issuer_key_id
              AND grant_row.qh_issued_at = authorization_row.qh_issued_at
              AND grant_row.qh_not_before = authorization_row.qh_not_before
              AND grant_row.qh_valid_until = authorization_row.qh_valid_until
              AND version_row.datax_release = authorization_row.datax_release
              AND version_row.runtime_sha256 = authorization_row.runtime_sha256
              AND version_row.reader_plugin_name = authorization_row.reader_plugin_name
              AND version_row.reader_plugin_sha256 = authorization_row.reader_plugin_sha256
              AND version_row.writer_plugin_name = authorization_row.writer_plugin_name
              AND version_row.writer_plugin_sha256 = authorization_row.writer_plugin_sha256
              AND (
                    (source_revision.engine = 'MYSQL_8'
                     AND authorization_row.reader_plugin_name = 'mysqlreader')
                    OR (source_revision.engine = 'POSTGRESQL_15'
                        AND authorization_row.reader_plugin_name = 'postgresqlreader')
              )
              AND (
                    (target_revision.engine = 'MYSQL_8'
                     AND authorization_row.writer_plugin_name = 'mysqlwriter')
                    OR (target_revision.engine = 'POSTGRESQL_15'
                        AND authorization_row.writer_plugin_name = 'postgresqlwriter')
              )
            FOR UPDATE OF authorization_row, grant_row, execution_row;
        END;
        $$;
        """
    )

    for function, signature in (
        (_EXECUTION_AUTHORIZATION_MODE_GUARD_FUNCTION, ""),
        (_AUTHORIZATION_GUARD_FUNCTION, ""),
        (_AUTHORIZE_FUNCTION, _AUTHORIZE_SIGNATURE),
        (_READ_FUNCTION, _READ_SIGNATURE),
    ):
        suffix = f"({signature})" if signature else "()"
        op.execute(f"ALTER FUNCTION {function}{suffix} OWNER TO {_LEDGER_OWNER_ROLE}")
        for role in ("PUBLIC", *_RUNTIME_ROLES, _ISSUER_ROLE, _CONSUMER_ROLE):
            op.execute(
                f"REVOKE ALL PRIVILEGES ON FUNCTION {function}{suffix} FROM {role}"
            )
    for role in ("PUBLIC", *_RUNTIME_ROLES, _ISSUER_ROLE, _CONSUMER_ROLE):
        op.execute(f"REVOKE ALL PRIVILEGES ON TABLE {_AUTHORIZATION_TABLE} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_AUTHORIZE_FUNCTION}({_AUTHORIZE_SIGNATURE}) TO {_ISSUER_ROLE}")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_READ_FUNCTION}({_READ_SIGNATURE}) TO {_CONSUMER_ROLE}")


def downgrade() -> None:
    _require_postgresql_superuser()
    for function, signature in (
        (_READ_FUNCTION, _READ_SIGNATURE),
        (_AUTHORIZE_FUNCTION, _AUTHORIZE_SIGNATURE),
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {function}({signature})")

    op.execute("DROP TRIGGER IF EXISTS executions_phase_a_authorization_mode_guard ON public.executions")
    op.execute(f"DROP FUNCTION IF EXISTS {_EXECUTION_AUTHORIZATION_MODE_GUARD_FUNCTION}()")

    # 0022 owns every policy it enables.  Remove them before the discriminator
    # column disappears so a downgrade restores the exact pre-0022 runtime-role
    # behavior rather than leaving an invisible RLS filter behind.
    for table, _predicate in reversed(_STANDARD_RUNTIME_RLS_POLICIES):
        policy_name = f"phase_a_standard_runtime_{table}"
        op.execute(f"DROP POLICY IF EXISTS {policy_name} ON public.{table}")
        op.execute(f"ALTER TABLE public.{table} DISABLE ROW LEVEL SECURITY")
    op.execute(
        "DROP POLICY IF EXISTS phase_a_ledger_execution_authorization "
        "ON public.executions"
    )

    # Dropping the table removes its two trigger dependencies, then the guard
    # function can be removed safely.  The 0021 shared truncate guard remains
    # owned by the protected ledger for its original tables.
    op.drop_index(
        "ix_phase_a_execution_authorizations_execution_created",
        table_name=_AUTHORIZATION_TABLE_NAME,
        schema=_PRIVATE_SCHEMA,
    )
    op.drop_table(_AUTHORIZATION_TABLE_NAME, schema=_PRIVATE_SCHEMA)
    op.execute(f"DROP FUNCTION IF EXISTS {_AUTHORIZATION_GUARD_FUNCTION}()")

    op.execute(
        "REVOKE UPDATE (queue_eligibility_state, queue_block_reason, "
        f"queue_state_changed_at, state_version) ON TABLE public.executions FROM {_LEDGER_OWNER_ROLE}"
    )
    for table in _PUBLIC_READ_TABLES:
        op.execute(f"REVOKE SELECT ON TABLE {table} FROM {_LEDGER_OWNER_ROLE}")
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {_LEDGER_OWNER_ROLE}")

    op.drop_index("ix_executions_authorization_queue", table_name="executions")
    op.drop_constraint(
        "ck_executions_authorization_mode",
        "executions",
        type_="check",
    )
    op.drop_column("executions", "authorization_mode")
