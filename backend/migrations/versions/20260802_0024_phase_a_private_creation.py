"""atomically create, authorize, and reserve a private Phase-A execution

Revision ID: 20260802_0024
Revises: 20260802_0023
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0024"
down_revision: str | Sequence[str] | None = "20260802_0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRIVATE_SCHEMA = "des_phase_a_qualification"
_GRANT_TABLE = f"{_PRIVATE_SCHEMA}.phase_a_qualification_grants"
_AUTHORIZATION_TABLE = f"{_PRIVATE_SCHEMA}.phase_a_execution_authorizations"
_CHECKPOINT_TABLE_NAME = "phase_a_execution_create_checkpoints"
_CHECKPOINT_TABLE = f"{_PRIVATE_SCHEMA}.{_CHECKPOINT_TABLE_NAME}"
_LEDGER_OWNER_ROLE = "datax_phase_a_ledger_owner"
_ISSUER_ROLE = "datax_phase_a_issuer"
_CONSUMER_ROLE = "datax_phase_a_consumer"
_RUNNER_ROLE = "datax_phase_a_runner"
_RUNTIME_ROLES = ("datax_api", "datax_worker", "datax_egress_guard")

_CHECKPOINT_GUARD_FUNCTION = (
    f"{_PRIVATE_SCHEMA}.des_phase_a_execution_create_checkpoint_guard"
)
_CREATE_FUNCTION = f"{_PRIVATE_SCHEMA}.des_create_authorize_reserve_phase_a_execution"
_AUTHORIZE_FUNCTION = f"{_PRIVATE_SCHEMA}.des_authorize_phase_a_execution"
_CREATE_SIGNATURE = "uuid, uuid, uuid, uuid, uuid, uuid, jsonb, jsonb"
_AUTHORIZE_SIGNATURE = "uuid, uuid, uuid"

# 0022 already gives the NOLOGIN ledger owner precisely the public reads it
# needs to bind an existing execution.  Private creation additionally needs
# to validate the requested user, its organization/project role, the two
# datasource-use grants, and the system admission fact before it creates the
# otherwise invisible PHASE_A_HARNESS row.
_ADDITIONAL_PUBLIC_READ_TABLES = (
    "public.system_control",
    "public.organizations",
    "public.users",
    "public.organization_members",
    "public.role_assignments",
    "public.datasource_usage_grants",
)
_SYSTEM_CONTROL_LOCK_COLUMN = "singleton_id"

# The function explicitly names only these execution columns.  Do not grant
# a broad INSERT capability to the ledger owner: it is a NOLOGIN role, but its
# SECURITY DEFINER surface is still intentionally kept as narrow as possible.
_EXECUTION_INSERT_COLUMNS = (
    "id",
    "project_id",
    "job_id",
    "job_version_id",
    "trigger_type",
    "authorization_mode",
    "requested_by",
    "process_state",
    "data_effect",
    "verification_state",
    "capacity_profile",
    "service_reservation_seconds",
    "queue_eligibility_state",
    "queue_block_reason",
    "queue_state_changed_at",
    "queued_at",
    "timeout_seconds",
    "source_datasource_revision_id",
    "target_datasource_revision_id",
    "source_endpoint_policy_revision_id",
    "target_endpoint_policy_revision_id",
    "target_namespace_id",
    "source_quiescence_confirmation",
    "target_exclusivity_confirmation",
    "target_exclusivity_status",
    "created_at",
)


def _require_postgresql_superuser() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("Phase-A private creation requires PostgreSQL")
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A private creation migration requires superuser';
            END IF;
        END
        $$;
        """
    )


def upgrade() -> None:
    _require_postgresql_superuser()

    # The checkpoint ledger has no foreign key to a public Execution/lock.
    # Standard backup intentionally excludes this schema but retains public
    # tables; a cross-schema FK would make that exclusion non-restorable.  The
    # issuer-only function writes all three receipts in the same transaction,
    # and the immutable PEA/unique public lock remain the authoritative links.
    op.create_table(
        _CHECKPOINT_TABLE_NAME,
        sa.Column("execution_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=True),
        sa.Column(
            "grant_id",
            sa.Uuid(),
            sa.ForeignKey(f"{_GRANT_TABLE}.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("lock_id", sa.Uuid(), nullable=True),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("job_version_id", sa.Uuid(), nullable=False),
        sa.Column("target_namespace_id", sa.Uuid(), nullable=False),
        sa.Column("checkpoint", sa.String(length=32), nullable=False),
        # This is a private checkpoint state, not public.executions.process_state.
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("lock_state", sa.String(length=24), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("execution_id", "checkpoint"),
        sa.ForeignKeyConstraint(
            ["authorization_id"],
            [f"{_AUTHORIZATION_TABLE}.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "(checkpoint = 'EXECUTION_CREATED' "
            "AND state = 'BLOCKED' "
            "AND authorization_id IS NULL "
            "AND grant_id IS NULL "
            "AND lock_id IS NULL "
            "AND lock_state IS NULL) "
            "OR (checkpoint = 'PEA_BOUND' "
            "AND state = 'BLOCKED' "
            "AND authorization_id IS NOT NULL "
            "AND grant_id IS NOT NULL "
            "AND lock_id IS NULL "
            "AND lock_state IS NULL) "
            "OR (checkpoint = 'LOCK_RESERVED' "
            "AND state = 'RESERVED' "
            "AND authorization_id IS NOT NULL "
            "AND grant_id IS NOT NULL "
            "AND lock_id IS NOT NULL "
            "AND lock_state = 'RESERVED')",
            name="ck_phase_a_execution_create_checkpoint_shape",
        ),
        schema=_PRIVATE_SCHEMA,
    )
    op.create_index(
        "ix_phase_a_execution_create_checkpoints_execution_occurred",
        _CHECKPOINT_TABLE_NAME,
        ["execution_id", "occurred_at", "checkpoint"],
        schema=_PRIVATE_SCHEMA,
    )
    op.execute(f"ALTER TABLE {_CHECKPOINT_TABLE} OWNER TO {_LEDGER_OWNER_ROLE}")

    op.execute(
        f"""
        CREATE FUNCTION {_CHECKPOINT_GUARD_FUNCTION}()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.occurred_at > clock_timestamp() THEN
                    RAISE EXCEPTION
                        USING ERRCODE = '22023',
                              MESSAGE = 'Phase-A private create checkpoint timestamp is invalid';
                END IF;
                RETURN NEW;
            END IF;
            RAISE EXCEPTION
                USING ERRCODE = '55000',
                      MESSAGE = 'Phase-A private create checkpoints are append-only';
        END;
        $$;
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER phase_a_execution_create_checkpoint_immutable
        BEFORE INSERT OR UPDATE OR DELETE ON {_CHECKPOINT_TABLE}
        FOR EACH ROW
        EXECUTE FUNCTION {_CHECKPOINT_GUARD_FUNCTION}()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER phase_a_execution_create_checkpoint_no_truncate
        BEFORE TRUNCATE ON {_CHECKPOINT_TABLE}
        FOR EACH STATEMENT
        EXECUTE FUNCTION {_PRIVATE_SCHEMA}.des_reject_phase_a_qualification_truncate()
        """
    )

    # The normal runtime roles still cannot see or mutate private rows.  The
    # issuer receives one exact function entrypoint only; it does not receive
    # direct table DML or a role membership edge into the ledger owner.
    for role in ("PUBLIC", *_RUNTIME_ROLES, _ISSUER_ROLE, _CONSUMER_ROLE, _RUNNER_ROLE):
        op.execute(f"REVOKE ALL PRIVILEGES ON TABLE {_CHECKPOINT_TABLE} FROM {role}")
        op.execute(f"REVOKE ALL PRIVILEGES ON FUNCTION {_CHECKPOINT_GUARD_FUNCTION}() FROM {role}")

    op.execute(f"GRANT USAGE ON SCHEMA public TO {_LEDGER_OWNER_ROLE}")
    for table in _ADDITIONAL_PUBLIC_READ_TABLES:
        op.execute(f"GRANT SELECT ON TABLE {table} TO {_LEDGER_OWNER_ROLE}")
    # PostgreSQL requires UPDATE on at least one column for SELECT ... FOR
    # UPDATE. `singleton_id` is constrained to the only valid value (1), so
    # this narrow privilege permits row serialization with the local stop
    # transition without granting any mutable control field.
    op.execute(
        "GRANT UPDATE ("
        f"{_SYSTEM_CONTROL_LOCK_COLUMN}"
        ") ON TABLE public.system_control "
        f"TO {_LEDGER_OWNER_ROLE}"
    )
    insert_columns = ", ".join(_EXECUTION_INSERT_COLUMNS)
    op.execute(
        f"GRANT INSERT ({insert_columns}) ON TABLE public.executions "
        f"TO {_LEDGER_OWNER_ROLE}"
    )

    # There is deliberately no public API, Worker, Compose, Settings, or
    # Launcher caller for this entrypoint.  It is a protected issuer boundary
    # that creates all three durable facts in one transaction and leaves the
    # new row BLOCKED for the still-unimplemented private worker.
    op.execute(
        f"""
        CREATE FUNCTION {_CREATE_FUNCTION}(
            p_execution_id uuid,
            p_authorization_id uuid,
            p_lock_id uuid,
            p_grant_id uuid,
            p_job_version_id uuid,
            p_requested_by uuid,
            p_source_quiescence_confirmation jsonb,
            p_target_exclusivity_confirmation jsonb
        )
        RETURNS TABLE (
            execution_id uuid,
            authorization_id uuid,
            grant_id uuid,
            lock_id uuid,
            job_id uuid,
            job_version_id uuid,
            target_namespace_id uuid,
            checkpoint text,
            execution_process_state text,
            queue_eligibility_state text,
            queue_block_reason text,
            target_lock_state text,
            occurred_at timestamptz
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            v_now timestamptz := clock_timestamp();
            v_created_at timestamptz;
            v_bound_at timestamptz;
            v_reserved_at timestamptz;
            v_source_confirmed_at timestamptz;
            v_target_confirmed_at timestamptz;
            v_target_valid_until timestamptz;
            v_job_id uuid;
            v_project_id uuid;
            v_source_revision_id uuid;
            v_target_revision_id uuid;
            v_source_policy_revision_id uuid;
            v_target_policy_revision_id uuid;
            v_target_namespace_id uuid;
            v_target_physical_table_identity_hash text;
            v_timeout_seconds integer;
            v_system_draining boolean;
        BEGIN
            IF session_user <> '{_ISSUER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A issuer role is required';
            END IF;
            IF p_execution_id IS NULL
               OR p_authorization_id IS NULL
               OR p_lock_id IS NULL
               OR p_grant_id IS NULL
               OR p_job_version_id IS NULL
               OR p_requested_by IS NULL
               OR p_source_quiescence_confirmation IS NULL
               OR p_target_exclusivity_confirmation IS NULL THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A private creation input is incomplete';
            END IF;

            -- The caller cannot smuggle arbitrary JSON into a public
            -- execution.  This is the same non-secret confirmation shape as
            -- the normal API contract, checked again at this private boundary.
            IF jsonb_typeof(p_source_quiescence_confirmation) <> 'object'
               OR EXISTS (
                    SELECT 1
                    FROM jsonb_object_keys(p_source_quiescence_confirmation) AS key_row(key)
                    WHERE key_row.key NOT IN ('confirmed', 'confirmed_at', 'note')
               )
               OR NOT p_source_quiescence_confirmation ? 'confirmed'
               OR NOT p_source_quiescence_confirmation ? 'confirmed_at'
               OR jsonb_typeof(p_source_quiescence_confirmation -> 'confirmed') <> 'boolean'
               OR (p_source_quiescence_confirmation -> 'confirmed') <> 'true'::jsonb
               OR jsonb_typeof(p_source_quiescence_confirmation -> 'confirmed_at') <> 'string'
               OR (p_source_quiescence_confirmation ->> 'confirmed_at') !~
                    '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}([.][0-9]{{1,6}})?(Z|[+-][0-9]{{2}}:[0-9]{{2}})$'
               OR (
                    p_source_quiescence_confirmation ? 'note'
                    AND (
                        jsonb_typeof(p_source_quiescence_confirmation -> 'note')
                            NOT IN ('null', 'string')
                        OR (
                            jsonb_typeof(p_source_quiescence_confirmation -> 'note') = 'string'
                            AND char_length(p_source_quiescence_confirmation ->> 'note') > 500
                        )
                    )
               ) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A source quiescence confirmation is invalid';
            END IF;
            IF jsonb_typeof(p_target_exclusivity_confirmation) <> 'object'
               OR EXISTS (
                    SELECT 1
                    FROM jsonb_object_keys(p_target_exclusivity_confirmation) AS key_row(key)
                    WHERE key_row.key NOT IN (
                        'statement_version', 'confirmed', 'confirmed_at',
                        'valid_until', 'responsible_party', 'note'
                    )
               )
               OR NOT p_target_exclusivity_confirmation ? 'statement_version'
               OR NOT p_target_exclusivity_confirmation ? 'confirmed'
               OR NOT p_target_exclusivity_confirmation ? 'confirmed_at'
               OR NOT p_target_exclusivity_confirmation ? 'valid_until'
               OR NOT p_target_exclusivity_confirmation ? 'responsible_party'
               OR jsonb_typeof(p_target_exclusivity_confirmation -> 'statement_version') <> 'string'
               OR p_target_exclusivity_confirmation ->> 'statement_version' <> '1.0'
               OR jsonb_typeof(p_target_exclusivity_confirmation -> 'confirmed') <> 'boolean'
               OR (p_target_exclusivity_confirmation -> 'confirmed') <> 'true'::jsonb
               OR jsonb_typeof(p_target_exclusivity_confirmation -> 'confirmed_at') <> 'string'
               OR jsonb_typeof(p_target_exclusivity_confirmation -> 'valid_until') <> 'string'
               OR (p_target_exclusivity_confirmation ->> 'confirmed_at') !~
                    '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}([.][0-9]{{1,6}})?(Z|[+-][0-9]{{2}}:[0-9]{{2}})$'
               OR (p_target_exclusivity_confirmation ->> 'valid_until') !~
                    '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}([.][0-9]{{1,6}})?(Z|[+-][0-9]{{2}}:[0-9]{{2}})$'
               OR jsonb_typeof(p_target_exclusivity_confirmation -> 'responsible_party') <> 'string'
               OR (p_target_exclusivity_confirmation ->> 'responsible_party')
                    NOT IN ('OPERATOR', 'DBA')
               OR (
                    p_target_exclusivity_confirmation ? 'note'
                    AND (
                        jsonb_typeof(p_target_exclusivity_confirmation -> 'note')
                            NOT IN ('null', 'string')
                        OR (
                            jsonb_typeof(p_target_exclusivity_confirmation -> 'note') = 'string'
                            AND char_length(p_target_exclusivity_confirmation ->> 'note') > 500
                        )
                    )
               ) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A target exclusivity confirmation is invalid';
            END IF;
            BEGIN
                v_source_confirmed_at :=
                    (p_source_quiescence_confirmation ->> 'confirmed_at')::timestamptz;
                v_target_confirmed_at :=
                    (p_target_exclusivity_confirmation ->> 'confirmed_at')::timestamptz;
                v_target_valid_until :=
                    (p_target_exclusivity_confirmation ->> 'valid_until')::timestamptz;
            EXCEPTION
                WHEN invalid_datetime_format OR datetime_field_overflow THEN
                    RAISE EXCEPTION
                        USING ERRCODE = '22023',
                              MESSAGE = 'Phase-A confirmation timestamp is invalid';
            END;
            IF v_source_confirmed_at > v_now + INTERVAL '5 minutes'
               OR v_target_confirmed_at > v_now + INTERVAL '5 minutes'
               OR v_target_valid_until <= v_target_confirmed_at
               OR v_target_valid_until <= v_now THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A confirmation window is invalid';
            END IF;

            -- Match the product-wide SystemControl -> Organization lock order
            -- before reading any current business fact.  This exact row lock
            -- serializes with the Launcher/Worker draining UPDATE, so neither
            -- side can commit after a stale admission observation.
            SELECT draining
            INTO v_system_draining
            FROM public.system_control
            WHERE singleton_id = 1
            FOR UPDATE;
            IF NOT FOUND OR v_system_draining THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A system is not accepting new executions';
            END IF;
            SELECT
                version_row.job_id,
                job_row.project_id,
                version_row.source_datasource_revision_id,
                version_row.target_datasource_revision_id,
                version_row.source_endpoint_policy_revision_id,
                version_row.target_endpoint_policy_revision_id,
                version_row.target_namespace_id,
                CASE
                    WHEN (version_row.spec_json #>> '{{execution_policy,timeout_seconds}}')
                        ~ '^[0-9]{{1,6}}$'
                    THEN (version_row.spec_json #>> '{{execution_policy,timeout_seconds}}')::integer
                    ELSE NULL
                END
            INTO
                v_job_id,
                v_project_id,
                v_source_revision_id,
                v_target_revision_id,
                v_source_policy_revision_id,
                v_target_policy_revision_id,
                v_target_namespace_id,
                v_timeout_seconds
            FROM public.job_versions AS version_row
            JOIN public.sync_jobs AS job_row ON job_row.id = version_row.job_id
            JOIN public.projects AS project_row ON project_row.id = job_row.project_id
            JOIN public.organizations AS organization_row
              ON organization_row.id = project_row.organization_id
            JOIN public.users AS requested_user ON requested_user.id = p_requested_by
            JOIN public.organization_members AS membership
              ON membership.organization_id = organization_row.id
             AND membership.user_id = requested_user.id
            JOIN public.datasource_revisions AS source_revision
              ON source_revision.id = version_row.source_datasource_revision_id
            JOIN public.datasource_revisions AS target_revision
              ON target_revision.id = version_row.target_datasource_revision_id
            WHERE version_row.id = p_job_version_id
              AND version_row.job_spec_schema_version = '1.0'
              AND jsonb_typeof(version_row.spec_json) = 'object'
              AND jsonb_typeof(version_row.spec_json -> 'execution_policy') = 'object'
              AND (
                    version_row.spec_json #>> '{{execution_policy,timeout_seconds}}'
                  ) ~ '^[0-9]{{1,6}}$'
              AND job_row.status = 'PUBLISHED'
              AND project_row.status = 'ACTIVE'
              AND organization_row.status = 'ACTIVE'
              AND requested_user.status = 'ACTIVE'
              AND requested_user.must_change_password = false
              AND membership.status = 'ACTIVE'
              AND EXISTS (
                    SELECT 1
                    FROM public.role_assignments AS role_assignment
                    WHERE role_assignment.organization_member_id = membership.id
                      AND (
                          (
                              role_assignment.scope_type = 'ORGANIZATION'
                              AND role_assignment.scope_id = organization_row.id
                              AND role_assignment.role = 'ADMIN'
                          )
                          OR (
                              role_assignment.scope_type = 'PROJECT'
                              AND role_assignment.scope_id = project_row.id
                              AND role_assignment.role = 'OPERATOR'
                          )
                      )
               )
              AND EXISTS (
                    SELECT 1
                    FROM public.datasource_usage_grants AS source_grant
                    WHERE source_grant.organization_member_id = membership.id
                      AND source_grant.datasource_id = source_revision.datasource_id
                      AND source_grant.usage = 'SOURCE_USE'
                      AND source_grant.status = 'ACTIVE'
              )
              AND EXISTS (
                    SELECT 1
                    FROM public.datasource_usage_grants AS target_grant
                    WHERE target_grant.organization_member_id = membership.id
                      AND target_grant.datasource_id = target_revision.datasource_id
                      AND target_grant.usage = 'TARGET_USE'
                      AND target_grant.status = 'ACTIVE'
              );
            IF NOT FOUND
               OR v_timeout_seconds < 60
               OR v_timeout_seconds > 604800 THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A requested user or job version is not eligible';
            END IF;
            -- The newly created row starts in the exact pending state 0022
            -- accepts. Its own SECURITY DEFINER authorization call then
            -- derives the full PEA snapshot from current public facts.
            v_created_at := clock_timestamp();
            IF v_target_valid_until <= v_created_at THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A target exclusivity expired during creation';
            END IF;
            INSERT INTO public.executions (
                id,
                project_id,
                job_id,
                job_version_id,
                trigger_type,
                authorization_mode,
                requested_by,
                process_state,
                data_effect,
                verification_state,
                capacity_profile,
                service_reservation_seconds,
                queue_eligibility_state,
                queue_block_reason,
                queue_state_changed_at,
                queued_at,
                timeout_seconds,
                source_datasource_revision_id,
                target_datasource_revision_id,
                source_endpoint_policy_revision_id,
                target_endpoint_policy_revision_id,
                target_namespace_id,
                source_quiescence_confirmation,
                target_exclusivity_confirmation,
                target_exclusivity_status,
                created_at
            ) VALUES (
                p_execution_id,
                v_project_id,
                v_job_id,
                p_job_version_id,
                'MANUAL',
                'PHASE_A_HARNESS',
                p_requested_by,
                'QUEUED',
                'NONE',
                'NOT_STARTED',
                'LARGE',
                3600,
                'BLOCKED',
                'PHASE_A_AUTHORIZATION_PENDING',
                v_created_at,
                v_created_at,
                v_timeout_seconds,
                v_source_revision_id,
                v_target_revision_id,
                v_source_policy_revision_id,
                v_target_policy_revision_id,
                v_target_namespace_id,
                p_source_quiescence_confirmation,
                p_target_exclusivity_confirmation,
                'ACTIVE',
                v_created_at
            );
            INSERT INTO {_CHECKPOINT_TABLE} (
                execution_id,
                authorization_id,
                grant_id,
                lock_id,
                job_id,
                job_version_id,
                target_namespace_id,
                checkpoint,
                state,
                lock_state,
                occurred_at
            ) VALUES (
                p_execution_id,
                NULL,
                NULL,
                NULL,
                v_job_id,
                p_job_version_id,
                v_target_namespace_id,
                'EXECUTION_CREATED',
                'BLOCKED',
                NULL,
                v_created_at
            );

            PERFORM {_AUTHORIZE_FUNCTION}(
                p_authorization_id,
                p_grant_id,
                p_execution_id
            );
            SELECT
                authorization_row.target_namespace_id,
                authorization_row.target_physical_table_identity_hash
            INTO
                v_target_namespace_id,
                v_target_physical_table_identity_hash
            FROM {_AUTHORIZATION_TABLE} AS authorization_row
            WHERE authorization_row.id = p_authorization_id
              AND authorization_row.grant_id = p_grant_id
              AND authorization_row.execution_id = p_execution_id;
            IF NOT FOUND
               OR v_target_namespace_id IS NULL
               OR v_target_physical_table_identity_hash !~ '^[a-f0-9]{{64}}$' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A authorization binding was not persisted';
            END IF;
            v_bound_at := clock_timestamp();
            INSERT INTO {_CHECKPOINT_TABLE} (
                execution_id,
                authorization_id,
                grant_id,
                lock_id,
                job_id,
                job_version_id,
                target_namespace_id,
                checkpoint,
                state,
                lock_state,
                occurred_at
            ) VALUES (
                p_execution_id,
                p_authorization_id,
                p_grant_id,
                NULL,
                v_job_id,
                p_job_version_id,
                v_target_namespace_id,
                'PEA_BOUND',
                'BLOCKED',
                NULL,
                v_bound_at
            );

            -- Reuse the public global lock table rather than creating a
            -- private namespace. The existing partial unique index makes a
            -- concurrent STANDARD/PHASE_A_HARNESS reservation fail atomically.
            v_reserved_at := clock_timestamp();
            IF v_target_valid_until <= v_reserved_at THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A target exclusivity expired before reservation';
            END IF;
            INSERT INTO public.target_copy_locks (
                id,
                target_namespace_id,
                physical_table_identity_hash,
                execution_id,
                attempt_id,
                fence_epoch,
                state,
                reserved_at,
                acquired_at,
                released_at
            ) VALUES (
                p_lock_id,
                v_target_namespace_id,
                v_target_physical_table_identity_hash,
                p_execution_id,
                NULL,
                NULL,
                'RESERVED',
                v_reserved_at,
                NULL,
                NULL
            );
            INSERT INTO {_CHECKPOINT_TABLE} (
                execution_id,
                authorization_id,
                grant_id,
                lock_id,
                job_id,
                job_version_id,
                target_namespace_id,
                checkpoint,
                state,
                lock_state,
                occurred_at
            ) VALUES (
                p_execution_id,
                p_authorization_id,
                p_grant_id,
                p_lock_id,
                v_job_id,
                p_job_version_id,
                v_target_namespace_id,
                'LOCK_RESERVED',
                'RESERVED',
                'RESERVED',
                v_reserved_at
            );

            -- The intermediate receipts remain private audit rows.  The only
            -- external result is the final atomic fact; do not expose a
            -- successfully-created-but-not-authorized or unlocked receipt.
            IF NOT EXISTS (
                SELECT 1
                FROM public.executions AS execution_row
                JOIN public.target_copy_locks AS target_lock
                  ON target_lock.id = p_lock_id
                 AND target_lock.execution_id = execution_row.id
                WHERE execution_row.id = p_execution_id
                  AND execution_row.authorization_mode = 'PHASE_A_HARNESS'
                  AND execution_row.process_state = 'QUEUED'
                  AND execution_row.queue_eligibility_state = 'BLOCKED'
                  AND execution_row.queue_block_reason = 'PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED'
                  AND target_lock.target_namespace_id = v_target_namespace_id
                  AND target_lock.state = 'RESERVED'
                  AND target_lock.attempt_id IS NULL
                  AND target_lock.fence_epoch IS NULL
                  AND target_lock.acquired_at IS NULL
                  AND target_lock.released_at IS NULL
            ) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A final create authorization lock state is incomplete';
            END IF;
            RETURN QUERY
            SELECT
                checkpoint_row.execution_id,
                checkpoint_row.authorization_id,
                checkpoint_row.grant_id,
                checkpoint_row.lock_id,
                checkpoint_row.job_id,
                checkpoint_row.job_version_id,
                checkpoint_row.target_namespace_id,
                checkpoint_row.checkpoint::text,
                execution_row.process_state::text,
                execution_row.queue_eligibility_state::text,
                execution_row.queue_block_reason::text,
                target_lock.state::text,
                checkpoint_row.occurred_at
            FROM {_CHECKPOINT_TABLE} AS checkpoint_row
            JOIN public.executions AS execution_row
              ON execution_row.id = checkpoint_row.execution_id
            JOIN public.target_copy_locks AS target_lock
              ON target_lock.id = checkpoint_row.lock_id
             AND target_lock.execution_id = checkpoint_row.execution_id
            WHERE checkpoint_row.execution_id = p_execution_id
              AND checkpoint_row.checkpoint = 'LOCK_RESERVED'
              AND checkpoint_row.authorization_id = p_authorization_id
              AND checkpoint_row.grant_id = p_grant_id
              AND checkpoint_row.lock_id = p_lock_id
              AND execution_row.authorization_mode = 'PHASE_A_HARNESS'
              AND execution_row.process_state = 'QUEUED'
              AND execution_row.queue_eligibility_state = 'BLOCKED'
              AND execution_row.queue_block_reason = 'PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED'
              AND target_lock.state = 'RESERVED';
        END;
        $$;
        """
    )

    for function, signature in (
        (_CHECKPOINT_GUARD_FUNCTION, ""),
        (_CREATE_FUNCTION, _CREATE_SIGNATURE),
    ):
        suffix = f"({signature})" if signature else "()"
        op.execute(f"ALTER FUNCTION {function}{suffix} OWNER TO {_LEDGER_OWNER_ROLE}")
        for role in ("PUBLIC", *_RUNTIME_ROLES, _ISSUER_ROLE, _CONSUMER_ROLE, _RUNNER_ROLE):
            op.execute(f"REVOKE ALL PRIVILEGES ON FUNCTION {function}{suffix} FROM {role}")
    op.execute(f"GRANT USAGE ON SCHEMA {_PRIVATE_SCHEMA} TO {_ISSUER_ROLE}")
    op.execute(
        f"GRANT EXECUTE ON FUNCTION {_CREATE_FUNCTION}({_CREATE_SIGNATURE}) "
        f"TO {_ISSUER_ROLE}"
    )


def downgrade() -> None:
    _require_postgresql_superuser()
    # A downgrade must never discard the private creation ledger while its
    # public Execution/lock counterpart still exists.  In particular, letting
    # 0022 subsequently remove the authorization discriminator would expose
    # an orphaned protected row to the older standard runtime model.  The only
    # safe rollback is before any protected execution/authorization/checkpoint
    # state has been created; operators must otherwise use a protected
    # disposition workflow that does not exist in this slice.
    #
    # The locks must precede the inspection.  Without them, an issuer could
    # commit create -> PEA -> lock after a clean EXISTS check and before the
    # subsequent DROP statements.  ACCESS EXCLUSIVE is intentional maintenance
    # serialization: this downgrade cannot coexist with any ordinary or
    # protected execution lifecycle transaction.
    op.execute(
        f"""
        LOCK TABLE
            public.executions,
            public.execution_attempts,
            public.target_copy_locks,
            {_GRANT_TABLE},
            {_AUTHORIZATION_TABLE},
            {_CHECKPOINT_TABLE}
        IN ACCESS EXCLUSIVE MODE;

        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM public.executions
                WHERE authorization_mode = 'PHASE_A_HARNESS'
            )
            OR EXISTS (SELECT 1 FROM {_AUTHORIZATION_TABLE})
            OR EXISTS (SELECT 1 FROM {_CHECKPOINT_TABLE}) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A protected execution state blocks lifecycle downgrade';
            END IF;
        END
        $$;
        """
    )
    op.execute(f"DROP FUNCTION IF EXISTS {_CREATE_FUNCTION}({_CREATE_SIGNATURE})")
    op.execute(
        "DROP TRIGGER IF EXISTS phase_a_execution_create_checkpoint_no_truncate "
        f"ON {_CHECKPOINT_TABLE}"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS phase_a_execution_create_checkpoint_immutable "
        f"ON {_CHECKPOINT_TABLE}"
    )
    op.drop_index(
        "ix_phase_a_execution_create_checkpoints_execution_occurred",
        table_name=_CHECKPOINT_TABLE_NAME,
        schema=_PRIVATE_SCHEMA,
    )
    op.drop_table(_CHECKPOINT_TABLE_NAME, schema=_PRIVATE_SCHEMA)
    op.execute(f"DROP FUNCTION IF EXISTS {_CHECKPOINT_GUARD_FUNCTION}()")

    insert_columns = ", ".join(_EXECUTION_INSERT_COLUMNS)
    op.execute(
        f"REVOKE INSERT ({insert_columns}) ON TABLE public.executions "
        f"FROM {_LEDGER_OWNER_ROLE}"
    )
    for table in _ADDITIONAL_PUBLIC_READ_TABLES:
        op.execute(f"REVOKE SELECT ON TABLE {table} FROM {_LEDGER_OWNER_ROLE}")
    op.execute(
        "REVOKE UPDATE ("
        f"{_SYSTEM_CONTROL_LOCK_COLUMN}"
        ") ON TABLE public.system_control "
        f"FROM {_LEDGER_OWNER_ROLE}"
    )
