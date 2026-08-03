"""fence protected Phase-A execution locks through the global target lock

Revision ID: 20260802_0023
Revises: 20260802_0022
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260802_0023"
down_revision: str | Sequence[str] | None = "20260802_0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRIVATE_SCHEMA = "des_phase_a_qualification"
_AUTHORIZATION_TABLE = f"{_PRIVATE_SCHEMA}.phase_a_execution_authorizations"
_GRANT_TABLE = f"{_PRIVATE_SCHEMA}.phase_a_qualification_grants"
_LEDGER_OWNER_ROLE = "datax_phase_a_ledger_owner"
_RUNNER_ROLE = "datax_phase_a_runner"
_RUNTIME_ROLES = ("datax_api", "datax_worker", "datax_egress_guard")
_SUPERUSER_REQUIRED_MESSAGE = "Phase-A execution lock migration requires a PostgreSQL superuser"

_RESERVE_FUNCTION = f"{_PRIVATE_SCHEMA}.des_reserve_phase_a_execution_lock"
_CLAIM_FUNCTION = f"{_PRIVATE_SCHEMA}.des_claim_phase_a_execution_lock"
_HEARTBEAT_FUNCTION = f"{_PRIVATE_SCHEMA}.des_heartbeat_phase_a_execution_lock"
_RECOVERY_FUNCTION = f"{_PRIVATE_SCHEMA}.des_require_phase_a_execution_recovery"
_RELEASE_FUNCTION = f"{_PRIVATE_SCHEMA}.des_release_phase_a_execution_lock"
_READ_FUNCTION = f"{_PRIVATE_SCHEMA}.des_read_phase_a_execution_lock"

_RESERVE_SIGNATURE = "uuid, uuid"
_CLAIM_SIGNATURE = "uuid, uuid, text, text, text, text, integer"
_HEARTBEAT_SIGNATURE = "uuid, uuid, bigint, text, integer"
_RECOVERY_SIGNATURE = "uuid, uuid, bigint, text, text"
_RELEASE_SIGNATURE = "uuid, uuid, bigint, text, text"
_READ_SIGNATURE = "uuid"


def _require_postgresql_superuser() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("Phase-A execution locking requires PostgreSQL")
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = '{_SUPERUSER_REQUIRED_MESSAGE}';
            END IF;
        END
        $$;
        """
    )


def _create_no_login_runner_role() -> None:
    # Like the issuer and consumer roles, this is deliberately not a usable
    # product credential.  A later protected-harness slice must provision a
    # short-lived login out of band; standard Compose/Settings/Launcher never
    # receive it.  Reject any pre-existing principal or membership instead of
    # trying to normalize an authority whose prior grants cannot be audited.
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{_RUNNER_ROLE}') THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A private runner role must not pre-exist';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM pg_auth_members AS membership
                JOIN pg_roles AS member_role ON member_role.oid = membership.member
                JOIN pg_roles AS parent_role ON parent_role.oid = membership.roleid
                WHERE member_role.rolname = '{_RUNNER_ROLE}'
                   OR parent_role.rolname = '{_RUNNER_ROLE}'
            ) THEN
                RAISE EXCEPTION
                    USING ERRCODE = '55000',
                          MESSAGE = 'Phase-A private runner role membership is not allowed';
            END IF;
            CREATE ROLE {_RUNNER_ROLE}
                NOLOGIN
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOINHERIT
                NOREPLICATION
                NOBYPASSRLS
                CONNECTION LIMIT 1;
        END
        $$;
        """
    )


def upgrade() -> None:
    _require_postgresql_superuser()
    _create_no_login_runner_role()

    # Do not create a second per-Phase-A namespace lock table.  The existing
    # public target_copy_locks partial unique index is the product-wide target
    # exclusion invariant: it spans STANDARD and PHASE_A_HARNESS executions
    # and retains RECOVERY_REQUIRED rows.  These two owner-only RLS policies
    # give the SECURITY DEFINER functions access to private descendants while
    # retaining 0022's STANDARD-only policies for every normal runtime role.
    for table, predicate in (
        (
            "execution_attempts",
            """
            EXISTS (
                SELECT 1
                FROM public.executions AS parent_execution
                WHERE parent_execution.id = execution_attempts.execution_id
                  AND parent_execution.authorization_mode = 'PHASE_A_HARNESS'
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
                  AND parent_execution.authorization_mode = 'PHASE_A_HARNESS'
            )
            """,
        ),
    ):
        policy_name = f"phase_a_ledger_private_{table}"
        op.execute(
            f"""
            CREATE POLICY {policy_name}
            ON public.{table}
            FOR ALL TO {_LEDGER_OWNER_ROLE}
            USING ({predicate})
            WITH CHECK ({predicate})
            """
        )

    # The ledger owner remains NOLOGIN and no role may inherit it.  These are
    # intentionally the exact public columns its narrowly-scoped functions
    # need; neither the runner nor normal runtime roles receive direct DML.
    op.execute(
        "GRANT UPDATE (fence_epoch, active_attempt_id, attempt_count, "
        "process_state, data_effect, verification_state, state_version, "
        "finished_at, failure_code, failure_message) ON TABLE public.executions "
        f"TO {_LEDGER_OWNER_ROLE}"
    )
    op.execute(
        "GRANT SELECT, INSERT (id, execution_id, attempt_no, worker_id, "
        "lease_token_hash, fence_epoch, lease_expires_at, heartbeat_at, "
        "host_boot_id, cgroup_identity), UPDATE (lease_expires_at, heartbeat_at, "
        "finished_at, termination_reason) ON TABLE public.execution_attempts "
        f"TO {_LEDGER_OWNER_ROLE}"
    )
    op.execute(
        "GRANT SELECT, INSERT (id, target_namespace_id, "
        "physical_table_identity_hash, execution_id, attempt_id, fence_epoch, "
        "state, reserved_at, acquired_at, released_at), UPDATE (state, attempt_id, "
        "fence_epoch, acquired_at, released_at) ON TABLE public.target_copy_locks "
        f"TO {_LEDGER_OWNER_ROLE}"
    )

    # The role was introduced after 0021's default-ACL hardening.  Make the
    # same closed-default rule explicit for any future ledger-owner objects.
    for privilege_kind in ("TABLES", "SEQUENCES", "FUNCTIONS"):
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {_LEDGER_OWNER_ROLE} "
            f"IN SCHEMA {_PRIVATE_SCHEMA} REVOKE ALL ON {privilege_kind} FROM {_RUNNER_ROLE}"
        )
    for role in ("PUBLIC", *_RUNTIME_ROLES, _RUNNER_ROLE):
        op.execute(f"REVOKE ALL ON SCHEMA {_PRIVATE_SCHEMA} FROM {role}")
        op.execute(
            f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA {_PRIVATE_SCHEMA} FROM {role}"
        )
        op.execute(
            f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA {_PRIVATE_SCHEMA} FROM {role}"
        )
        op.execute(
            f"REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA {_PRIVATE_SCHEMA} FROM {role}"
        )

    # Reserving a Phase-A execution writes the existing *global* target lock,
    # but still leaves the execution BLOCKED.  The reserve operation has no
    # API/Worker caller in this release; it is a private, future-runner-only
    # database primitive and therefore cannot become a standard path bypass.
    op.execute(
        f"""
        CREATE FUNCTION {_RESERVE_FUNCTION}(
            p_lock_id uuid,
            p_execution_id uuid
        )
        RETURNS uuid
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            v_now timestamptz := clock_timestamp();
            v_authorization RECORD;
            v_execution public.executions%ROWTYPE;
            v_existing_lock_id uuid;
        BEGIN
            IF session_user <> '{_RUNNER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A runner role is required';
            END IF;
            IF p_lock_id IS NULL OR p_execution_id IS NULL THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A lock reservation input is incomplete';
            END IF;

            SELECT
                authorization_row.execution_id,
                authorization_row.target_namespace_id,
                authorization_row.target_physical_table_identity_hash
            INTO v_authorization
            FROM {_AUTHORIZATION_TABLE} AS authorization_row
            JOIN {_GRANT_TABLE} AS grant_row ON grant_row.id = authorization_row.grant_id
            WHERE authorization_row.execution_id = p_execution_id
              AND grant_row.state = 'ACTIVE'
              AND grant_row.qh_not_before <= v_now
              AND grant_row.qh_valid_until > v_now
            FOR UPDATE OF authorization_row, grant_row;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution authorization is not active';
            END IF;

            SELECT * INTO v_execution
            FROM public.executions
            WHERE id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND
               OR v_execution.authorization_mode <> 'PHASE_A_HARNESS'
               OR v_execution.process_state <> 'QUEUED'
               OR v_execution.active_attempt_id IS NOT NULL
               OR v_execution.attempt_count <> 0
               OR v_execution.fence_epoch <> 0
               OR v_execution.queue_eligibility_state <> 'BLOCKED'
               OR v_execution.queue_block_reason <> 'PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED'
               OR v_execution.target_namespace_id <> v_authorization.target_namespace_id
               OR v_execution.target_exclusivity_status <> 'ACTIVE'
               OR v_execution.target_exclusivity_revoked_at IS NOT NULL
               OR v_execution.target_exclusivity_revocation_reason IS NOT NULL THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution is not reservable';
            END IF;

            SELECT id INTO v_existing_lock_id
            FROM public.target_copy_locks
            WHERE execution_id = p_execution_id
            FOR UPDATE;
            IF FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution already has a target lock';
            END IF;

            INSERT INTO public.target_copy_locks (
                id, target_namespace_id, physical_table_identity_hash,
                execution_id, attempt_id, fence_epoch, state,
                reserved_at, acquired_at, released_at
            ) VALUES (
                p_lock_id, v_authorization.target_namespace_id,
                v_authorization.target_physical_table_identity_hash,
                p_execution_id, NULL, NULL, 'RESERVED', v_now, NULL, NULL
            );
            RETURN p_lock_id;
        END;
        $$;
        """
    )

    # Claim uses the same Execution.fence_epoch, ExecutionAttempt, and
    # TargetCopyLock lifecycle as the ordinary Worker.  A future runner must
    # add all PEA/QH/current-fact, confirmation, credential, audit and Popen
    # checkpoints before it calls this primitive.  Today no product process
    # has the NOLOGIN role or invokes the function, so this cannot start
    # DataX or make a private execution eligible.
    op.execute(
        f"""
        CREATE FUNCTION {_CLAIM_FUNCTION}(
            p_execution_id uuid,
            p_attempt_id uuid,
            p_worker_id text,
            p_lease_token_hash text,
            p_host_boot_id text,
            p_cgroup_identity text,
            p_lease_seconds integer
        )
        RETURNS TABLE (
            attempt_id uuid,
            fence_epoch bigint,
            lease_expires_at timestamptz
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            v_now timestamptz := clock_timestamp();
            v_authorization RECORD;
            v_execution public.executions%ROWTYPE;
            v_lock public.target_copy_locks%ROWTYPE;
            v_next_fence bigint;
        BEGIN
            IF session_user <> '{_RUNNER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A runner role is required';
            END IF;
            IF p_execution_id IS NULL OR p_attempt_id IS NULL
               OR p_worker_id !~ '^[A-Za-z0-9._:-]{{1,128}}$'
               OR p_lease_token_hash !~ '^[a-f0-9]{{64}}$'
               OR p_host_boot_id !~ '^[A-Za-z0-9._:-]{{1,128}}$'
               OR p_cgroup_identity !~ '^[-A-Za-z0-9._:/@+]{{1,255}}[-A-Za-z0-9._:/@+]?$'
               OR p_lease_seconds < 5 OR p_lease_seconds > 300 THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution claim input is invalid';
            END IF;

            SELECT
                authorization_row.execution_id,
                authorization_row.target_namespace_id,
                authorization_row.target_physical_table_identity_hash
            INTO v_authorization
            FROM {_AUTHORIZATION_TABLE} AS authorization_row
            JOIN {_GRANT_TABLE} AS grant_row ON grant_row.id = authorization_row.grant_id
            WHERE authorization_row.execution_id = p_execution_id
              AND grant_row.state = 'ACTIVE'
              AND grant_row.qh_not_before <= v_now
              AND grant_row.qh_valid_until > v_now
            FOR UPDATE OF authorization_row, grant_row;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution authorization is not active';
            END IF;

            SELECT * INTO v_execution
            FROM public.executions
            WHERE id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND
               OR v_execution.authorization_mode <> 'PHASE_A_HARNESS'
               OR v_execution.process_state <> 'QUEUED'
               OR v_execution.active_attempt_id IS NOT NULL
               OR v_execution.attempt_count <> 0
               OR v_execution.queue_eligibility_state <> 'BLOCKED'
               OR v_execution.queue_block_reason <> 'PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED'
               OR v_execution.target_namespace_id <> v_authorization.target_namespace_id
               OR v_execution.target_exclusivity_status <> 'ACTIVE'
               OR v_execution.target_exclusivity_revoked_at IS NOT NULL
               OR v_execution.target_exclusivity_revocation_reason IS NOT NULL
               OR v_execution.fence_epoch >= 9223372036854775807 THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution is not claimable';
            END IF;

            SELECT * INTO v_lock
            FROM public.target_copy_locks
            WHERE execution_id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND
               OR v_lock.state <> 'RESERVED'
               OR v_lock.attempt_id IS NOT NULL
               OR v_lock.fence_epoch IS NOT NULL
               OR v_lock.target_namespace_id <> v_authorization.target_namespace_id
               OR v_lock.physical_table_identity_hash <>
                  v_authorization.target_physical_table_identity_hash THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A target reservation is not current';
            END IF;

            v_next_fence := v_execution.fence_epoch + 1;
            INSERT INTO public.execution_attempts (
                id, execution_id, attempt_no, worker_id, lease_token_hash,
                fence_epoch, lease_expires_at, heartbeat_at, host_boot_id,
                cgroup_identity
            ) VALUES (
                p_attempt_id, p_execution_id, v_execution.attempt_count + 1,
                p_worker_id, p_lease_token_hash, v_next_fence,
                v_now + make_interval(secs => p_lease_seconds), v_now,
                p_host_boot_id, p_cgroup_identity
            );
            UPDATE public.executions AS execution_row
            SET process_state = 'STARTING',
                state_version = state_version + 1,
                fence_epoch = v_next_fence,
                active_attempt_id = p_attempt_id,
                attempt_count = attempt_count + 1
            WHERE execution_row.id = p_execution_id
              AND execution_row.authorization_mode = 'PHASE_A_HARNESS'
              AND execution_row.process_state = 'QUEUED'
              AND execution_row.active_attempt_id IS NULL
              AND execution_row.fence_epoch = v_execution.fence_epoch;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution changed during claim';
            END IF;
            UPDATE public.target_copy_locks AS target_lock
            SET state = 'ACTIVE',
                attempt_id = p_attempt_id,
                fence_epoch = v_next_fence,
                acquired_at = v_now
            WHERE target_lock.id = v_lock.id
              AND target_lock.execution_id = p_execution_id
              AND target_lock.state = 'RESERVED'
              AND target_lock.attempt_id IS NULL
              AND target_lock.fence_epoch IS NULL;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A target reservation changed during claim';
            END IF;
            RETURN QUERY
            SELECT p_attempt_id, v_next_fence,
                   v_now + make_interval(secs => p_lease_seconds);
        END;
        $$;
        """
    )

    # A fence holder may extend only its own unexpired lease.  The PEA/PAG
    # recheck is deliberately repeated here so a later revoke/expiry cannot
    # be hidden by an old in-memory claim object.
    op.execute(
        f"""
        CREATE FUNCTION {_HEARTBEAT_FUNCTION}(
            p_execution_id uuid,
            p_attempt_id uuid,
            p_fence_epoch bigint,
            p_lease_token_hash text,
            p_lease_seconds integer
        )
        RETURNS timestamptz
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            v_now timestamptz := clock_timestamp();
            v_authorization_id uuid;
            v_execution public.executions%ROWTYPE;
            v_attempt public.execution_attempts%ROWTYPE;
            v_lock public.target_copy_locks%ROWTYPE;
            v_lease_expires_at timestamptz;
        BEGIN
            IF session_user <> '{_RUNNER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A runner role is required';
            END IF;
            IF p_execution_id IS NULL OR p_attempt_id IS NULL
               OR p_fence_epoch < 1
               OR p_lease_token_hash !~ '^[a-f0-9]{{64}}$'
               OR p_lease_seconds < 5 OR p_lease_seconds > 300 THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A execution heartbeat input is invalid';
            END IF;

            SELECT authorization_row.id INTO v_authorization_id
            FROM {_AUTHORIZATION_TABLE} AS authorization_row
            JOIN {_GRANT_TABLE} AS grant_row ON grant_row.id = authorization_row.grant_id
            WHERE authorization_row.execution_id = p_execution_id
              AND grant_row.state = 'ACTIVE'
              AND grant_row.qh_not_before <= v_now
              AND grant_row.qh_valid_until > v_now
            FOR UPDATE OF authorization_row, grant_row;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution authorization is not active';
            END IF;

            SELECT * INTO v_execution
            FROM public.executions
            WHERE id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution fence is no longer current';
            END IF;
            SELECT * INTO v_attempt
            FROM public.execution_attempts
            WHERE id = p_attempt_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution fence is no longer current';
            END IF;
            SELECT * INTO v_lock
            FROM public.target_copy_locks
            WHERE execution_id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND
               OR v_execution.authorization_mode <> 'PHASE_A_HARNESS'
               OR v_execution.active_attempt_id <> p_attempt_id
               OR v_execution.fence_epoch <> p_fence_epoch
               OR v_attempt.execution_id <> p_execution_id
               OR v_attempt.fence_epoch <> p_fence_epoch
               OR v_attempt.lease_token_hash <> p_lease_token_hash
               OR v_attempt.lease_expires_at <= v_now
               OR v_lock.state <> 'ACTIVE'
               OR v_lock.attempt_id <> p_attempt_id
               OR v_lock.fence_epoch <> p_fence_epoch THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution fence is no longer current';
            END IF;
            v_lease_expires_at := v_now + make_interval(secs => p_lease_seconds);
            UPDATE public.execution_attempts
            SET heartbeat_at = v_now,
                lease_expires_at = v_lease_expires_at
            WHERE id = p_attempt_id
              AND execution_id = p_execution_id
              AND fence_epoch = p_fence_epoch
              AND lease_token_hash = p_lease_token_hash
              AND lease_expires_at > v_now;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution fence changed during heartbeat';
            END IF;
            UPDATE public.executions
            SET state_version = state_version + 1
            WHERE id = p_execution_id
              AND authorization_mode = 'PHASE_A_HARNESS'
              AND active_attempt_id = p_attempt_id
              AND fence_epoch = p_fence_epoch;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution changed during heartbeat';
            END IF;
            RETURN v_lease_expires_at;
        END;
        $$;
        """
    )

    # A fence holder can only fail closed into RECOVERY_REQUIRED; this does
    # not release the target namespace.  There is intentionally no automatic
    # rerun or standard recovery integration.  A future protected recovery
    # slice must add independent confirmation/audit/reconciliation gates.
    op.execute(
        f"""
        CREATE FUNCTION {_RECOVERY_FUNCTION}(
            p_execution_id uuid,
            p_attempt_id uuid,
            p_fence_epoch bigint,
            p_lease_token_hash text,
            p_reason text
        )
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            v_now timestamptz := clock_timestamp();
            v_execution public.executions%ROWTYPE;
            v_attempt public.execution_attempts%ROWTYPE;
            v_lock public.target_copy_locks%ROWTYPE;
        BEGIN
            IF session_user <> '{_RUNNER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A runner role is required';
            END IF;
            IF p_execution_id IS NULL OR p_attempt_id IS NULL
               OR p_fence_epoch < 1
               OR p_lease_token_hash !~ '^[a-f0-9]{{64}}$'
               OR p_reason !~ '^[A-Z][A-Z0-9_]{{2,63}}$' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A recovery input is invalid';
            END IF;

            -- The PEA join proves this is a protected execution, but a
            -- revoked/expired grant must still be recoverable into a safe
            -- locked state rather than becoming an orphaned active write.
            PERFORM 1
            FROM {_AUTHORIZATION_TABLE}
            WHERE execution_id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution has no private authorization record';
            END IF;
            SELECT * INTO v_execution
            FROM public.executions
            WHERE id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution fence is no longer current';
            END IF;
            SELECT * INTO v_attempt
            FROM public.execution_attempts
            WHERE id = p_attempt_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution fence is no longer current';
            END IF;
            SELECT * INTO v_lock
            FROM public.target_copy_locks
            WHERE execution_id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND
               OR v_execution.authorization_mode <> 'PHASE_A_HARNESS'
               OR v_execution.active_attempt_id <> p_attempt_id
               OR v_execution.fence_epoch <> p_fence_epoch
               OR v_attempt.execution_id <> p_execution_id
               OR v_attempt.fence_epoch <> p_fence_epoch
               OR v_attempt.lease_token_hash <> p_lease_token_hash
               OR v_lock.state <> 'ACTIVE'
               OR v_lock.attempt_id <> p_attempt_id
               OR v_lock.fence_epoch <> p_fence_epoch THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution fence is no longer current';
            END IF;
            UPDATE public.execution_attempts
            SET finished_at = COALESCE(finished_at, v_now),
                termination_reason = p_reason
            WHERE id = p_attempt_id
              AND execution_id = p_execution_id
              AND fence_epoch = p_fence_epoch
              AND lease_token_hash = p_lease_token_hash;
            UPDATE public.executions
            SET process_state = 'LOST',
                data_effect = 'UNKNOWN',
                verification_state = 'INCONCLUSIVE',
                state_version = state_version + 1,
                finished_at = v_now,
                failure_code = 'PHASE_A_RUNNER_RECOVERY_REQUIRED',
                failure_message = 'protected Phase-A runner requires manual recovery'
            WHERE id = p_execution_id
              AND authorization_mode = 'PHASE_A_HARNESS'
              AND active_attempt_id = p_attempt_id
              AND fence_epoch = p_fence_epoch
              AND process_state IN ('STARTING', 'RUNNING', 'VERIFYING', 'CANCEL_REQUESTED');
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution changed during recovery transition';
            END IF;
            UPDATE public.target_copy_locks
            SET state = 'RECOVERY_REQUIRED'
            WHERE id = v_lock.id
              AND execution_id = p_execution_id
              AND state = 'ACTIVE'
              AND attempt_id = p_attempt_id
              AND fence_epoch = p_fence_epoch;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A target lock changed during recovery transition';
            END IF;
            RETURN true;
        END;
        $$;
        """
    )

    # Releasing is deliberately restricted to a terminal private execution
    # that is already RECOVERY_REQUIRED and still presents the exact prior
    # fence/token.  No current product workflow can reach it; it exists so a
    # later protected recovery design has an atomic, global-lock primitive.
    op.execute(
        f"""
        CREATE FUNCTION {_RELEASE_FUNCTION}(
            p_execution_id uuid,
            p_attempt_id uuid,
            p_fence_epoch bigint,
            p_lease_token_hash text,
            p_reason text
        )
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            v_now timestamptz := clock_timestamp();
            v_execution public.executions%ROWTYPE;
            v_attempt public.execution_attempts%ROWTYPE;
            v_lock public.target_copy_locks%ROWTYPE;
        BEGIN
            IF session_user <> '{_RUNNER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A runner role is required';
            END IF;
            IF p_execution_id IS NULL OR p_attempt_id IS NULL
               OR p_fence_epoch < 1
               OR p_lease_token_hash !~ '^[a-f0-9]{{64}}$'
               OR p_reason !~ '^[A-Z][A-Z0-9_]{{2,63}}$' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A release input is invalid';
            END IF;
            PERFORM 1
            FROM {_AUTHORIZATION_TABLE}
            WHERE execution_id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A execution has no private authorization record';
            END IF;
            SELECT * INTO v_execution
            FROM public.executions
            WHERE id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A recovery lock is no longer current';
            END IF;
            SELECT * INTO v_attempt
            FROM public.execution_attempts
            WHERE id = p_attempt_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A recovery lock is no longer current';
            END IF;
            SELECT * INTO v_lock
            FROM public.target_copy_locks
            WHERE execution_id = p_execution_id
            FOR UPDATE;
            IF NOT FOUND
               OR v_execution.authorization_mode <> 'PHASE_A_HARNESS'
               OR v_execution.process_state NOT IN ('FAILED', 'TIMED_OUT', 'CANCELED', 'LOST')
               OR v_execution.active_attempt_id <> p_attempt_id
               OR v_execution.fence_epoch <> p_fence_epoch
               OR v_attempt.execution_id <> p_execution_id
               OR v_attempt.fence_epoch <> p_fence_epoch
               OR v_attempt.lease_token_hash <> p_lease_token_hash
               OR v_lock.state <> 'RECOVERY_REQUIRED'
               OR v_lock.attempt_id <> p_attempt_id
               OR v_lock.fence_epoch <> p_fence_epoch THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A recovery lock is no longer current';
            END IF;
            UPDATE public.execution_attempts
            SET termination_reason = p_reason
            WHERE id = p_attempt_id
              AND execution_id = p_execution_id
              AND fence_epoch = p_fence_epoch
              AND lease_token_hash = p_lease_token_hash;
            UPDATE public.target_copy_locks
            SET state = 'RELEASED',
                released_at = v_now
            WHERE id = v_lock.id
              AND execution_id = p_execution_id
              AND state = 'RECOVERY_REQUIRED'
              AND attempt_id = p_attempt_id
              AND fence_epoch = p_fence_epoch;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    USING ERRCODE = 'P0001',
                          MESSAGE = 'Phase-A recovery lock changed during release';
            END IF;
            RETURN true;
        END;
        $$;
        """
    )

    # This private reader returns only lifecycle/fence facts.  It deliberately
    # omits the lease-token hash and every credential/configuration value.
    op.execute(
        f"""
        CREATE FUNCTION {_READ_FUNCTION}(
            p_execution_id uuid
        )
        RETURNS TABLE (
            lock_id uuid,
            execution_id uuid,
            target_namespace_id uuid,
            physical_table_identity_hash text,
            lock_state text,
            attempt_id uuid,
            fence_epoch bigint,
            worker_id text,
            host_boot_id text,
            cgroup_identity text,
            reserved_at timestamptz,
            acquired_at timestamptz,
            heartbeat_at timestamptz,
            lease_expires_at timestamptz,
            released_at timestamptz
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        BEGIN
            IF session_user <> '{_RUNNER_ROLE}' THEN
                RAISE EXCEPTION
                    USING ERRCODE = '42501',
                          MESSAGE = 'Phase-A runner role is required';
            END IF;
            IF p_execution_id IS NULL THEN
                RAISE EXCEPTION
                    USING ERRCODE = '22023',
                          MESSAGE = 'Phase-A lock lookup input is incomplete';
            END IF;
            RETURN QUERY
            SELECT
                target_lock.id,
                target_lock.execution_id,
                target_lock.target_namespace_id,
                target_lock.physical_table_identity_hash::text,
                target_lock.state::text,
                target_lock.attempt_id,
                target_lock.fence_epoch,
                attempt.worker_id::text,
                attempt.host_boot_id::text,
                attempt.cgroup_identity::text,
                target_lock.reserved_at,
                target_lock.acquired_at,
                attempt.heartbeat_at,
                attempt.lease_expires_at,
                target_lock.released_at
            FROM public.target_copy_locks AS target_lock
            JOIN {_AUTHORIZATION_TABLE} AS authorization_row
              ON authorization_row.execution_id = target_lock.execution_id
            JOIN public.executions AS execution_row
              ON execution_row.id = target_lock.execution_id
             AND execution_row.authorization_mode = 'PHASE_A_HARNESS'
            LEFT JOIN public.execution_attempts AS attempt
              ON attempt.id = target_lock.attempt_id
             AND attempt.execution_id = target_lock.execution_id
             AND attempt.fence_epoch = target_lock.fence_epoch
            WHERE target_lock.execution_id = p_execution_id;
        END;
        $$;
        """
    )

    functions = (
        (_RESERVE_FUNCTION, _RESERVE_SIGNATURE),
        (_CLAIM_FUNCTION, _CLAIM_SIGNATURE),
        (_HEARTBEAT_FUNCTION, _HEARTBEAT_SIGNATURE),
        (_RECOVERY_FUNCTION, _RECOVERY_SIGNATURE),
        (_RELEASE_FUNCTION, _RELEASE_SIGNATURE),
        (_READ_FUNCTION, _READ_SIGNATURE),
    )
    for function, signature in functions:
        op.execute(f"ALTER FUNCTION {function}({signature}) OWNER TO {_LEDGER_OWNER_ROLE}")
        for role in ("PUBLIC", *_RUNTIME_ROLES, _RUNNER_ROLE):
            op.execute(
                f"REVOKE ALL PRIVILEGES ON FUNCTION {function}({signature}) FROM {role}"
            )

    op.execute(
        f"""
        DO $$
        BEGIN
            EXECUTE format(
                'GRANT CONNECT ON DATABASE %I TO %I',
                current_database(),
                '{_RUNNER_ROLE}'
            );
        END
        $$;
        """
    )
    op.execute(f"GRANT USAGE ON SCHEMA {_PRIVATE_SCHEMA} TO {_RUNNER_ROLE}")
    for function, signature in functions:
        op.execute(
            f"GRANT EXECUTE ON FUNCTION {function}({signature}) TO {_RUNNER_ROLE}"
        )


def downgrade() -> None:
    _require_postgresql_superuser()
    functions = (
        (_READ_FUNCTION, _READ_SIGNATURE),
        (_RELEASE_FUNCTION, _RELEASE_SIGNATURE),
        (_RECOVERY_FUNCTION, _RECOVERY_SIGNATURE),
        (_HEARTBEAT_FUNCTION, _HEARTBEAT_SIGNATURE),
        (_CLAIM_FUNCTION, _CLAIM_SIGNATURE),
        (_RESERVE_FUNCTION, _RESERVE_SIGNATURE),
    )
    for function, signature in functions:
        op.execute(f"DROP FUNCTION IF EXISTS {function}({signature})")

    for table in ("target_copy_locks", "execution_attempts"):
        policy_name = f"phase_a_ledger_private_{table}"
        op.execute(f"DROP POLICY IF EXISTS {policy_name} ON public.{table}")

    op.execute(
        "REVOKE UPDATE (fence_epoch, active_attempt_id, attempt_count, "
        "process_state, data_effect, verification_state, state_version, "
        "finished_at, failure_code, failure_message) ON TABLE public.executions "
        f"FROM {_LEDGER_OWNER_ROLE}"
    )
    op.execute(
        "REVOKE SELECT, INSERT (id, execution_id, attempt_no, worker_id, "
        "lease_token_hash, fence_epoch, lease_expires_at, heartbeat_at, "
        "host_boot_id, cgroup_identity), UPDATE (lease_expires_at, heartbeat_at, "
        "finished_at, termination_reason) ON TABLE public.execution_attempts "
        f"FROM {_LEDGER_OWNER_ROLE}"
    )
    op.execute(
        "REVOKE SELECT, INSERT (id, target_namespace_id, "
        "physical_table_identity_hash, execution_id, attempt_id, fence_epoch, "
        "state, reserved_at, acquired_at, released_at), UPDATE (state, attempt_id, "
        "fence_epoch, acquired_at, released_at) ON TABLE public.target_copy_locks "
        f"FROM {_LEDGER_OWNER_ROLE}"
    )
    for privilege_kind in ("TABLES", "SEQUENCES", "FUNCTIONS"):
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {_LEDGER_OWNER_ROLE} "
            f"IN SCHEMA {_PRIVATE_SCHEMA} REVOKE ALL ON {privilege_kind} FROM {_RUNNER_ROLE}"
        )
    op.execute(
        f"""
        DO $$
        BEGIN
            EXECUTE format(
                'REVOKE ALL ON DATABASE %I FROM %I',
                current_database(),
                '{_RUNNER_ROLE}'
            );
        END
        $$;
        """
    )
    op.execute(f"DROP OWNED BY {_RUNNER_ROLE}")
    op.execute(f"DROP ROLE {_RUNNER_ROLE}")
