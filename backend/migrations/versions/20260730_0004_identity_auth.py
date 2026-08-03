"""create identity and authentication facts

Revision ID: 20260730_0004
Revises: 20260730_0003
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260730_0004"
down_revision: str | Sequence[str] | None = "20260730_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")

    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'SUSPENDED')",
            name="ck_organizations_status",
        ),
        sa.CheckConstraint("row_version >= 1", name="ck_organizations_row_version"),
    )
    op.create_index(
        "uq_organizations_single_active",
        "organizations",
        ["status"],
        unique=True,
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", postgresql.CITEXT(), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'LOCKED', 'DISABLED')",
            name="ck_users_status",
        ),
        sa.CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_count"),
        sa.CheckConstraint("row_version >= 1", name="ck_users_row_version"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_status_created", "users", ["status", "created_at", "id"])

    op.create_table(
        "organization_members",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'SUSPENDED')",
            name="ck_organization_members_status",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "user_id",
            name="uq_organization_members_org_user",
        ),
    )
    op.create_index(
        "ix_organization_members_user_status",
        "organization_members",
        ["user_id", "status"],
    )

    op.create_table(
        "role_assignments",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_member_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope_type", sa.String(length=16), nullable=False),
        sa.Column("scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("granted_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_member_id"],
            ["organization_members.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["granted_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "scope_type IN ('ORGANIZATION', 'PROJECT')",
            name="ck_role_assignments_scope_type",
        ),
        sa.CheckConstraint(
            "role IN ('ADMIN', 'DEVELOPER', 'OPERATOR', 'VIEWER')",
            name="ck_role_assignments_role",
        ),
        sa.CheckConstraint(
            "(scope_type = 'ORGANIZATION' AND role = 'ADMIN') OR "
            "(scope_type = 'PROJECT' AND role IN ('DEVELOPER', 'OPERATOR', 'VIEWER'))",
            name="ck_role_assignments_scope_role",
        ),
        sa.UniqueConstraint(
            "organization_member_id",
            "scope_type",
            "scope_id",
            "role",
            name="uq_role_assignments_member_scope_role",
        ),
    )
    op.create_index(
        "ix_role_assignments_member_scope",
        "role_assignments",
        ["organization_member_id", "scope_type", "scope_id"],
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("family_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rotated_from_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(length=64), nullable=True),
        sa.Column("ip_hash", sa.LargeBinary(length=32), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["rotated_from_id"],
            ["auth_sessions.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_auth_sessions_token_hash"),
        sa.UniqueConstraint("rotated_from_id", name="uq_auth_sessions_rotated_from"),
    )
    op.create_index(
        "ix_auth_sessions_user_active",
        "auth_sessions",
        ["user_id", "revoked_at", "expires_at"],
    )
    op.create_index(
        "ix_auth_sessions_family",
        "auth_sessions",
        ["family_id", "issued_at"],
    )

    op.create_table(
        "idempotency_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("response_body", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "actor_id",
            "scope",
            "idempotency_key",
            name="uq_idempotency_actor_scope_key",
        ),
    )
    op.create_index(
        "ix_idempotency_expires",
        "idempotency_records",
        ["expires_at"],
    )

    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_sequence", sa.BigInteger(), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "canonicalization_version",
            sa.String(length=16),
            nullable=False,
            server_default="RFC8785-v1",
        ),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "previous_hash IS NULL OR previous_hash ~ '^[a-f0-9]{64}$'",
            name="ck_audit_events_previous_hash",
        ),
        sa.CheckConstraint(
            "event_hash ~ '^[a-f0-9]{64}$'",
            name="ck_audit_events_event_hash",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "organization_sequence",
            name="uq_audit_events_org_sequence",
        ),
        sa.UniqueConstraint("event_hash", name="uq_audit_events_event_hash"),
    )
    op.create_index(
        "ix_audit_events_org_sequence",
        "audit_events",
        ["organization_id", "organization_sequence"],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_org_sequence", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_idempotency_expires", table_name="idempotency_records")
    op.drop_table("idempotency_records")
    op.drop_index("ix_auth_sessions_family", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_user_active", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index("ix_role_assignments_member_scope", table_name="role_assignments")
    op.drop_table("role_assignments")
    op.drop_index("ix_organization_members_user_status", table_name="organization_members")
    op.drop_table("organization_members")
    op.drop_index("ix_users_status_created", table_name="users")
    op.drop_table("users")
    op.drop_index("uq_organizations_single_active", table_name="organizations")
    op.drop_table("organizations")
