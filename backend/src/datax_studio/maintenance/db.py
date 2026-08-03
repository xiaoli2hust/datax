from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from datax_studio.auth.db import Base


class RetentionHold(Base):
    """An immutable retention exception with an explicit release lifecycle.

    The generic scope identifier deliberately does not cascade with business
    records. A hold must survive long enough to explain why cleanup was
    blocked, even if the referenced resource is later removed after release.
    """

    __tablename__ = "retention_holds"
    __table_args__ = (
        CheckConstraint(
            "scope_type IN ('ORGANIZATION','PROJECT','EXECUTION','AUDIT_EVENT')",
            name="ck_retention_holds_scope_type",
        ),
        CheckConstraint(
            "(released_at IS NULL AND released_by IS NULL) "
            "OR (released_at IS NOT NULL AND released_by IS NOT NULL)",
            name="ck_retention_holds_release_pair",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name="ck_retention_holds_expiry",
        ),
        Index(
            "ix_retention_holds_scope_active",
            "organization_id",
            "scope_type",
            "scope_id",
            "released_at",
            "expires_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    scope_type: Mapped[str] = mapped_column(String(24), nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
    )
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
