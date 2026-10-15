"""Add verified public target scope.

Revision ID: 0018_public_target_verification
Revises: 0017_manual_api_requests
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0018_public_target_verification"
down_revision: str | None = "0017_manual_api_requests"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    document_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.add_column(
        "targets",
        sa.Column("allowed_hosts", document_type, nullable=False, server_default="[]"),
    )
    op.add_column(
        "targets",
        sa.Column(
            "requires_ownership_verification",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column("targets", sa.Column("ownership_verification_token", sa.String(160)))
    op.add_column("targets", sa.Column("ownership_verified_at", sa.DateTime(timezone=True)))
    op.add_column(
        "targets", sa.Column("ownership_verification_expires_at", sa.DateTime(timezone=True))
    )


def downgrade() -> None:
    op.drop_column("targets", "ownership_verification_expires_at")
    op.drop_column("targets", "ownership_verified_at")
    op.drop_column("targets", "ownership_verification_token")
    op.drop_column("targets", "requires_ownership_verification")
    op.drop_column("targets", "allowed_hosts")
