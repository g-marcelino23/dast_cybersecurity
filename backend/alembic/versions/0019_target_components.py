"""Add target components.

Revision ID: 0019_target_components
Revises: 0018_public_target_verification
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0019_target_components"
down_revision: str | None = "0018_public_target_verification"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    document_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.add_column(
        "targets",
        sa.Column("components", document_type, nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("targets", "components")
