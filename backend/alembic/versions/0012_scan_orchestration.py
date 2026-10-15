"""Add scan presets, progress and cooperative cancellation.

Revision ID: 0012_scan_orchestration
Revises: 0011_finding_workflow
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_scan_orchestration"
down_revision: str | None = "0011_finding_workflow"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'CANCELLED'")
    with op.batch_alter_table("scans") as batch:
        batch.add_column(
            sa.Column("preset", sa.String(32), nullable=False, server_default="PASSIVE")
        )
        batch.add_column(
            sa.Column("phase", sa.String(40), nullable=False, server_default="PENDING")
        )
        batch.add_column(
            sa.Column("progress_percent", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(
            sa.Column(
                "cancellation_requested", sa.Boolean(), nullable=False, server_default=sa.false()
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("cancellation_requested")
        batch.drop_column("progress_percent")
        batch.drop_column("phase")
        batch.drop_column("preset")
    # PostgreSQL enum values are intentionally retained because removing one requires
    # rebuilding the type and can invalidate historical rows.
