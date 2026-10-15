"""Add normalized OpenAPI inventory to targets.

Revision ID: 0013_openapi_inventory
Revises: 0012_scan_orchestration
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_openapi_inventory"
down_revision: str | None = "0012_scan_orchestration"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE discoverysource ADD VALUE IF NOT EXISTS 'OPENAPI'")
    document_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    with op.batch_alter_table("targets") as batch:
        batch.add_column(sa.Column("openapi_document", document_type, nullable=True))
        batch.add_column(sa.Column("openapi_title", sa.String(240), nullable=True))
        batch.add_column(sa.Column("openapi_version", sa.String(40), nullable=True))
        batch.add_column(
            sa.Column(
                "openapi_operation_count", sa.Integer(), nullable=False, server_default="0"
            )
        )
        batch.add_column(sa.Column("openapi_imported_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    with op.batch_alter_table("targets") as batch:
        batch.drop_column("openapi_imported_at")
        batch.drop_column("openapi_operation_count")
        batch.drop_column("openapi_version")
        batch.drop_column("openapi_title")
        batch.drop_column("openapi_document")
    # PostgreSQL enum values are intentionally retained on downgrade.
