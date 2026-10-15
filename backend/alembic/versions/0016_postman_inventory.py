"""Add sanitized Postman collection inventory to targets.

Revision ID: 0016_postman_inventory
Revises: 0015_generic_domain
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0016_postman_inventory"
down_revision: str | None = "0015_generic_domain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE discoverysource ADD VALUE IF NOT EXISTS 'POSTMAN'")
    document_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    with op.batch_alter_table("targets") as batch:
        batch.add_column(sa.Column("postman_document", document_type, nullable=True))
        batch.add_column(sa.Column("postman_name", sa.String(240), nullable=True))
        batch.add_column(sa.Column("postman_version", sa.String(40), nullable=True))
        batch.add_column(
            sa.Column("postman_request_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(sa.Column("postman_imported_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    with op.batch_alter_table("targets") as batch:
        batch.drop_column("postman_imported_at")
        batch.drop_column("postman_request_count")
        batch.drop_column("postman_version")
        batch.drop_column("postman_name")
        batch.drop_column("postman_document")
    # PostgreSQL enum values are intentionally retained on downgrade.
