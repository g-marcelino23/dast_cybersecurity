"""Add sanitized manual API request templates.

Revision ID: 0017_manual_api_requests
Revises: 0016_postman_inventory
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0017_manual_api_requests"
down_revision: str | None = "0016_postman_inventory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE discoverysource ADD VALUE IF NOT EXISTS 'MANUAL_API'")
    document_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table(
        "api_request_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "target_id",
            sa.Integer(),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("query_parameters", document_type, nullable=False),
        sa.Column("header_names", document_type, nullable=False),
        sa.Column("body_mode", sa.String(24), nullable=False, server_default="NONE"),
        sa.Column("content_type", sa.String(128), nullable=True),
        sa.Column("requires_auth", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_api_request_templates_target_id", "api_request_templates", ["target_id"])


def downgrade() -> None:
    op.drop_index("ix_api_request_templates_target_id", table_name="api_request_templates")
    op.drop_table("api_request_templates")
    # PostgreSQL enum values are intentionally retained on downgrade.
