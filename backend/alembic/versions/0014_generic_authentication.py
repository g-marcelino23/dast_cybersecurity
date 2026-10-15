"""Add generic authentication profiles.

Revision ID: 0014_generic_authentication
Revises: 0013_openapi_inventory
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_generic_authentication"
down_revision: str | None = "0013_openapi_inventory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

AUTH_TYPES = ("FORM_LOGIN", "BASIC", "BEARER_TOKEN", "API_KEY", "CUSTOM_HEADERS")


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            for value in AUTH_TYPES:
                op.execute(f"ALTER TYPE authtype ADD VALUE IF NOT EXISTS '{value}'")
    document_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    with op.batch_alter_table("auth_profiles") as batch:
        batch.add_column(
            sa.Column("body_encoding", sa.String(16), nullable=False, server_default="JSON")
        )
        batch.add_column(sa.Column("header_template", document_type, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("auth_profiles") as batch:
        batch.drop_column("header_template")
        batch.drop_column("body_encoding")
    # PostgreSQL enum values are intentionally retained on downgrade.
