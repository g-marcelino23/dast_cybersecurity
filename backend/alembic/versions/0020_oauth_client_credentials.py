"""Add OAuth client credentials profiles.

Revision ID: 0020_oauth_client_credentials
Revises: 0019_target_components
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0020_oauth_client_credentials"
down_revision: str | None = "0019_target_components"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE authtype ADD VALUE IF NOT EXISTS 'OAUTH2_CLIENT_CREDENTIALS'")
    document_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    with op.batch_alter_table("auth_profiles") as batch:
        batch.add_column(sa.Column("oidc_discovery_url", sa.String(2048)))
        batch.add_column(
            sa.Column("oauth_scopes", document_type, nullable=False, server_default="[]")
        )
        batch.add_column(sa.Column("oauth_audience", sa.String(255)))


def downgrade() -> None:
    with op.batch_alter_table("auth_profiles") as batch:
        batch.drop_column("oauth_audience")
        batch.drop_column("oauth_scopes")
        batch.drop_column("oidc_discovery_url")
    # PostgreSQL enum values are intentionally retained on downgrade.
