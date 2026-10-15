"""Remove persisted Auth Profile passwords in favor of transient validation input.

Revision ID: 0009_transient_auth_passwords
Revises: 0008_auth_profile_mfa
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0009_transient_auth_passwords"
down_revision: str | None = "0008_auth_profile_mfa"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(sa.text("UPDATE auth_profiles SET encrypted_password = NULL"))


def downgrade() -> None:
    # Cleared secrets are intentionally unrecoverable.
    pass
