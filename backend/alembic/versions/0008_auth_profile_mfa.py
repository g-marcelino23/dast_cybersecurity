"""Add generic assisted MFA configuration to Auth Profiles.

Revision ID: 0008_auth_profile_mfa
Revises: 0007_auth_clinical_discovery
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0008_auth_profile_mfa"
down_revision: str | None = "0007_auth_clinical_discovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("auth_profiles", sa.Column("mfa_url", sa.String(2048)))
    op.add_column(
        "auth_profiles", sa.Column("mfa_challenge_json_path", sa.String(255))
    )
    op.add_column("auth_profiles", sa.Column("mfa_challenge_field", sa.String(128)))
    op.add_column("auth_profiles", sa.Column("mfa_code_field", sa.String(128)))
    op.add_column("auth_profiles", sa.Column("role_json_path", sa.String(255)))


def downgrade() -> None:
    op.drop_column("auth_profiles", "role_json_path")
    op.drop_column("auth_profiles", "mfa_code_field")
    op.drop_column("auth_profiles", "mfa_challenge_field")
    op.drop_column("auth_profiles", "mfa_challenge_json_path")
    op.drop_column("auth_profiles", "mfa_url")
