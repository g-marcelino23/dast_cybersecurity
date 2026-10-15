"""Add reproducible authenticated experiment metadata.

Revision ID: 0006_authenticated_experiments
Revises: 0005_clinical_integration
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0006_authenticated_experiments"
down_revision: str | None = "0005_clinical_integration"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def json_document() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB() if op.get_bind().dialect.name == "postgresql" else sa.JSON()


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TYPE targetenvironment ADD VALUE IF NOT EXISTS 'FIXTURE'")
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("experiment_label", sa.String(160), nullable=True))
        batch.add_column(
            sa.Column("clindast_version", sa.String(32), nullable=False, server_default="0.6.0")
        )
        batch.add_column(
            sa.Column("modules_enabled", json_document(), nullable=False, server_default="[]")
        )
        batch.add_column(
            sa.Column(
                "configuration_snapshot",
                json_document(),
                nullable=False,
                server_default="{}",
            )
        )
        batch.add_column(
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            )
        )
        batch.create_index("ix_scans_experiment_label", ["experiment_label"])
    with op.batch_alter_table("auth_profiles") as batch:
        batch.add_column(sa.Column("last_auth_success", sa.Boolean(), nullable=True))
        batch.add_column(sa.Column("last_auth_status_code", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column("last_auth_tested_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("auth_profiles") as batch:
        batch.drop_column("last_auth_tested_at")
        batch.drop_column("last_auth_status_code")
        batch.drop_column("last_auth_success")
    with op.batch_alter_table("scans") as batch:
        batch.drop_index("ix_scans_experiment_label")
        batch.drop_column("created_at")
        batch.drop_column("configuration_snapshot")
        batch.drop_column("modules_enabled")
        batch.drop_column("clindast_version")
        batch.drop_column("experiment_label")
