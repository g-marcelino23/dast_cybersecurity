"""Add controlled clinical application integration.

Revision ID: 0005_clinical_integration
Revises: 0004_authorization_testing
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005_clinical_integration"
down_revision: str | None = "0004_authorization_testing"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    target_environment = sa.Enum("LOCAL", name="targetenvironment")
    scan_mode = sa.Enum("DISCOVERY_PASSIVE", name="scanmode")
    rule_status = sa.Enum(
        "SUGGESTED", "APPROVED", "REJECTED", "DISABLED", name="authorizationrulestatus"
    )
    confidence = sa.Enum("LOW", "MEDIUM", "HIGH", name="confidence", create_type=False)
    target_environment.create(op.get_bind(), checkfirst=True)
    scan_mode.create(op.get_bind(), checkfirst=True)
    rule_status.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "targets",
        sa.Column("environment", target_environment, nullable=False, server_default="LOCAL"),
    )
    op.add_column(
        "targets",
        sa.Column(
            "is_tcc_target", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "targets",
        sa.Column("safe_clinical_mode", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "scans",
        sa.Column("mode", scan_mode, nullable=False, server_default="DISCOVERY_PASSIVE"),
    )
    op.add_column(
        "authorization_rules",
        sa.Column("status", rule_status, nullable=False, server_default="APPROVED"),
    )
    op.add_column("authorization_rules", sa.Column("suggestion_reason", sa.Text(), nullable=True))
    op.add_column(
        "authorization_rules",
        sa.Column("suggestion_confidence", confidence, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("authorization_rules", "suggestion_confidence")
    op.drop_column("authorization_rules", "suggestion_reason")
    op.drop_column("authorization_rules", "status")
    op.drop_column("scans", "mode")
    op.drop_column("targets", "safe_clinical_mode")
    op.drop_column("targets", "is_tcc_target")
    op.drop_column("targets", "environment")
    sa.Enum(name="authorizationrulestatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="scanmode").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="targetenvironment").drop(op.get_bind(), checkfirst=True)
