"""Add generic finding classification and workflow state.

Revision ID: 0011_finding_workflow
Revises: 0010_authz_scenario_execution
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_finding_workflow"
down_revision: str | None = "0010_authz_scenario_execution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(
            sa.Column(
                "finding_type",
                sa.String(40),
                nullable=False,
                server_default="MISCONFIGURATION",
            )
        )
        batch.add_column(
            sa.Column("status", sa.String(32), nullable=False, server_default="OPEN")
        )
        batch.create_index("ix_findings_status", ["status"])

    op.execute(
        sa.text(
            """
            UPDATE findings
            SET finding_type = CASE
                WHEN issue_key LIKE 'authz:%' AND confidence = 'HIGH'
                    THEN 'CONFIRMED_VULNERABILITY'
                WHEN issue_key LIKE 'authz:%'
                    THEN 'POTENTIAL_VULNERABILITY'
                WHEN severity = 'INFO'
                    THEN 'INFORMATION'
                ELSE 'MISCONFIGURATION'
            END
            """
        )
    )


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_status")
        batch.drop_column("status")
        batch.drop_column("finding_type")
