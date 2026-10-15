"""Add persistent authorization scenario execution state.

Revision ID: 0010_authz_scenario_execution
Revises: 0009_transient_auth_passwords
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0010_authz_scenario_execution"
down_revision: str | None = "0009_transient_auth_passwords"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATUS_VALUES = ["READY", "RUNNING", "COMPLETED", "FAILED", "INTERRUPTED"]
ENUM_NAME = "authorizationscenarioexecutionstatus"


def execution_status_type() -> sa.types.TypeEngine[object]:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.ENUM(*STATUS_VALUES, name=ENUM_NAME, create_type=False)
    return sa.Enum(*STATUS_VALUES, name=ENUM_NAME)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        postgresql.ENUM(*STATUS_VALUES, name=ENUM_NAME).create(bind, checkfirst=True)

    with op.batch_alter_table("authorization_test_scenarios") as batch:
        batch.add_column(
            sa.Column(
                "execution_status",
                execution_status_type(),
                nullable=False,
                server_default="READY",
            )
        )
        batch.add_column(
            sa.Column("execution_started_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("execution_finished_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(sa.Column("execution_error_code", sa.String(80), nullable=True))
        batch.add_column(
            sa.Column("execution_attempt", sa.Integer(), nullable=False, server_default="0")
        )
        batch.create_index(
            "ix_authorization_test_scenarios_execution_status", ["execution_status"]
        )

    op.execute(
        sa.text(
            """
            UPDATE authorization_test_scenarios
            SET execution_status = 'COMPLETED',
                execution_finished_at = (
                    SELECT MAX(created_at)
                    FROM authorization_probes
                    WHERE authorization_probes.scenario_id = authorization_test_scenarios.id
                ),
                execution_attempt = 1
            WHERE EXISTS (
                SELECT 1
                FROM authorization_probes
                WHERE authorization_probes.scenario_id = authorization_test_scenarios.id
            )
            """
        )
    )


def downgrade() -> None:
    with op.batch_alter_table("authorization_test_scenarios") as batch:
        batch.drop_index("ix_authorization_test_scenarios_execution_status")
        batch.drop_column("execution_attempt")
        batch.drop_column("execution_error_code")
        batch.drop_column("execution_finished_at")
        batch.drop_column("execution_started_at")
        batch.drop_column("execution_status")
    if op.get_bind().dialect.name == "postgresql":
        postgresql.ENUM(*STATUS_VALUES, name=ENUM_NAME).drop(
            op.get_bind(), checkfirst=True
        )
