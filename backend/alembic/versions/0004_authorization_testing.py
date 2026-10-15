"""Add controlled authorization testing.

Revision ID: 0004_authorization_testing
Revises: 0003_auth_privacy
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004_authorization_testing"
down_revision: str | None = "0003_auth_privacy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def json_document() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB() if op.get_bind().dialect.name == "postgresql" else sa.JSON()


def upgrade() -> None:
    expected_access = sa.Enum("ALLOW", "DENY", "CONDITIONAL", "UNKNOWN", name="expectedaccess")
    probe_result = sa.Enum(
        "ALLOWED_AS_EXPECTED",
        "DENIED_AS_EXPECTED",
        "POSSIBLE_BYPASS",
        "CONFIRMED_BYPASS",
        "INCONCLUSIVE",
        "ERROR",
        "SKIPPED",
        name="authorizationproberesult",
    )
    confidence = (
        postgresql.ENUM(name="confidence", create_type=False)
        if op.get_bind().dialect.name == "postgresql"
        else sa.Enum("LOW", "MEDIUM", "HIGH", name="confidence")
    )
    op.add_column("findings", sa.Column("privacy_reason", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("issue_key", sa.String(255), nullable=True))
    op.create_index("ix_findings_issue_key", "findings", ["issue_key"])
    op.create_table(
        "authorization_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "target_id",
            sa.Integer(),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("source_role", sa.String(120), nullable=False),
        sa.Column("resource_pattern", sa.String(2048), nullable=False),
        sa.Column("http_method", sa.String(16), nullable=False),
        sa.Column("expected_access", expected_access, nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_authorization_rules_target_id", "authorization_rules", ["target_id"])
    op.create_table(
        "authorization_test_scenarios",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "target_id",
            sa.Integer(),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column(
            "owner_profile_id",
            sa.Integer(),
            sa.ForeignKey("auth_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "test_profile_id",
            sa.Integer(),
            sa.ForeignKey("auth_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "authorization_rule_id",
            sa.Integer(),
            sa.ForeignKey("authorization_rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index(
        "ix_authorization_test_scenarios_target_id", "authorization_test_scenarios", ["target_id"]
    )
    op.create_index(
        "ix_authorization_test_scenarios_owner_profile_id",
        "authorization_test_scenarios",
        ["owner_profile_id"],
    )
    op.create_index(
        "ix_authorization_test_scenarios_test_profile_id",
        "authorization_test_scenarios",
        ["test_profile_id"],
    )
    op.create_index(
        "ix_authorization_test_scenarios_authorization_rule_id",
        "authorization_test_scenarios",
        ["authorization_rule_id"],
    )
    op.create_table(
        "authorization_probes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "scenario_id",
            sa.Integer(),
            sa.ForeignKey("authorization_test_scenarios.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "owner_profile_id", sa.Integer(), sa.ForeignKey("auth_profiles.id"), nullable=False
        ),
        sa.Column(
            "test_profile_id", sa.Integer(), sa.ForeignKey("auth_profiles.id"), nullable=False
        ),
        sa.Column("endpoint", sa.String(2048), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("expected_access", expected_access, nullable=False),
        sa.Column("result", probe_result, nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("confidence", confidence, nullable=False),
        sa.Column("baseline_fingerprint", sa.String(64), nullable=True),
        sa.Column("tested_fingerprint", sa.String(64), nullable=True),
        sa.Column("sensitive_categories", json_document(), nullable=False, server_default="[]"),
        sa.Column("baseline_metadata", json_document(), nullable=True),
        sa.Column("tested_metadata", json_document(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_authorization_probes_scan_id", "authorization_probes", ["scan_id"])
    op.create_index("ix_authorization_probes_scenario_id", "authorization_probes", ["scenario_id"])


def downgrade() -> None:
    op.drop_table("authorization_probes")
    op.drop_table("authorization_test_scenarios")
    op.drop_table("authorization_rules")
    op.drop_index("ix_findings_issue_key", table_name="findings")
    op.drop_column("findings", "issue_key")
    op.drop_column("findings", "privacy_reason")
