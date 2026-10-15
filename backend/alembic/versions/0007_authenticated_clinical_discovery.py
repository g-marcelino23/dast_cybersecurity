"""Add role surface snapshots and authorization candidates.

Revision ID: 0007_auth_clinical_discovery
Revises: 0006_authenticated_experiments
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0007_auth_clinical_discovery"
down_revision: str | None = "0006_authenticated_experiments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def json_document() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB() if op.get_bind().dialect.name == "postgresql" else sa.JSON()


def existing_enum(name: str, values: list[str]) -> sa.types.TypeEngine[object]:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.ENUM(*values, name=name, create_type=False)
    return sa.Enum(*values, name=name)


def upgrade() -> None:
    with op.batch_alter_table("auth_profiles") as batch:
        batch.add_column(sa.Column("last_authenticated_scan_id", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column("last_authenticated_scan_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.create_index(
            "ix_auth_profiles_last_authenticated_scan_id",
            ["last_authenticated_scan_id"],
        )
        batch.create_foreign_key(
            "fk_auth_profiles_last_authenticated_scan_id_scans",
            "scans",
            ["last_authenticated_scan_id"],
            ["id"],
            ondelete="SET NULL",
        )

    op.create_table(
        "role_surface_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "target_id",
            sa.Integer(),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "auth_profile_id",
            sa.Integer(),
            sa.ForeignKey("auth_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role_name", sa.String(120), nullable=False),
        sa.Column("pages_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("api_endpoints", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("forms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("methods", json_document(), nullable=False, server_default="[]"),
        sa.Column(
            "sensitive_categories", json_document(), nullable=False, server_default="[]"
        ),
        sa.Column("cwes", json_document(), nullable=False, server_default="[]"),
        sa.Column("passive_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unique_issues", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "authorization_rules_related", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("scan_id", name="uq_role_surface_snapshot_scan"),
    )
    op.create_index("ix_role_surface_snapshots_target_id", "role_surface_snapshots", ["target_id"])
    op.create_index("ix_role_surface_snapshots_scan_id", "role_surface_snapshots", ["scan_id"])
    op.create_index(
        "ix_role_surface_snapshots_auth_profile_id",
        "role_surface_snapshots",
        ["auth_profile_id"],
    )

    op.create_table(
        "authorization_candidates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "target_id",
            sa.Integer(),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
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
            "owner_scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "test_scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("resource_pattern", sa.String(2048), nullable=False),
        sa.Column(
            "expected_access",
            existing_enum(
                "expectedaccess", ["ALLOW", "DENY", "CONDITIONAL", "UNKNOWN"]
            ),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "confidence",
            existing_enum("confidence", ["LOW", "MEDIUM", "HIGH"]),
            nullable=False,
        ),
        sa.Column(
            "sensitive_categories", json_document(), nullable=False, server_default="[]"
        ),
        sa.Column(
            "status",
            existing_enum(
                "authorizationrulestatus",
                ["SUGGESTED", "APPROVED", "REJECTED", "DISABLED"],
            ),
            nullable=False,
            server_default="SUGGESTED",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "target_id",
            "owner_profile_id",
            "test_profile_id",
            "owner_scan_id",
            "method",
            "resource_pattern",
            name="uq_authorization_candidate_observation",
        ),
    )
    for column in (
        "target_id",
        "owner_profile_id",
        "test_profile_id",
        "owner_scan_id",
        "test_scan_id",
    ):
        op.create_index(
            f"ix_authorization_candidates_{column}", "authorization_candidates", [column]
        )


def downgrade() -> None:
    op.drop_table("authorization_candidates")
    op.drop_table("role_surface_snapshots")
    with op.batch_alter_table("auth_profiles") as batch:
        batch.drop_constraint(
            "fk_auth_profiles_last_authenticated_scan_id_scans", type_="foreignkey"
        )
        batch.drop_index("ix_auth_profiles_last_authenticated_scan_id")
        batch.drop_column("last_authenticated_scan_at")
        batch.drop_column("last_authenticated_scan_id")
