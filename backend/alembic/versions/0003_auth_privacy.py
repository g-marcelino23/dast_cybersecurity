"""Add authentication profiles and sensitive-data observations.

Revision ID: 0003_auth_privacy
Revises: 0002_discovery
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0003_auth_privacy"
down_revision: str | None = "0002_discovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    auth_type = sa.Enum("NONE", "BEARER_LOGIN", "COOKIE_LOGIN", name="authtype")
    category = sa.Enum(
        "PERSONAL_IDENTIFIER",
        "CONTACT_INFORMATION",
        "AUTHENTICATION_DATA",
        "HEALTH_INFORMATION",
        "MEDICAL_RECORD",
        "PRESCRIPTION",
        "MEDICATION",
        "EXAM_RESULT",
        "DIAGNOSIS",
        "APPOINTMENT_INFORMATION",
        "FINANCIAL_INFORMATION",
        "OTHER_SENSITIVE",
        name="sensitivedatacategory",
    )
    detector = sa.Enum(
        "FIELD_NAME", "CPF_PATTERN", "EMAIL_PATTERN", "PHONE_PATTERN", name="detectortype"
    )
    confidence = (
        postgresql.ENUM(name="confidence", create_type=False)
        if op.get_bind().dialect.name == "postgresql"
        else sa.Enum("LOW", "MEDIUM", "HIGH", name="confidence")
    )

    op.create_table(
        "auth_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "target_id",
            sa.Integer(),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("role_name", sa.String(120), nullable=False),
        sa.Column("auth_type", auth_type, nullable=False),
        sa.Column("login_url", sa.String(2048), nullable=True),
        sa.Column("validation_url", sa.String(2048), nullable=True),
        sa.Column("http_method", sa.String(16), nullable=False, server_default="POST"),
        sa.Column("body_template", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("username_field", sa.String(128), nullable=True),
        sa.Column("password_field", sa.String(128), nullable=True),
        sa.Column("token_json_path", sa.String(255), nullable=True),
        sa.Column("token_header_name", sa.String(128), nullable=True),
        sa.Column("token_prefix", sa.String(64), nullable=True),
        sa.Column("encrypted_username", sa.Text(), nullable=True),
        sa.Column("encrypted_password", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_auth_profiles_target_id", "auth_profiles", ["target_id"])
    op.add_column("scans", sa.Column("auth_profile_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_scans_auth_profile_id",
        "scans",
        "auth_profiles",
        ["auth_profile_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_scans_auth_profile_id", "scans", ["auth_profile_id"])
    op.create_table(
        "sensitive_data_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "endpoint_id",
            sa.Integer(),
            sa.ForeignKey("discovered_endpoints.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("category", category, nullable=False),
        sa.Column("field_path", sa.String(1024), nullable=False),
        sa.Column("detector_type", detector, nullable=False),
        sa.Column("confidence", confidence, nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "detected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint(
            "scan_id",
            "endpoint_id",
            "category",
            "field_path",
            "detector_type",
            name="uq_sensitive_observation_logical",
        ),
    )
    op.create_index(
        "ix_sensitive_data_observations_scan_id", "sensitive_data_observations", ["scan_id"]
    )
    op.create_index(
        "ix_sensitive_data_observations_endpoint_id",
        "sensitive_data_observations",
        ["endpoint_id"],
    )


def downgrade() -> None:
    op.drop_table("sensitive_data_observations")
    op.drop_index("ix_scans_auth_profile_id", table_name="scans")
    op.drop_constraint("fk_scans_auth_profile_id", "scans", type_="foreignkey")
    op.drop_column("scans", "auth_profile_id")
    op.drop_table("auth_profiles")
