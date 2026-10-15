"""Adopt or create the original ClinDAST schema.

Revision ID: 0001_initial
Revises: None
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("targets"):
        op.create_table(
            "targets",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("base_url", sa.String(2048), nullable=False),
            sa.Column("api_url", sa.String(2048), nullable=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("scans"):
        op.create_table(
            "scans",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
            sa.Column(
                "status",
                sa.Enum("PENDING", "RUNNING", "COMPLETED", "FAILED", name="scanstatus"),
                nullable=False,
                server_default="PENDING",
            ),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("total_findings", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("observations", sa.JSON(), nullable=False, server_default="[]"),
        )
        op.create_index("ix_scans_target_id", "scans", ["target_id"])
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("findings"):
        op.create_table(
            "findings",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
            sa.Column("title", sa.String(240), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("endpoint", sa.String(2048), nullable=False),
            sa.Column(
                "severity",
                sa.Enum("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity"),
                nullable=False,
            ),
            sa.Column(
                "confidence",
                sa.Enum("LOW", "MEDIUM", "HIGH", name="confidence"),
                nullable=False,
            ),
            sa.Column("cwe", sa.String(24), nullable=False),
            sa.Column("owasp_category", sa.String(160), nullable=True),
            sa.Column(
                "privacy_impact",
                sa.Enum("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="privacyimpact"),
                nullable=False,
            ),
            sa.Column("evidence", sa.Text(), nullable=False),
            sa.Column("recommendation", sa.Text(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_findings_scan_id", "findings", ["scan_id"])


def downgrade() -> None:
    # This revision can adopt a pre-Alembic database, so downgrading must not delete core data.
    pass
