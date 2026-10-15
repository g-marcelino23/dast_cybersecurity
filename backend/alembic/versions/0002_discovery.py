"""Add crawler inventory and request metrics.

Revision ID: 0002_discovery
Revises: 0001_initial
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002_discovery"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def json_document() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB() if op.get_bind().dialect.name == "postgresql" else sa.JSON()


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    scan_columns = {column["name"] for column in inspector.get_columns("scans")}
    if "discovery_requests_observed" not in scan_columns:
        op.add_column(
            "scans",
            sa.Column(
                "discovery_requests_observed", sa.Integer(), nullable=False, server_default="0"
            ),
        )
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("discovered_endpoints"):
        return
    op.create_table(
        "discovered_endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column(
            "source",
            sa.Enum("CRAWLER", "NETWORK", "HTML", "FORM", "JAVASCRIPT", name="discoverysource"),
            nullable=False,
        ),
        sa.Column(
            "resource_type",
            sa.Enum("PAGE", "API", "FORM", "SCRIPT", "OTHER", name="resourcetype"),
            nullable=False,
        ),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(255), nullable=True),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("requires_auth", sa.Boolean(), nullable=True),
        sa.Column("parameters", json_document(), nullable=True),
        sa.Column("metadata", json_document(), nullable=True),
        sa.UniqueConstraint(
            "scan_id", "method", "url", "resource_type", name="uq_discovered_endpoint_logical"
        ),
    )
    op.create_index("ix_discovered_endpoints_scan_id", "discovered_endpoints", ["scan_id"])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("discovered_endpoints"):
        op.drop_index("ix_discovered_endpoints_scan_id", table_name="discovered_endpoints")
        op.drop_table("discovered_endpoints")
    inspector = sa.inspect(op.get_bind())
    if "discovery_requests_observed" in {
        column["name"] for column in inspector.get_columns("scans")
    }:
        op.drop_column("scans", "discovery_requests_observed")
