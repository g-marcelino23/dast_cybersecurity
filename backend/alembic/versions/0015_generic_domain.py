"""Replace legacy product-domain column names with generic DAST names.

Revision ID: 0015_generic_domain
Revises: 0014_generic_authentication
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0015_generic_domain"
down_revision: str | None = "0014_generic_authentication"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("targets") as batch:
        batch.alter_column("is_tcc_target", new_column_name="is_protected_target")
        batch.alter_column("safe_clinical_mode", new_column_name="safe_scan_mode")
    with op.batch_alter_table("scans") as batch:
        batch.alter_column("clindast_version", new_column_name="dast_version")


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.alter_column("dast_version", new_column_name="clindast_version")
    with op.batch_alter_table("targets") as batch:
        batch.alter_column("safe_scan_mode", new_column_name="safe_clinical_mode")
        batch.alter_column("is_protected_target", new_column_name="is_tcc_target")
