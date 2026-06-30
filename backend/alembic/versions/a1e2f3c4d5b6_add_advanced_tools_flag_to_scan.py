"""add_advanced_tools_flag_to_scan

Revision ID: a1e2f3c4d5b6
Revises: 61bc0e3f062b
Create Date: 2026-06-04 13:35:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "a1e2f3c4d5b6"
down_revision = "d284428da4c2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "advanced_tools", sa.Boolean(), nullable=False, server_default="false"
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "advanced_tools")
