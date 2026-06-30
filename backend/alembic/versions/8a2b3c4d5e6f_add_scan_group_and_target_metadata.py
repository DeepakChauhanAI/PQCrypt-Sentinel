"""add_scan_group_and_target_metadata

Revision ID: 8a2b3c4d5e6f
Revises: f7a1c90b2d34
Create Date: 2026-06-17 13:00:00.000000

Phase B - correlation model.

Adds scan_groups table and scans.scan_group_id / target_label / target_kind
so multi-scan operations (e.g. Q2 Estate Audit) can be correlated.
"""

from alembic import op
import sqlalchemy as sa


revision = "8a2b3c4d5e6f"
down_revision = "f7a1c90b2d34"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_groups",
        sa.Column(
            "id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "running",
                "completed",
                "failed",
                "cancelled",
                name="scan_group_status_enum",
                native_enum=False,
            ),
            server_default="queued",
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name="fk_scan_groups_created_by_users"
        ),
    )

    op.add_column("scans", sa.Column("scan_group_id", sa.UUID(), nullable=True))
    op.add_column(
        "scans", sa.Column("target_label", sa.String(length=255), nullable=True)
    )
    op.add_column(
        "scans",
        sa.Column(
            "target_kind",
            sa.Enum(
                "host",
                "cloud_account",
                "code_repo",
                "domain",
                "saas_tenant",
                "network_range",
                "interface",
                "other",
                name="scan_target_kind_enum",
                native_enum=False,
            ),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_scans_scan_group_id_scan_groups",
        "scans",
        "scan_groups",
        ["scan_group_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_scans_scan_group_id", "scans", ["scan_group_id"])


def downgrade() -> None:
    op.drop_index("ix_scans_scan_group_id", table_name="scans")
    op.drop_constraint(
        "fk_scans_scan_group_id_scan_groups", "scans", type_="foreignkey"
    )
    op.drop_column("scans", "target_kind")
    op.drop_column("scans", "target_label")
    op.drop_column("scans", "scan_group_id")
    op.drop_table("scan_groups")
