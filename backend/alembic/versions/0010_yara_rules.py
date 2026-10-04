"""Add persistent YARA rule authoring and simulation."""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0010_yara_rules"
down_revision = "0009_response_simulation"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "yara_rules" not in set(inspector.get_table_names()):
        op.create_table(
            "yara_rules",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(160), nullable=False, unique=True),
            sa.Column("namespace", sa.String(120), nullable=False, server_default="default"),
            sa.Column("description", sa.String(1000), nullable=False, server_default=""),
            sa.Column("source", sa.Text(), nullable=False),
            sa.Column("severity", sa.String(20), nullable=False, server_default="High"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    indexes = {index["name"] for index in inspect(bind).get_indexes("yara_rules")}
    if "ix_yara_rules_enabled" not in indexes:
        op.create_index("ix_yara_rules_enabled", "yara_rules", ["enabled"])


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "yara_rules" in set(inspector.get_table_names()):
        indexes = {index["name"] for index in inspector.get_indexes("yara_rules")}
        if "ix_yara_rules_enabled" in indexes:
            op.drop_index("ix_yara_rules_enabled", table_name="yara_rules")
        op.drop_table("yara_rules")
