"""Add opt-in TOTP MFA to user accounts."""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import context, op

revision = "0002_totp_mfa"
down_revision = "0001_phase1"
branch_labels = None
depends_on = None


def upgrade():
    # Keep the initial Phase 1 baseline usable for new checkouts while also
    # upgrading databases that already applied its first revision.
    if context.is_offline_mode():
        # The baseline model includes these columns; offline SQL renders from
        # current metadata and therefore already contains the final schema.
        return
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("users")}
    if "mfa_enabled" not in columns:
        op.add_column(
            "users",
            sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
    if "mfa_secret" not in columns:
        op.add_column("users", sa.Column("mfa_secret", sa.String(length=64), nullable=True))


def downgrade():
    if context.is_offline_mode():
        return
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("users")}
    if "mfa_secret" in columns:
        op.drop_column("users", "mfa_secret")
    if "mfa_enabled" in columns:
        op.drop_column("users", "mfa_enabled")
