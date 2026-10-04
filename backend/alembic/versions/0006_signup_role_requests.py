"""Store signup role requests separately from granted permissions."""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import context, op

revision = "0006_signup_role_requests"
down_revision = "0005_account_profile_recovery"
branch_labels = None
depends_on = None


def upgrade():
    if context.is_offline_mode():
        return
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("users")}
    if "requested_role" not in columns:
        op.add_column("users", sa.Column("requested_role", sa.String(80), nullable=True))


def downgrade():
    if context.is_offline_mode():
        return
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("users")}
    if "requested_role" in columns:
        op.drop_column("users", "requested_role")
