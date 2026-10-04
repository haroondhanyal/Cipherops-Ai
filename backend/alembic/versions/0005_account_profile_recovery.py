"""Add self-service account profile and password recovery fields."""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import context, op

revision = "0005_account_profile_recovery"
down_revision = "0004_domains_governance"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if context.is_offline_mode():
        return
    columns = {column["name"] for column in inspect(bind).get_columns("users")}
    profile_columns = {
        "first_name": sa.String(80),
        "last_name": sa.String(80),
        "phone_country": sa.String(2),
        "phone_dial_code": sa.String(8),
        "mobile_number": sa.String(24),
        "country_code": sa.String(2),
        "country": sa.String(100),
        "city": sa.String(120),
        "avatar_data": sa.Text(),
    }
    for name, column_type in profile_columns.items():
        if name not in columns:
            op.add_column("users", sa.Column(name, column_type, nullable=True))
    if "session_version" not in columns:
        op.add_column(
            "users", sa.Column("session_version", sa.Integer(), nullable=False, server_default="0")
        )
    if "password_reset_tokens" not in inspect(bind).get_table_names():
        op.create_table(
            "password_reset_tokens",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
            sa.Column(
                "user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
    indexes = {index["name"] for index in inspect(bind).get_indexes("password_reset_tokens")}
    for name, column in (
        ("ix_password_reset_tokens_token_hash", "token_hash"),
        ("ix_password_reset_tokens_user_id", "user_id"),
        ("ix_password_reset_tokens_expires_at", "expires_at"),
        ("ix_password_reset_tokens_created_at", "created_at"),
    ):
        if name not in indexes:
            op.create_index(name, "password_reset_tokens", [column])


def downgrade():
    bind = op.get_bind()
    if context.is_offline_mode():
        return
    if "password_reset_tokens" in inspect(bind).get_table_names():
        indexes = {index["name"] for index in inspect(bind).get_indexes("password_reset_tokens")}
        for name in (
            "ix_password_reset_tokens_created_at",
            "ix_password_reset_tokens_expires_at",
            "ix_password_reset_tokens_user_id",
            "ix_password_reset_tokens_token_hash",
        ):
            if name in indexes:
                op.drop_index(name, table_name="password_reset_tokens")
        op.drop_table("password_reset_tokens")
    columns = {column["name"] for column in inspect(bind).get_columns("users")}
    for column in (
        "session_version",
        "avatar_data",
        "city",
        "country",
        "mobile_number",
        "country_code",
        "phone_dial_code",
        "phone_country",
        "last_name",
        "first_name",
    ):
        if column in columns:
            op.drop_column("users", column)
