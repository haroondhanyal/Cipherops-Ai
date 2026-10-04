"""Add self-service account profile and password recovery fields."""

import sqlalchemy as sa

from alembic import op

revision = "0005_account_profile_recovery"
down_revision = "0004_domains_governance"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("first_name", sa.String(80), nullable=True))
    op.add_column("users", sa.Column("last_name", sa.String(80), nullable=True))
    op.add_column("users", sa.Column("phone_country", sa.String(2), nullable=True))
    op.add_column("users", sa.Column("phone_dial_code", sa.String(8), nullable=True))
    op.add_column("users", sa.Column("mobile_number", sa.String(24), nullable=True))
    op.add_column("users", sa.Column("country_code", sa.String(2), nullable=True))
    op.add_column("users", sa.Column("country", sa.String(100), nullable=True))
    op.add_column("users", sa.Column("city", sa.String(120), nullable=True))
    op.add_column("users", sa.Column("avatar_data", sa.Text(), nullable=True))
    op.add_column(
        "users", sa.Column("session_version", sa.Integer(), nullable=False, server_default="0")
    )
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_password_reset_tokens_token_hash", "password_reset_tokens", ["token_hash"])
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"])
    op.create_index("ix_password_reset_tokens_expires_at", "password_reset_tokens", ["expires_at"])
    op.create_index("ix_password_reset_tokens_created_at", "password_reset_tokens", ["created_at"])


def downgrade():
    op.drop_index("ix_password_reset_tokens_created_at", table_name="password_reset_tokens")
    op.drop_index("ix_password_reset_tokens_expires_at", table_name="password_reset_tokens")
    op.drop_index("ix_password_reset_tokens_user_id", table_name="password_reset_tokens")
    op.drop_index("ix_password_reset_tokens_token_hash", table_name="password_reset_tokens")
    op.drop_table("password_reset_tokens")
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
        op.drop_column("users", column)
