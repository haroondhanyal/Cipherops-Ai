"""Store signup role requests separately from granted permissions."""

import sqlalchemy as sa

from alembic import op

revision = "0006_signup_role_requests"
down_revision = "0005_account_profile_recovery"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("requested_role", sa.String(80), nullable=True))


def downgrade():
    op.drop_column("users", "requested_role")
