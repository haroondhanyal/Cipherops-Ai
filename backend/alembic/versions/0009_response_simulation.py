"""Persist approval-gated response dry-run results."""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0009_response_simulation"
down_revision = "0008_integration_health"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in inspect(bind).get_columns("playbook_runs")}
    if "execution_result" not in columns:
        op.add_column("playbook_runs", sa.Column("execution_result", sa.JSON(), nullable=True))
    if "executed_by" not in columns:
        op.add_column(
            "playbook_runs",
            sa.Column("executed_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        )
    if "executed_at" not in columns:
        op.add_column("playbook_runs", sa.Column("executed_at", sa.DateTime(timezone=True)))


def downgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in inspect(bind).get_columns("playbook_runs")}
    for name in ("executed_at", "executed_by", "execution_result"):
        if name in columns:
            op.drop_column("playbook_runs", name)
