"""Persist ingestion outcomes for connector health and diagnostics."""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0008_integration_health"
down_revision = "0007_hunting_collaboration_rules"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in inspect(bind).get_columns("integrations")}
    additions = (
        ("last_attempt_at", sa.DateTime(timezone=True), True, None),
        ("last_status", sa.String(24), False, "Waiting"),
        ("last_error", sa.String(1000), True, None),
        ("successful_batches", sa.Integer(), False, 0),
        ("failed_batches", sa.Integer(), False, 0),
        ("last_event_count", sa.Integer(), False, 0),
    )
    for name, column_type, nullable, default in additions:
        if name not in columns:
            kwargs = {"nullable": nullable}
            if default is not None:
                kwargs["server_default"] = str(default)
            op.add_column("integrations", sa.Column(name, column_type, **kwargs))


def downgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in inspect(bind).get_columns("integrations")}
    for name in (
        "last_event_count",
        "failed_batches",
        "successful_batches",
        "last_error",
        "last_status",
        "last_attempt_at",
    ):
        if name in columns:
            op.drop_column("integrations", name)
