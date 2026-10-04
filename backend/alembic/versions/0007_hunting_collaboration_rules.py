"""Add saved hunting queries, collaboration mentions and detection rules."""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0007_hunting_collaboration_rules"
down_revision = "0006_signup_role_requests"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "mentions" not in {column["name"] for column in inspector.get_columns("incident_events")}:
        op.add_column(
            "incident_events", sa.Column("mentions", sa.JSON(), nullable=False, server_default="[]")
        )
    tables = set(inspector.get_table_names())
    if "saved_hunt_queries" not in tables:
        op.create_table(
            "saved_hunt_queries",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("query", sa.String(500), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    if "detection_rules" not in tables:
        op.create_table(
            "detection_rules",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(160), nullable=False, unique=True),
            sa.Column("description", sa.String(1000), nullable=False, server_default=""),
            sa.Column("event_type", sa.String(100), nullable=True),
            sa.Column("minimum_severity", sa.String(20), nullable=False, server_default="Medium"),
            sa.Column("summary_contains", sa.String(240), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column(
                "created_by",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    for table, name, column in (
        ("saved_hunt_queries", "ix_saved_hunt_queries_user_id", "user_id"),
        ("detection_rules", "ix_detection_rules_event_type", "event_type"),
        ("detection_rules", "ix_detection_rules_enabled", "enabled"),
    ):
        indexes = {index["name"] for index in inspect(bind).get_indexes(table)}
        if name not in indexes:
            op.create_index(name, table, [column])


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())
    for table in ("detection_rules", "saved_hunt_queries"):
        if table not in tables:
            continue
        for index in inspect(bind).get_indexes(table):
            if index["name"].startswith("ix_"):
                op.drop_index(index["name"], table_name=table)
        op.drop_table(table)
    if "mentions" in {column["name"] for column in inspect(bind).get_columns("incident_events")}:
        op.drop_column("incident_events", "mentions")
