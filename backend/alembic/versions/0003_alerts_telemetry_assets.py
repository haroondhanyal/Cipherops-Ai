"""Persistent alerts, incident response events, integrations and assets."""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op
from app import models  # noqa: F401
from app.database import Base

revision = "0003_alerts_telemetry_assets"
down_revision = "0002_totp_mfa"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    columns = {column["name"] for column in inspect(bind).get_columns("incidents")}
    if "updated_at" not in columns:
        op.add_column(
            "incidents",
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )


def downgrade():
    bind = op.get_bind()
    for table in ("telemetry_events", "integrations", "assets", "alerts", "incident_events"):
        if inspect(bind).has_table(table):
            op.drop_table(table)
    columns = {column["name"] for column in inspect(bind).get_columns("incidents")}
    if "updated_at" in columns:
        op.drop_column("incidents", "updated_at")
