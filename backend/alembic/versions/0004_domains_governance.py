"""Security domains, approved response workflows and governance records."""

from alembic import op
from app import models  # noqa: F401
from app.database import Base

revision = "0004_domains_governance"
down_revision = "0003_alerts_telemetry_assets"
branch_labels = None
depends_on = None


def upgrade():
    Base.metadata.create_all(bind=op.get_bind())


def downgrade():
    bind = op.get_bind()
    for table in (
        "sso_login_tickets",
        "report_snapshots",
        "control_evidence",
        "compliance_controls",
        "playbook_runs",
        "response_playbooks",
        "response_actions",
        "incident_evidence",
        "security_findings",
    ):
        if table in Base.metadata.tables:
            Base.metadata.tables[table].drop(bind=bind, checkfirst=True)
