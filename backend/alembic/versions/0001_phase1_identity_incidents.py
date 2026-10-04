"""Phase 1 identity, RBAC, audit, and incident tables.

Revision ID: 0001_phase1
"""

from alembic import op
from app import models  # noqa: F401
from app.database import Base

revision = "0001_phase1"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade():
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
