"""events: the process an access or remote-thread event is aimed at

Revision ID: 0005
Revises: 0004
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("events", sa.Column("target_process_guid", sa.String(), nullable=True))
    op.add_column("events", sa.Column("granted_access", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("events", "granted_access")
    op.drop_column("events", "target_process_guid")
