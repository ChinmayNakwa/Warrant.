"""telemetry tables: captures, events

Revision ID: 0002
Revises: 0001
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "captures",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("scenario", sa.String(), nullable=True),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("starts_at", sa.DateTime(), nullable=True),
        sa.Column("ends_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_captures_name", "captures", ["name"], unique=True)

    op.create_table(
        "events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("capture_id", sa.String(), nullable=False),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("process_guid", sa.String(), nullable=True),
        sa.Column("parent_process_guid", sa.String(), nullable=True),
        sa.Column("image", sa.String(), nullable=True),
        sa.Column("command_line", sa.String(), nullable=True),
        sa.Column("actor_user", sa.String(), nullable=True),
        sa.Column("dest_ip", sa.String(), nullable=True),
        sa.Column("dest_port", sa.Integer(), nullable=True),
        sa.Column("target_object", sa.String(), nullable=True),
        sa.Column("raw_json", sa.String(), nullable=False),
        sa.Column("rarity", sa.Float(), nullable=False),
        sa.Column("dedupe_key", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["capture_id"], ["captures.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("capture_id", "dedupe_key", name="uq_event_capture_dedupe"),
    )
    # One index per query shape in telemetry/query.py
    op.create_index("ix_events_capture_type_ts", "events", ["capture_id", "event_type", "ts"])
    op.create_index(
        "ix_events_capture_guid", "events", ["capture_id", "process_guid", "event_type", "ts"]
    )
    op.create_index(
        "ix_events_capture_parent_guid", "events", ["capture_id", "parent_process_guid", "event_type"]
    )
    op.create_index(
        "ix_events_capture_rarity", "events", ["capture_id", sa.text("rarity DESC"), "ts"]
    )


def downgrade() -> None:
    op.drop_table("events")
    op.drop_table("captures")
