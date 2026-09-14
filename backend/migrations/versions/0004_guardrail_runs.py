"""guardrail_runs

Revision ID: 0004
Revises: 0003
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "guardrail_runs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("incident_id", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("verdict", sa.String(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("model", sa.String(), nullable=False),
        sa.Column("techniques_json", sa.String(), nullable=False),
        sa.Column("answer_json", sa.String(), nullable=True),
        sa.Column("first_answer_json", sa.String(), nullable=True),
        sa.Column("violations_json", sa.String(), nullable=False),
        sa.Column("repair_rounds", sa.Integer(), nullable=False),
        sa.Column("dropped_json", sa.String(), nullable=False),
        sa.Column("slice_json", sa.String(), nullable=False),
        sa.Column("llm_calls", sa.Integer(), nullable=False),
        sa.Column("note", sa.String(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_guardrail_runs_incident_id", "guardrail_runs", ["incident_id"])


def downgrade() -> None:
    op.drop_table("guardrail_runs")
