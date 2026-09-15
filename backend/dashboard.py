"""Dashboard numbers. Everything is counted in SQL and scoped to one user;
the frontend only displays what this returns."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database import utcnow
from backend.models import GuardrailRun, Incident


def get_summary(db: Session, user_id: str) -> dict:
    own_runs = (
        select(func.count())
        .select_from(GuardrailRun)
        .join(Incident, GuardrailRun.incident_id == Incident.id)
        .where(Incident.user_id == user_id)
    )

    open_incidents = db.scalar(
        select(func.count())
        .select_from(Incident)
        .where(Incident.user_id == user_id, Incident.status == "open")
    )
    total_runs = db.scalar(own_runs)
    runs_with_violations = db.scalar(own_runs.where(GuardrailRun.violations_json != "[]"))

    verdict_breakdown = dict(
        db.execute(
            select(Incident.verdict, func.count())
            .where(Incident.user_id == user_id, Incident.verdict.is_not(None))
            .group_by(Incident.verdict)
        ).all()
    )
    severity_breakdown = dict(
        db.execute(
            select(Incident.severity, func.count())
            .where(Incident.user_id == user_id)
            .group_by(Incident.severity)
        ).all()
    )

    day = func.date(GuardrailRun.started_at)
    runs_per_day = db.execute(
        select(day, func.count())
        .join(Incident, GuardrailRun.incident_id == Incident.id)
        .where(Incident.user_id == user_id, GuardrailRun.started_at >= utcnow() - timedelta(days=30))
        .group_by(day)
        .order_by(day)
    ).all()

    recent_incidents = db.scalars(
        select(Incident)
        .where(Incident.user_id == user_id)
        .order_by(Incident.created_at.desc(), Incident.id)
        .limit(10)
    ).all()

    return {
        "open_incidents": open_incidents or 0,
        "total_runs": total_runs or 0,
        "runs_with_violations": runs_with_violations or 0,
        "verdict_breakdown": verdict_breakdown,
        "severity_breakdown": severity_breakdown,
        "runs_over_time": [{"date": str(d), "count": c} for d, c in runs_per_day],
        "recent_incidents": recent_incidents,
    }
