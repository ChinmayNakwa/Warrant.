"""Incident access. An incident is only ever loaded together with its owner's
id, so a missing incident and someone else's look the same to the caller."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from backend.database import utcnow
from backend.models import Incident


class IncidentNotFound(Exception):
    """Missing, or not owned by the caller."""


def get_owned_incident(db: Session, incident_id: str, user_id: str) -> Incident | None:
    return db.scalar(
        select(Incident).where(Incident.id == incident_id, Incident.user_id == user_id)
    )


def claim_run(db: Session, incident_id: str, user_id: str, *, ttl_seconds: int) -> datetime | None:
    """Mark the incident as having a run in progress. Returns the claim's
    timestamp, or None if another run already holds it. One conditional
    UPDATE, so of two racing requests only one gets it.

    A claim older than `ttl_seconds` can be taken over, so a server killed
    mid-run does not lock the incident for good."""
    now = utcnow()
    claimed = db.execute(
        update(Incident)
        .where(
            Incident.id == incident_id,
            Incident.user_id == user_id,
            or_(
                Incident.run_claimed_at.is_(None),
                Incident.run_claimed_at < now - timedelta(seconds=ttl_seconds),
            ),
        )
        .values(run_claimed_at=now)
        .execution_options(synchronize_session=False)
    )
    return now if claimed.rowcount == 1 else None


def release_run(db: Session, incident_id: str, user_id: str, claimed_at: datetime) -> None:
    """Clear the claim taken at `claimed_at`. If it expired and another run
    took the incident over, that run's claim is left alone."""
    db.execute(
        update(Incident)
        .where(
            Incident.id == incident_id,
            Incident.user_id == user_id,
            Incident.run_claimed_at == claimed_at,
        )
        .values(run_claimed_at=None)
        .execution_options(synchronize_session=False)
    )
