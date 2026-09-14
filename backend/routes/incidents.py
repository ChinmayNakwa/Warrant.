"""Incident endpoints.

    POST /api/incidents
    GET  /api/incidents
    GET  /api/incidents/{incident_id}

A missing incident and one owned by someone else are both 404.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.auth import get_current_user
from backend.database import get_db
from backend.incidents import get_owned_incident
from backend.models import Capture, Incident, User
from backend.schemas import IncidentCreate, IncidentResponse

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

NOT_FOUND = "Incident not found."


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    body: IncidentCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Incident:
    capture = db.scalar(select(Capture).where(Capture.name == body.capture_name))
    if capture is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown capture.")
    incident = Incident(
        user_id=user.id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        capture_id=capture.id,
        anchor_process_guid=body.anchor_process_guid,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[Incident]:
    return list(
        db.scalars(
            select(Incident)
            .where(Incident.user_id == user.id)
            .order_by(Incident.created_at.desc(), Incident.id)
        )
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Incident:
    incident = get_owned_incident(db, incident_id, user.id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, NOT_FOUND)
    return incident
