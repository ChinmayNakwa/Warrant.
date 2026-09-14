"""GET /api/captures - the captures an incident can be filed against."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.auth import get_current_user
from backend.database import get_db
from backend.models import Capture, User
from backend.schemas import CaptureResponse

router = APIRouter(prefix="/api/captures", tags=["captures"])


@router.get("", response_model=list[CaptureResponse])
def list_captures(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[Capture]:
    return list(db.scalars(select(Capture).order_by(Capture.name)))
