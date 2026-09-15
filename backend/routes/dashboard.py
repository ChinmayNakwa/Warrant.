"""GET /api/dashboard/summary - the caller's own numbers."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.auth import get_current_user
from backend.dashboard import get_summary
from backend.database import get_db
from backend.models import User
from backend.schemas import DashboardSummary

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> dict:
    return get_summary(db, user.id)
