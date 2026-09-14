"""Run endpoints.

    POST /api/incidents/{incident_id}/guardrail-runs   run one
    GET  /api/incidents/{incident_id}/guardrail-runs   list that incident's runs
    GET  /api/guardrail-runs/{run_id}                  one run in full

A run is reachable only through an incident the caller owns; anything else is 404.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.auth import get_current_user
from backend.config import get_settings
from backend.database import get_db
from backend.guardrail.analyst import Mode, run_analysis
from backend.incidents import IncidentNotFound, claim_run, get_owned_incident, release_run
from backend.llm import Completer, NoModelConfigured, ollama_completer
from backend.models import GuardrailRun, Incident, User
from backend.routes.incidents import NOT_FOUND as INCIDENT_NOT_FOUND

router = APIRouter(prefix="/api", tags=["guardrail"])

_RUN_NOT_FOUND = "Run not found."
_ALREADY_RUNNING = "A run of this incident is already in progress. Wait for it to finish, then try again."
_NO_MODEL = "No model is configured. Set WARRANT_OLLAMA_MODEL and restart the server."

# Returns the model to call and its name
ModelSelector = Callable[[], tuple[Completer, str]]


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Mode = "baseline"


class RunSummary(BaseModel):
    id: str
    incident_id: str
    mode: str
    status: str
    verdict: str | None
    confidence: float | None
    model: str
    techniques: list[str]
    llm_calls: int
    # Rules the model's first answer broke
    violation_count: int
    # Guarded only: repair rounds asked, and items then removed or changed
    repair_rounds: int
    dropped_count: int
    note: str | None
    started_at: datetime
    finished_at: datetime | None


class RunDetail(RunSummary):
    """`answer`, `first_answer` and the items in `dropped` are model text, and
    `events` is telemetry: clients must display them as data."""

    answer: dict | None
    first_answer: dict | None
    violations: list[dict]
    dropped: list[dict]
    events: list[dict]


def get_model_selector() -> ModelSelector:
    """A dependency so tests can swap in a scripted model. It returns a
    callable so that a missing model is only reported after the ownership check."""

    def select_model() -> tuple[Completer, str]:
        settings = get_settings()
        return ollama_completer(settings), settings.ollama_model

    return select_model


def _summary(run: GuardrailRun) -> dict:
    return {
        "id": run.id,
        "incident_id": run.incident_id,
        "mode": run.mode,
        "status": run.status,
        "verdict": run.verdict,
        "confidence": run.confidence,
        "model": run.model,
        "techniques": json.loads(run.techniques_json),
        "llm_calls": run.llm_calls,
        "violation_count": len(json.loads(run.violations_json)),
        "repair_rounds": run.repair_rounds,
        "dropped_count": len(json.loads(run.dropped_json)),
        "note": run.note,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
    }


def _detail(run: GuardrailRun) -> dict:
    return {
        **_summary(run),
        "answer": json.loads(run.answer_json) if run.answer_json else None,
        "first_answer": json.loads(run.first_answer_json) if run.first_answer_json else None,
        "violations": json.loads(run.violations_json),
        "dropped": json.loads(run.dropped_json),
        "events": json.loads(run.slice_json),
    }


@router.post(
    "/incidents/{incident_id}/guardrail-runs",
    response_model=RunDetail,
    status_code=status.HTTP_201_CREATED,
)
def create_run(
    incident_id: str,
    body: RunRequest | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    select_model: ModelSelector = Depends(get_model_selector),
) -> dict:
    body = body or RunRequest()
    if get_owned_incident(db, incident_id, user.id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, INCIDENT_NOT_FOUND)
    try:
        complete, model = select_model()
    except NoModelConfigured:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, _NO_MODEL)
    # One run per incident at a time. Committed straight away so other
    # requests see the claim while the model works.
    claimed_at = claim_run(
        db, incident_id, user.id, ttl_seconds=get_settings().run_claim_ttl_seconds
    )
    if claimed_at is None:
        raise HTTPException(status.HTTP_409_CONFLICT, _ALREADY_RUNNING)
    db.commit()
    run = None
    try:
        run = run_analysis(
            db, user_id=user.id, incident_id=incident_id, mode=body.mode,
            complete=complete, model=model,
        )
    except IncidentNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, INCIDENT_NOT_FOUND)
    finally:
        if run is None:
            db.rollback()
        release_run(db, incident_id, user.id, claimed_at)
        db.commit()
    return _detail(run)


@router.get("/incidents/{incident_id}/guardrail-runs", response_model=list[RunSummary])
def list_runs(
    incident_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    if get_owned_incident(db, incident_id, user.id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, INCIDENT_NOT_FOUND)
    runs = db.scalars(
        select(GuardrailRun)
        .where(GuardrailRun.incident_id == incident_id)
        .order_by(GuardrailRun.started_at.desc(), GuardrailRun.id)
    )
    return [_summary(r) for r in runs]


@router.get("/guardrail-runs/{run_id}", response_model=RunDetail)
def get_run(
    run_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    run = db.scalar(
        select(GuardrailRun)
        .join(Incident, GuardrailRun.incident_id == Incident.id)
        .where(GuardrailRun.id == run_id, Incident.user_id == user.id)
    )
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _RUN_NOT_FOUND)
    return _detail(run)
