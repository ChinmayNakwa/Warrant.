"""One run: slice the incident's telemetry, have a model read it, check its
answer against the ontology.

`baseline` accepts the answer as given and only records what the check finds.
`guarded` sends a failing answer back for repair, then removes whatever is
still wrong. Both start from the same prompt.

The model only ever returns text that is parsed into an `Answer`; every
database row is written here.
"""
from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Literal

from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.database import utcnow
from backend.guardrail.answer import Answer, AnswerError, parse_answer
from backend.guardrail.guard import build_repair_prompt, enforce
from backend.guardrail.prompt import build_system_prompt, build_user_prompt
from backend.guardrail.slicer import build_slice
from backend.guardrail.validator import Violation, validate
from backend.incidents import IncidentNotFound, get_owned_incident
from backend.llm import Completer, ModelError
from backend.models import GuardrailRun

Mode = Literal["baseline", "guarded"]

# Progress only: ids, counts and timings, never telemetry or model text.
log = logging.getLogger("warrant.guardrail")


def _failure(exc: Exception) -> str:
    """A reason that is safe to store: our own messages, or just the type."""
    return str(exc) if isinstance(exc, (ModelError, AnswerError)) else type(exc).__name__


def _ask(complete: Completer, system: str, user: str) -> Answer:
    """Retries once if the reply is not a valid answer, saying which fields
    failed. This is about format only, so both modes get it."""
    try:
        return parse_answer(complete(system, user))
    except AnswerError as exc:
        retry = (
            f"{user}\n\nYour last reply was not valid: {exc.reason}. "
            "Respond with exactly one valid JSON object in the format given."
        )
        return parse_answer(complete(system, retry))


def _repair(
    complete: Completer,
    system: str,
    user: str,
    answer: Answer,
    violations: list[Violation],
    events: list[dict],
    *,
    nonce: str,
    max_rounds: int,
) -> tuple[Answer, list[Violation], int, str | None]:
    """Send a failing answer back with its violations, up to `max_rounds`
    times. A reply replaces the answer only if it breaks fewer rules; otherwise
    the loop stops with the answer in hand. Returns that answer, its
    violations, the rounds used and a note if the loop stopped early."""
    rounds = 0
    while violations and rounds < max_rounds:
        rounds += 1
        prompt = build_repair_prompt(user, answer, violations, nonce=nonce)
        try:
            candidate = parse_answer(complete(system, prompt))
        except Exception as exc:
            return answer, violations, rounds, f"repair stopped: {_failure(exc)}"
        found = validate(candidate, events)
        if len(found) >= len(violations):
            return answer, violations, rounds, "repair stopped: the reply broke no fewer rules"
        answer, violations = candidate, found
    return answer, violations, rounds, None


def run_analysis(
    db: Session,
    *,
    user_id: str,
    incident_id: str,
    mode: Mode,
    complete: Completer,
    model: str,
) -> GuardrailRun:
    """Run one analysis and add its row to the session. The caller commits."""
    incident = get_owned_incident(db, incident_id, user_id)
    if incident is None:
        raise IncidentNotFound(incident_id)

    settings = get_settings()
    run = GuardrailRun(
        incident_id=incident.id,
        mode=mode,
        status="completed",
        model=model,
        llm_calls=0,
        repair_rounds=0,
        started_at=utcnow(),
    )
    events = build_slice(
        db,
        incident.capture_id,
        incident.anchor_process_guid,
        max_events=settings.max_slice_events,
        window_seconds=settings.slice_window_seconds,
    )
    run.slice_json = json.dumps(events, sort_keys=True)
    log.info("run started: incident %s, mode=%s, %d events", incident.id[:8], mode, len(events))

    def counted(system: str, user: str) -> str:
        run.llm_calls += 1
        return complete(system, user)

    answer: Answer | None = None
    violations: list[Violation] = []
    started = time.monotonic()
    if not events:
        run.verdict, run.confidence = "INSUFFICIENT_EVIDENCE", 0.0
        run.note = "the capture has no telemetry for this incident"
    else:
        nonce = secrets.token_hex(8)
        system = build_system_prompt()
        user = build_user_prompt(
            title=incident.title,
            description=incident.description,
            anchor_process_guid=incident.anchor_process_guid,
            events=events,
            nonce=nonce,
        )
        try:
            answer = _ask(counted, system, user)
        except Exception as exc:  # a model failure ends the run, it never crashes it
            run.status = "failed"
            run.note = f"model failed: {_failure(exc)}"

    if answer is not None:
        # Both modes record the first answer and what the check finds in it.
        violations = validate(answer, events)
        run.first_answer_json = answer.model_dump_json()
        run.violations_json = json.dumps([v.as_dict() for v in violations])
        if mode == "guarded":
            answer, remaining, run.repair_rounds, run.note = _repair(
                counted, system, user, answer, violations, events,
                nonce=nonce, max_rounds=settings.max_repairs,
            )
            answer, dropped = enforce(answer, remaining, events)
            run.dropped_json = json.dumps(dropped)
        run.verdict = answer.verdict
        run.confidence = answer.confidence
        run.techniques_json = json.dumps(sorted({t.id for t in answer.techniques}))
        run.answer_json = answer.model_dump_json()

    run.finished_at = utcnow()
    db.add(run)
    if run.verdict is not None:
        incident.verdict, incident.confidence = run.verdict, run.confidence
    db.flush()
    log.info(
        "run %s %s in %.1fs: verdict=%s, %d model calls, %d violations in the first answer, "
        "%d repair rounds",
        run.id[:8], run.status, time.monotonic() - started, run.verdict or "-", run.llm_calls,
        len(violations), run.repair_rounds,
    )
    return run
