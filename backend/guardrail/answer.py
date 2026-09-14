"""The structured answer a model returns after reading a slice.

Parsing checks structure only: field names, types and sizes. Whether a
technique id is real, a cited event exists or a relation is allowed is the
ontology's job, so that a wrong answer can still be recorded and measured.
"""
from __future__ import annotations

import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

Verdict = Literal["MALICIOUS", "SUSPICIOUS", "BENIGN", "INSUFFICIENT_EVIDENCE"]

MAX_TECHNIQUES = 10
MAX_CLAIMS = 40
MAX_EVENTS_PER_TECHNIQUE = 20
MAX_SUMMARY_CHARS = 2000

Ref = Annotated[str, Field(min_length=1, max_length=20)]
Name = Annotated[str, Field(min_length=1, max_length=60)]
Value = Annotated[str, Field(min_length=1, max_length=600)]


class TechniqueClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Name
    events: list[Ref] = Field(default_factory=list, max_length=MAX_EVENTS_PER_TECHNIQUE)


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject_type: Name
    subject: Value
    relation: Name
    object_type: Name
    object: Value
    event: Ref


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    techniques: list[TechniqueClaim] = Field(default_factory=list, max_length=MAX_TECHNIQUES)
    claims: list[Claim] = Field(default_factory=list, max_length=MAX_CLAIMS)
    summary: str = Field(default="", max_length=MAX_SUMMARY_CHARS)


class AnswerError(Exception):
    """A reply that is not a valid answer. `reason` names only field names and
    error types, never a value from the reply, so it is safe to store and to
    put in the retry prompt."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"model reply is not a valid answer ({reason})")
        self.reason = reason


_KNOWN_FIELDS = set(Answer.model_fields) | set(TechniqueClaim.model_fields) | set(Claim.model_fields)


def _safe_reason(exc: ValidationError) -> str:
    reasons = []
    for err in exc.errors()[:3]:
        loc = ".".join(
            str(p) if isinstance(p, int) or p in _KNOWN_FIELDS else "<unknown field>"
            for p in err["loc"]
        )
        reasons.append(f"{loc or '<root>'}: {err['type']}")
    return "; ".join(reasons)


def parse_answer(text: str) -> Answer:
    """Accepts a bare JSON object, or one inside prose or a code fence.
    Anything else raises `AnswerError`."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise AnswerError("no JSON object")
    try:
        return Answer.model_validate(json.loads(text[start : end + 1]))
    except json.JSONDecodeError as exc:
        raise AnswerError("invalid JSON") from exc
    except ValidationError as exc:
        raise AnswerError(_safe_reason(exc)) from exc
