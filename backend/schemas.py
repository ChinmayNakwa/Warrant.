"""Pydantic request/response models for the API."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, field_validator

from backend.config import get_settings

_HAS_LETTER = re.compile(r"[A-Za-z]")
_HAS_DIGIT = re.compile(r"\d")

# Times are stored as UTC with no zone. This marks them as UTC in responses,
# so a browser does not read them as local time.
UtcDatetime = Annotated[datetime, AfterValidator(lambda v: v.replace(tzinfo=timezone.utc))]


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def _password_strength(cls, v: str) -> str:
        settings = get_settings()
        if len(v) < settings.min_password_length:
            raise ValueError(
                f"Password must be at least {settings.min_password_length} characters."
            )
        if len(v.encode("utf-8")) > 4096:
            raise ValueError("Password is too long.")
        if not _HAS_LETTER.search(v) or not _HAS_DIGIT.search(v):
            raise ValueError("Password must contain at least one letter and one digit.")
        if len(set(v)) < 4:
            raise ValueError("Password is not complex enough.")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    created_at: UtcDatetime


class MessageResponse(BaseModel):
    detail: str


Severity = Literal["low", "medium", "high", "critical"]


class CaptureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    host: str
    scenario: str | None
    synthetic: bool
    event_count: int


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    severity: Severity = "medium"
    capture_name: str = Field(min_length=1, max_length=200)
    anchor_process_guid: str | None = Field(default=None, max_length=100)

    @field_validator("anchor_process_guid")
    @classmethod
    def _blank_anchor_is_none(cls, v: str | None) -> str | None:
        return v or None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: str
    severity: str
    status: str
    capture_id: str
    anchor_process_guid: str | None
    verdict: str | None
    confidence: float | None
    created_at: UtcDatetime


class DashboardSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    open_incidents: int
    total_runs: int
    # Runs whose first answer broke at least one rule
    runs_with_violations: int
    verdict_breakdown: dict[str, int]
    severity_breakdown: dict[str, int]
    runs_over_time: list[dict]
    recent_incidents: list[IncidentResponse]
