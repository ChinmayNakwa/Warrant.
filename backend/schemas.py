"""Pydantic request/response models for the API."""
from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from backend.config import get_settings

_HAS_LETTER = re.compile(r"[A-Za-z]")
_HAS_DIGIT = re.compile(r"\d")


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
    created_at: datetime


class MessageResponse(BaseModel):
    detail: str
