"""ORM models."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base, utcnow


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # sha256 of the token; the token itself is never stored
    token_hash: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    replaced_by_id: Mapped[str | None] = mapped_column(String, nullable=True)

    user: Mapped[User] = relationship(back_populates="refresh_tokens")


class RateLimitHit(Base):
    """Attempts per bucket in one fixed time window."""

    __tablename__ = "rate_limit_hits"
    __table_args__ = (UniqueConstraint("bucket_key", "window_start", name="uq_bucket_window"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    bucket_key: Mapped[str] = mapped_column(String, index=True, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class Capture(Base):
    """One host's recorded telemetry. Shared reference data: every user can
    file incidents against any capture."""

    __tablename__ = "captures"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False)
    scenario: Mapped[str | None] = mapped_column(String, nullable=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    starts_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    events: Mapped[list["Event"]] = relationship(
        back_populates="capture", cascade="all, delete-orphan"
    )


class Event(Base):
    """One Sysmon event. Untrusted input: `raw_json` is the original record and
    the typed columns are extracted from it for querying."""

    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("capture_id", "dedupe_key", name="uq_event_capture_dedupe"),
        Index("ix_events_capture_type_ts", "capture_id", "event_type", "ts"),
        Index("ix_events_capture_guid", "capture_id", "process_guid", "event_type", "ts"),
        Index("ix_events_capture_parent_guid", "capture_id", "parent_process_guid", "event_type"),
        Index("ix_events_capture_rarity", "capture_id", text("rarity DESC"), "ts"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    capture_id: Mapped[str] = mapped_column(
        ForeignKey("captures.id", ondelete="CASCADE"), nullable=False
    )
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # process | network | file | registry
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    process_guid: Mapped[str | None] = mapped_column(String, nullable=True)
    parent_process_guid: Mapped[str | None] = mapped_column(String, nullable=True)
    image: Mapped[str | None] = mapped_column(String, nullable=True)
    command_line: Mapped[str | None] = mapped_column(String, nullable=True)
    actor_user: Mapped[str | None] = mapped_column(String, nullable=True)
    dest_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    dest_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target_object: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_json: Mapped[str] = mapped_column(String, nullable=False)
    rarity: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    # sha256(capture name + raw record), so re-ingesting adds nothing
    dedupe_key: Mapped[str] = mapped_column(String, nullable=False)

    capture: Mapped[Capture] = relationship(back_populates="events")
