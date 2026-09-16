"""Read-only queries over `events`. The only module that reads telemetry."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import literal_column, select
from sqlalchemy.orm import Session

from backend.models import Event

_MAX_SEARCH_LIMIT = 200
_MAX_RARITY_LIMIT = 50
_MAX_ANCESTRY_DEPTH = 10
# SQLite's insertion order, so "the last row stored" is well defined.
_ROWID = literal_column("events.rowid")
# Values per `IN (...)`, kept well under SQLite's parameter limit.
_IN_CHUNK = 500


def _serialize(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "ts": event.ts.isoformat(),
        "event_type": event.event_type,
        "process_guid": event.process_guid,
        "parent_process_guid": event.parent_process_guid,
        "image": event.image,
        "command_line": event.command_line,
        "actor_user": event.actor_user,
        "dest_ip": event.dest_ip,
        "dest_port": event.dest_port,
        "target_object": event.target_object,
        "target_process_guid": event.target_process_guid,
        "granted_access": event.granted_access,
        "rarity": event.rarity,
    }


def search_events(
    db: Session,
    capture_id: str,
    event_type: str,
    *,
    process_guid: str | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
) -> list[dict[str, Any]]:
    """Events of one type, earliest first, optionally for one process or
    within a time window."""
    stmt = select(Event).where(Event.capture_id == capture_id, Event.event_type == event_type)
    if process_guid:
        stmt = stmt.where(Event.process_guid == process_guid)
    if time_from is not None:
        stmt = stmt.where(Event.ts >= time_from)
    if time_to is not None:
        stmt = stmt.where(Event.ts <= time_to)
    return [_serialize(e) for e in db.scalars(stmt.order_by(Event.ts).limit(_MAX_SEARCH_LIMIT))]


def _process_rows(db: Session, capture_id: str, column, values: list[str]) -> list[Event]:
    """Process-create events whose `column` is one of `values`, in the order
    they were stored."""
    processes = select(Event, _ROWID).where(
        Event.capture_id == capture_id, Event.event_type == "process"
    )
    rows = []
    for i in range(0, len(values), _IN_CHUNK):
        rows += db.execute(processes.where(column.in_(values[i : i + _IN_CHUNK]))).all()
    return [event for event, _ in sorted(rows, key=lambda row: row[1])]


def _by_guid(db: Session, capture_id: str, guids: list[str]) -> dict[str, Event]:
    # A GUID logged more than once resolves to the last row stored.
    return {e.process_guid: e for e in _process_rows(db, capture_id, Event.process_guid, guids)}


def get_ancestors(db: Session, capture_id: str, process_guid: str) -> list[dict[str, Any]]:
    """The process's parent, grandparent and so on, earliest first."""
    found: dict[str, Event] = {}
    current = _by_guid(db, capture_id, [process_guid]).get(process_guid)
    for _ in range(_MAX_ANCESTRY_DEPTH):
        if current is None or not current.parent_process_guid:
            break
        parent_guid = current.parent_process_guid
        current = _by_guid(db, capture_id, [parent_guid]).get(parent_guid)
        if current is not None:
            found[current.id] = current
    return [_serialize(e) for e in sorted(found.values(), key=lambda e: e.ts)]


def get_descendants(db: Session, capture_id: str, process_guid: str) -> list[dict[str, Any]]:
    """Every process started by this one, directly or not, earliest first."""
    found: dict[str, Event] = {}
    frontier = [process_guid]
    for _ in range(_MAX_ANCESTRY_DEPTH):
        if not frontier:
            break
        children = _process_rows(db, capture_id, Event.parent_process_guid, frontier)
        latest = _by_guid(db, capture_id, sorted({e.process_guid for e in children if e.process_guid}))
        frontier = []
        for e in children:
            if e.process_guid and latest.get(e.process_guid) is e and e.id not in found:
                found[e.id] = e
                frontier.append(e.process_guid)
    return [_serialize(e) for e in sorted(found.values(), key=lambda e: e.ts)]


def _rights(granted_access: str | None) -> int:
    """How many access rights a mask such as 0x1fffff asks for."""
    try:
        return int(granted_access or "0", 16).bit_count()
    except ValueError:
        return 0


def widest_accesses(
    db: Session, capture_id: str, process_guid: str, *, limit: int
) -> list[dict[str, Any]]:
    """The times this process opened another one, asking for the most rights
    first. A process is opened over and over with the same rights, so each
    target and mask is returned once, as its earliest event."""
    stmt = (
        select(Event)
        .where(
            Event.capture_id == capture_id,
            Event.event_type == "access",
            Event.process_guid == process_guid,
        )
        .order_by(Event.ts)
    )
    first: dict[tuple, Event] = {}
    for event in db.scalars(stmt):
        first.setdefault((event.target_object, event.granted_access), event)
    widest = sorted(first.values(), key=lambda e: -_rights(e.granted_access))
    return [_serialize(e) for e in widest[:limit]]


def rarest_events(
    db: Session,
    capture_id: str,
    *,
    event_type: str | None = None,
    process_guid: str | None = None,
    limit: int = _MAX_RARITY_LIMIT,
) -> list[dict[str, Any]]:
    """The rarest events, optionally of one type or for one process."""
    stmt = select(Event).where(Event.capture_id == capture_id)
    if event_type:
        stmt = stmt.where(Event.event_type == event_type)
    if process_guid:
        stmt = stmt.where(Event.process_guid == process_guid)
    stmt = stmt.order_by(Event.rarity.desc(), Event.ts).limit(min(limit, _MAX_RARITY_LIMIT))
    return [_serialize(e) for e in db.scalars(stmt)]
