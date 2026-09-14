"""The telemetry a model reads for one incident.

No model is involved, so both modes see the same events. Picked in this order
until the cap is reached:

1. the alerted process and what it did (network, file, registry)
2. the processes it started, then what they did
3. its ancestors' process-create events
4. whatever else the host logged close to the alert, nearest in time first:
   the alerted process is often one step of an attack whose other steps are
   its siblings

Within each group the rarest events are taken first. With no alerted process,
or one the capture does not contain, the slice is the capture's rarest events.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from backend.telemetry import query

Event = dict[str, Any]

_ACTIVITY = ("network", "file", "registry")


def _activity(db: Session, capture_id: str, process_guid: str) -> list[Event]:
    events: list[Event] = []
    for event_type in _ACTIVITY:
        events += query.search_events(db, capture_id, event_type, process_guid=process_guid)
    return events


def _nearby(db: Session, capture_id: str, around: datetime, window_seconds: int) -> list[Event]:
    window = timedelta(seconds=window_seconds)
    events: list[Event] = []
    for event_type in ("process", *_ACTIVITY):
        events += query.search_events(
            db, capture_id, event_type, time_from=around - window, time_to=around + window
        )
    return events


def build_slice(
    db: Session,
    capture_id: str,
    anchor_process_guid: str | None,
    *,
    max_events: int,
    window_seconds: int,
) -> list[Event]:
    """Events in time order, each with a short `ref` ("e1", "e2", ...) for the
    model to cite."""
    picked: dict[str, Event] = {}

    def rarest_first(e: Event) -> tuple:
        return (-e["rarity"], e["ts"], e["id"])

    def take(events: list[Event], key=rarest_first) -> None:
        for event in sorted(events, key=key):
            if len(picked) >= max_events:
                return
            picked.setdefault(event["id"], event)

    own = []
    if anchor_process_guid:
        own = query.search_events(db, capture_id, "process", process_guid=anchor_process_guid)
    if own:
        descendants = query.get_descendants(db, capture_id, anchor_process_guid)
        take(own + _activity(db, capture_id, anchor_process_guid))
        take(descendants)
        child_activity: list[Event] = []
        for child in descendants[:max_events]:
            child_activity += _activity(db, capture_id, child["process_guid"])
        take(child_activity)
        take(query.get_ancestors(db, capture_id, anchor_process_guid))
        alerted_at = datetime.fromisoformat(own[0]["ts"])
        take(
            _nearby(db, capture_id, alerted_at, window_seconds),
            key=lambda e: (abs(datetime.fromisoformat(e["ts"]) - alerted_at), e["ts"], e["id"]),
        )
    else:
        take(query.rarest_events(db, capture_id))

    ordered = sorted(picked.values(), key=lambda e: (e["ts"], e["id"]))
    return [{"ref": f"e{i}", **event} for i, event in enumerate(ordered, 1)]
