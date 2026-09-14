"""Sysmon JSON-lines -> `events` rows.

One JSON object per line, shaped like `Get-WinEvent ... | ConvertTo-Json`
output: a `System.EventID` plus an `EventData` field bag. Understood event
IDs: 1 (process create), 3 (network connect), 11 (file create) and 12/13/14
(registry add/set/rename, stored as one `registry` type).

Telemetry is untrusted input: a malformed or unrecognised line is skipped.
`raw_json` keeps the original record; the other columns are extracted from it
for querying.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import func, insert, select, update
from sqlalchemy.orm import Session

from backend.models import Capture, Event

_PROCESS_CREATE = 1
_NETWORK_CONNECT = 3
_FILE_CREATE = 11
_REGISTRY_EVENT_IDS = {12, 13, 14}

_EVENT_TYPE_BY_ID = {
    _PROCESS_CREATE: "process",
    _NETWORK_CONNECT: "network",
    _FILE_CREATE: "file",
}

_TS_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")


def _parse_ts(raw: str) -> datetime | None:
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def normalize_command_line(cmd: str | None) -> str:
    """Lower-cased with whitespace collapsed, for grouping equal commands."""
    if not cmd:
        return ""
    return re.sub(r"\s+", " ", cmd.strip().lower())


@dataclass(frozen=True)
class ParsedEvent:
    ts: datetime
    event_type: str
    process_guid: str | None
    parent_process_guid: str | None
    image: str | None
    command_line: str | None
    actor_user: str | None
    dest_ip: str | None
    dest_port: int | None
    target_object: str | None
    raw_json: str


def _parse_line(line: str) -> ParsedEvent | None:
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(record, dict):
        return None

    system = record.get("System") or {}
    data = record.get("EventData") or {}
    if not isinstance(system, dict) or not isinstance(data, dict):
        return None

    event_id = system.get("EventID")
    if event_id in _EVENT_TYPE_BY_ID:
        event_type = _EVENT_TYPE_BY_ID[event_id]
    elif event_id in _REGISTRY_EVENT_IDS:
        event_type = "registry"
    else:
        return None

    ts = _parse_ts(data.get("UtcTime") or "")
    if ts is None:
        return None

    dest_port = data.get("DestinationPort")
    try:
        dest_port = int(dest_port) if dest_port is not None else None
    except (TypeError, ValueError):
        dest_port = None

    return ParsedEvent(
        ts=ts,
        event_type=event_type,
        process_guid=data.get("ProcessGuid"),
        parent_process_guid=data.get("ParentProcessGuid"),
        image=data.get("Image"),
        command_line=data.get("CommandLine"),
        actor_user=data.get("User"),
        dest_ip=data.get("DestinationIp"),
        dest_port=dest_port,
        target_object=data.get("TargetFilename") or data.get("TargetObject"),
        raw_json=json.dumps(record, sort_keys=True),
    )


def _dedupe_key(capture_name: str, parsed: ParsedEvent) -> str:
    digest = hashlib.sha256()
    digest.update(capture_name.encode("utf-8"))
    digest.update(parsed.raw_json.encode("utf-8"))
    return digest.hexdigest()


def _rarity_group(record) -> tuple[str, ...]:
    """Events in the same group count as the same thing happening again;
    an event's rarity is 1 / its group's size. Each event type is grouped on
    the field that identifies it: the command line, the destination, or the
    file or registry path."""
    event_type = record.event_type
    image = record.image or ""
    if event_type == "process":
        return (event_type, image, normalize_command_line(record.command_line))
    if event_type == "network":
        port = "" if record.dest_port is None else str(record.dest_port)
        return (event_type, image, record.dest_ip or "", port)
    if event_type in ("file", "registry"):
        return (event_type, image, (record.target_object or "").strip().lower())
    return (event_type, image)


def ingest_capture(
    db: Session,
    *,
    name: str,
    host: str,
    events_path: Path,
    scenario: str | None = None,
    synthetic: bool = False,
) -> Capture:
    """Ingest a Sysmon JSON-lines file into `captures`/`events`.

    Re-ingesting the same file adds nothing: each record is deduped on a hash
    of the capture name and the raw record. Rarity is computed over every
    event the capture holds, so rows from an earlier ingest stay correct.
    """
    capture = db.scalar(select(Capture).where(Capture.name == name))
    if capture is None:
        capture = Capture(name=name, host=host, scenario=scenario, synthetic=synthetic)
        db.add(capture)
        db.flush()

    # Only the columns rarity grouping needs, not whole ORM objects.
    existing = db.execute(
        select(
            Event.id, Event.event_type, Event.image, Event.command_line, Event.dest_ip,
            Event.dest_port, Event.target_object, Event.rarity, Event.dedupe_key,
        ).where(Event.capture_id == capture.id)
    ).all()
    seen_keys = {row.dedupe_key for row in existing}

    new_events: list[tuple[str, ParsedEvent]] = []
    with events_path.open("r", encoding="utf-8") as f:
        for line in f:
            parsed = _parse_line(line)
            if parsed is None:
                continue
            dedupe_key = _dedupe_key(name, parsed)
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            new_events.append((dedupe_key, parsed))

    # New rows get their rarity at insert; stored rows are updated only if
    # theirs changed.
    group_counts = Counter(_rarity_group(row) for row in existing)
    group_counts.update(_rarity_group(parsed) for _, parsed in new_events)

    if new_events:
        db.execute(
            insert(Event),
            [
                {
                    "id": str(uuid.uuid4()),
                    "capture_id": capture.id,
                    "ts": parsed.ts,
                    "event_type": parsed.event_type,
                    "process_guid": parsed.process_guid,
                    "parent_process_guid": parsed.parent_process_guid,
                    "image": parsed.image,
                    "command_line": parsed.command_line,
                    "actor_user": parsed.actor_user,
                    "dest_ip": parsed.dest_ip,
                    "dest_port": parsed.dest_port,
                    "target_object": parsed.target_object,
                    "raw_json": parsed.raw_json,
                    "rarity": 1.0 / group_counts[_rarity_group(parsed)],
                    "dedupe_key": dedupe_key,
                }
                for dedupe_key, parsed in new_events
            ],
        )
        stale = [
            {"id": row.id, "rarity": correct}
            for row in existing
            if row.rarity != (correct := 1.0 / group_counts[_rarity_group(row)])
        ]
        if stale:
            db.execute(update(Event), stale)

    count, min_ts, max_ts = db.execute(
        select(func.count(Event.id), func.min(Event.ts), func.max(Event.ts)).where(
            Event.capture_id == capture.id
        )
    ).one()
    capture.event_count = count
    capture.starts_at = min_ts
    capture.ends_at = max_ts
    db.flush()
    return capture


def ingest_capture_dir(db: Session, directory: Path) -> Capture:
    """Ingest a capture directory (`manifest.json` + `events.jsonl`)."""
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    return ingest_capture(
        db,
        name=manifest["name"],
        host=manifest["host"],
        events_path=directory / "events.jsonl",
        scenario=manifest.get("scenario"),
        synthetic=bool(manifest.get("synthetic", False)),
    )
