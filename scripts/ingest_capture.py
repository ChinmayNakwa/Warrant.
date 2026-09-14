"""CLI: ingest a telemetry capture directory into the database.

Usage:
    ./.venv/Scripts/python.exe -m scripts.ingest_capture data/captures/small_lab

The directory must contain `manifest.json` (name, host, scenario, synthetic)
and `events.jsonl` (Sysmon JSON-lines; see backend/telemetry/ingest.py).
"""
from __future__ import annotations

import argparse
from pathlib import Path

from backend.database import SessionLocal
from backend.telemetry.ingest import ingest_capture_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest a telemetry capture directory")
    parser.add_argument("capture_dir", type=Path)
    args = parser.parse_args()

    with SessionLocal() as db:
        capture = ingest_capture_dir(db, args.capture_dir)
        db.commit()
        print(
            f"ingested '{capture.name}': {capture.event_count} events "
            f"({capture.starts_at} .. {capture.ends_at})"
        )


if __name__ == "__main__":
    main()
