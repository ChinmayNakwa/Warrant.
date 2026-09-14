"""`data/captures/real_atomic`: real telemetry, converted by
`scripts/adapt_otrf_capture.py` from two OTRF/Security-Datasets recordings
(MIT licence; see the provenance in its labels.json).

A check that ingestion works on data this project did not write.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.database import SessionLocal
from backend.models import Capture
from backend.telemetry import query
from backend.telemetry.ingest import ingest_capture_dir

CAPTURE_DIR = Path(__file__).resolve().parents[1] / "data" / "captures" / "real_atomic"
LABELS = json.loads((CAPTURE_DIR / "labels.json").read_text(encoding="utf-8"))["scenarios"]
CRED_ACCESS, PERSISTENCE = LABELS


@pytest.fixture
def capture_id():
    with SessionLocal() as db:
        cap = ingest_capture_dir(db, CAPTURE_DIR)
        db.commit()
        return cap.id


def test_real_capture_ingests_whole(capture_id):
    # 127 adapted lines, of which 8 are exact duplicates in the source log.
    with SessionLocal() as db:
        cap = db.get(Capture, capture_id)
    assert cap.event_count == 119
    assert cap.synthetic is False


def test_the_real_command_line_and_registry_value_survive(capture_id):
    with SessionLocal() as db:
        procs = query.search_events(
            db, capture_id, "process", process_guid=CRED_ACCESS["anchor_process_guid"]
        )
        regs = query.search_events(
            db, capture_id, "registry", process_guid=PERSISTENCE["anchor_process_guid"]
        )
    assert "comsvcs.dll" in procs[0]["command_line"] and "MiniDump" in procs[0]["command_line"]
    assert any(r["target_object"].endswith("Run\\Updater") for r in regs)
