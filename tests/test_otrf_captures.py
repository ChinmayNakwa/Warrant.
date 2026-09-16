"""The fifteen `data/captures/otrf_*` captures: one real OTRF/Security-Datasets
recording each, built by `scripts/fetch_otrf_capture.py`.

These tests are about the data: that each capture ingests whole, that its
alerted process is really in it, that the required techniques are OTRF's own
mapping, and that the alert text a model is shown says nothing beyond a host
and a process name.

A recording's first scenario is its attack. Two recordings are long enough to
also hold a process that has nothing to do with it, labelled benign.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import Path

import pytest

from backend.config import get_settings
from backend.database import SessionLocal
from backend.guardrail.slicer import build_slice
from backend.telemetry import query
from backend.telemetry.ingest import ingest_capture_dir
from scripts.fetch_otrf_capture import COMMIT, adapt_zip

CAPTURES = Path(__file__).resolve().parents[1] / "data" / "captures"
OTRF_CAPTURE_NAMES = sorted(p.name for p in CAPTURES.glob("otrf_*") if p.is_dir())
TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?")
ALERT = re.compile(r"Alert on (\S+): process (\S+)\. Review this process and its related activity\.")


def _load(name: str) -> tuple[dict, dict]:
    directory = CAPTURES / name
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    labels = json.loads((directory / "labels.json").read_text(encoding="utf-8"))
    scenario = labels["scenarios"][0]
    assert labels["capture"] == manifest["name"] == name
    assert labels["provenance"]["source_file"] == manifest["source"]["path"]
    assert labels["provenance"]["commit"] == manifest["source"]["commit"] == COMMIT
    return manifest, scenario


def test_there_are_fifteen():
    assert len(OTRF_CAPTURE_NAMES) == 15


@pytest.mark.parametrize("name", OTRF_CAPTURE_NAMES)
def test_capture_ingests_whole_and_holds_its_alerted_process(name):
    manifest, scenario = _load(name)

    with SessionLocal() as db:
        capture = ingest_capture_dir(db, CAPTURES / name)
        db.commit()
        created = query.search_events(
            db, capture.id, "process", process_guid=scenario["anchor_process_guid"]
        )

    # Ingest skips what it cannot parse, so a skipped line would silently
    # shrink the capture the manifest describes.
    assert capture.event_count == manifest["event_count"]
    assert capture.synthetic is False
    assert manifest["synthetic"] is False
    # Every alerted process has its own process-create event, command line and all.
    assert len(created) == 1
    assert created[0]["command_line"]

    # The alert a model reads is a host and that process's image name, and
    # nothing else.
    host, image = ALERT.fullmatch(scenario["alert"]).groups()
    assert host in manifest["host"].split(" / ")
    assert image.lower() == created[0]["image"].replace("/", "\\").rsplit("\\", 1)[-1].lower()
    assert scenario["alert_title"] == f"Endpoint alert: {image} on {host}"


@pytest.mark.parametrize("name", OTRF_CAPTURE_NAMES)
def test_required_techniques_are_otrfs_own_mapping(name):
    _, scenario = _load(name)
    expected, accepted = scenario["expected_techniques"], scenario["accepted_techniques"]

    # What a model must find comes from OTRF's metadata, verbatim. Accepted
    # techniques are this project's own reading of the telemetry; they remove
    # a penalty and never add a requirement.
    assert expected == scenario["otrf_metadata"]["techniques"]
    assert len(expected) == 1
    assert not set(expected) & set(accepted)
    assert all(TECHNIQUE_ID.fullmatch(t) for t in [*expected, *accepted])
    assert scenario["expected_verdict"] == "MALICIOUS"
    assert scenario["label_note"]


def test_the_dumper_opening_lsass_is_in_the_capture():
    """The event that shows the memory being read, not only the dump file
    written afterwards."""
    _, scenario = _load("otrf_lsass_dumpert")
    with SessionLocal() as db:
        capture = ingest_capture_dir(db, CAPTURES / "otrf_lsass_dumpert")
        db.commit()
        (opened,) = query.widest_accesses(db, capture.id, scenario["anchor_process_guid"], limit=1)

    assert opened["target_object"].lower().endswith("\\lsass.exe")
    assert opened["granted_access"] == "0x1fffff"


def test_no_two_otrf_scenarios_share_a_name():
    names = [
        scenario["name"]
        for name in OTRF_CAPTURE_NAMES
        for scenario in json.loads((CAPTURES / name / "labels.json").read_text(encoding="utf-8"))["scenarios"]
    ]
    assert len(names) == 17
    assert len(set(names)) == len(names)


@pytest.mark.parametrize("name", ["otrf_lsass_taskmgr", "otrf_ntds_ntdsutil"])
def test_a_benign_scenario_reads_nothing_of_the_attack_beside_it(name):
    attack, benign = json.loads((CAPTURES / name / "labels.json").read_text(encoding="utf-8"))["scenarios"]
    assert (benign["expected_verdict"], benign["expected_techniques"]) == ("BENIGN", [])
    assert ALERT.fullmatch(benign["alert"])

    settings = get_settings()
    with SessionLocal() as db:
        capture = ingest_capture_dir(db, CAPTURES / name)
        db.commit()
        anchor = attack["anchor_process_guid"]
        tree = {anchor} | {
            e["process_guid"]
            for e in query.get_ancestors(db, capture.id, anchor) + query.get_descendants(db, capture.id, anchor)
        }
        events = build_slice(
            db, capture.id, benign["anchor_process_guid"],
            max_events=settings.max_slice_events, window_seconds=settings.slice_window_seconds,
        )

    assert benign["anchor_process_guid"] in {e["process_guid"] for e in events}
    assert not [e for e in events if e["process_guid"] in tree or e["target_process_guid"] in tree]


# --- scripts/fetch_otrf_capture.py ---------------------------------------------


def _zip(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)
    return buffer.getvalue()


def test_adapt_zip_keeps_only_sysmon_records_it_understands_in_time_order():
    sysmon = {"Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "HOST-A"}
    records = [
        {**sysmon, "EventID": 1, "UtcTime": "2020-01-01 00:00:02.000", "ProcessGuid": "{b}", "Image": "b.exe"},
        {**sysmon, "EventID": 1, "UtcTime": "2020-01-01 00:00:01.000", "ProcessGuid": "{a}", "Image": "a.exe"},
        {**sysmon, "EventID": 5, "UtcTime": "2020-01-01 00:00:03.000"},  # process end: not ingested
        {"Channel": "Security", "EventID": 4688, "Hostname": "HOST-A"},
    ]
    # A member name is never used as a path: nothing is extracted to disk.
    data = _zip({"../../outside.json": "\n".join([*map(json.dumps, records), "not json", "[1, 2]"])})

    lines, hosts, counts = adapt_zip(data, source="unit test")

    assert [json.loads(line)["EventData"]["ProcessGuid"] for line in lines] == ["{a}", "{b}"]
    assert all(json.loads(line)["EventData"]["_source"] == "unit test" for line in lines)
    assert dict(hosts) == {"HOST-A": 2}
    assert (counts["kept"], counts["dropped"], counts["malformed"]) == (2, 3, 1)
