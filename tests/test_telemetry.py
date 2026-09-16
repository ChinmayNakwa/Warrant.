"""Telemetry ingestion and queries, against the small_lab capture."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select

from backend.database import SessionLocal
from backend.models import Capture, Event
from backend.telemetry import query as q
from backend.telemetry.ingest import ingest_capture, ingest_capture_dir

CAPTURE_DIR = Path(__file__).resolve().parents[1] / "data" / "captures" / "small_lab"
EVENTS_PATH = CAPTURE_DIR / "events.jsonl"

PS_MALICIOUS_GUID = "{00000000-0000-0000-0000-000000000201}"
CMD_CHILD_GUID = "{00000000-0000-0000-0000-000000000202}"
OUTLOOK_PARENT_GUID = "{00000000-0000-0000-0000-000000000200}"
PS_BENIGN_GUID = "{00000000-0000-0000-0000-000000000401}"


@pytest.fixture
def capture() -> Capture:
    with SessionLocal() as db:
        cap = ingest_capture(
            db, name="small_lab_test", host="WIN11-LAB", events_path=EVENTS_PATH, synthetic=True
        )
        db.commit()
        cap_id = cap.id
    with SessionLocal() as db:
        return db.get(Capture, cap_id)


def test_ingest_creates_expected_event_count(capture):
    assert capture.event_count == 13
    with SessionLocal() as db:
        count = db.scalar(select(func.count(Event.id)).where(Event.capture_id == capture.id))
        assert count == 13


def test_ingest_is_idempotent(capture):
    with SessionLocal() as db:
        ingest_capture(
            db, name="small_lab_test", host="WIN11-LAB", events_path=EVENTS_PATH, synthetic=True
        )
        db.commit()
        count = db.scalar(select(func.count(Event.id)).where(Event.capture_id == capture.id))
        assert count == 13
        assert db.get(Capture, capture.id).event_count == 13


def test_capture_dir_ingest_reads_the_manifest():
    with SessionLocal() as db:
        cap = ingest_capture_dir(db, CAPTURE_DIR)
        db.commit()
        assert (cap.name, cap.host, cap.scenario, cap.synthetic) == (
            "small_lab", "WIN11-LAB", "small_lab_mixed", True,
        )


def test_ingest_skips_malformed_lines(tmp_path):
    bad_file = tmp_path / "events.jsonl"
    bad_file.write_text(
        "not json at all\n"
        '{"System": {"EventID": 1}, "EventData": {}}\n'  # missing UtcTime
        '{"System": {"EventID": 999}, "EventData": {"UtcTime": "2026-01-15 10:00:00.000"}}\n'  # unknown id
        "\n",
        encoding="utf-8",
    )
    with SessionLocal() as db:
        cap = ingest_capture(db, name="malformed_test", host="H", events_path=bad_file)
        db.commit()
        assert cap.event_count == 0


def test_search_by_time_window(capture):
    with SessionLocal() as db:
        events = q.search_events(
            db,
            capture.id,
            "process",
            time_from=datetime(2026, 1, 15, 10, 5, 0),
            time_to=datetime(2026, 1, 15, 10, 5, 59),
        )
        assert {e["process_guid"] for e in events} == {PS_MALICIOUS_GUID, CMD_CHILD_GUID}


def test_search_by_type_and_process(capture):
    with SessionLocal() as db:
        network = q.search_events(db, capture.id, "network", process_guid=PS_MALICIOUS_GUID)
        registry = q.search_events(db, capture.id, "registry", process_guid=PS_MALICIOUS_GUID)
        nothing = q.search_events(db, capture.id, "network", process_guid=PS_BENIGN_GUID)
    assert [(e["dest_ip"], e["dest_port"]) for e in network] == [("127.0.0.1", 8080)]
    assert len(registry) == 1 and "CurrentVersion\\Run" in registry[0]["target_object"]
    assert nothing == []


def test_ancestors_and_descendants_follow_the_process_guid(capture):
    with SessionLocal() as db:
        ancestors = q.get_ancestors(db, capture.id, CMD_CHILD_GUID)
        descendants = q.get_descendants(db, capture.id, PS_MALICIOUS_GUID)
    assert [e["process_guid"] for e in ancestors] == [PS_MALICIOUS_GUID]
    assert [e["process_guid"] for e in descendants] == [CMD_CHILD_GUID]


def test_ancestors_stop_where_the_capture_does(capture):
    """Outlook was already running when the capture began, so it has no
    process-create event of its own."""
    with SessionLocal() as db:
        assert q.get_ancestors(db, capture.id, OUTLOOK_PARENT_GUID) == []
        assert q.get_ancestors(db, capture.id, PS_MALICIOUS_GUID) == []


def test_rarest_events_come_first(capture):
    with SessionLocal() as db:
        ranked = q.rarest_events(db, capture.id)
    rarities = [e["rarity"] for e in ranked]
    assert rarities == sorted(rarities, reverse=True)
    # 5 identical svchost starts (rarity 0.2) against one-off processes (1.0)
    unique = {e["process_guid"] for e in ranked if e["rarity"] == 1.0}
    assert {PS_MALICIOUS_GUID, PS_BENIGN_GUID} <= unique
    svchost = next(e for e in ranked if e["image"].endswith("svchost.exe"))
    assert svchost["rarity"] == pytest.approx(0.2)


def _write_jsonl(path: Path, records: list[dict]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return path


def _record(event_id: int, ts: str, guid: str, image: str, **data) -> dict:
    return {
        "System": {"EventID": event_id},
        "EventData": {"UtcTime": ts, "ProcessGuid": guid, "Image": image, **data},
    }


def test_rarity_distinguishes_network_events_by_destination(tmp_path):
    path = _write_jsonl(
        tmp_path / "events.jsonl",
        [
            _record(3, "2026-02-01 00:00:00.000", "{g1}", "beacon.exe", DestinationIp="1.1.1.1", DestinationPort=443),
            _record(3, "2026-02-01 00:00:01.000", "{g1}", "beacon.exe", DestinationIp="2.2.2.2", DestinationPort=8443),
        ],
    )
    with SessionLocal() as db:
        cap = ingest_capture(db, name="net_rarity_test", host="H", events_path=path)
        db.commit()
        events = q.search_events(db, cap.id, "network")
    assert {e["rarity"] for e in events} == {1.0}


def test_rarity_distinguishes_file_events_by_target_path(tmp_path):
    path = _write_jsonl(
        tmp_path / "events.jsonl",
        [
            _record(11, "2026-02-01 00:00:00.000", "{g1}", "rundll32.exe", TargetFilename="C:\\Temp\\a.dmp"),
            _record(11, "2026-02-01 00:00:01.000", "{g1}", "rundll32.exe", TargetFilename="C:\\Temp\\b.dmp"),
        ],
    )
    with SessionLocal() as db:
        cap = ingest_capture(db, name="file_rarity_test", host="H", events_path=path)
        db.commit()
        events = q.search_events(db, cap.id, "file")
    assert {e["rarity"] for e in events} == {1.0}


def test_rarity_is_recomputed_when_a_capture_grows(tmp_path):
    def evil(i: int) -> dict:
        return _record(1, f"2026-02-01 00:0{i}:00.000", f"{{g{i}}}", "evil.exe", CommandLine="evil.exe -run")

    path = _write_jsonl(tmp_path / "events.jsonl", [evil(0)])
    with SessionLocal() as db:
        cap = ingest_capture(db, name="growing_capture", host="H", events_path=path)
        db.commit()
        assert q.search_events(db, cap.id, "process")[0]["rarity"] == 1.0

    _write_jsonl(path, [evil(i) for i in range(5)])
    with SessionLocal() as db:
        cap = ingest_capture(db, name="growing_capture", host="H", events_path=path)
        db.commit()
        # the first event is no longer unique, and its stored rarity must say so
        assert {e["rarity"] for e in q.search_events(db, cap.id, "process")} == {0.2}


def test_queries_are_scoped_to_one_capture(capture):
    with SessionLocal() as db:
        other = ingest_capture(db, name="other_capture", host="OTHER-HOST", events_path=EVENTS_PATH)
        db.commit()
        events_a = q.search_events(db, capture.id, "process")
        events_b = q.search_events(db, other.id, "process")
    assert len(events_a) == len(events_b) == 9
    assert {e["id"] for e in events_a}.isdisjoint({e["id"] for e in events_b})


def _two_process_record(event_id: int, ts: str, guid_field: str, target: str, **data) -> dict:
    return {
        "System": {"EventID": event_id},
        "EventData": {
            "UtcTime": ts, f"Source{guid_field}": "{g1}", "SourceImage": "C:\\Temp\\dump.exe",
            f"Target{guid_field}": "{g2}", "TargetImage": target, **data,
        },
    }


def test_ingest_reads_process_access_remote_thread_dll_load_and_dns(tmp_path):
    lsass = "C:\\Windows\\System32\\lsass.exe"
    path = _write_jsonl(
        tmp_path / "events.jsonl",
        [
            # Sysmon spells the GUID fields ProcessGUID in 10 and ProcessGuid in 8.
            _two_process_record(10, "2026-02-01 00:00:00.000", "ProcessGUID", lsass, GrantedAccess="0x1fffff"),
            _two_process_record(8, "2026-02-01 00:00:01.000", "ProcessGuid", lsass),
            _record(7, "2026-02-01 00:00:02.000", "{g1}", "dump.exe", ImageLoaded="C:\\Windows\\System32\\dbghelp.dll"),
            _record(22, "2026-02-01 00:00:03.000", "{g1}", "dump.exe", QueryName="example.org"),
        ],
    )
    with SessionLocal() as db:
        cap = ingest_capture(db, name="more_types_test", host="H", events_path=path)
        db.commit()
        (access,), (thread,), (module,), (dns,) = (
            q.search_events(db, cap.id, t, process_guid="{g1}") for t in ("access", "thread", "module", "dns")
        )

    # The process acting is the event's own; the one acted on is its target.
    for event in (access, thread):
        assert (event["image"], event["target_object"], event["target_process_guid"]) == (
            "C:\\Temp\\dump.exe", lsass, "{g2}",
        )
    assert (access["granted_access"], thread["granted_access"]) == ("0x1fffff", None)
    assert module["target_object"].endswith("dbghelp.dll")
    assert dns["target_object"] == "example.org"


def test_a_dll_is_rare_when_few_processes_load_it(tmp_path):
    path = _write_jsonl(
        tmp_path / "events.jsonl",
        [
            _record(7, "2026-02-01 00:00:00.000", "{g1}", "a.exe", ImageLoaded="C:\\Windows\\System32\\kernel32.dll"),
            _record(7, "2026-02-01 00:00:01.000", "{g2}", "b.exe", ImageLoaded="C:\\Windows\\System32\\kernel32.dll"),
            _record(7, "2026-02-01 00:00:02.000", "{g2}", "b.exe", ImageLoaded="C:\\Temp\\evil.dll"),
        ],
    )
    with SessionLocal() as db:
        cap = ingest_capture(db, name="module_rarity_test", host="H", events_path=path)
        db.commit()
        rarest = q.rarest_events(db, cap.id, event_type="module", process_guid="{g2}", limit=1)
        everything = q.search_events(db, cap.id, "module")
    assert [e["target_object"] for e in rarest] == ["C:\\Temp\\evil.dll"]
    assert sorted(e["rarity"] for e in everything) == [0.5, 0.5, 1.0]


def test_widest_accesses_asks_for_the_most_rights_first_and_lists_each_target_once(tmp_path):
    def opened(second: int, target: str, mask: str) -> dict:
        return _two_process_record(10, f"2026-02-01 00:00:{second:02d}.000", "ProcessGUID", target, GrantedAccess=mask)

    path = _write_jsonl(
        tmp_path / "events.jsonl",
        [
            opened(0, "svchost.exe", "0x1000"),
            opened(1, "winlogon.exe", "0x1410"),
            opened(2, "lsass.exe", "0x1fffff"),
            opened(3, "lsass.exe", "0x1fffff"),   # a dump opens its target again and again
            opened(4, "csrss.exe", "not a mask"),  # telemetry is untrusted
        ],
    )
    with SessionLocal() as db:
        cap = ingest_capture(db, name="access_test", host="H", events_path=path)
        db.commit()
        widest = q.widest_accesses(db, cap.id, "{g1}", limit=3)
        nobody = q.widest_accesses(db, cap.id, "{g2}", limit=3)

    assert [(e["target_object"], e["ts"][17:19]) for e in widest] == [
        ("lsass.exe", "02"), ("winlogon.exe", "01"), ("svchost.exe", "00"),
    ]
    assert nobody == []
