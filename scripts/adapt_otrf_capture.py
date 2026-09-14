"""Convert an OTRF Security-Datasets (github.com/OTRF/Security-Datasets, MIT
licensed) flat JSON-lines export into the nested Sysmon JSON-lines shape
`backend/telemetry/ingest.py` consumes: one JSON object per
line, `{"System": {"EventID": ...}, "EventData": {...}}`.

OTRF's export is flat (fields like `EventID`, `UtcTime`, `ProcessGuid` sit at
the top level, not nested) and mixes multiple Windows Event Log channels
(`Security`, `Windows PowerShell`, `Microsoft-Windows-PowerShell/Operational`)
in with the Sysmon ones in the same file. This script keeps only records from
`Microsoft-Windows-Sysmon/Operational` whose EventID is one `ingest.py`
understands (1, 3, 11, 12/13/14) and re-shapes those into the nested form.
Everything else is dropped and counted, never guessed at or passed through.

Usage:
    ./.venv/Scripts/python.exe -m scripts.adapt_otrf_capture <in.json> <out.jsonl> \
        --source "psh_lsass_memory_dump_comsvcs (OTRF Security-Datasets, MIT)"
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_UNDERSTOOD_EVENT_IDS = {1, 3, 11, 12, 13, 14}

# OTRF field name -> nested EventData field name. Names already match
# ingest.py's expectations once un-nested; only TargetFilename/TargetObject
# vary by event type, both passed through under their own names since
# `_parse_line` already reads `TargetFilename or TargetObject`.
_FIELDS = (
    "UtcTime", "ProcessGuid", "ParentProcessGuid", "Image", "CommandLine",
    "User", "DestinationIp", "DestinationPort", "TargetFilename", "TargetObject",
)


def adapt_record(record: dict, *, source: str) -> dict | None:
    if record.get("Channel") != _SYSMON_CHANNEL:
        return None
    event_id = record.get("EventID")
    if event_id not in _UNDERSTOOD_EVENT_IDS:
        return None
    event_data = {k: record[k] for k in _FIELDS if k in record}
    event_data["_source"] = source  # provenance, kept in the stored raw_json
    return {"System": {"EventID": event_id, "Channel": _SYSMON_CHANNEL}, "EventData": event_data}


def adapt_file(in_path: Path, out_lines: list[str], *, source: str, counts: Counter) -> None:
    with in_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                counts["malformed"] += 1
                continue
            adapted = adapt_record(record, source=source)
            if adapted is None:
                counts[f"dropped:{record.get('Channel')}:{record.get('EventID')}"] += 1
                continue
            out_lines.append(json.dumps(adapted, sort_keys=True))
            counts[f"kept:EventID{adapted['System']['EventID']}"] += 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, nargs="+", help="OTRF flat JSON-lines file(s)")
    parser.add_argument("output", type=Path, help="Sysmon JSON-lines file to write")
    parser.add_argument("--source", required=True, help="Provenance note stored on every kept record")
    args = parser.parse_args()

    out_lines: list[str] = []
    counts: Counter = Counter()
    for in_path in args.input:
        adapt_file(in_path, out_lines, source=args.source, counts=counts)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    print(f"wrote {len(out_lines)} events to {args.output}")
    for key, n in sorted(counts.items()):
        print(f"  {key}: {n}")


if __name__ == "__main__":
    main()
