"""Build one capture directory from one OTRF Security-Datasets recording
(github.com/OTRF/Security-Datasets, MIT licensed).

Downloads the dataset's zip at a pinned commit, runs every record through
`scripts/adapt_otrf_capture.py`'s `adapt_record`, and writes `events.jsonl`
and `manifest.json` under `data/captures/<name>/`. `labels.json` (the anchor
process and the ground truth) is written by hand afterwards and is never
touched here.

The zip is read in memory. Member names are never used as paths, and nothing
in a record is interpreted: a record is either re-shaped by the
adapter or dropped.

Usage:
    ./.venv/Scripts/python.exe -m scripts.fetch_otrf_capture \
        credential_access/host/cmd_sam_copy_esentutl otrf_sam_esentutl

    # from a zip already on disk (still checked into the manifest by hash)
    ./.venv/Scripts/python.exe -m scripts.fetch_otrf_capture \
        credential_access/host/cmd_sam_copy_esentutl otrf_sam_esentutl --zip tmp/x.zip
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import zipfile
from collections import Counter
from pathlib import Path

import httpx

from scripts.adapt_otrf_capture import adapt_record

REPOSITORY = "OTRF/Security-Datasets"
# The commit every committed otrf_* capture was built from.
COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
CAPTURES_ROOT = Path(__file__).resolve().parents[1] / "data" / "captures"
MAX_MEMBER_BYTES = 200_000_000  # the largest dataset used is ~22 MB unzipped


def dataset_url(dataset: str) -> str:
    return (
        f"https://raw.githubusercontent.com/{REPOSITORY}/{COMMIT}"
        f"/datasets/atomic/windows/{dataset}.zip"
    )


def adapt_zip(data: bytes, *, source: str) -> tuple[list[str], Counter, Counter]:
    """(adapted lines in time order, hostnames of the kept records, drop counts)."""
    kept: list[tuple[str, str]] = []
    hosts: Counter = Counter()
    counts: Counter = Counter()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            if member.file_size > MAX_MEMBER_BYTES:
                raise SystemExit(f"a member of the zip is {member.file_size} bytes; refusing to read it")
            for raw in archive.read(member).decode("utf-8", errors="replace").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError:
                    counts["malformed"] += 1
                    continue
                adapted = adapt_record(record, source=source) if isinstance(record, dict) else None
                if adapted is None:
                    counts["dropped"] += 1
                    continue
                counts["kept"] += 1
                hosts[str(record.get("Hostname") or "unknown")] += 1
                kept.append((adapted["EventData"].get("UtcTime", ""), json.dumps(adapted, sort_keys=True)))
    # Time order, then the line itself, so the file does not depend on the
    # order the export happened to list its records in.
    kept.sort()
    return [line for _, line in kept], hosts, counts


def build_capture(dataset: str, name: str, data: bytes) -> dict:
    title = dataset.rsplit("/", 1)[-1]
    lines, hosts, counts = adapt_zip(data, source=f"{title} (OTRF Security-Datasets, MIT)")
    if not lines:
        raise SystemExit(f"{dataset}: no Sysmon process/network/file/registry records")

    out_dir = CAPTURES_ROOT / name
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "events.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    stamps = sorted(json.loads(line)["EventData"]["UtcTime"] for line in lines)
    manifest = {
        "name": name,
        "host": " / ".join(host for host, _ in hosts.most_common()),
        "scenario": title,
        "synthetic": False,
        # Byte-identical log lines are one event once ingested.
        "event_count": len(set(lines)),
        "starts_at": stamps[0].replace(" ", "T"),
        "ends_at": stamps[-1].replace(" ", "T"),
        "source": {
            "repository": f"github.com/{REPOSITORY}",
            "license": "MIT",
            "commit": COMMIT,
            "path": f"datasets/atomic/windows/{dataset}.zip",
            "zip_sha256": hashlib.sha256(data).hexdigest(),
            "converted_by": "scripts/fetch_otrf_capture.py",
            "records_kept": counts["kept"],
            "records_dropped": counts["dropped"],
            "records_malformed": counts["malformed"],
        },
        "notes": (
            "Real Sysmon telemetry from one OTRF/Security-Datasets atomic recording. Only "
            "Microsoft-Windows-Sysmon/Operational records with an EventID ingest.py understands "
            "(1/3/11/12/13/14) are kept; every other record in the export is dropped. Ground "
            "truth in labels.json."
        ),
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", help="path under datasets/atomic/windows/, without .zip")
    parser.add_argument("name", help="capture directory name under data/captures/")
    parser.add_argument("--zip", type=Path, help="use this local copy of the zip instead of downloading")
    args = parser.parse_args()

    if args.zip is not None:
        data = args.zip.read_bytes()
    else:
        response = httpx.get(dataset_url(args.dataset), follow_redirects=True, timeout=120)
        response.raise_for_status()
        data = response.content

    manifest = build_capture(args.dataset, args.name, data)
    source = manifest["source"]
    print(
        f"wrote data/captures/{args.name}: {manifest['event_count']} events "
        f"({source['records_kept']} kept, {source['records_dropped']} dropped, "
        f"{source['records_malformed']} malformed), sha256 {source['zip_sha256'][:16]}..."
    )


if __name__ == "__main__":
    main()
