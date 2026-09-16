"""Build `backend/guardrail/ontology/attack.ttl`: MITRE ATT&CK's techniques as
ontology individuals.

For every technique in MITRE's STIX bundle:
  * in use        -> `wr:Technique`, with its name, tactics, platforms, and the
                     kinds of telemetry event that can show it;
  * revoked       -> `wr:RetiredTechnique` with `wr:replacedBy` its current id;
  * deprecated    -> `wr:RetiredTechnique` with no replacement.

"The kinds of event that can show it" is derived from ATT&CK itself, which
links a technique to detection strategies, those to analytics, and each
analytic to the data components it reads. The Windows analytics' components
are mapped to the event kinds stored here (`COMPONENT_KINDS`). A technique
none of whose components map gets no kind, and the guardrail then puts no
evidence-kind requirement on it.

Usage (the bundle is ~50 MB and is not committed):
    curl -L -o tmp/attack/enterprise-attack.json \
        https://raw.githubusercontent.com/mitre/cti/<commit>/enterprise-attack/enterprise-attack.json
    ./.venv/Scripts/python.exe -m scripts.build_attack_ontology \
        tmp/attack/enterprise-attack.json --commit <commit>
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

OUTPUT = Path(__file__).resolve().parents[1] / "backend" / "guardrail" / "ontology" / "attack.ttl"
MAX_HOPS = 10  # a replacement can itself have been revoked later

# ATT&CK data component -> the event kind that records it here (Sysmon 1, 3,
# 7, 8, 10, 11, 12/13/14). Components with no entry (File Access, Logon
# Session Creation, ...) are not in this telemetry. Nor is there one for a
# DNS lookup made on the host, so no technique is tied to the dns kind.
COMPONENT_KINDS = {
    "Process Creation": "process",
    "Command Execution": "process",
    "Process Access": "access",
    "Process Modification": "thread",
    "Module Load": "module",
    "Network Connection Creation": "network",
    "File Creation": "file",
    "Windows Registry Key Creation": "registry",
    "Windows Registry Key Modification": "registry",
    "Windows Registry Key Deletion": "registry",
}


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def revoked_map(bundle: dict) -> dict[str, str]:
    """`{revoked id: current id}` for every revoked technique whose chain of
    replacements ends at a technique that is still in use."""
    objects = bundle["objects"]
    techniques = {o["id"]: o for o in objects if o["type"] == "attack-pattern"}
    replaced_by = {
        o["source_ref"]: o["target_ref"]
        for o in objects
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by"
    }

    mapping: dict[str, str] = {}
    for stix_id, technique in techniques.items():
        if not technique.get("revoked"):
            continue
        current = stix_id
        for _ in range(MAX_HOPS):
            if current not in replaced_by:
                break
            current = replaced_by[current]
        target = techniques.get(current)
        if target is None or target.get("revoked") or target.get("x_mitre_deprecated"):
            continue
        old, new = _attack_id(technique), _attack_id(target)
        if old and new and old != new:
            mapping[old] = new
    return mapping


def _observable_kinds(objects: list[dict]) -> dict[str, set[str]]:
    """`{technique stix id: event kinds}` via detects -> analytics -> components."""
    by_id = {o["id"]: o for o in objects}
    kinds: dict[str, set[str]] = {}
    for rel in objects:
        if rel["type"] != "relationship" or rel.get("relationship_type") != "detects":
            continue
        if rel.get("revoked") or rel.get("x_mitre_deprecated"):
            continue
        strategy = by_id.get(rel["source_ref"], {})
        for analytic_ref in strategy.get("x_mitre_analytic_refs", []):
            analytic = by_id.get(analytic_ref, {})
            if "Windows" not in analytic.get("x_mitre_platforms", []):
                continue
            for source in analytic.get("x_mitre_log_source_references", []):
                component = by_id.get(source.get("x_mitre_data_component_ref"), {})
                kind = COMPONENT_KINDS.get(component.get("name"))
                if kind:
                    kinds.setdefault(rel["target_ref"], set()).add(kind)
    # A parent technique shows in whatever shows any of its sub-techniques:
    # T1003 cited on the dump file T1003.001 writes is not a wrong kind of event.
    for rel in objects:
        if rel["type"] == "relationship" and rel.get("relationship_type") == "subtechnique-of":
            if rel["source_ref"] in kinds:
                kinds.setdefault(rel["target_ref"], set()).update(kinds[rel["source_ref"]])
    return kinds


def _literal(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def render(bundle: dict, commit: str) -> str:
    objects = bundle["objects"]
    kinds = _observable_kinds(objects)
    replaced = revoked_map(bundle)
    lines = [
        "# Generated by scripts/build_attack_ontology.py - do not edit.",
        "# Source: github.com/mitre/cti enterprise-attack/enterprise-attack.json",
        f"# Commit: {commit}",
        "# (c) The MITRE Corporation. Reproduced and distributed with the permission of",
        "# The MITRE Corporation (attack.mitre.org/resources/terms-of-use).",
        "",
        "@prefix wr: <https://warrant.example/ontology#> .",
        "@prefix attack: <https://warrant.example/attack/> .",
        "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .",
        "",
    ]
    techniques = sorted(
        (o for o in objects if o["type"] == "attack-pattern" and _attack_id(o)),
        key=_attack_id,
    )
    seen: set[str] = set()
    for technique in techniques:
        tid = _attack_id(technique)
        if tid in seen:
            continue
        seen.add(tid)
        retired = technique.get("revoked") or technique.get("x_mitre_deprecated")
        parts = [
            f"attack:{tid} a wr:{'RetiredTechnique' if retired else 'Technique'}",
            f"wr:techniqueId {_literal(tid)}",
            f"rdfs:label {_literal(technique['name'])}",
        ]
        if retired:
            if tid in replaced:
                parts.append(f"wr:replacedBy attack:{replaced[tid]}")
        else:
            tactics = sorted(
                p["phase_name"]
                for p in technique.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            )
            if tactics:
                parts.append("wr:tactic " + ", ".join(_literal(t) for t in tactics))
            platforms = sorted(technique.get("x_mitre_platforms", []))
            if platforms:
                parts.append("wr:platform " + ", ".join(_literal(p) for p in platforms))
            observable = sorted(kinds.get(technique["id"], ()))
            if observable:
                parts.append("wr:observableAs " + ", ".join(f"wr:kind_{k}" for k in observable))
        lines.append(" ;\n    ".join(parts) + " .")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="MITRE's enterprise-attack.json")
    parser.add_argument("--commit", required=True, help="mitre/cti commit the bundle was fetched at")
    args = parser.parse_args()

    text = render(json.loads(args.bundle.read_text(encoding="utf-8")), args.commit)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {text.count(' a wr:Technique')} techniques and "
          f"{text.count(' a wr:RetiredTechnique')} retired ids to {OUTPUT}")


if __name__ == "__main__":
    main()
