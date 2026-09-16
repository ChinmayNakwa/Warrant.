"""Checks a model's answer against the ontology. No database, no model.

The answer and the events it was read from become a small RDF graph, the SHACL
shapes in `ontology/shapes.ttl` are run over it, and each result comes back as
a `Violation`.

Model text and telemetry enter the graph only as literals. A `Violation` holds
a rule's name, the path of the item at fault and fixed text, never a value
from the answer or the telemetry, so it is safe to store and to show a model.
"""
from __future__ import annotations

import ntpath
from dataclasses import asdict, dataclass
from typing import Any

from pyshacl import validate as shacl_validate
from rdflib import RDF, Graph, Literal, URIRef
from rdflib.namespace import SH

from backend.guardrail.answer import Answer
from backend.guardrail.ontology import (
    WR,
    WRS,
    indicators,
    observable_kinds,
    ontology_graph,
    platforms,
    replacement_for,
    rule_messages,
    shapes_graph,
)

VERDICT_PATH = "verdict"
_NODE = "urn:warrant:answer:"
# The shortest path prefix a claim may name in place of the full target:
# HKLM\System\CurrentControlSet, not HKLM alone.
_MIN_PATH_DEPTH = 3
_EVENT_KINDS = {
    "process": WR.kind_process,
    "network": WR.kind_network,
    "file": WR.kind_file,
    "registry": WR.kind_registry,
}


@dataclass(frozen=True)
class Violation:
    code: str     # a shape's name in shapes.ttl
    path: str     # "techniques[0]" | "claims[2]" | "verdict"
    message: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _key(value: Any) -> Literal:
    """Values are compared ignoring case and surrounding space."""
    return Literal(str(value).strip().lower())


def _event_values(event: dict[str, Any]) -> set[str]:
    """Everything in an event that a claim may name as its subject or object."""
    values = {
        event.get(field)
        for field in ("process_guid", "parent_process_guid", "image", "actor_user", "dest_ip", "target_object")
    }
    if event.get("image"):
        values.add(ntpath.basename(event["image"]))
    if event.get("dest_ip") and event.get("dest_port") is not None:
        values.add(f"{event['dest_ip']}:{event['dest_port']}")
    # A claim may name the key or folder the target is in: an event that sets
    # ...\Services\Fax\ImagePath shows that ...\Services\Fax was modified.
    parts = (event.get("target_object") or "").split("\\")
    for depth in range(_MIN_PATH_DEPTH, len(parts)):
        values.add("\\".join(parts[:depth]))
    return {str(v) for v in values if v}


def _event_texts(event: dict[str, Any]) -> set[str]:
    """The text a technique's indicators are looked for in."""
    texts = {event.get(field) for field in ("image", "command_line", "target_object")}
    if event.get("dest_ip") and event.get("dest_port") is not None:
        texts.add(f"{event['dest_ip']}:{event['dest_port']}")
    lowered = {str(t).lower() for t in texts if t}
    # Windows takes either slash in a path: config/SAM is config\SAM.
    return lowered | {t.replace("/", "\\") for t in lowered}


def _data_graph(answer: Answer, events: list[dict[str, Any]]) -> tuple[Graph, dict[URIRef, str]]:
    # The ontology is copied in so the shapes' SPARQL queries can read it.
    graph = Graph()
    for triple in ontology_graph():
        graph.add(triple)
    paths: dict[URIRef, str] = {}

    def node(path: str) -> URIRef:
        ref = URIRef(_NODE + path)
        paths[ref] = path
        return ref

    for i, event in enumerate(events):
        e = URIRef(f"{_NODE}event:{i}")
        graph.add((e, RDF.type, WR.Event))
        graph.add((e, WR.ref, Literal(event["ref"])))
        kind = _EVENT_KINDS.get(event.get("event_type"))
        if kind is not None:
            graph.add((e, WR.kind, kind))
            graph.add((e, WR.showsKind, kind))
        # Whatever kind it is, an event also shows the process that logged it
        # running: a file written by powershell.exe is evidence of PowerShell.
        if event.get("process_guid") or event.get("image"):
            graph.add((e, WR.showsKind, WR.kind_process))
        for value in _event_values(event):
            graph.add((e, WR.value, _key(value)))
        for text in _event_texts(event):
            graph.add((e, WR.text, Literal(text)))

    a = node(VERDICT_PATH)
    graph.add((a, RDF.type, WR.Answer))
    graph.add((a, WR.verdict, Literal(answer.verdict)))

    for i, technique in enumerate(answer.techniques):
        t = node(f"techniques[{i}]")
        graph.add((t, RDF.type, WR.TechniqueClaim))
        graph.add((t, WR.techniqueId, Literal(technique.id)))
        for ref in technique.events:
            graph.add((t, WR.citesRef, Literal(ref)))

    for i, claim in enumerate(answer.claims):
        c = node(f"claims[{i}]")
        graph.add((c, RDF.type, WR.Claim))
        graph.add((c, WR.subjectType, Literal(claim.subject_type)))
        graph.add((c, WR.relationName, Literal(claim.relation)))
        graph.add((c, WR.objectType, Literal(claim.object_type)))
        graph.add((c, WR.citesRef, Literal(claim.event)))
        graph.add((c, WR.subjectKey, _key(claim.subject)))
        if claim.object_type == "Technique":
            graph.add((c, WR.objectTechniqueId, Literal(claim.object.strip())))
        else:
            graph.add((c, WR.objectKey, _key(claim.object)))
    return graph, paths


def _detail(code: str, answer: Answer, path: str) -> str:
    """What the ontology knows about the technique id at fault, added to the
    rule's message."""
    if path == VERDICT_PATH:
        return ""
    group, index = path[:-1].split("[")
    if group == "techniques":
        technique_id = answer.techniques[int(index)].id
    else:
        technique_id = answer.claims[int(index)].object.strip()
    if code == "technique_retired" and (current := replacement_for(technique_id)):
        return f" (the id in use is {current})"
    if code == "technique_evidence_kind" and (kinds := observable_kinds(technique_id)):
        return f" (it shows in {', '.join(kinds)} events)"
    if code == "technique_platform" and (listed := platforms(technique_id)):
        return f" (it is listed for {', '.join(listed)})"
    if code == "technique_indicator" and (wanted := indicators(technique_id)):
        return f" (one would contain any of: {', '.join(wanted)})"
    return ""


def _order(path: str) -> tuple[int, int]:
    if path == VERDICT_PATH:
        return (0, 0)
    group, index = path[:-1].split("[")
    return (1 if group == "techniques" else 2, int(index))


def validate(answer: Answer, events: list[dict[str, Any]]) -> list[Violation]:
    """Every rule the answer breaks, in answer order; `[]` when it conforms."""
    data, paths = _data_graph(answer, events)
    _conforms, results, _text = shacl_validate(
        data, shacl_graph=shapes_graph(), inference="none"
    )
    messages = rule_messages()
    found: set[tuple[str, str]] = set()
    for result in results.subjects(RDF.type, SH.ValidationResult):
        code = str(results.value(result, SH.sourceShape)).removeprefix(str(WRS))
        found.add((paths[results.value(result, SH.focusNode)], code))
    return [
        Violation(code, path, messages[code] + _detail(code, answer, path))
        for path, code in sorted(found, key=lambda pc: (_order(pc[0]), pc[1]))
    ]
