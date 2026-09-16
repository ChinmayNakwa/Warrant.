"""Loads the ontology: `schema.ttl` (entity types and relations), `attack.ttl`
(ATT&CK techniques, generated), `indicators.ttl` (what a technique looks like
in telemetry) and `shapes.ttl` (the rules an answer must meet).

The files are parsed once per process.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from rdflib import RDF, RDFS, Graph, Literal, Namespace
from rdflib.namespace import SH

_DIR = Path(__file__).resolve().parent

WR = Namespace("https://warrant.example/ontology#")
WRS = Namespace("https://warrant.example/shapes#")


@lru_cache
def ontology_graph() -> Graph:
    graph = Graph()
    graph.parse(_DIR / "schema.ttl", format="turtle")
    graph.parse(_DIR / "attack.ttl", format="turtle")
    graph.parse(_DIR / "indicators.ttl", format="turtle")
    return graph


@lru_cache
def shapes_graph() -> Graph:
    graph = Graph()
    graph.parse(_DIR / "shapes.ttl", format="turtle")
    return graph


def _name(graph: Graph, node) -> str:
    return str(graph.value(node, WR.name))


@lru_cache
def allowed_triples() -> tuple[tuple[str, str, str], ...]:
    """(subject type, relation, object type), by the names a model writes."""
    graph = ontology_graph()
    return tuple(
        sorted(
            (
                _name(graph, graph.value(relation, RDFS.domain)),
                _name(graph, relation),
                _name(graph, graph.value(relation, RDFS.range)),
            )
            for relation in graph.subjects(RDF.type, WR.Relation)
        )
    )


@lru_cache
def rule_messages() -> dict[str, str]:
    """`{violation code: fixed message}` - every shape's name and sh:message."""
    graph = shapes_graph()
    return {
        str(shape).removeprefix(str(WRS)): str(graph.value(shape, SH.message))
        for shape in graph.subjects(RDF.type, SH.NodeShape)
    }


@lru_cache
def _techniques() -> dict[str, tuple[str | None, tuple[str, ...]]]:
    """`{id: (replacement id if retired, event kinds that can show it)}`."""
    graph = ontology_graph()
    out = {}
    for cls in (WR.Technique, WR.RetiredTechnique):
        for node in graph.subjects(RDF.type, cls):
            replacement = graph.value(node, WR.replacedBy)
            out[str(graph.value(node, WR.techniqueId))] = (
                str(graph.value(replacement, WR.techniqueId)) if replacement is not None else None,
                tuple(sorted(_name(graph, kind) for kind in graph.objects(node, WR.observableAs))),
            )
    return out


def replacement_for(technique_id: str) -> str | None:
    """The id in use that replaced a retired one, if ATT&CK names one."""
    return _techniques().get(technique_id, (None, ()))[0]


def observable_kinds(technique_id: str) -> tuple[str, ...]:
    return _techniques().get(technique_id, (None, ()))[1]


def _literals(technique_id: str, prop) -> tuple[str, ...]:
    graph = ontology_graph()
    return tuple(
        sorted(
            str(value)
            for node in graph.subjects(WR.techniqueId, Literal(technique_id))
            for value in graph.objects(node, prop)
        )
    )


@lru_cache
def platforms(technique_id: str) -> tuple[str, ...]:
    """The platforms ATT&CK lists the technique for."""
    return _literals(technique_id, WR.platform)


@lru_cache
def indicators(technique_id: str) -> tuple[str, ...]:
    """The text one of the technique's cited events must contain; `()` if the
    technique is not checked this way."""
    return _literals(technique_id, WR.indicator)
