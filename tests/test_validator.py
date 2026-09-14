"""The ontology and its validator.

No model is involved: an answer with one known fault goes in, and exactly that
fault must come out.
"""
from __future__ import annotations


import pytest

from backend.guardrail.answer import Answer
from backend.guardrail.ontology import allowed_triples, observable_kinds, replacement_for, rule_messages
from backend.guardrail.validator import validate

PS = "{g-1}"
EVENTS = [
    {"ref": "e1", "event_type": "process", "process_guid": PS, "parent_process_guid": "{g-0}",
     "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "actor_user": "LAB\\victim"},
    {"ref": "e2", "event_type": "network", "process_guid": PS, "dest_ip": "10.0.0.5", "dest_port": 8080},
    {"ref": "e3", "event_type": "file", "process_guid": PS, "target_object": "C:\\Temp\\payload.dat"},
    {"ref": "e4", "event_type": "registry", "process_guid": PS, "target_object": "HKU\\Run\\x"},
]


def claim(subject_type, subject, relation, object_type, obj, event) -> dict:
    return {"subject_type": subject_type, "subject": subject, "relation": relation,
            "object_type": object_type, "object": obj, "event": event}


def answer(verdict="MALICIOUS", techniques=(("T1059.001", ["e1"]),), claims=()) -> Answer:
    return Answer(
        verdict=verdict,
        confidence=0.9,
        techniques=[{"id": t, "events": e} for t, e in techniques],
        claims=list(claims),
        summary="s",
    )


def found(a: Answer) -> list[tuple[str, str]]:
    return [(v.path, v.code) for v in validate(a, EVENTS)]


# --- the ontology ------------------------------------------------------------ #


def test_ontology_allows_eight_relations():
    assert set(allowed_triples()) == {
        ("Process", "spawned", "Process"),
        ("Process", "authenticated_as", "User"),
        ("Process", "connected_to", "Network"),
        ("Process", "wrote", "File"),
        ("Process", "read", "File"),
        ("File", "dropped_by", "Process"),
        ("Process", "modified", "RegistryKey"),
        ("Process", "exhibits", "Technique"),
    }


def test_attack_techniques_are_loaded_from_mitre_data():
    assert replacement_for("T1060") == "T1547.001"   # revoked, with a successor
    assert replacement_for("T1059.001") is None       # in use
    assert observable_kinds("T1105") == ("file", "network", "process")
    assert observable_kinds("T9999") == ()
    # A parent shows in whatever shows a sub-technique: T1003's own analytics
    # read process events only, T1003.001's also read the dump file.
    assert "file" in observable_kinds("T1003")
    assert found(answer(techniques=[("T1003", ["e3"])])) == []


# --- the validator: a conforming answer --------------------------------------- #


def test_a_conforming_answer_has_no_violations():
    a = answer(
        techniques=[("T1059.001", ["e1"]), ("T1105", ["e2", "e3"])],
        claims=[
            claim("Process", "{g-0}", "spawned", "Process", PS, "e1"),
            claim("Process", "powershell.exe", "authenticated_as", "User", "lab\\VICTIM", "e1"),
            claim("Process", PS.upper(), "connected_to", "Network", "10.0.0.5:8080", "e2"),
            claim("Process", PS, "wrote", "File", "c:\\temp\\payload.dat", "e3"),
            claim("File", "C:\\Temp\\payload.dat", "dropped_by", "Process", PS, "e3"),
            claim("Process", PS, "modified", "RegistryKey", "HKU\\Run\\x", "e4"),
            claim("Process", PS, "exhibits", "Technique", "T1105", "e2"),
        ],
    )

    assert validate(a, EVENTS) == []
    assert found(answer(verdict="BENIGN", techniques=[])) == []
    assert found(answer(verdict="SUSPICIOUS", techniques=[])) == []


def test_any_event_shows_the_process_that_logged_it():
    """T1059.001 shows in process events. A network event logged by
    powershell.exe is evidence of it too: the first live run flagged exactly
    this and a repair then removed a correct technique."""
    assert observable_kinds("T1059.001") == ("process",)
    assert found(answer(techniques=[("T1059.001", ["e2"])])) == []


def test_a_claim_may_name_the_key_or_folder_the_target_is_in():
    events = [{"ref": "e1", "event_type": "registry", "process_guid": PS,
               "target_object": r"HKLM\System\CurrentControlSet\Services\Fax\ImagePath"}]

    def check(key):
        a = answer(techniques=[], verdict="SUSPICIOUS",
                   claims=[claim("Process", PS, "modified", "RegistryKey", key, "e1")])
        return [v.code for v in validate(a, events)]

    assert check(r"HKLM\System\CurrentControlSet\Services\Fax") == []
    assert check(r"hklm\system\currentcontrolset") == []
    assert check(r"HKLM\System") == ["value_not_in_event"]              # too short to mean anything
    assert check(r"HKLM\System\CurrentControlSet\Serv") == ["value_not_in_event"]  # not a whole key
    assert check(r"HKLM\System\CurrentControlSet\Services\Fax\Start") == ["value_not_in_event"]


# --- the validator: one fault in, that fault out ------------------------------ #


@pytest.mark.parametrize(
    "faulty, expected",
    [
        (answer(techniques=[("T9999", ["e1"])]), [("techniques[0]", "technique_unknown")]),
        (answer(techniques=[("PowerShell", ["e1"])]), [("techniques[0]", "technique_unknown")]),
        (answer(techniques=[("T1060", ["e4"])]), [("techniques[0]", "technique_retired")]),
        (answer(techniques=[("T1105", [])]), [("techniques[0]", "technique_uncited")]),
        (answer(techniques=[("T1105", ["e9"])]), [("techniques[0]", "event_missing")]),
        # T1071.001 (web protocols) shows in network events only; e3 is a file event.
        (answer(techniques=[("T1071.001", ["e3"])]), [("techniques[0]", "technique_evidence_kind")]),
        (
            answer(claims=[claim("Process", PS, "wrote", "File", "C:\\Temp\\payload.dat", "e77")]),
            [("claims[0]", "event_missing")],
        ),
        (
            answer(claims=[claim("Malware", PS, "wrote", "File", "C:\\Temp\\payload.dat", "e3")]),
            [("claims[0]", "type_unknown")],
        ),
        (
            answer(claims=[claim("Process", PS, "befriended", "File", "C:\\Temp\\payload.dat", "e3")]),
            [("claims[0]", "relation_unknown")],
        ),
        (
            answer(claims=[claim("File", "C:\\Temp\\payload.dat", "wrote", "Process", PS, "e3")]),
            [("claims[0]", "triple_not_allowed")],
        ),
        (
            answer(claims=[claim("Process", PS, "wrote", "File", "10.0.0.5", "e2")]),
            [("claims[0]", "claim_evidence_kind")],
        ),
        (
            answer(claims=[claim("Process", PS, "wrote", "File", "C:\\Temp\\other.dat", "e3")]),
            [("claims[0]", "value_not_in_event")],
        ),
        (
            answer(claims=[claim("Process", "{g-9}", "wrote", "File", "C:\\Temp\\payload.dat", "e3")]),
            [("claims[0]", "value_not_in_event")],
        ),
        (
            answer(claims=[claim("Process", PS, "exhibits", "Technique", "T1060", "e1")]),
            [("claims[0]", "claim_technique_unknown")],
        ),
        (answer(techniques=[]), [("verdict", "verdict_malicious_without_technique")]),
        (answer(verdict="BENIGN"), [("verdict", "verdict_benign_with_technique")]),
    ],
)
def test_each_fault_is_reported_as_exactly_that_fault(faulty, expected):
    assert found(faulty) == expected


def test_every_rule_in_the_shapes_file_is_exercised_above():
    exercised = {
        "technique_unknown", "technique_retired", "technique_uncited", "technique_evidence_kind",
        "event_missing", "type_unknown", "relation_unknown", "triple_not_allowed",
        "claim_evidence_kind", "value_not_in_event", "claim_technique_unknown",
        "verdict_malicious_without_technique", "verdict_benign_with_technique",
    }
    assert set(rule_messages()) == exercised


def test_violations_come_in_answer_order_and_name_no_value_from_the_answer():
    a = answer(
        techniques=[("T1059.001", ["e1"]), ("T1060", ["e4"])],
        claims=[claim("Process", "INJECTED-SUBJECT", "wrote", "File", "INJECTED-OBJECT", "e3")],
    )

    violations = validate(a, EVENTS)

    assert [(v.path, v.code) for v in violations] == [
        ("techniques[1]", "technique_retired"),
        ("claims[0]", "value_not_in_event"),
    ]
    # The one id a message names is the ontology's (the successor), not the model's.
    assert violations[0].message == "this ATT&CK id is no longer in use (the id in use is T1547.001)"
    assert not any("INJECTED" in v.message or "T1060" in v.message for v in violations)
