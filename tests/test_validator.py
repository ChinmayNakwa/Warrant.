"""The ontology and its validator.

No model is involved: an answer with one known fault goes in, and exactly that
fault must come out.
"""
from __future__ import annotations


import pytest

from backend.guardrail.answer import Answer
from backend.guardrail.ontology import (
    WR,
    allowed_triples,
    indicators,
    observable_kinds,
    ontology_graph,
    platforms,
    replacement_for,
    rule_messages,
)
from backend.guardrail.validator import validate

PS = "{g-1}"
EVENTS = [
    {"ref": "e1", "event_type": "process", "process_guid": PS, "parent_process_guid": "{g-0}",
     "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "actor_user": "LAB\\victim"},
    {"ref": "e2", "event_type": "network", "process_guid": PS, "dest_ip": "10.0.0.5", "dest_port": 8080,
     "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
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


def test_ontology_allows_twelve_relations():
    assert set(allowed_triples()) == {
        ("Process", "spawned", "Process"),
        ("Process", "accessed", "Process"),
        ("Process", "injected_into", "Process"),
        ("Process", "loaded", "File"),
        ("Process", "resolved", "Network"),
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


def test_techniques_carry_their_platforms_and_some_carry_indicators():
    assert platforms("T1003.001") == ("Windows",)
    assert "Windows" not in platforms("T1059.004")   # Unix Shell
    assert "lsass" in indicators("T1003.001")
    assert indicators("T1105") == ()                  # no signature of its own
    assert indicators("T1003") == ()                  # a parent is not checked


def test_every_indicator_is_for_a_windows_technique_in_use_and_is_lower_case():
    graph = ontology_graph()
    described = set(graph.subjects(WR.indicator, None))
    assert len(described) > 30
    for node in described:
        technique_id = str(graph.value(node, WR.techniqueId))
        assert "Windows" in platforms(technique_id), f"{node} is not a Windows technique in use"
        # Event text is lower-cased before it is searched.
        assert all(i == i.lower() and len(i) >= 2 for i in indicators(technique_id)), technique_id


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
    assert "network" not in observable_kinds("T1059.001")
    assert found(answer(techniques=[("T1059.001", ["e2"])])) == []


def test_an_indicator_is_found_in_any_cited_event_whatever_its_case_or_slashes():
    events = [
        {"ref": "e1", "event_type": "process", "process_guid": PS, "image": "C:\\Windows\\System32\\esentutl.exe",
         "command_line": "esentutl.exe /y /vss C:\\windows/system32/config/SAM /d C:\\ProgramData\\SAM"},
        {"ref": "e2", "event_type": "file", "process_guid": PS, "target_object": "C:\\ProgramData\\notes.txt"},
    ]

    def check(technique, cited):
        return [v.code for v in validate(answer(techniques=[(technique, cited)]), events)]

    assert check("T1003.002", ["e1"]) == []
    assert check("T1003.002", ["e2", "e1"]) == []   # one cited event showing it is enough
    assert check("T1003.002", ["e2"]) == ["technique_indicator"]
    # A technique indicators.ttl does not describe is not checked this way.
    assert check("T1105", ["e2"]) == []


def test_the_message_says_what_the_ontology_expected_and_nothing_from_the_answer():
    faulty = answer(techniques=[("T1059.004", ["e1"]), ("T1037.001", ["e3"])])

    messages = {v.code: v.message for v in validate(faulty, EVENTS)}

    assert messages["technique_platform"].endswith("(it is listed for ESXi, Linux, Network Devices, macOS)")
    assert messages["technique_indicator"].endswith("(one would contain any of: userinitmprlogonscript)")


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


def test_claims_about_a_second_process_a_dll_or_a_lookup():
    dumper, lsass = "C:\\Temp\\dump.exe", "C:\\Windows\\System32\\lsass.exe"
    events = [
        {"ref": "e1", "event_type": "access", "process_guid": PS, "image": dumper,
         "target_object": lsass, "target_process_guid": "{g-7}", "granted_access": "0x1fffff"},
        {"ref": "e2", "event_type": "thread", "process_guid": PS, "image": dumper,
         "target_object": "C:\\Windows\\System32\\notepad.exe", "target_process_guid": "{g-8}"},
        {"ref": "e3", "event_type": "module", "process_guid": PS, "image": dumper,
         "target_object": "C:\\Windows\\System32\\comsvcs.dll"},
        {"ref": "e4", "event_type": "dns", "process_guid": PS, "image": dumper, "target_object": "example.org"},
        {"ref": "e5", "event_type": "file", "process_guid": PS, "image": dumper,
         "target_object": "C:\\Temp\\lsass.dmp"},
    ]

    def check(*claims, techniques=(("T1003.001", ["e1"]),)):
        return [v.code for v in validate(answer(techniques=techniques, claims=claims), events)]

    # The process opened is named by its GUID, its path or its file name.
    assert check(
        claim("Process", PS, "accessed", "Process", "{g-7}", "e1"),
        claim("Process", "dump.exe", "accessed", "Process", "LSASS.EXE", "e1"),
        claim("Process", PS, "accessed", "Process", lsass, "e1"),
        claim("Process", PS, "injected_into", "Process", "{g-8}", "e2"),
        claim("Process", PS, "loaded", "File", "comsvcs.dll", "e3"),
        claim("Process", PS, "resolved", "Network", "example.org", "e4"),
    ) == []
    # T1055 shows in thread events; no technique is tied to a lookup.
    assert check(techniques=[("T1055", ["e2"])]) == []
    assert "thread" in observable_kinds("T1055") and "dns" not in observable_kinds("T1055")

    # e5 is the dump file being written: it does not show a process being opened.
    assert check(claim("Process", PS, "accessed", "Process", "C:\Temp\lsass.dmp", "e5")) == ["claim_evidence_kind"]
    assert check(claim("Process", PS, "accessed", "Process", "{g-8}", "e1")) == ["value_not_in_event"]
    # A file written is still named in full.
    assert check(claim("Process", PS, "wrote", "File", "lsass.dmp", "e5")) == ["value_not_in_event"]


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
        # T1059.004 is Unix Shell: ATT&CK does not list it for Windows.
        (answer(techniques=[("T1059.004", ["e1"])]), [("techniques[0]", "technique_platform")]),
        # T1003.001 is LSASS memory; e3 writes payload.dat and names nothing of the kind.
        (answer(techniques=[("T1003.001", ["e3"])]), [("techniques[0]", "technique_indicator")]),
        (
            answer(claims=[claim("Process", PS, "exhibits", "Technique", "T1218.005", "e1")]),
            [("claims[0]", "technique_indicator")],
        ),
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
        "technique_platform", "technique_indicator",
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
