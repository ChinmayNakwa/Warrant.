"""Baseline mode: slice -> model reads it -> answer stored as given."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select

from backend.app import app
from backend.database import SessionLocal
from backend.llm import ModelError
from backend.models import Incident
from backend.telemetry.ingest import ingest_capture
from backend.guardrail.analyst import run_analysis
from backend.guardrail.answer import AnswerError, parse_answer
from backend.models import GuardrailRun
from backend.guardrail.routes import get_model_selector
from backend.guardrail.slicer import build_slice
from tests.conftest import auth, make_capture, make_incident

CAPTURE_DIR = Path(__file__).resolve().parents[1] / "data" / "captures" / "small_lab"

CHAIN = "{00000000-0000-0000-0000-000000000201}"
CHAIN_CHILD = "{00000000-0000-0000-0000-000000000202}"
CRED = "{00000000-0000-0000-0000-000000000301}"


@pytest.fixture
def lab() -> str:
    with SessionLocal() as db:
        cap = ingest_capture(
            db, name="small_lab", host="WIN11-LAB",
            events_path=CAPTURE_DIR / "events.jsonl", synthetic=True,
        )
        db.commit()
        return cap.id


@pytest.fixture
def user_id(user_factory) -> str:
    return user_factory("guard-a@example.com")["id"]


def _incident(user_id, capture_id, anchor=CHAIN, **kw) -> str:
    with SessionLocal() as db:
        inc = make_incident(db, user_id, capture_id=capture_id, anchor_process_guid=anchor, **kw)
        db.commit()
        return inc.id


def _slice(capture_id, anchor, max_events=120, window_seconds=120):
    with SessionLocal() as db:
        return build_slice(
            db, capture_id, anchor, max_events=max_events, window_seconds=window_seconds
        )


def _answer(verdict="MALICIOUS", techniques=(("T1059.001", ["e1"]),), claims=None, **kw) -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": 0.9,
            "techniques": [{"id": t, "events": e} for t, e in techniques],
            "claims": claims
            if claims is not None
            else [
                {"subject_type": "Process", "subject": CHAIN, "relation": "spawned",
                 "object_type": "Process", "object": CHAIN_CHILD, "event": "e5"}
            ],
            "summary": "encoded PowerShell",
            **kw,
        }
    )


class FakeModel:
    """A scripted stand-in for the LLM: replays `replies` in order, records prompts.
    A reply that is an exception is raised."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts: list[str] = []

    def __call__(self, system: str, user: str) -> str:
        self.prompts.append(user)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def _run(user_id, incident_id, model) -> GuardrailRun:
    with SessionLocal() as db:
        run = run_analysis(
            db, user_id=user_id, incident_id=incident_id, mode="baseline", complete=model,
            model="test",
        )
        db.commit()
        db.refresh(run)
        db.expunge(run)
        return run


# --- slicer ----------------------------------------------------------------- #


def test_slice_is_the_alerted_process_tree_and_its_activity(lab):
    events = _slice(lab, CHAIN)

    assert {e["process_guid"] for e in events} == {CHAIN, CHAIN_CHILD}
    assert sorted(e["event_type"] for e in events) == [
        "file", "network", "process", "process", "registry",
    ]
    assert [e["ref"] for e in events] == ["e1", "e2", "e3", "e4", "e5"]
    assert [e["ts"] for e in events] == sorted(e["ts"] for e in events)


def test_slice_over_the_cap_keeps_the_alerted_process_first(lab):
    events = _slice(lab, CHAIN, max_events=2)

    assert len(events) == 2
    assert {e["process_guid"] for e in events} == {CHAIN}


def test_slice_fills_spare_room_with_what_else_happened_near_the_alert(lab):
    """small_lab's scenarios are five minutes apart: a 2-minute window (the
    default) adds nothing, a 10-minute one reaches the neighbours."""
    assert len(_slice(lab, CHAIN, window_seconds=120)) == 5

    wide = _slice(lab, CHAIN, window_seconds=600)
    assert len(wide) == 12  # everything but the 10:20 process, 15 minutes away
    assert CRED in {e["process_guid"] for e in wide}

    # Over the cap the tree comes first, then the nearest in time: 10:00:04.
    capped = _slice(lab, CHAIN, max_events=6, window_seconds=600)
    outside_tree = [e for e in capped if e["process_guid"] not in (CHAIN, CHAIN_CHILD)]
    assert [e["ts"][11:19] for e in outside_tree] == ["10:00:04"]


def test_slice_without_a_usable_anchor_is_the_rarest_events(lab):
    unanchored = _slice(lab, None)
    unknown = _slice(lab, "{00000000-0000-0000-0000-00000000dead}")

    assert len(unanchored) == 13
    assert [e["id"] for e in unknown] == [e["id"] for e in unanchored]


# --- answer parsing ---------------------------------------------------------- #


def test_parse_answer_is_structural_only():
    """An unreal technique id, an unknown relation and a ref that cites nothing
    all parse: recording them is the point of baseline mode."""
    answer = parse_answer(
        "Here you go:\n```json\n"
        + _answer(
            techniques=[("T9999", ["e404"])],
            claims=[{"subject_type": "File", "subject": "a", "relation": "befriended",
                     "object_type": "User", "object": "b", "event": "e404"}],
        )
        + "\n```"
    )

    assert answer.techniques[0].id == "T9999"
    assert answer.claims[0].relation == "befriended"


@pytest.mark.parametrize(
    "text, reason",
    [
        ("no json here", "no JSON object"),
        ("{not json}", "invalid JSON"),
        (_answer(verdict="UNSURE"), "verdict: literal_error"),
        (_answer(extra_field=1), "<unknown field>: extra_forbidden"),
    ],
)
def test_parse_answer_rejects_with_a_value_free_reason(text, reason):
    with pytest.raises(AnswerError) as exc:
        parse_answer(text)
    assert exc.value.reason == reason


# --- a run ------------------------------------------------------------------- #


def test_baseline_run_stores_the_models_answer_as_given(lab, user_id):
    model = FakeModel(_answer(techniques=[("T1059.001", ["e1"]), ("T9999", ["e404"])]))

    run = _run(user_id, _incident(user_id, lab), model)

    assert (run.mode, run.status, run.verdict, run.confidence) == ("baseline", "completed", "MALICIOUS", 0.9)
    assert json.loads(run.techniques_json) == ["T1059.001", "T9999"]
    assert json.loads(run.answer_json)["claims"][0]["relation"] == "spawned"
    assert [e["ref"] for e in json.loads(run.slice_json)] == ["e1", "e2", "e3", "e4", "e5"]
    assert (run.llm_calls, run.note) == (1, None)
    # The check is recorded, and changes nothing in a baseline answer.
    assert [(v["path"], v["code"]) for v in json.loads(run.violations_json)] == [
        ("techniques[1]", "event_missing"),
        ("techniques[1]", "technique_unknown"),
    ]
    assert run.answer_json == run.first_answer_json
    assert (run.repair_rounds, json.loads(run.dropped_json)) == (0, [])


def test_a_completed_run_sets_the_incidents_verdict(lab, user_id):
    incident_id = _incident(user_id, lab)

    _run(user_id, incident_id, FakeModel(_answer()))

    with SessionLocal() as db:
        incident = db.get(Incident, incident_id)
        assert (incident.verdict, incident.confidence) == ("MALICIOUS", 0.9)


def test_a_failed_run_leaves_the_incidents_verdict_alone(lab, user_id):
    incident_id = _incident(user_id, lab)

    _run(user_id, incident_id, FakeModel("nope", "still nope"))

    with SessionLocal() as db:
        assert db.get(Incident, incident_id).verdict is None


def test_telemetry_reaches_the_model_only_inside_the_fence(lab, user_id):
    model = FakeModel(_answer())

    _run(user_id, _incident(user_id, lab, title="Alert"), model)

    prompt = model.prompts[0]
    opening = prompt.index("<<<UNTRUSTED_DATA id=")
    closing = prompt.index("<<<END_UNTRUSTED_DATA id=")
    assert opening < prompt.index("payload.dat") < closing
    assert opening < prompt.index('"ref": "e1"') < closing
    assert prompt.count("payload.dat") == 1
    # Event uuids are not shown; the model cites refs.
    with SessionLocal() as db:
        run = db.scalar(select(GuardrailRun))
        assert all(e["id"] not in prompt for e in json.loads(run.slice_json))


def test_fence_nonce_in_telemetry_cannot_close_the_fence(lab, user_id, monkeypatch):
    monkeypatch.setattr("backend.guardrail.analyst.secrets.token_hex", lambda _n: "payload.dat")
    model = FakeModel(_answer())

    _run(user_id, _incident(user_id, lab), model)

    assert model.prompts[0].count("payload.dat") == 2  # the two markers only
    assert "[fence-id]" in model.prompts[0]


def test_invalid_reply_is_retried_once_with_the_reason(lab, user_id):
    model = FakeModel("I think it is malicious.", _answer())

    run = _run(user_id, _incident(user_id, lab), model)

    assert (run.status, run.verdict, run.llm_calls) == ("completed", "MALICIOUS", 2)
    assert "Your last reply was not valid: no JSON object." in model.prompts[1]
    assert "I think it is malicious" not in model.prompts[1]


def test_two_invalid_replies_fail_the_run_without_a_verdict(lab, user_id):
    run = _run(user_id, _incident(user_id, lab), FakeModel("nope", "still nope"))

    assert (run.status, run.verdict, run.answer_json, run.llm_calls) == ("failed", None, None, 2)
    assert run.note == "model failed: model reply is not a valid answer (no JSON object)"


@pytest.mark.parametrize(
    "error, note",
    [
        (ModelError("could not reach Ollama - is it running?"),
         "model failed: could not reach Ollama - is it running?"),
        # An unexpected error's text is not stored or returned.
        (RuntimeError("secret internal detail"), "model failed: RuntimeError"),
    ],
)
def test_model_failure_ends_the_run_with_a_safe_note(lab, user_id, error, note):
    run = _run(user_id, _incident(user_id, lab), FakeModel(error))

    assert (run.status, run.verdict, run.llm_calls, run.note) == ("failed", None, 1, note)


def test_no_telemetry_is_insufficient_evidence_without_asking_the_model(user_id):
    with SessionLocal() as db:
        empty = make_capture(db, "empty_capture").id
        db.commit()
    model = FakeModel()

    run = _run(user_id, _incident(user_id, empty), model)

    assert (run.status, run.verdict, run.llm_calls) == ("completed", "INSUFFICIENT_EVIDENCE", 0)
    assert model.prompts == []


# --- API --------------------------------------------------------------------- #


@pytest.fixture
def scripted():
    """Routes a scripted model into the API for one test."""

    def use(*replies) -> FakeModel:
        model = FakeModel(*replies)
        app.dependency_overrides[get_model_selector] = lambda: lambda: (model, "test")
        return model

    yield use
    app.dependency_overrides.pop(get_model_selector, None)


def _auth(user) -> dict:
    return auth(user["access_token"])


def test_api_run_list_and_get(client, user_factory, lab, scripted):
    user = user_factory("guard-api@example.com")
    incident_id = _incident(user["id"], lab)
    scripted(_answer())

    created = client.post(f"/api/incidents/{incident_id}/guardrail-runs", headers=_auth(user))

    assert created.status_code == 201, created.text
    body = created.json()
    assert (body["mode"], body["verdict"], body["techniques"]) == ("baseline", "MALICIOUS", ["T1059.001"])
    assert body["answer"]["claims"][0]["event"] == "e5"
    assert len(body["events"]) == 5
    assert body["started_at"].endswith("Z") and body["finished_at"].endswith("Z")
    listed = client.get(f"/api/incidents/{incident_id}/guardrail-runs", headers=_auth(user)).json()
    assert [r["id"] for r in listed] == [body["id"]]
    assert client.get(f"/api/guardrail-runs/{body['id']}", headers=_auth(user)).json() == body


def test_api_requires_auth(client):
    assert client.post("/api/incidents/x/guardrail-runs").status_code == 401
    assert client.get("/api/incidents/x/guardrail-runs").status_code == 401
    assert client.get("/api/guardrail-runs/x").status_code == 401


def test_api_another_users_incident_and_run_are_404(client, user_factory, lab, scripted):
    """Someone else's and missing look the same."""
    owner, other = user_factory("guard-own@example.com"), user_factory("guard-other@example.com")
    incident_id = _incident(owner["id"], lab)
    model = scripted(_answer())
    run_id = client.post(
        f"/api/incidents/{incident_id}/guardrail-runs", headers=_auth(owner)
    ).json()["id"]

    for incident in (incident_id, "missing"):
        post = client.post(f"/api/incidents/{incident}/guardrail-runs", headers=_auth(other))
        got = client.get(f"/api/incidents/{incident}/guardrail-runs", headers=_auth(other))
        assert (post.status_code, got.status_code) == (404, 404)
        assert post.json() == got.json() == {"detail": "Incident not found."}
    for run in (run_id, "missing"):
        r = client.get(f"/api/guardrail-runs/{run}", headers=_auth(other))
        assert (r.status_code, r.json()) == (404, {"detail": "Run not found."})
    assert len(model.prompts) == 1  # the other user's attempts never reached the model


def test_api_without_a_model_is_503(client, user_factory, lab):
    """The tests' settings name no model (conftest)."""
    user = user_factory("guard-nomodel@example.com")
    incident_id = _incident(user["id"], lab)

    r = client.post(f"/api/incidents/{incident_id}/guardrail-runs", headers=_auth(user))

    assert r.status_code == 503
    assert "No model is configured" in r.json()["detail"]


def test_api_rejects_an_unknown_mode(client, user_factory, lab, scripted):
    user = user_factory("guard-mode@example.com")
    incident_id = _incident(user["id"], lab)
    scripted()

    r = client.post(
        f"/api/incidents/{incident_id}/guardrail-runs", headers=_auth(user), json={"mode": "strict"}
    )

    assert r.status_code == 422
