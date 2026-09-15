"""Incident, capture and evaluation routes: auth, ownership, and what they return."""
from __future__ import annotations

import json

from backend.config import get_settings
from backend.database import SessionLocal
from tests.conftest import auth, make_capture, make_incident

PROTECTED_GET_ROUTES = [
    "/api/auth/me",
    "/api/captures",
    "/api/incidents",
    "/api/incidents/does-not-exist",
    "/api/incidents/does-not-exist/guardrail-runs",
    "/api/guardrail-runs/does-not-exist",
    "/api/evaluation/results",
]


def test_every_protected_route_returns_401_without_auth(client):
    for path in PROTECTED_GET_ROUTES:
        r = client.get(path)
        assert r.status_code == 401, path
        assert "Traceback" not in r.text
    assert client.post("/api/incidents", json={}).status_code == 401


def test_captures_are_listed_for_every_user(client, user_factory):
    user = user_factory("captures@example.com")
    with SessionLocal() as db:
        make_capture(db, "lab_b")
        make_capture(db, "lab_a")
        db.commit()

    body = client.get("/api/captures", headers=auth(user["access_token"])).json()

    assert [c["name"] for c in body] == ["lab_a", "lab_b"]


def test_create_list_and_get_an_incident(client, user_factory):
    user = user_factory("incidents@example.com")
    headers = auth(user["access_token"])
    with SessionLocal() as db:
        make_capture(db, "lab")
        db.commit()

    created = client.post(
        "/api/incidents",
        headers=headers,
        json={"title": " Odd PowerShell ", "severity": "high", "capture_name": "lab",
              "anchor_process_guid": ""},
    )

    assert created.status_code == 201, created.text
    body = created.json()
    assert (body["title"], body["severity"], body["status"]) == ("Odd PowerShell", "high", "open")
    assert (body["anchor_process_guid"], body["verdict"]) == (None, None)
    assert client.get("/api/incidents", headers=headers).json() == [body]
    assert client.get(f"/api/incidents/{body['id']}", headers=headers).json() == body


def test_an_incident_needs_a_known_capture(client, user_factory):
    user = user_factory("nocapture@example.com")

    r = client.post(
        "/api/incidents",
        headers=auth(user["access_token"]),
        json={"title": "x", "capture_name": "no_such_capture"},
    )

    assert (r.status_code, r.json()["detail"]) == (422, "Unknown capture.")


def test_another_users_incident_looks_missing(client, user_factory):
    owner, other = user_factory("owner@example.com"), user_factory("other@example.com")
    with SessionLocal() as db:
        incident_id = make_incident(db, owner["id"]).id
        db.commit()
    headers = auth(other["access_token"])

    missing = client.get("/api/incidents/does-not-exist", headers=headers)
    forbidden = client.get(f"/api/incidents/{incident_id}", headers=headers)

    assert missing.status_code == forbidden.status_code == 404
    assert missing.json() == forbidden.json()
    assert client.get("/api/incidents", headers=headers).json() == []


def test_evaluation_results_are_the_files_as_written(client, user_factory, tmp_path, monkeypatch):
    user = user_factory("evaluation@example.com")
    headers = auth(user["access_token"])
    monkeypatch.setattr(get_settings(), "evaluation_dir", str(tmp_path))

    assert client.get("/api/evaluation/results", headers=headers).json() == {"results": []}

    (tmp_path / "results_b.json").write_text(json.dumps({"model": "b"}), encoding="utf-8")
    (tmp_path / "results_a.json").write_text(json.dumps({"model": "a"}), encoding="utf-8")
    (tmp_path / "results_half-written.json").write_text('{"model": ', encoding="utf-8")

    body = client.get("/api/evaluation/results", headers=headers).json()
    assert body == {"results": [{"model": "a"}, {"model": "b"}]}
