"""GET /api/dashboard/summary: counted on the server, for the caller only."""
from __future__ import annotations

from datetime import timedelta

from backend.database import SessionLocal, utcnow
from backend.models import GuardrailRun
from tests.conftest import auth, make_capture, make_incident


def _run(db, incident_id: str, *, violations: str = "[]", days_ago: int = 0) -> None:
    db.add(
        GuardrailRun(
            incident_id=incident_id, mode="guarded", status="completed", model="test",
            violations_json=violations, started_at=utcnow() - timedelta(days=days_ago),
        )
    )


def test_an_empty_account_has_an_empty_summary(client, user_factory):
    user = user_factory("empty@example.com")

    body = client.get("/api/dashboard/summary", headers=auth(user["access_token"])).json()

    assert body == {
        "open_incidents": 0,
        "total_runs": 0,
        "runs_with_violations": 0,
        "verdict_breakdown": {},
        "severity_breakdown": {},
        "runs_over_time": [],
        "recent_incidents": [],
    }


def test_summary_counts_the_callers_incidents_and_runs(client, user_factory):
    user = user_factory("busy@example.com")
    with SessionLocal() as db:
        capture_id = make_capture(db).id
        a = make_incident(db, user["id"], capture_id=capture_id, severity="high", verdict="MALICIOUS")
        b = make_incident(db, user["id"], capture_id=capture_id, severity="high", verdict="BENIGN")
        make_incident(db, user["id"], capture_id=capture_id, severity="low", status="closed")
        _run(db, a.id, violations='[{"code": "technique_unknown"}]')
        _run(db, a.id)
        _run(db, b.id, days_ago=45)  # outside the 30-day chart, still a run
        db.commit()

    body = client.get("/api/dashboard/summary", headers=auth(user["access_token"])).json()

    assert (body["open_incidents"], body["total_runs"], body["runs_with_violations"]) == (2, 3, 1)
    assert body["verdict_breakdown"] == {"MALICIOUS": 1, "BENIGN": 1}
    assert body["severity_breakdown"] == {"high": 2, "low": 1}
    assert body["runs_over_time"] == [{"date": str(utcnow().date()), "count": 2}]
    assert len(body["recent_incidents"]) == 3


def test_summary_never_includes_another_users_data(client, user_factory):
    owner, other = user_factory("dash-owner@example.com"), user_factory("dash-other@example.com")
    with SessionLocal() as db:
        incident = make_incident(db, owner["id"], verdict="MALICIOUS")
        _run(db, incident.id, violations='[{"code": "event_missing"}]')
        db.commit()

    body = client.get("/api/dashboard/summary", headers=auth(other["access_token"])).json()

    assert (body["open_incidents"], body["total_runs"], body["runs_with_violations"]) == (0, 0, 0)
    assert body["verdict_breakdown"] == {} and body["recent_incidents"] == []
