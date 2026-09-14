"""One user's tokens never act for another."""
from __future__ import annotations


def test_each_user_sees_only_their_own_identity(user_factory):
    a = user_factory("iso-a@example.com")
    b = user_factory("iso-b@example.com")

    from fastapi.testclient import TestClient

    from backend.app import app

    c = TestClient(app)
    ra = c.get("/api/auth/me", headers={"Authorization": f"Bearer {a['access_token']}"})
    rb = c.get("/api/auth/me", headers={"Authorization": f"Bearer {b['access_token']}"})

    assert ra.json()["email"] == "iso-a@example.com"
    assert rb.json()["email"] == "iso-b@example.com"
    assert ra.json()["id"] != rb.json()["id"]


def test_user_a_refresh_token_is_useless_to_user_b(user_factory, client):
    a = user_factory("iso-c@example.com")
    user_factory("iso-d@example.com")

    # b's client cannot do anything with a's refresh cookie beyond acting as a
    client.cookies["warrant_refresh"] = a["refresh_cookie"]
    r = client.post("/api/auth/refresh")
    assert r.status_code == 200
    # the freshly minted access token still resolves to user a
    tok = r.json()["access_token"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
    assert me.json()["email"] == "iso-c@example.com"


def test_logout_cannot_revoke_another_users_refresh_token(user_factory, client):
    """A request authenticated as user B, carrying user A's refresh cookie
    (e.g. a stale cookie on a shared client), must not revoke user A's
    refresh chain - logout only ever acts on the caller's own tokens."""
    a = user_factory("iso-e@example.com")
    b = user_factory("iso-f@example.com")

    client.cookies["warrant_refresh"] = a["refresh_cookie"]
    r = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {b['access_token']}"})
    assert r.status_code == 200

    # user a's refresh token must still be live
    client.cookies["warrant_refresh"] = a["refresh_cookie"]
    assert client.post("/api/auth/refresh").status_code == 200
