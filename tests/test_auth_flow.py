"""End-to-end auth journey: register -> login -> authenticated -> refresh -> logout."""
from __future__ import annotations

from tests.conftest import login, register


def test_register_returns_user_without_tokens(client):
    r = register(client, "alice@example.com")
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "alice@example.com"
    assert "id" in body and body["created_at"].endswith("Z")
    assert "password" not in body and "password_hash" not in body
    assert "access_token" not in body


def test_email_is_normalised_to_lowercase(client):
    assert register(client, "MixedCase@Example.com").status_code == 201
    # same address, different case -> duplicate
    assert register(client, "mixedcase@example.com").status_code == 409


def test_login_returns_access_token_and_refresh_cookie(client):
    register(client, "bob@example.com")
    r = login(client, "bob@example.com")
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] <= 15 * 60
    assert body["access_token"]
    assert "warrant_refresh" in r.cookies


def test_me_requires_and_accepts_access_token(client):
    register(client, "carol@example.com")
    token = login(client, "carol@example.com").json()["access_token"]

    assert client.get("/api/auth/me").status_code == 401

    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["email"] == "carol@example.com"


def test_refresh_rotates_and_issues_new_access_token(client):
    register(client, "dave@example.com")
    login(client, "dave@example.com")
    old_cookie = client.cookies["warrant_refresh"]

    r = client.post("/api/auth/refresh")
    assert r.status_code == 200
    assert r.json()["access_token"]
    new_cookie = client.cookies["warrant_refresh"]
    assert new_cookie != old_cookie


def test_logout_revokes_refresh_token(client):
    register(client, "erin@example.com")
    token = login(client, "erin@example.com").json()["access_token"]

    r = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200

    # the refresh cookie the client still holds is now dead
    assert client.post("/api/auth/refresh").status_code == 401
