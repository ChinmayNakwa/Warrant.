"""Passwords are never stored or returned in plain text, and a server error
never leaks its detail."""
from __future__ import annotations

from sqlalchemy import select

from backend.auth import verify_password
from backend.database import SessionLocal
from backend.models import User
from tests.conftest import VALID_PASSWORD, login, register


def test_password_is_bcrypt_hashed_and_never_stored_plaintext(client):
    register(client, "hash@example.com")
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "hash@example.com"))
        assert user is not None
        assert user.password_hash != VALID_PASSWORD
        assert user.password_hash.startswith("$2")  # bcrypt marker
        # cost factor of at least 12
        assert int(user.password_hash.split("$")[2]) >= 12
        assert verify_password(VALID_PASSWORD, user.password_hash)


def test_password_hash_is_not_in_any_api_response(client):
    r = register(client, "leak@example.com")
    assert "password" not in r.text.lower()
    token = login(client, "leak@example.com").json()["access_token"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert "password" not in me.text.lower()


def test_unhandled_errors_return_generic_500_without_traceback(client):
    from backend.app import app

    @app.get("/api/_boom")
    def _boom():
        raise RuntimeError("secret internal detail: /etc/passwd")

    from fastapi.testclient import TestClient

    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/api/_boom")
    assert r.status_code == 500
    assert r.json() == {"detail": "Internal server error"}
    assert "secret internal detail" not in r.text
    assert "Traceback" not in r.text
