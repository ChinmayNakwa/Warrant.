"""Token rotation and validation, password policy, generic login errors and rate limiting."""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException
from sqlalchemy import select

from backend.auth import enforce_rate_limit
from backend.config import get_settings
from backend.database import SessionLocal
from backend.models import RateLimitHit
from tests.conftest import login, register


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- refresh-token rotation / reuse ------------------------- #


def test_old_refresh_token_is_rejected_after_rotation(client):
    register(client, "rot@example.com")
    login(client, "rot@example.com")
    old = client.cookies["warrant_refresh"]

    assert client.post("/api/auth/refresh").status_code == 200
    new = client.cookies["warrant_refresh"]

    client.cookies["warrant_refresh"] = old
    assert client.post("/api/auth/refresh").status_code == 401

    # reuse of a revoked token nukes the whole chain
    client.cookies["warrant_refresh"] = new
    assert client.post("/api/auth/refresh").status_code == 401


# --- access-token validation ------------------------------- #


def test_invalid_access_token_is_401(client):
    assert client.get("/api/auth/me", headers=_bearer("not-a-jwt")).status_code == 401


def test_expired_access_token_is_401(client):
    settings = get_settings()
    now = datetime.now(timezone.utc)
    stale = jwt.encode(
        {
            "sub": "whoever",
            "type": "access",
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    assert client.get("/api/auth/me", headers=_bearer(stale)).status_code == 401


def test_access_token_signed_with_wrong_secret_is_401(client):
    forged = jwt.encode(
        {
            "sub": "x",
            "type": "access",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        "attacker-secret",
        algorithm="HS256",
    )
    assert client.get("/api/auth/me", headers=_bearer(forged)).status_code == 401


# --- access-token lifetime --------------------------------- #


def test_issued_access_token_is_a_jwt_that_lives_at_most_15_minutes(client):
    from backend.config import Settings

    register(client, "ttl@example.com")
    token = login(client, "ttl@example.com").json()["access_token"]
    settings = get_settings()
    claims = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])

    assert claims["type"] == "access"
    assert 0 < claims["exp"] - claims["iat"] <= 15 * 60
    # The shipped default, not just this suite's env override.
    assert Settings.model_fields["access_token_ttl_seconds"].default <= 15 * 60


# --- password policy ------------------------------------- #


def test_weak_password_is_rejected(client):
    for weak in ["short1", "allletters", "1234567890", "aaaaaaaaaa1"]:
        r = client.post(
            "/api/auth/register", json={"email": f"{weak}@example.com", "password": weak}
        )
        assert r.status_code == 422, weak


# --- duplicate email --------------------------------------------------- #


def test_duplicate_email_is_rejected(client):
    assert register(client, "dup@example.com").status_code == 201
    assert register(client, "dup@example.com").status_code == 409


# --- generic login errors ----------------------------- #


def test_login_errors_are_generic_and_identical(client):
    register(client, "real@example.com")

    missing = login(client, "ghost@example.com")
    wrong = login(client, "real@example.com", "WrongPassword123")

    assert missing.status_code == wrong.status_code == 401
    assert missing.json() == wrong.json()
    assert "not found" not in missing.text.lower()
    assert "exist" not in missing.text.lower()


# --- rate limiting ----------------------------------- #


def test_login_is_rate_limited_per_ip_and_identifier(client):
    register(client, "rl@example.com")
    limit = get_settings().rate_limit_max_attempts

    # loop past 2x the limit so a fixed-window rollover mid-loop can't hide the 429
    codes = [
        login(client, "rl@example.com", "WrongPassword123").status_code
        for _ in range(limit * 2)
    ]
    assert codes[0] == 401  # first attempt is never rate limited
    assert 429 in codes
    assert codes[-1] == 429

    # a different identifier from the same IP is unaffected
    register(client, "other@example.com")
    assert login(client, "other@example.com").status_code == 200


def test_register_is_rate_limited(client):
    limit = get_settings().rate_limit_max_attempts
    codes = [register(client, "spam@example.com").status_code for _ in range(limit * 2)]
    assert 429 in codes
    assert codes[-1] == 429


def test_enforce_rate_limit_counts_concurrent_hits_without_losing_updates():
    """A Python-side read-then-write counter can silently lose increments
    under concurrency (two requests read the same starting count, the second
    commit clobbers the first); the atomic upsert must not."""
    n = 25
    bucket_key = "concurrency_test:1.2.3.4:someone"
    barrier = threading.Barrier(n)
    errors: list[Exception] = []

    def hit():
        barrier.wait()
        try:
            with SessionLocal() as db:
                enforce_rate_limit(db, "concurrency_test", "1.2.3.4", "someone")
        except HTTPException:
            pass  # expected once past the configured limit; only the count matters
        except Exception as exc:  # pragma: no cover - would surface as a test failure
            errors.append(exc)

    threads = [threading.Thread(target=hit) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors

    with SessionLocal() as db:
        rows = db.scalars(select(RateLimitHit).where(RateLimitHit.bucket_key == bucket_key)).all()
        assert sum(r.count for r in rows) == n


def test_x_forwarded_for_header_cannot_bypass_rate_limiting(client):
    """A caller-supplied X-Forwarded-For must not let an attacker pick a
    fresh rate-limit bucket per request; only the real socket peer counts."""
    register(client, "xff@example.com")
    limit = get_settings().rate_limit_max_attempts

    codes = [
        login(
            client,
            "xff@example.com",
            "WrongPassword123",
            headers={"X-Forwarded-For": f"10.0.0.{i}"},
        ).status_code
        for i in range(limit * 2)
    ]
    assert 429 in codes
    assert codes[-1] == 429
