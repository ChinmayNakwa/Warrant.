"""Shared test fixtures.

One temporary SQLite database is created through Alembic, and every table is
emptied between tests.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_TMP_DB = Path(tempfile.gettempdir()) / "warrant_test.db"
if _TMP_DB.exists():
    _TMP_DB.unlink()

# Environment variables win over .env, so a developer's own settings never
# reach the tests.
os.environ["WARRANT_DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"
os.environ["WARRANT_JWT_SECRET"] = "test-secret"
os.environ["WARRANT_ACCESS_TOKEN_TTL_SECONDS"] = "900"
os.environ["WARRANT_RATE_LIMIT_MAX_ATTEMPTS"] = "10"
os.environ["WARRANT_RATE_LIMIT_WINDOW_SECONDS"] = "300"

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.app import app  # noqa: E402
from backend.database import Base, engine  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _migrate() -> None:
    command.upgrade(Config("alembic.ini"), "head")
    yield
    engine.dispose()
    try:
        _TMP_DB.unlink(missing_ok=True)
    except PermissionError:
        pass


@pytest.fixture(autouse=True)
def _clean_tables():
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
    yield


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


VALID_PASSWORD = "Sup3rSecret-pass"


def register(client: TestClient, email: str, password: str = VALID_PASSWORD):
    return client.post("/api/auth/register", json={"email": email, "password": password})


def login(client: TestClient, email: str, password: str = VALID_PASSWORD, **kwargs):
    return client.post("/api/auth/login", json={"email": email, "password": password}, **kwargs)


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def user_factory(client: TestClient):
    def _make(email: str, password: str = VALID_PASSWORD):
        r = register(client, email, password)
        assert r.status_code == 201, r.text
        lr = login(client, email, password)
        assert lr.status_code == 200, lr.text
        return {
            "id": r.json()["id"],
            "email": email,
            "password": password,
            "access_token": lr.json()["access_token"],
            "refresh_cookie": lr.cookies.get("warrant_refresh"),
        }

    return _make
