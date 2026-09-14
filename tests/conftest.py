"""Shared test fixtures: a temporary SQLite database and a test client."""
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

from fastapi.testclient import TestClient  # noqa: E402

from backend.app import app  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)
