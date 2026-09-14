"""CORS: only the configured frontend origins may call the API from a browser."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings, get_settings


def test_frontend_origin_is_a_comma_separated_list():
    settings = Settings(frontend_origin=" http://localhost:3000, http://localhost:3001 ,")
    assert settings.frontend_origins == ["http://localhost:3000", "http://localhost:3001"]


def test_a_single_origin_still_works():
    assert Settings(frontend_origin="http://localhost:3000").frontend_origins == ["http://localhost:3000"]


def test_only_listed_origins_get_cors_headers(monkeypatch):
    monkeypatch.setenv("WARRANT_FRONTEND_ORIGIN", "http://localhost:3000,http://localhost:3001")
    get_settings.cache_clear()
    try:
        client = TestClient(create_app())
        for origin in ("http://localhost:3000", "http://localhost:3001"):
            response = client.get("/api/health", headers={"Origin": origin})
            assert response.headers["access-control-allow-origin"] == origin
        response = client.get("/api/health", headers={"Origin": "http://localhost:3002"})
        assert "access-control-allow-origin" not in response.headers
    finally:
        get_settings.cache_clear()
