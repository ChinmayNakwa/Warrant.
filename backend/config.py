"""Application settings, read from WARRANT_* environment variables or .env."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WARRANT_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/warrant.db"

    # CORS: the frontend's origin, comma-separated if there are several
    frontend_origin: str = "http://localhost:3000"

    @property
    def frontend_origins(self) -> list[str]:
        return [o.strip() for o in self.frontend_origin.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
