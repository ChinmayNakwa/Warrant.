"""Application settings, read from WARRANT_* environment variables or .env."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WARRANT_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/warrant.db"

    # Auth
    jwt_secret: str = "dev-insecure-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 15 * 60
    refresh_token_ttl_seconds: int = 14 * 24 * 60 * 60
    bcrypt_rounds: int = 12
    min_password_length: int = 10

    # Login/register rate limit: a fixed window per (action, ip, email)
    rate_limit_window_seconds: int = 5 * 60
    rate_limit_max_attempts: int = 10

    refresh_cookie_name: str = "warrant_refresh"
    cookie_secure: bool = False  # True in production over HTTPS

    # CORS: the frontend's origin, comma-separated if there are several
    frontend_origin: str = "http://localhost:3000"

    @property
    def frontend_origins(self) -> list[str]:
        return [o.strip() for o in self.frontend_origin.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
