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

    # The model, served by Ollama. Leave the model unset and runs answer 503.
    # For Ollama's hosted API set the base URL to https://ollama.com and a key.
    ollama_model: str | None = None
    ollama_base_url: str = "http://localhost:11434"
    ollama_api_key: str | None = None
    ollama_timeout_seconds: float = 300.0
    # One reply carries the verdict, every technique and every claim, and the
    # prompt carries the whole slice, so both limits are generous.
    max_reply_tokens: int = 8192
    ollama_num_ctx: int = 32768

    # How much telemetry the model reads for one incident
    max_slice_events: int = 120
    slice_window_seconds: int = 120
    # Guarded mode: how often a failing answer goes back to the model before
    # whatever is still wrong is removed
    max_repairs: int = 2
    # One run per incident at a time. A claim left behind by a server killed
    # mid-run expires after this long.
    run_claim_ttl_seconds: int = 15 * 60

    evaluation_dir: str = "data/evaluation"

    # CORS: the frontend's origin, comma-separated if there are several
    frontend_origin: str = "http://localhost:3000"

    @property
    def frontend_origins(self) -> list[str]:
        return [o.strip() for o in self.frontend_origin.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
