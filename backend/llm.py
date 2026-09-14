"""The model call. Everything else treats a model as a `Completer`: a function
from (system prompt, user prompt) to the reply text."""
from __future__ import annotations

import logging
from typing import Callable

import httpx

from backend.config import Settings

Completer = Callable[[str, str], str]

log = logging.getLogger("warrant.llm")


class ModelError(Exception):
    """The model could not be reached or gave no usable reply. The message is
    safe to store and show."""


class NoModelConfigured(Exception):
    pass


def _headers(settings: Settings) -> dict[str, str]:
    if not settings.ollama_api_key:
        return {}
    return {"Authorization": f"Bearer {settings.ollama_api_key}"}


def ollama_completer(settings: Settings) -> Completer:
    if not settings.ollama_model:
        raise NoModelConfigured()
    url = settings.ollama_base_url.rstrip("/") + "/api/chat"

    def complete(system: str, user: str) -> str:
        try:
            response = httpx.post(
                url,
                json={
                    "model": settings.ollama_model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "format": "json",
                    # Thinking is slow and, with format=json, can use up the
                    # reply's tokens before the answer starts.
                    "think": False,
                    "options": {
                        "num_predict": settings.max_reply_tokens,
                        "num_ctx": settings.ollama_num_ctx,
                    },
                },
                headers=_headers(settings),
                timeout=settings.ollama_timeout_seconds,
            )
        except httpx.ConnectError as exc:
            raise ModelError("could not reach Ollama - is it running?") from exc
        except httpx.TimeoutException as exc:
            raise ModelError("the model timed out") from exc
        if response.status_code in (401, 403):
            raise ModelError("Ollama rejected the API key")
        if response.status_code == 404:
            raise ModelError(f"Ollama model {settings.ollama_model} is not available")
        if response.status_code != 200:
            raise ModelError(f"Ollama returned HTTP {response.status_code}")
        body = response.json()
        log.info(
            "ollama %s: %s prompt tokens, %s output tokens, %.1fs",
            settings.ollama_model, body.get("prompt_eval_count", "?"), body.get("eval_count", "?"),
            (body.get("total_duration") or 0) / 1e9,
        )
        if body.get("done_reason") == "length":
            raise ModelError("the model's reply was cut off before it finished")
        return (body.get("message") or {}).get("content") or ""

    return complete


def ollama_unavailable(settings: Settings) -> str | None:
    """Why the configured model cannot be used right now, or None if it can.
    Checked once before a long evaluation."""
    try:
        response = httpx.get(
            settings.ollama_base_url.rstrip("/") + "/api/tags",
            headers=_headers(settings), timeout=10.0,
        )
    except httpx.HTTPError:
        return f"could not reach Ollama at {settings.ollama_base_url} - is it running?"
    if response.status_code in (401, 403):
        return "Ollama rejected the API key"
    if response.status_code != 200:
        return f"Ollama returned HTTP {response.status_code}"
    names = {m.get("name") for m in response.json().get("models", [])}
    wanted = settings.ollama_model
    if wanted not in names and f"{wanted}:latest" not in names:
        return f"Ollama model {wanted} is not available at {settings.ollama_base_url}"
    return None
