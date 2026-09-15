"""GET /api/evaluation/results - the evaluation's results files, as written.

Each file is one model's run of `backend.guardrail.evaluation`. The numbers
are not user-owned, so any signed-in user may read them.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends

from backend.auth import get_current_user
from backend.config import get_settings
from backend.models import User

router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])


@router.get("/results")
def get_evaluation_results(user: User = Depends(get_current_user)) -> dict:
    results: list[dict] = []
    for path in sorted(Path(get_settings().evaluation_dir).glob("results_*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            # A running evaluation rewrites its file after every repeat, so a
            # read can land mid-write. The next request sees the finished file.
            continue
        if isinstance(document, dict):
            results.append(document)
    return {"results": results}
