"""Baseline against guarded, over every labelled scenario.

Usage:
    ./.venv/Scripts/python.exe -m backend.guardrail.evaluation --repeats 3
    ./.venv/Scripts/python.exe -m backend.guardrail.evaluation --captures small_lab --repeats 1
    ./.venv/Scripts/python.exe -m backend.guardrail.evaluation --model gpt-oss:20b

Writes `data/evaluation/results_<model>.json`, saved again after every repeat
so a crash does not lose the repeats already done. A model is not
deterministic, so two runs of this give different numbers.

The comparison is paired. Both modes start from the same prompt, so a guarded
run's first answer is exactly what baseline would have accepted. Each scenario
is therefore run once per repeat, guarded, and scored twice: its first answer
is the baseline, its accepted answer is the guarded result. Running the modes
separately would compare two different draws from the model.

Verdicts and techniques are scored against the scenario's label. Claims have
no label to score against, so each mode also reports grounding: how many of
its claims and techniques conform to the ontology.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import time
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.auth import hash_password
from backend.config import get_settings
from backend.database import SessionLocal
from backend.guardrail.analyst import run_analysis
from backend.guardrail.metrics import ScenarioResult, summarize, technique_precision_recall
from backend.llm import Completer, NoModelConfigured, ollama_completer, ollama_unavailable
from backend.models import GuardrailRun, Incident, User
from backend.telemetry.ingest import ingest_capture_dir

CAPTURES_ROOT = Path(__file__).resolve().parents[2] / "data" / "captures"
# The order scenarios appear in the results
CAPTURE_NAMES = (
    "small_lab",
    "real_atomic",
    "otrf_sam_esentutl",
    "otrf_lsa_secrets_psexec",
    "otrf_lsass_dumpert",
    "otrf_lsass_taskmgr",
    "otrf_ntds_ntdsutil",
    "otrf_bitsadmin_download",
    "otrf_logon_script",
    "otrf_mshta_remote_sct",
    "otrf_regsvr32_sct",
    "otrf_cmstp_uac_bypass",
    "otrf_fodhelper_uac_bypass",
    "otrf_schtasks_persistence",
    "otrf_vbs_launcher",
    "otrf_service_binpath",
    "otrf_cmdline_logging_disabled",
    "benign_lab",
    "injection_lab",
)
MODES = ("baseline", "guarded")
# The evaluation's incidents belong to this account. It is never logged into.
EVAL_EMAIL = "eval@warrant.local"
EVAL_PASSWORD = "eval-only-not-a-real-account-0000"
# A run the model never answered: scored as a wrong verdict with no techniques
FAILED = "FAILED"


def results_path(model: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9.]+", "-", model).strip("-")
    return Path(get_settings().evaluation_dir) / f"results_{slug}.json"


def _load_scenarios(db: Session, capture_names: tuple[str, ...]) -> tuple[list[dict], dict[str, str]]:
    """Every scenario in the captures' labels, and each capture's id. A
    capture not yet in the database is ingested first."""
    scenarios: list[dict] = []
    capture_ids: dict[str, str] = {}
    for name in capture_names:
        labels = json.loads((CAPTURES_ROOT / name / "labels.json").read_text(encoding="utf-8"))
        capture_ids[name] = ingest_capture_dir(db, CAPTURES_ROOT / name).id
        scenarios += [{**s, "capture": name} for s in labels["scenarios"]]
    db.commit()
    return scenarios, capture_ids


def _reset_eval_user(db: Session) -> User:
    """The evaluation's account, with the incidents and runs of earlier
    evaluations deleted."""
    user = db.scalar(select(User).where(User.email == EVAL_EMAIL))
    if user is None:
        user = User(email=EVAL_EMAIL, password_hash=hash_password(EVAL_PASSWORD))
        db.add(user)
    else:
        for incident in db.scalars(select(Incident).where(Incident.user_id == user.id)).all():
            db.delete(incident)
    db.commit()
    return user


def _result(scenario: dict, verdict: str, techniques: list[str]) -> ScenarioResult:
    return ScenarioResult(
        capture=scenario["capture"],
        scenario=scenario["name"],
        expected_verdict=scenario["expected_verdict"],
        expected_techniques=tuple(scenario["expected_techniques"]),
        accepted_techniques=tuple(scenario.get("accepted_techniques", ())),
        verdict=verdict,
        techniques=tuple(techniques),
        injected_verdict=scenario.get("injected_verdict"),
        injected_techniques=tuple(scenario.get("injected_techniques", ())),
    )


def _run_scenario(
    db: Session, *, user_id: str, capture_id: str, scenario: dict, complete: Completer, model: str
) -> tuple[GuardrailRun, dict[str, ScenarioResult], float]:
    # The model is shown the alert, not the label's description, which names
    # the technique.
    incident = Incident(
        user_id=user_id,
        title=scenario.get("alert_title") or f"eval: {scenario['name']}",
        description=scenario.get("alert") or scenario["description"],
        severity="high",
        capture_id=capture_id,
        anchor_process_guid=scenario["anchor_process_guid"],
    )
    db.add(incident)
    db.flush()
    started = time.monotonic()
    run = run_analysis(
        db, user_id=user_id, incident_id=incident.id, mode="guarded", complete=complete, model=model
    )
    seconds = time.monotonic() - started
    db.commit()

    if run.first_answer_json is None:
        # No answer at all (model failure, or no telemetry): the same for both modes.
        verdict = run.verdict or FAILED
        return run, {mode: _result(scenario, verdict, []) for mode in MODES}, seconds
    first = json.loads(run.first_answer_json)
    return run, {
        "baseline": _result(scenario, first["verdict"], sorted({t["id"] for t in first["techniques"]})),
        "guarded": _result(scenario, run.verdict, json.loads(run.techniques_json)),
    }, seconds


def _guardrail_summary(runs: list[GuardrailRun], seconds: list[float]) -> dict:
    """What the guardrail found and did, counted over every run."""
    answered = [r for r in runs if r.first_answer_json is not None]
    violations = [json.loads(r.violations_json) for r in answered]
    dropped = [json.loads(r.dropped_json) for r in answered]
    flagged = [i for i, v in enumerate(violations) if v]
    return {
        "runs": len(runs),
        "failed_runs": sum(r.status == "failed" for r in runs),
        "runs_with_violations": len(flagged),
        "violations": sum(len(v) for v in violations),
        "violations_by_code": dict(sorted(Counter(x["code"] for v in violations for x in v).items())),
        # Of the runs with violations: repair left nothing to remove
        "runs_fully_repaired": sum(1 for i in flagged if not dropped[i]),
        "runs_enforced": sum(1 for i in flagged if dropped[i]),
        "dropped_by_kind": dict(sorted(Counter(x["kind"] for d in dropped for x in d).items())),
        "repair_rounds": sum(r.repair_rounds for r in answered),
        "repairs_cut_short": sum(1 for r in answered if r.note),
        "answers_changed": sum(r.answer_json != r.first_answer_json for r in answered),
        "verdicts_changed": sum(
            json.loads(r.first_answer_json)["verdict"] != r.verdict for r in answered
        ),
        "mean_model_calls": sum(r.llm_calls for r in runs) / len(runs),
        "mean_seconds_per_run": sum(seconds) / len(seconds),
    }


def _grounding_summary(runs: list[GuardrailRun]) -> dict:
    """Per mode, the claims and techniques answers made and how many of them
    conform to the ontology. Baseline is the first answer, judged by the
    violations recorded for it. A guarded answer always conforms, so the number
    to read there is how much is left: whether repair fixed the evidence or
    only deleted it."""
    answered = [r for r in runs if r.first_answer_json is not None]

    def count(items: list[tuple[dict, set[str]]]) -> dict:
        out = {}
        for field in ("claims", "techniques"):
            total = sum(len(answer[field]) for answer, _ in items)
            broken = sum(
                sum(1 for i in range(len(answer[field])) if f"{field}[{i}]" in bad)
                for answer, bad in items
            )
            out[field] = total
            out[f"conforming_{field}"] = total - broken
            out[f"{field}_conformance"] = (total - broken) / total if total else None
            out[f"mean_conforming_{field}_per_run"] = (total - broken) / len(items) if items else None
        return out

    return {
        "baseline": count(
            [
                (json.loads(r.first_answer_json), {v["path"] for v in json.loads(r.violations_json)})
                for r in answered
            ]
        ),
        "guarded": count([(json.loads(r.answer_json), set()) for r in answered]),
    }


def _paired_summary(pairs: list[dict[str, ScenarioResult]]) -> dict:
    """Run by run: did the guardrail make that run's score better, worse or
    leave it the same?"""

    def tally(score: Callable[[ScenarioResult], float]) -> dict:
        deltas = [score(p["guarded"]) - score(p["baseline"]) for p in pairs]
        return {
            "better": sum(d > 0 for d in deltas),
            "worse": sum(d < 0 for d in deltas),
            "same": sum(d == 0 for d in deltas),
        }

    def precision_recall(r: ScenarioResult) -> tuple[float, float]:
        return technique_precision_recall(r.techniques, r.expected_techniques, r.accepted_techniques)

    return {
        "precision": tally(lambda r: precision_recall(r)[0]),
        "recall": tally(lambda r: precision_recall(r)[1]),
        "verdict": tally(lambda r: float(r.verdict == r.expected_verdict)),
    }


def run_evaluation(
    complete: Completer,
    *,
    model: str,
    repeats: int,
    capture_names: tuple[str, ...] = CAPTURE_NAMES,
    on_checkpoint: Callable[[dict], None] | None = None,
) -> dict:
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    settings = get_settings()

    with SessionLocal() as db:
        scenarios, capture_ids = _load_scenarios(db, capture_names)
        user = _reset_eval_user(db)

        done: list[list[dict[str, ScenarioResult]]] = []
        runs: list[GuardrailRun] = []
        seconds: list[float] = []

        def document() -> dict:
            return {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "captures": list(capture_names),
                "model": model,
                "repeats": repeats,
                "repeats_done": len(done),
                # False while the evaluation is still running
                "complete": len(done) == repeats,
                "max_slice_events": settings.max_slice_events,
                "slice_window_seconds": settings.slice_window_seconds,
                "max_repairs": settings.max_repairs,
                "scenarios": [
                    {
                        "capture": s["capture"],
                        "name": s["name"],
                        "description": s["description"],
                        "expected_verdict": s["expected_verdict"],
                        "expected_techniques": s["expected_techniques"],
                        "accepted_techniques": s.get("accepted_techniques", []),
                    }
                    for s in scenarios
                ],
                "arms": {mode: summarize([[p[mode] for p in rep] for rep in done]) for mode in MODES},
                "guardrail": _guardrail_summary(runs, seconds),
                "grounding": _grounding_summary(runs),
                "paired": _paired_summary([p for rep in done for p in rep]),
            }

        for _ in range(repeats):
            repeat = []
            for scenario in scenarios:
                run, pair, took = _run_scenario(
                    db, user_id=user.id, capture_id=capture_ids[scenario["capture"]],
                    scenario=scenario, complete=complete, model=model,
                )
                db.expunge(run)
                runs.append(run)
                seconds.append(took)
                repeat.append(pair)
            done.append(repeat)
            if on_checkpoint is not None:
                on_checkpoint(document())
        return document()


def _write(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run every labelled scenario, baseline against guarded.")
    parser.add_argument("--repeats", type=int, default=3, help="runs per scenario (default 3)")
    parser.add_argument(
        "--captures", default=",".join(CAPTURE_NAMES), help="comma-separated capture names (default: all)"
    )
    parser.add_argument("--model", help="Ollama model to use instead of WARRANT_OLLAMA_MODEL")
    args = parser.parse_args(argv)
    capture_names = tuple(name for name in args.captures.split(",") if name)
    if not capture_names or any(name not in CAPTURE_NAMES for name in capture_names):
        parser.error(f"--captures must name one or more of: {', '.join(CAPTURE_NAMES)}")
    if args.repeats < 1:
        parser.error("--repeats must be at least 1")

    settings = get_settings()
    if args.model:
        settings = settings.model_copy(update={"ollama_model": args.model})
    try:
        complete = ollama_completer(settings)
    except NoModelConfigured:
        raise SystemExit("no model is configured (set WARRANT_OLLAMA_MODEL, or pass --model)")
    if problem := ollama_unavailable(settings):
        raise SystemExit(problem)
    model = settings.ollama_model

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    path = results_path(model)
    result = run_evaluation(
        complete, model=model, repeats=args.repeats, capture_names=capture_names,
        on_checkpoint=lambda partial: _write(path, partial),
    )
    _write(path, result)
    print(
        f"wrote {path} ({model}: {len(result['scenarios'])} scenarios x "
        f"{args.repeats} repeats, {result['guardrail']['failed_runs']} failed runs)"
    )


if __name__ == "__main__":
    main()
