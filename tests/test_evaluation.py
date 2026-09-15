"""The evaluation: one guarded run per scenario, scored twice.

A scripted model stands in for the LLM, so these check the bookkeeping, not
whether a guardrail helps.
"""
from __future__ import annotations

import json

from backend.llm import ModelError
from backend.guardrail.evaluation import (
    CAPTURE_NAMES,
    CAPTURES_ROOT,
    FAILED,
    results_path,
    run_evaluation,
)

CHAIN = "{00000000-0000-0000-0000-000000000201}"
CRED = "{00000000-0000-0000-0000-000000000301}"
BENIGN = "{00000000-0000-0000-0000-000000000401}"


def _reply(verdict, *techniques) -> str:
    return json.dumps(
        {"verdict": verdict, "confidence": 0.9, "summary": "s", "claims": [],
         "techniques": [{"id": t, "events": ["e1"]} for t in techniques]}
    )


class Scripted:
    """Answers by which scenario's alerted process the prompt names, and by
    whether it is a first prompt or a repair."""

    def __init__(self, first: dict[str, str], repair: dict[str, str | Exception] | None = None):
        self.first, self.repair, self.calls = first, repair or {}, 0

    def __call__(self, system: str, user: str) -> str:
        self.calls += 1
        anchor = next(a for a in (CHAIN, CRED, BENIGN) if f"alerted process GUID: {a}" in user)
        reply = (self.repair if "PREVIOUS_ANSWER" in user else self.first)[anchor]
        if isinstance(reply, Exception):
            raise reply
        return reply


FIRST = {
    # Right, plus an id that does not exist.
    CHAIN: _reply("MALICIOUS", "T1059.001", "T1027", "T1105", "T1547.001", "T9999"),
    CRED: _reply("MALICIOUS", "T1003.001"),
    BENIGN: _reply("BENIGN"),
}


def _evaluate(model, repeats=2, **kw) -> dict:
    return run_evaluation(
        model, model="scripted", repeats=repeats, capture_names=("small_lab",), **kw
    )


def test_each_run_is_scored_as_its_first_answer_and_as_its_accepted_answer(client):
    # The model repeats itself when asked to repair, so enforcement removes T9999.
    model = Scripted(FIRST, repair={CHAIN: FIRST[CHAIN]})

    result = _evaluate(model)

    baseline, guarded = result["arms"]["baseline"], result["arms"]["guarded"]
    chain_b, chain_g = baseline["scenarios"][0], guarded["scenarios"][0]
    assert chain_b["scenario"] == chain_g["scenario"] == "malicious_powershell_chain"
    assert "T9999" in chain_b["techniques"][0] and "T9999" not in chain_g["techniques"][0]
    assert (chain_b["precision"], chain_g["precision"]) == (0.8, 1.0)
    assert chain_b["recall"] == chain_g["recall"] == 1.0
    # (0.8 + 1 + 1) / 3 per repeat; identical repeats, so no spread.
    assert baseline["precision"] == {"mean": 2.8 / 3, "stdev": 0.0}
    assert guarded["precision"] == {"mean": 1.0, "stdev": 0.0}
    assert baseline["verdict_accuracy"]["mean"] == guarded["verdict_accuracy"]["mean"] == 1.0
    assert baseline["benign_discrimination"] is guarded["benign_discrimination"] is True

    # One model call per scenario, plus one repair for the chain, per repeat.
    assert model.calls == 2 * (3 + 1)
    assert result["guardrail"] == {
        "runs": 6, "failed_runs": 0,
        "runs_with_violations": 2, "violations": 2,
        "violations_by_code": {"technique_unknown": 2},
        "runs_fully_repaired": 0, "runs_enforced": 2,
        "dropped_by_kind": {"technique": 2},
        "repair_rounds": 2, "repairs_cut_short": 2,
        "answers_changed": 2, "verdicts_changed": 0,
        "mean_model_calls": 8 / 6,
        "mean_seconds_per_run": result["guardrail"]["mean_seconds_per_run"],
    }
    assert result["paired"] == {
        "precision": {"better": 2, "worse": 0, "same": 4},
        "recall": {"better": 0, "worse": 0, "same": 6},
        "verdict": {"better": 0, "worse": 0, "same": 6},
    }
    assert (result["complete"], result["repeats_done"], result["model"]) == (True, 2, "scripted")
    # 6 techniques per repeat (5 + 1 + 0); the baseline's T9999 does not conform.
    grounding = result["grounding"]
    assert (grounding["baseline"]["techniques"], grounding["baseline"]["conforming_techniques"]) == (12, 10)
    assert (grounding["guarded"]["techniques"], grounding["guarded"]["conforming_techniques"]) == (10, 10)
    assert grounding["baseline"]["techniques_conformance"] == 10 / 12
    assert grounding["guarded"]["mean_conforming_techniques_per_run"] == 10 / 6
    assert grounding["baseline"]["claims_conformance"] is None  # these answers make no claims


def test_a_repair_that_deletes_a_true_technique_shows_as_recall_lost(client):
    """The cost side: asked to fix one id, the model drops a correct one too."""
    model = Scripted(FIRST, repair={CHAIN: _reply("MALICIOUS", "T1059.001", "T1027", "T1105")})

    result = _evaluate(model, repeats=1)

    assert result["arms"]["baseline"]["scenarios"][0]["recall"] == 1.0
    assert result["arms"]["guarded"]["scenarios"][0]["recall"] == 0.75
    assert result["paired"]["recall"] == {"better": 0, "worse": 1, "same": 2}
    assert result["paired"]["precision"] == {"better": 1, "worse": 0, "same": 2}
    assert result["guardrail"]["runs_fully_repaired"] == 1


def test_a_run_the_model_never_answers_counts_against_both_arms(client):
    model = Scripted({**FIRST, CRED: ModelError("the model timed out")})

    result = _evaluate(model, repeats=1)

    for arm in ("baseline", "guarded"):
        cred = result["arms"][arm]["scenarios"][1]
        assert (cred["verdicts"], cred["verdicts_correct"], cred["recall"]) == ([FAILED], [False], 0.0)
    assert result["guardrail"]["failed_runs"] == 1
    assert result["paired"]["verdict"]["same"] == 3


def test_results_file_is_named_for_the_model():
    assert results_path("gpt-oss:120b").name == "results_gpt-oss-120b.json"
    # A model name cannot move the file out of the results directory.
    assert results_path("../x").parent == results_path("a").parent


def test_a_checkpoint_is_written_after_every_repeat(client):
    seen = []

    _evaluate(Scripted(FIRST, repair={CHAIN: FIRST[CHAIN]}), repeats=2, on_checkpoint=seen.append)

    assert [(d["repeats_done"], d["complete"]) for d in seen] == [(1, False), (2, True)]
    assert seen[0]["guardrail"]["runs"] == 3


def test_every_capture_directory_is_evaluated():
    on_disk = {p.parent.name for p in CAPTURES_ROOT.glob("*/labels.json")} - {"large_workstation"}
    assert on_disk == set(CAPTURE_NAMES)
