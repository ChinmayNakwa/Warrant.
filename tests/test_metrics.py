"""Scoring functions. No database."""
from __future__ import annotations

import pytest

from backend.guardrail.metrics import (
    ScenarioResult,
    canonical_techniques,
    summarize,
    technique_precision_recall,
)


def _result(**overrides) -> ScenarioResult:
    fields = dict(
        capture="c",
        scenario="s",
        expected_verdict="MALICIOUS",
        expected_techniques=("T1059.001",),
        accepted_techniques=(),
        verdict="MALICIOUS",
        techniques=("T1059.001",),
    )
    fields.update(overrides)
    return ScenarioResult(**fields)


BENIGN = dict(expected_verdict="BENIGN", expected_techniques=(), techniques=())


def test_precision_recall_perfect_match():
    assert technique_precision_recall(("T1059.001", "T1027"), ("T1059.001", "T1027")) == (1.0, 1.0)


def test_precision_recall_partial_overlap():
    assert technique_precision_recall(("T1059.001", "T1027"), ("T1059.001",)) == (0.5, 1.0)


def test_precision_recall_no_overlap():
    assert technique_precision_recall(("T1027",), ("T1059.001",)) == (0.0, 0.0)


def test_nothing_expected_and_nothing_claimed_is_correct():
    assert technique_precision_recall((), ()) == (1.0, 1.0)


def test_a_claim_when_nothing_is_expected_costs_precision_only():
    assert technique_precision_recall(("T1059.001",), ()) == (0.0, 1.0)


def test_a_revoked_id_is_scored_as_the_id_that_replaced_it():
    """T1060 was the Run-key technique until 2020; it is T1547.001 now."""
    assert canonical_techniques(("T1060",)) == {"T1547.001"}
    assert technique_precision_recall(("T1059.001", "T1060"), ("T1059.001", "T1547.001")) == (1.0, 1.0)


def test_a_revoked_id_in_the_label_is_mapped_too():
    assert technique_precision_recall(("T1562.002",), ("T1562.002",)) == (1.0, 1.0)
    assert technique_precision_recall(("T1685.001",), ("T1562.002",)) == (1.0, 1.0)


def test_an_id_that_was_never_revoked_is_left_as_written():
    assert canonical_techniques(("T1059.001", "T9999")) == {"T1059.001", "T9999"}


def test_a_parent_listed_with_its_own_sub_technique_is_one_claim():
    assert canonical_techniques(("T1059", "T1059.001", "T1027")) == {"T1059.001", "T1027"}
    assert technique_precision_recall(("T1059", "T1059.001"), ("T1059.001",)) == (1.0, 1.0)
    # ... and does not pad the count of right claims next to a wrong one.
    precision, _ = technique_precision_recall(("T1059", "T1059.001", "T1036"), ("T1059.001",))
    assert precision == 0.5


def test_a_parent_alone_is_not_a_false_claim_but_does_not_find_the_sub_technique():
    assert technique_precision_recall(("T1003",), ("T1003.002",)) == (1.0, 0.0)


def test_a_claim_more_specific_than_the_label_finds_it():
    assert technique_precision_recall(("T1027.010",), ("T1027",)) == (1.0, 1.0)


def test_two_sub_techniques_of_one_parent_never_match():
    assert technique_precision_recall(("T1003.001",), ("T1003.002",)) == (0.0, 0.0)


def test_an_accepted_technique_is_not_a_false_claim_and_is_never_required():
    expected, accepted = ("T1218.010",), ("T1059.001", "T1027")
    # Claimed only what the label accepts: nothing false, the expected one missed.
    assert technique_precision_recall(("T1059.001", "T1027"), expected, accepted) == (1.0, 0.0)
    # Claimed the expected one and nothing else: accepted ones cost no recall.
    assert technique_precision_recall(("T1218.010",), expected, accepted) == (1.0, 1.0)
    # A technique the label lists nowhere is still a false claim.
    assert technique_precision_recall(("T1218.010", "T1003.001"), expected, accepted) == (0.5, 1.0)
    # The family rule covers accepted ones too.
    assert technique_precision_recall(("T1027.010",), expected, accepted) == (1.0, 0.0)


def test_accepted_techniques_do_not_change_a_benign_scenario():
    assert technique_precision_recall((), (), ("T1059.001",)) == (1.0, 1.0)


def test_summarize_reports_mean_and_spread_across_repeats():
    hit = _result(scenario="a")
    miss = _result(scenario="a", verdict="FAILED", techniques=())

    summary = summarize([[hit], [miss]])

    assert summary["precision"]["mean"] == pytest.approx(0.5)
    assert summary["precision"]["stdev"] == pytest.approx(0.7071, abs=1e-4)
    assert summary["verdict_accuracy"]["mean"] == pytest.approx(0.5)
    (scenario,) = summary["scenarios"]
    assert scenario["verdicts"] == ["MALICIOUS", "FAILED"]
    assert scenario["verdicts_correct"] == [True, False]
    assert scenario["verdict_correct_rate"] == pytest.approx(0.5)


def test_summarize_averages_across_a_passes_scenarios():
    results = [
        _result(scenario="a"),
        _result(scenario="b", verdict="SUSPICIOUS"),
        _result(scenario="c", verdict="BENIGN"),
        _result(scenario="d", verdict="BENIGN", **BENIGN),
    ]

    summary = summarize([results])

    assert summary["verdict_accuracy"]["mean"] == 0.5  # a and d
    # a and b, of the three attacks: a wrong verdict that is not a dismissal counts
    assert summary["detection_rate"]["mean"] == pytest.approx(2 / 3)
    assert summary["benign_discrimination"] is True


def test_summarize_scores_against_the_scenarios_accepted_techniques():
    result = _result(
        expected_techniques=("T1218.010",), accepted_techniques=("T1059.001",), techniques=("T1059.001",)
    )
    summary = summarize([[result]])
    assert (summary["precision"]["mean"], summary["recall"]["mean"]) == (1.0, 0.0)


def test_summarize_detection_rate_is_null_without_an_attack_scenario():
    assert summarize([[_result(verdict="BENIGN", **BENIGN)]])["detection_rate"] is None


def test_summarize_has_no_spread_for_a_single_repeat():
    assert summarize([[_result()]])["precision"] == {"mean": 1.0, "stdev": None}


def test_one_benign_scenario_called_malicious_fails_discrimination():
    summary = summarize(
        [[_result(verdict="BENIGN", **BENIGN)], [_result(verdict="MALICIOUS", **BENIGN)]]
    )
    assert summary["benign_discrimination"] is False


def test_summarize_rejects_empty_or_mismatched_repeats():
    with pytest.raises(ValueError):
        summarize([])
    with pytest.raises(ValueError):
        summarize([[_result(scenario="a")], [_result(scenario="b")]])
