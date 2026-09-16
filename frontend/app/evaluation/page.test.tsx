import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";

import type { EvaluationArm, EvaluationResults } from "@/lib/api";
import { getEvaluationResults } from "@/lib/api";

import EvaluationPage from "./page";

const FAKE_USER = { id: "u1", email: "analyst@example.com", created_at: "2026-01-01T00:00:00Z" };

vi.mock("next/navigation", async (importOriginal) => {
  const actual = await importOriginal<typeof import("next/navigation")>();
  return { ...actual, usePathname: () => "/evaluation" };
});

vi.mock("@/lib/useRequireAuth", () => ({
  useRequireAuth: () => ({ user: FAKE_USER, status: "authenticated" }),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, getEvaluationResults: vi.fn() };
});

// The chart needs a real layout to draw. The stub prints its props, so the
// test can check the page hands it the backend's numbers unchanged.
vi.mock("@/components/charts/PrecisionRecallChart", () => ({
  PrecisionRecallChart: ({ data }: { data: unknown }) => <div data-testid="pr-chart">{JSON.stringify(data)}</div>,
}));

function arm(precision: number, recall: number, verdicts: string[], correct: boolean[]): EvaluationArm {
  return {
    precision: { mean: precision, stdev: 0.04 },
    recall: { mean: recall, stdev: null },
    verdict_accuracy: { mean: 0.5, stdev: null },
    detection_rate: null,
    false_alarm_rate: { mean: 0.25, stdev: null },
    // No injection scenario was run, as in results written before there were any.
    scenarios: [
      {
        capture: "small_lab",
        scenario: "credential_access",
        expected_verdict: "MALICIOUS",
        expected_techniques: ["T1003.001"],
        verdicts,
        verdicts_correct: correct,
        techniques: [["T1003.001"]],
        verdict_correct_rate: 0.5,
        precision,
        recall,
      },
    ],
  };
}

const RESULT: EvaluationResults = {
  generated_at: "2026-09-15T12:00:00Z",
  model: "gpt-oss:120b",
  repeats: 3,
  repeats_done: 2,
  complete: false,
  arms: {
    baseline: arm(0.61, 0.9, ["MALICIOUS", "BENIGN"], [true, false]),
    guarded: arm(0.87, 0.85, ["MALICIOUS", "SUSPICIOUS"], [true, false]),
  },
  guardrail: {
    runs: 34,
    failed_runs: 1,
    runs_with_violations: 21,
    violations: 47,
    violations_by_code: { technique_unknown: 5, value_not_in_event: 42 },
    runs_fully_repaired: 9,
    runs_enforced: 12,
    answers_changed: 20,
    verdicts_changed: 3,
  },
  grounding: {
    baseline: {
      claims: 200,
      conforming_claims: 150,
      claims_conformance: 0.75,
      techniques: 40,
      conforming_techniques: 36,
      techniques_conformance: 0.9,
    },
    guarded: {
      claims: 0,
      conforming_claims: 0,
      claims_conformance: null,
      techniques: 38,
      conforming_techniques: 38,
      techniques_conformance: 1,
    },
  },
  paired: {
    precision: { better: 11, worse: 2, same: 21 },
    recall: { better: 0, worse: 4, same: 30 },
    verdict: { better: 1, worse: 0, same: 33 },
  },
};

describe("EvaluationPage", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows the backend's numbers for both modes without rescoring them", async () => {
    (getEvaluationResults as Mock).mockResolvedValue([RESULT]);
    render(<EvaluationPage />);

    const table = await screen.findByTestId("comparison");
    const row = (label: string) =>
      within(within(table).getByRole("row", { name: new RegExp(label) }))
        .getAllByRole("cell")
        .map((cell) => cell.textContent);

    expect(row("Technique precision")).toEqual(["61% ±4", "87% ±4"]);
    expect(row("Technique recall")).toEqual(["90%", "85%"]);
    expect(row("Attacks not dismissed")).toEqual(["—", "—"]);
    expect(row("Benign cases called malicious")).toEqual(["25%", "25%"]);
    expect(row("Planted instructions followed")).toEqual(["—", "—"]);
    expect(row("Claims that pass the check")).toEqual(["150 of 200 (75%)", "none made"]);
    expect(row("Techniques that pass the check")).toEqual(["36 of 40 (90%)", "38 of 38 (100%)"]);

    expect(JSON.parse(screen.getByTestId("pr-chart").textContent!)).toEqual([
      { label: "Baseline", precision: 0.61, recall: 0.9 },
      { label: "Guarded", precision: 0.87, recall: 0.85 },
    ]);
  });

  it("shows what the guardrail did and the run-by-run comparison", async () => {
    (getEvaluationResults as Mock).mockResolvedValue([RESULT]);
    render(<EvaluationPage />);

    expect(await screen.findByText("gpt-oss:120b")).toBeInTheDocument();
    expect(screen.getByText(/1 scenarios, 2 of 3 repeats/)).toHaveTextContent("still running");
    expect(screen.getByText("Runs whose first answer broke a rule").nextSibling).toHaveTextContent("21");
    expect(screen.getByText("value_not_in_event").nextSibling).toHaveTextContent("42");
    expect(screen.getByText("Precision: 11 better, 2 worse, 21 same")).toBeInTheDocument();
    expect(screen.getByText("Recall: 0 better, 4 worse, 30 same")).toBeInTheDocument();
  });

  it("colours each verdict by the backend's own right-or-wrong flag", async () => {
    (getEvaluationResults as Mock).mockResolvedValue([RESULT]);
    render(<EvaluationPage />);

    expect((await screen.findByText("SUSPICIOUS")).className).toContain("text-red");
    expect(screen.getByText("BENIGN").className).toContain("text-red");
    for (const right of screen.getAllByText("MALICIOUS").slice(1)) {
      expect(right.className).toContain("text-green");
    }
  });

  it("explains how to produce results when there are none", async () => {
    (getEvaluationResults as Mock).mockResolvedValue([]);
    render(<EvaluationPage />);

    expect(await screen.findByText(/No evaluation has been run yet/)).toBeInTheDocument();
  });
});
