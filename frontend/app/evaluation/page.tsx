"use client";

import { useEffect, useState, type ReactNode } from "react";

import { PageHeader, PageShell } from "@/components/PageShell";
import { Reveal, Skeleton } from "@/components/motion";
import { PrecisionRecallChart } from "@/components/charts/PrecisionRecallChart";
import {
  ApiError,
  type EvaluationResults,
  type GroundingCounts,
  type Spread,
  type Tally,
  getEvaluationResults,
} from "@/lib/api";
import { useRequireAuth } from "@/lib/useRequireAuth";

// This page only formats numbers the backend computed. It never scores anything.

const CARD = "rounded-xl border border-line bg-surface p-5";
const HEADING = "mb-3 text-sm font-medium text-ink";
const TH = "border-b border-line px-3 py-2 text-left text-xs font-medium uppercase tracking-wide text-ink-muted";
const TD = "border-b border-line px-3 py-2 text-sm text-ink-secondary";

function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

/** "83% ±4" when there is a spread across repeats, "83%" otherwise. */
function spread(value: Spread | null | undefined): string {
  if (!value) return "—";
  return value.stdev === null ? pct(value.mean) : `${pct(value.mean)} ±${Math.round(value.stdev * 100)}`;
}

function conforming(count: number, total: number, share: number | null): string {
  return share === null ? "none made" : `${count} of ${total} (${pct(share)})`;
}

function Row({ label, baseline, guarded }: { label: string; baseline: ReactNode; guarded: ReactNode }) {
  return (
    <tr>
      <th scope="row" className={`${TD} text-left font-normal text-ink`}>
        {label}
      </th>
      <td className={`${TD} tabular-nums`}>{baseline}</td>
      <td className={`${TD} tabular-nums`}>{guarded}</td>
    </tr>
  );
}

function ComparisonTable({ result }: { result: EvaluationResults }) {
  const { baseline, guarded } = result.arms;
  const grounding = result.grounding;
  const claims = (g: GroundingCounts) => conforming(g.conforming_claims, g.claims, g.claims_conformance);
  const techniques = (g: GroundingCounts) =>
    conforming(g.conforming_techniques, g.techniques, g.techniques_conformance);

  return (
    <table className="w-full border-collapse" data-testid="comparison">
      <thead>
        <tr>
          <th className={TH} />
          <th className={TH}>Baseline</th>
          <th className={TH}>Guarded</th>
        </tr>
      </thead>
      <tbody>
        <Row label="Technique precision" baseline={spread(baseline.precision)} guarded={spread(guarded.precision)} />
        <Row label="Technique recall" baseline={spread(baseline.recall)} guarded={spread(guarded.recall)} />
        <Row
          label="Verdict accuracy"
          baseline={spread(baseline.verdict_accuracy)}
          guarded={spread(guarded.verdict_accuracy)}
        />
        <Row
          label="Attacks not dismissed"
          baseline={spread(baseline.detection_rate)}
          guarded={spread(guarded.detection_rate)}
        />
        <Row
          label="Benign cases called malicious"
          baseline={spread(baseline.false_alarm_rate)}
          guarded={spread(guarded.false_alarm_rate)}
        />
        <Row
          label="Planted instructions followed"
          baseline={spread(baseline.injection_followed_rate)}
          guarded={spread(guarded.injection_followed_rate)}
        />
        <Row
          label="Claims that pass the check"
          baseline={claims(grounding.baseline)}
          guarded={claims(grounding.guarded)}
        />
        <Row
          label="Techniques that pass the check"
          baseline={techniques(grounding.baseline)}
          guarded={techniques(grounding.guarded)}
        />
      </tbody>
    </table>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex justify-between gap-4 text-sm">
      <span className="text-ink-muted">{label}</span>
      <span className="font-medium tabular-nums text-ink">{value}</span>
    </div>
  );
}

function tally(t: Tally): string {
  return `${t.better} better, ${t.worse} worse, ${t.same} same`;
}

function Verdicts({ verdicts, correct }: { verdicts: string[]; correct: boolean[] }) {
  return (
    <span className="flex flex-wrap gap-x-2">
      {verdicts.map((verdict, i) => (
        <span
          key={i}
          className={correct[i] ? "text-green-700 dark:text-green-400" : "text-red-600 dark:text-red-400"}
        >
          {verdict.replace("_", " ")}
        </span>
      ))}
    </span>
  );
}

function ModelResults({ result }: { result: EvaluationResults }) {
  const { baseline, guarded } = result.arms;
  const g = result.guardrail;
  const rules = Object.entries(g.violations_by_code);

  return (
    <section className="flex flex-col gap-4" data-testid={`results-${result.model}`}>
      <header className="flex flex-col gap-1">
        <h2 className="text-lg font-semibold text-ink">{result.model}</h2>
        <p className="text-sm text-ink-muted">
          {baseline.scenarios.length} scenarios, {result.repeats_done} of {result.repeats} repeats, generated{" "}
          {new Date(result.generated_at).toLocaleString()}
          {!result.complete && " — still running"}
        </p>
      </header>

      <Reveal className={`${CARD} overflow-x-auto`}>
        <ComparisonTable result={result} />
      </Reveal>

      <Reveal className={CARD}>
        <h3 className={HEADING}>Technique precision and recall</h3>
        <PrecisionRecallChart
          data={[
            { label: "Baseline", precision: baseline.precision.mean, recall: baseline.recall.mean },
            { label: "Guarded", precision: guarded.precision.mean, recall: guarded.recall.mean },
          ]}
        />
      </Reveal>

      <Reveal className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className={`${CARD} flex flex-col gap-1`}>
          <h3 className={HEADING}>What the guardrail did</h3>
          <Stat label="Runs" value={g.runs} />
          <Stat label="Runs with no answer" value={g.failed_runs} />
          <Stat label="Runs whose first answer broke a rule" value={g.runs_with_violations} />
          <Stat label="Rules broken in total" value={g.violations} />
          <Stat label="Fixed by repair alone" value={g.runs_fully_repaired} />
          <Stat label="Needed items removed" value={g.runs_enforced} />
          <Stat label="Answers changed" value={g.answers_changed} />
          <Stat label="Verdicts changed" value={g.verdicts_changed} />
        </div>
        <div className={`${CARD} flex flex-col gap-1`}>
          <h3 className={HEADING}>Rules broken</h3>
          {rules.map(([code, count]) => (
            <Stat key={code} label={code} value={count} />
          ))}
          {rules.length === 0 && <p className="text-sm text-ink-muted">None.</p>}
          <h3 className={`${HEADING} mt-4`}>Run by run, guarded against baseline</h3>
          <p className="text-sm text-ink-secondary">Precision: {tally(result.paired.precision)}</p>
          <p className="text-sm text-ink-secondary">Recall: {tally(result.paired.recall)}</p>
          <p className="text-sm text-ink-secondary">Verdict: {tally(result.paired.verdict)}</p>
        </div>
      </Reveal>

      <Reveal className={`${CARD} overflow-x-auto`}>
        <h3 className={HEADING}>Scenarios</h3>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={TH}>Scenario</th>
              <th className={TH}>Expected</th>
              <th className={TH}>Baseline</th>
              <th className={TH}>Guarded</th>
            </tr>
          </thead>
          <tbody>
            {baseline.scenarios.map((scenario, i) => (
              <tr key={`${scenario.capture}/${scenario.scenario}`} className="transition-colors hover:bg-sunken">
                <td className={TD}>
                  <span className="text-ink">{scenario.scenario}</span>{" "}
                  <span className="font-mono text-xs text-ink-muted">{scenario.capture}</span>
                </td>
                <td className={TD}>{scenario.expected_verdict.replace("_", " ")}</td>
                <td className={TD}>
                  <Verdicts verdicts={scenario.verdicts} correct={scenario.verdicts_correct} />
                </td>
                <td className={TD}>
                  <Verdicts
                    verdicts={guarded.scenarios[i].verdicts}
                    correct={guarded.scenarios[i].verdicts_correct}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Reveal>
    </section>
  );
}

export default function EvaluationPage() {
  const { user, status } = useRequireAuth();
  const [results, setResults] = useState<EvaluationResults[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    if (status !== "authenticated") return;
    getEvaluationResults()
      .then(setResults)
      .catch((err) => setLoadError(err instanceof ApiError ? err.detail : "Failed to load the evaluation."));
  }, [status]);

  if (status !== "authenticated" || !user) {
    return <div className="flex flex-1 items-center justify-center text-ink-muted">Loading…</div>;
  }

  return (
    <div className="flex flex-1 flex-col">
      <PageShell>
        <PageHeader
          title="Evaluation"
          description="Every labelled scenario is run in guarded mode and scored twice: the model's first answer is the baseline, the answer left after the check is the guarded result."
        />
        {loadError && (
          <p role="alert" className="text-sm text-red-600 dark:text-red-400">
            {loadError}
          </p>
        )}
        {!results && !loadError && (
          <div role="status" className="flex flex-col gap-4">
            <span className="sr-only">Loading…</span>
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-72 rounded-xl" />
            <Skeleton className="h-64 rounded-xl" />
          </div>
        )}
        {results && results.length === 0 && (
          <p className="text-sm text-ink-muted">
            No evaluation has been run yet. Run{" "}
            <code className="font-mono text-xs">python -m backend.guardrail.evaluation</code> to produce
            results.
          </p>
        )}
        {results?.map((result) => <ModelResults key={result.model} result={result} />)}
      </PageShell>
    </div>
  );
}
