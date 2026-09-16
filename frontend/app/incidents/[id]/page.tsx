"use client";

import { LoaderCircle, Play } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { ClaimGraph } from "@/components/ClaimGraph";
import { PageHeader, PageShell } from "@/components/PageShell";
import { SeverityBadge, VerdictBadge } from "@/components/Badges";
import { Hint } from "@/components/Hint";
import { Skeleton, Stagger, StaggerItem } from "@/components/motion";
import {
  ApiError,
  type Answer,
  type Incident,
  type RunDetail,
  type RunMode,
  type RunSummary,
  createRun,
  getIncident,
  getRun,
  listRuns,
} from "@/lib/api";
import { useRequireAuth } from "@/lib/useRequireAuth";

const MODES: { mode: RunMode; label: string; hint: string }[] = [
  { mode: "baseline", label: "Baseline", hint: "Keep the model's answer as given." },
  { mode: "guarded", label: "Guarded", hint: "Check the answer, ask for repairs, remove what still fails." },
];

const CARD = "rounded-xl border border-line bg-surface p-5";
const HEADING = "mb-3 text-sm font-medium text-ink";

/** Techniques and claims of one answer. Everything in it is model text. */
function AnswerBody({ answer }: { answer: Answer }) {
  return (
    <div className="flex flex-col gap-4 text-sm">
      {answer.summary && <p className="text-ink-secondary">{answer.summary}</p>}
      <div>
        <h4 className="mb-1 text-xs uppercase tracking-wide text-ink-muted">
          Techniques ({answer.techniques.length})
        </h4>
        <ul className="flex flex-col gap-1">
          {answer.techniques.map((t, i) => (
            <li key={i} className="font-mono text-xs text-ink-secondary">
              {t.id} <span className="text-ink-muted">cites {t.events.join(", ") || "nothing"}</span>
            </li>
          ))}
          {answer.techniques.length === 0 && <li className="text-ink-muted">None.</li>}
        </ul>
      </div>
      <div>
        <h4 className="mb-1 text-xs uppercase tracking-wide text-ink-muted">
          Claims ({answer.claims.length})
        </h4>
        <ul className="flex flex-col gap-1">
          {answer.claims.map((c, i) => (
            <li key={i} className="break-all font-mono text-xs text-ink-secondary">
              ({c.subject_type}) {c.subject} —{c.relation}→ {c.object} ({c.object_type}){" "}
              <span className="text-ink-muted">cites {c.event}</span>
            </li>
          ))}
          {answer.claims.length === 0 && <li className="text-ink-muted">None.</li>}
        </ul>
      </div>
    </div>
  );
}

/** What the check found in the first answer, and what guarded mode did about it. */
function CheckResult({ run }: { run: RunDetail }) {
  if (run.violations.length === 0) {
    return <p className="text-sm text-ink-secondary">The model&apos;s first answer passed every rule.</p>;
  }
  return (
    <div className="flex flex-col gap-4 text-sm">
      <div>
        <p className="mb-2 text-ink-secondary">
          The model&apos;s first answer broke {run.violation_count} rule
          {run.violation_count === 1 ? "" : "s"}:
        </p>
        <ul className="flex flex-col gap-1">
          {run.violations.map((v, i) => (
            <li key={i} className="text-ink-secondary">
              <code className="font-mono text-xs text-amber-700 dark:text-amber-400">{v.path}</code>{" "}
              {v.message}
            </li>
          ))}
        </ul>
      </div>
      {run.mode === "baseline" ? (
        <p className="text-ink-muted">Baseline mode records these and changes nothing.</p>
      ) : (
        <div>
          <p className="mb-2 text-ink-secondary">
            Asked the model to repair it {run.repair_rounds} time{run.repair_rounds === 1 ? "" : "s"}, then
            removed or changed {run.dropped_count} item{run.dropped_count === 1 ? "" : "s"}.
          </p>
          <ul className="flex flex-col gap-1">
            {run.dropped.map((d, i) => (
              <li key={i} className="break-all font-mono text-xs text-ink-secondary">
                {d.kind} {JSON.stringify(d.item)} <span className="text-ink-muted">({d.codes.join(", ")})</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function RunView({ run, anchorGuid }: { run: RunDetail; anchorGuid: string | null }) {
  return (
    <Stagger className="flex flex-col gap-4">
      <StaggerItem className={CARD}>
        <div className="flex flex-wrap items-center gap-3 text-sm text-ink-muted">
          <VerdictBadge verdict={run.verdict} />
          {run.confidence !== null && <span>confidence {run.confidence.toFixed(2)}</span>}
          <span>{run.mode}</span>
          <span>{run.model}</span>
          <span>
            {run.llm_calls} model call{run.llm_calls === 1 ? "" : "s"}
          </span>
        </div>
        {run.note && <p className="mt-3 text-sm text-ink-secondary">{run.note}</p>}
      </StaggerItem>

      {run.first_answer && (
        <StaggerItem className={CARD}>
          <h3 className={HEADING}>Check</h3>
          <CheckResult run={run} />
        </StaggerItem>
      )}

      {run.answer && (
        <StaggerItem className={CARD}>
          <h3 className={HEADING}>Accepted answer</h3>
          <div className="flex flex-col gap-4">
            <ClaimGraph
              claims={run.answer.claims}
              dropped={run.dropped}
              events={run.events}
              anchorGuid={anchorGuid}
            />
            <AnswerBody answer={run.answer} />
          </div>
        </StaggerItem>
      )}

      {run.first_answer && run.mode === "guarded" && run.violations.length > 0 && (
        <StaggerItem>
          <details className={CARD}>
            <summary className="cursor-pointer text-sm font-medium text-ink">First answer, before the check</summary>
            <div className="mt-4">
              <AnswerBody answer={run.first_answer} />
            </div>
          </details>
        </StaggerItem>
      )}

      <StaggerItem>
        <details className={CARD}>
          <summary className="cursor-pointer text-sm font-medium text-ink">
            Telemetry the model read ({run.events.length} events)
          </summary>
          <ul className="mt-4 flex flex-col gap-2">
            {run.events.map((event) => (
              <li key={event.ref} className="rounded-md border border-line p-2">
                <pre className="overflow-x-auto text-xs text-ink-muted">{JSON.stringify(event, null, 2)}</pre>
              </li>
            ))}
          </ul>
        </details>
      </StaggerItem>
    </Stagger>
  );
}

export default function IncidentDetailPage() {
  const { user, status } = useRequireAuth();
  const incidentId = useParams<{ id: string }>().id;

  const [incident, setIncident] = useState<Incident | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedRun, setSelectedRun] = useState<RunDetail | null>(null);
  const [mode, setMode] = useState<RunMode>("guarded");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (status !== "authenticated") return;
    Promise.all([getIncident(incidentId), listRuns(incidentId)])
      .then(async ([inc, runList]) => {
        setIncident(inc);
        setRuns(runList);
        if (runList.length > 0) setSelectedRun(await getRun(runList[0].id));
      })
      .catch((err) => {
        if (err instanceof ApiError && err.status === 404) {
          setNotFound(true);
        } else {
          setError(err instanceof ApiError ? err.detail : "Failed to load this incident.");
        }
      });
  }, [status, incidentId]);

  async function handleRun() {
    setRunning(true);
    setError(null);
    try {
      setSelectedRun(await createRun(incidentId, mode));
      const [inc, runList] = await Promise.all([getIncident(incidentId), listRuns(incidentId)]);
      setIncident(inc);
      setRuns(runList);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "The run failed to start.");
    } finally {
      setRunning(false);
    }
  }

  function selectRun(runId: string) {
    getRun(runId)
      .then(setSelectedRun)
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Failed to load this run."));
  }

  if (status !== "authenticated" || !user) {
    return <div className="flex flex-1 items-center justify-center text-ink-muted">Loading…</div>;
  }

  if (notFound) {
    return (
      <div className="flex flex-1 items-center justify-center text-ink-muted">Incident not found.</div>
    );
  }

  return (
    <div className="flex flex-1 flex-col">
      <PageShell width="narrow">
        {error && (
          <p role="alert" className="text-sm text-red-600 dark:text-red-400">
            {error}
          </p>
        )}
        {!incident && !error && (
          <div role="status" className="flex flex-col gap-6">
            <span className="sr-only">Loading…</span>
            <Skeleton className="h-8 w-64" />
            <Skeleton className="h-24 rounded-xl" />
            <Skeleton className="h-64 rounded-xl" />
          </div>
        )}
        {incident && (
          <>
            <PageHeader title={incident.title} description={incident.description || undefined}>
              <SeverityBadge severity={incident.severity} />
              <VerdictBadge verdict={incident.verdict} />
            </PageHeader>

            <section className={`${CARD} flex flex-wrap items-center gap-4`}>
              <fieldset className="flex flex-col gap-2">
                <legend className="sr-only">Mode</legend>
                {MODES.map((m) => (
                  <label key={m.mode} className="flex items-baseline gap-2 text-sm text-ink">
                    <input
                      type="radio"
                      name="mode"
                      checked={mode === m.mode}
                      onChange={() => setMode(m.mode)}
                    />
                    <span className="font-medium">{m.label}</span>
                    <span className="text-ink-muted">{m.hint}</span>
                  </label>
                ))}
              </fieldset>
              <button
                onClick={handleRun}
                disabled={running}
                className="ml-auto inline-flex h-10 items-center gap-2 rounded-md bg-accent px-5 text-sm font-medium text-on-accent transition hover:opacity-90 active:scale-[0.98] disabled:opacity-60"
              >
                {running ? (
                  <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
                ) : (
                  <Play aria-hidden="true" className="size-4" />
                )}
                {running ? "Running…" : "Run analysis"}
              </button>
            </section>

            <AnimatePresence>
              {running && (
                <motion.p
                  role="status"
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  className="overflow-hidden text-sm text-ink-muted"
                >
                  Waiting for the model. The page updates when the run finishes.
                </motion.p>
              )}
            </AnimatePresence>

            {runs.length > 1 && (
              <div className="flex flex-wrap gap-2">
                {runs.map((r) => {
                  const selected = selectedRun?.id === r.id;
                  return (
                    <Hint key={r.id} text={MODES.find((m) => m.mode === r.mode)?.hint ?? r.mode}>
                      <button
                        onClick={() => selectRun(r.id)}
                        aria-pressed={selected}
                        className={`relative rounded-md border px-3 py-1 text-xs transition-colors ${
                          selected
                            ? "border-transparent font-medium text-accent"
                            : "border-line text-ink-secondary hover:bg-sunken"
                        }`}
                      >
                        {selected && (
                          <motion.span
                            layoutId="run-active"
                            className="absolute inset-0 rounded-md bg-accent-soft"
                            transition={{ type: "spring", stiffness: 500, damping: 40 }}
                          />
                        )}
                        <span className="relative">
                          {r.mode} · {new Date(r.started_at).toLocaleString()}
                        </span>
                      </button>
                    </Hint>
                  );
                })}
              </div>
            )}

            {selectedRun ? (
              <RunView key={selectedRun.id} run={selectedRun} anchorGuid={incident.anchor_process_guid} />
            ) : (
              <p className="text-sm text-ink-muted">No runs yet. Pick a mode and run one above.</p>
            )}
          </>
        )}
      </PageShell>
    </div>
  );
}
