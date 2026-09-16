"use client";

import { Check, Circle, LoaderCircle, RotateCcw, X } from "lucide-react";
import { AnimatePresence, motion, useInView } from "motion/react";
import { useEffect, useRef, useState } from "react";

import { EASE, Reveal, useStill } from "@/components/motion";

// A made-up answer, written to look like a real one. Two of its five
// statements break a rule: one cites an event that was never recorded, the
// other names a technique that does not exist.
const ROWS: { kind: "claim" | "technique"; text: string; cites: string; broke?: { code: string; why: string } }[] = [
  { kind: "claim", text: "powershell.exe —spawned→ rundll32.exe", cites: "e3" },
  {
    kind: "claim",
    text: "rundll32.exe —connected_to→ 10.0.0.5:445",
    cites: "e9",
    broke: { code: "event_missing", why: "e9 is not in the telemetry" },
  },
  { kind: "claim", text: "rundll32.exe —wrote→ C:\\Temp\\lsass.dmp", cites: "e5" },
  {
    kind: "technique",
    text: "T9999",
    cites: "e3",
    broke: { code: "technique_unknown", why: "not a MITRE ATT&CK technique id" },
  },
  { kind: "technique", text: "T1003.001", cites: "e5" },
];

// The demo is a clock. Rows appear one per tick, then are checked one per
// tick, then the ones that failed are removed.
const CHECK_FROM = ROWS.length;
const ALL_CHECKED = ROWS.length * 2;
const REMOVED = ALL_CHECKED + 1;

function tickLength(tick: number): number {
  if (tick < CHECK_FROM) return 320;
  if (tick < ALL_CHECKED) return 650;
  return 1100;
}

const PHASES = ["The model's first answer", "Checking each statement", "The accepted answer"];

function phaseOf(tick: number): number {
  if (tick < CHECK_FROM) return 0;
  if (tick < REMOVED) return 1;
  return 2;
}

function StatusIcon({ state }: { state: "waiting" | "checking" | "passed" | "broke" }) {
  const size = "size-4 shrink-0";
  if (state === "checking") return <LoaderCircle aria-hidden="true" className={`${size} animate-spin text-accent`} />;
  if (state === "passed") return <Check aria-hidden="true" className={`${size} text-green-700 dark:text-green-400`} />;
  if (state === "broke") return <X aria-hidden="true" className={`${size} text-amber-700 dark:text-amber-400`} />;
  return <Circle aria-hidden="true" className={`${size} text-line-strong`} />;
}

/**
 * The landing page's worked example: an answer arrives, each statement is
 * checked, and the two that fail are removed. It plays once when scrolled into
 * view and can be replayed. With reduced motion it shows the end state only.
 */
export function ClaimDemo() {
  const still = useStill();
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { amount: 0.4 });
  const [clock, setClock] = useState(0);
  const tick = still ? REMOVED : clock;

  useEffect(() => {
    if (still || !inView || clock >= REMOVED) return;
    const timer = setTimeout(() => setClock((c) => c + 1), tickLength(clock));
    return () => clearTimeout(timer);
  }, [clock, inView, still]);

  const phase = phaseOf(tick);
  const kept = ROWS.filter((row) => !row.broke).length;

  return (
    <section className="mx-auto w-full max-w-3xl px-6 pb-8">
      <Reveal>
        <figure
          ref={ref}
          className="overflow-hidden rounded-xl border border-line bg-surface shadow-sm"
          aria-label="An example: of five statements in a model's answer, two break a rule and are removed."
        >
          <div className="flex items-center justify-between gap-4 border-b border-line px-5 py-3">
            <div className="flex items-center gap-2 text-sm">
              <span className="font-medium text-ink">LSASS dump</span>
              <span className="text-ink-muted">guarded run</span>
            </div>
            <ol className="flex items-center gap-1.5" aria-hidden="true">
              {PHASES.map((label, i) => (
                <li
                  key={label}
                  className={`h-1.5 rounded-full transition-all duration-500 ${
                    i === phase ? "w-6 bg-accent" : i < phase ? "w-1.5 bg-accent" : "w-1.5 bg-line-strong"
                  }`}
                />
              ))}
            </ol>
          </div>

          <div className="flex min-h-[19rem] flex-col gap-3 px-5 py-4" aria-hidden="true">
            <div className="h-5 text-xs font-medium uppercase tracking-wide text-ink-muted">
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={phase}
                  className="block"
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  transition={{ duration: 0.2 }}
                >
                  {PHASES[phase]}
                </motion.span>
              </AnimatePresence>
            </div>

            <ul className="flex flex-col">
              <AnimatePresence initial={false}>
                {ROWS.map((row, i) => {
                  if (tick < i || (row.broke && tick >= REMOVED)) return null;
                  const checked = tick > CHECK_FROM + i;
                  const state =
                    tick < CHECK_FROM + i ? "waiting" : !checked ? "checking" : row.broke ? "broke" : "passed";
                  return (
                    <motion.li
                      key={row.text}
                      layout
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.35, ease: EASE }}
                      className="overflow-hidden"
                    >
                      <div className="flex items-start gap-3 py-1.5">
                        <span className="mt-0.5">
                          <StatusIcon state={state} />
                        </span>
                        <div className="flex min-w-0 flex-col gap-0.5">
                          <span
                            className={`break-all font-mono text-xs transition-colors duration-300 ${
                              state === "broke" ? "text-ink-muted line-through" : "text-ink-secondary"
                            }`}
                          >
                            <span className="text-ink-muted">{row.kind}</span> {row.text}{" "}
                            <span className="text-ink-muted">cites {row.cites}</span>
                          </span>
                          {state === "broke" && row.broke && (
                            <motion.span
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              className="text-xs text-ink-muted"
                            >
                              <code className="font-mono text-amber-700 dark:text-amber-400">{row.broke.code}</code>{" "}
                              {row.broke.why}
                            </motion.span>
                          )}
                        </div>
                      </div>
                    </motion.li>
                  );
                })}
              </AnimatePresence>
            </ul>

            {tick >= REMOVED && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.4, delay: 0.3 }}
                className="mt-auto flex flex-wrap items-center justify-between gap-3 border-t border-line pt-3 text-sm"
              >
                <span className="text-ink-secondary">
                  {kept} of {ROWS.length} statements kept, {ROWS.length - kept} removed.
                </span>
                <span className="inline-flex items-center rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-medium text-red-800 dark:bg-red-950 dark:text-red-300">
                  MALICIOUS
                </span>
              </motion.div>
            )}
          </div>

          <figcaption className="flex items-center justify-between gap-4 border-t border-line bg-sunken px-5 py-2.5 text-xs text-ink-muted">
            <span>An illustrative example, not a recorded run.</span>
            {!still && (
              <button
                type="button"
                onClick={() => setClock(0)}
                disabled={clock < REMOVED}
                className="inline-flex items-center gap-1.5 font-medium text-ink-secondary transition-opacity hover:text-ink disabled:opacity-0"
              >
                <RotateCcw aria-hidden="true" className="size-3.5" />
                Replay
              </button>
            )}
          </figcaption>
        </figure>
      </Reveal>
    </section>
  );
}
