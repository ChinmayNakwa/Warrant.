import { Hint } from "@/components/Hint";
import type { Severity, Verdict } from "@/lib/api";

const SEVERITY_CLASSES: Record<Severity, string> = {
  low: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  critical: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
};

const VERDICT_CLASSES: Record<Verdict, string> = {
  MALICIOUS: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  SUSPICIOUS: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  BENIGN: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300",
  INSUFFICIENT_EVIDENCE: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

function Pill({ text, className }: { text: string; className: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${className}`}
    >
      {text}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Pill text={severity} className={SEVERITY_CLASSES[severity]} />;
}

export function VerdictBadge({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) {
    return (
      <Hint text="No run has given a verdict yet.">
        <Pill text="pending" className="bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400" />
      </Hint>
    );
  }
  return <Pill text={verdict.replace("_", " ")} className={VERDICT_CLASSES[verdict]} />;
}
