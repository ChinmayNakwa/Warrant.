import type { LucideIcon } from "lucide-react";

import { CountUp } from "@/components/motion";

/** One headline number with its label. The number counts up when the tile appears. */
export function StatTile({ label, value, icon: Icon }: { label: string; value: number; icon: LucideIcon }) {
  return (
    <div className="flex h-full flex-col gap-2 rounded-xl border border-line bg-surface px-5 py-4 transition-colors hover:border-line-strong">
      <span className="flex items-start justify-between gap-3 text-sm text-ink-muted">
        {label}
        <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      </span>
      <span className="mt-auto text-4xl font-semibold tracking-tight text-ink">
        <CountUp value={value} />
      </span>
    </div>
  );
}
