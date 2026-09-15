/** One headline number with its label. */
export function StatTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-line bg-surface px-5 py-4">
      <span className="text-sm text-ink-muted">{label}</span>
      <span className="text-4xl font-semibold tracking-tight text-ink">{value}</span>
    </div>
  );
}
