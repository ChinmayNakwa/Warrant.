"use client";

import { FolderOpen, Inbox, Play, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { SeverityBadge, VerdictBadge } from "@/components/Badges";
import { Reveal, Skeleton, Stagger, StaggerItem } from "@/components/motion";
import { PageHeader, PageShell } from "@/components/PageShell";
import { RunsLineChart } from "@/components/charts/RunsLineChart";
import { SeverityBarChart } from "@/components/charts/SeverityBarChart";
import { StatTile } from "@/components/charts/StatTile";
import { VerdictPieChart } from "@/components/charts/VerdictPieChart";
import { ApiError, type DashboardSummary, type Severity, type Verdict, getDashboardSummary } from "@/lib/api";
import { useRequireAuth } from "@/lib/useRequireAuth";

// Every number on this page is a field of the backend's summary. Nothing is
// counted or averaged here.

function RecentIncidentsTable({ incidents }: { incidents: DashboardSummary["recent_incidents"] }) {
  return (
    <table className="w-full text-left text-sm">
      <thead>
        <tr className="border-b border-line text-xs uppercase tracking-wide text-ink-muted">
          <th className="px-5 py-2.5 font-medium">Title</th>
          <th className="px-5 py-2.5 font-medium">Severity</th>
          <th className="px-5 py-2.5 font-medium">Verdict</th>
          <th className="px-5 py-2.5 font-medium">Filed</th>
        </tr>
      </thead>
      <tbody>
        {incidents.map((incident) => (
          <tr key={incident.id} className="border-b border-line transition-colors last:border-0 hover:bg-sunken">
            <td className="px-5 py-3">
              <Link
                href={`/incidents/${incident.id}`}
                className="font-medium text-ink hover:text-accent hover:underline"
              >
                {incident.title}
              </Link>
            </td>
            <td className="px-5 py-3">
              <SeverityBadge severity={incident.severity as Severity} />
            </td>
            <td className="px-5 py-3">
              <VerdictBadge verdict={incident.verdict as Verdict | null} />
            </td>
            <td className="px-5 py-3 tabular-nums text-ink-muted">
              {new Date(incident.created_at).toLocaleDateString()}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function EmptyState() {
  return (
    <Reveal className="flex flex-1 flex-col items-center justify-center gap-4 px-6 py-24 text-center">
      <span className="flex size-12 items-center justify-center rounded-full bg-accent-soft text-accent">
        <Inbox aria-hidden="true" className="size-6" />
      </span>
      <h1 className="text-2xl font-semibold tracking-tight text-ink">No incidents yet</h1>
      <p className="max-w-sm text-sm text-ink-muted">
        File your first incident and run an analysis to see it here.
      </p>
      <Link
        href="/incidents"
        className="flex h-10 items-center rounded-md bg-accent px-5 text-sm font-medium text-on-accent transition-opacity hover:opacity-90"
      >
        File an incident
      </Link>
    </Reveal>
  );
}

/** The dashboard's outline, shown until the summary arrives. */
function LoadingState() {
  return (
    <div role="status" className="flex w-full max-w-6xl flex-col gap-6 px-6 py-8 md:px-10">
      <span className="sr-only">Loading…</span>
      <Skeleton className="h-8 w-40" />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Skeleton className="h-28 rounded-xl" />
        <Skeleton className="h-28 rounded-xl" />
        <Skeleton className="h-28 rounded-xl" />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Skeleton className="h-72 rounded-xl" />
        <Skeleton className="h-72 rounded-xl" />
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { user, status } = useRequireAuth();

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    if (status !== "authenticated") return;
    getDashboardSummary()
      .then(setSummary)
      .catch((err) => setLoadError(err instanceof ApiError ? err.detail : "Failed to load the dashboard."));
  }, [status]);

  if (status !== "authenticated" || !user) {
    return (
      <div className="flex flex-1 items-center justify-center text-ink-muted">
        Loading…
      </div>
    );
  }

  return (
    <div className="flex flex-1 flex-col">
      {loadError && (
        <p className="px-6 py-4 text-sm text-red-600 dark:text-red-400 md:px-10" role="alert">
          {loadError}
        </p>
      )}
      {!summary && !loadError && <LoadingState />}
      {summary && summary.recent_incidents.length === 0 && <EmptyState />}
      {summary && summary.recent_incidents.length > 0 && (
        <PageShell width="wide">
          <PageHeader title="Dashboard" description="Your incidents and what the runs found." />

          <Stagger as="section" className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <StaggerItem>
              <StatTile label="Open incidents" value={summary.open_incidents} icon={FolderOpen} />
            </StaggerItem>
            <StaggerItem>
              <StatTile label="Runs" value={summary.total_runs} icon={Play} />
            </StaggerItem>
            <StaggerItem>
              <StatTile
                label="Runs whose first answer broke a rule"
                value={summary.runs_with_violations}
                icon={TriangleAlert}
              />
            </StaggerItem>
          </Stagger>

          <Stagger as="section" className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <StaggerItem className="rounded-xl border border-line bg-surface p-5">
              <h2 className="mb-3 text-sm font-medium text-ink">Verdicts</h2>
              {Object.keys(summary.verdict_breakdown).length > 0 ? (
                <VerdictPieChart breakdown={summary.verdict_breakdown} />
              ) : (
                <p className="py-16 text-center text-sm text-ink-muted">
                  No completed runs yet.
                </p>
              )}
            </StaggerItem>
            <StaggerItem className="rounded-xl border border-line bg-surface p-5">
              <h2 className="mb-3 text-sm font-medium text-ink">Severity</h2>
              <SeverityBarChart breakdown={summary.severity_breakdown} />
            </StaggerItem>
            <StaggerItem className="rounded-xl border border-line bg-surface p-5 lg:col-span-2">
              <h2 className="mb-3 text-sm font-medium text-ink">Runs, last 30 days (UTC)</h2>
              {summary.runs_over_time.length > 0 ? (
                <RunsLineChart data={summary.runs_over_time} />
              ) : (
                <p className="py-16 text-center text-sm text-ink-muted">No runs in the last 30 days.</p>
              )}
            </StaggerItem>
          </Stagger>

          <Reveal>
            <section className="overflow-x-auto rounded-xl border border-line bg-surface">
              <h2 className="px-5 pb-1 pt-5 text-sm font-medium text-ink">Recent incidents</h2>
              <RecentIncidentsTable incidents={summary.recent_incidents} />
            </section>
          </Reveal>
        </PageShell>
      )}
    </div>
  );
}
