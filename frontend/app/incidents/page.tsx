"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";

import { Nav } from "@/components/Nav";
import { SeverityBadge, VerdictBadge } from "@/components/Badges";
import {
  ApiError,
  type Capture,
  type Incident,
  type Severity,
  createIncident,
  listCaptures,
  listIncidents,
} from "@/lib/api";
import { useRequireAuth } from "@/lib/useRequireAuth";

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

function IncidentList({ incidents }: { incidents: Incident[] }) {
  if (incidents.length === 0) {
    return (
      <p className="text-sm text-ink-muted">
        No incidents yet. File one with the form on the right.
      </p>
    );
  }

  return (
    <ul className="flex flex-col gap-2">
      {incidents.map((incident) => (
        <li key={incident.id}>
          <Link
            href={`/incidents/${incident.id}`}
            className="flex items-center justify-between rounded-lg border border-line bg-surface px-4 py-3 transition-colors hover:border-line-strong"
          >
            <div className="flex flex-col gap-1">
              <span className="font-medium text-ink">{incident.title}</span>
              <span className="text-xs text-ink-muted">
                {new Date(incident.created_at).toLocaleString()}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={incident.severity} />
              <VerdictBadge verdict={incident.verdict} />
            </div>
          </Link>
        </li>
      ))}
    </ul>
  );
}

export default function IncidentsPage() {
  const { user, status } = useRequireAuth();
  const router = useRouter();

  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [captures, setCaptures] = useState<Capture[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [captureName, setCaptureName] = useState("");
  const [anchorGuid, setAnchorGuid] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (status !== "authenticated") return;
    Promise.all([listIncidents(), listCaptures()])
      .then(([incidentList, captureList]) => {
        setIncidents(incidentList);
        setCaptures(captureList);
        if (captureList.length > 0) setCaptureName((c) => c || captureList[0].name);
      })
      .catch((err) => setLoadError(err instanceof ApiError ? err.detail : "Failed to load incidents."));
  }, [status]);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);
    try {
      const incident = await createIncident({
        title,
        description,
        severity,
        capture_name: captureName,
        anchor_process_guid: anchorGuid || undefined,
      });
      router.push(`/incidents/${incident.id}`);
    } catch (err) {
      setFormError(err instanceof ApiError ? err.detail : "Something went wrong. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  if (status !== "authenticated" || !user) {
    return (
      <div className="flex flex-1 items-center justify-center text-ink-muted">
        Loading…
      </div>
    );
  }

  return (
    <div className="flex flex-1 flex-col">
      <Nav />
      <div className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-8 px-6 py-10 sm:flex-row">
        <section className="flex-1">
          <h1 className="mb-4 text-xl font-semibold text-ink">Incidents</h1>
          {loadError && <p className="text-sm text-red-600 dark:text-red-400">{loadError}</p>}
          {incidents === null && !loadError ? (
            <p className="text-sm text-ink-muted">Loading…</p>
          ) : (
            <IncidentList incidents={incidents ?? []} />
          )}
        </section>

        <section className="w-full sm:w-80">
          <h2 className="mb-4 text-lg font-semibold text-ink">File an incident</h2>
          <form onSubmit={handleCreate} className="flex flex-col gap-3">
            <label className="flex flex-col gap-1 text-sm text-ink-secondary">
              Title
              <input
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="rounded-md border border-line-strong bg-surface px-3 py-2 text-ink outline-none focus:border-accent"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm text-ink-secondary">
              Description
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                className="rounded-md border border-line-strong bg-surface px-3 py-2 text-ink outline-none focus:border-accent"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm text-ink-secondary">
              Severity
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity)}
                className="rounded-md border border-line-strong bg-surface px-3 py-2 text-ink outline-none focus:border-accent"
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm text-ink-secondary">
              Capture
              <select
                required
                value={captureName}
                onChange={(e) => setCaptureName(e.target.value)}
                className="rounded-md border border-line-strong bg-surface px-3 py-2 text-ink outline-none focus:border-accent"
              >
                {captures.length === 0 && <option value="">No captures available</option>}
                {captures.map((c) => (
                  <option key={c.name} value={c.name}>
                    {c.name} ({c.event_count} events)
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm text-ink-secondary">
              Anchor process GUID (optional)
              <input
                value={anchorGuid}
                onChange={(e) => setAnchorGuid(e.target.value)}
                placeholder="leave blank to use the rarest events"
                className="rounded-md border border-line-strong bg-surface px-3 py-2 text-ink outline-none focus:border-accent"
              />
            </label>
            {formError && (
              <p data-testid="form-error" role="alert" className="text-sm text-red-600 dark:text-red-400">
                {formError}
              </p>
            )}
            <button
              type="submit"
              disabled={submitting || captures.length === 0}
              className="mt-2 h-11 rounded-md bg-accent font-medium text-on-accent transition-opacity hover:opacity-90 disabled:opacity-60"
            >
              {submitting ? "Filing…" : "File incident"}
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}
