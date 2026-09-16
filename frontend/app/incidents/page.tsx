"use client";

import { ChevronRight, Inbox } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";

import { SeverityBadge, VerdictBadge } from "@/components/Badges";
import { PageHeader, PageShell } from "@/components/PageShell";
import { FIELD, FormError, SubmitButton } from "@/components/forms";
import { Skeleton, Stagger, StaggerItem } from "@/components/motion";
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
      <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-line-strong px-6 py-12 text-center">
        <Inbox aria-hidden="true" className="size-6 text-ink-muted" />
        <p className="text-sm text-ink-muted">No incidents yet. File one with the form on the right.</p>
      </div>
    );
  }

  return (
    <Stagger as="ul" className="flex flex-col gap-2">
      {incidents.map((incident) => (
        <StaggerItem as="li" key={incident.id}>
          <Link
            href={`/incidents/${incident.id}`}
            className="group flex items-center justify-between gap-3 rounded-lg border border-line bg-surface px-4 py-3 transition-colors hover:border-line-strong"
          >
            <div className="flex min-w-0 flex-col gap-1">
              <span className="truncate font-medium text-ink">{incident.title}</span>
              <span className="text-xs text-ink-muted">
                {new Date(incident.created_at).toLocaleString()}
              </span>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <SeverityBadge severity={incident.severity} />
              <VerdictBadge verdict={incident.verdict} />
              <ChevronRight
                aria-hidden="true"
                className="size-4 text-ink-muted transition-transform group-hover:translate-x-0.5"
              />
            </div>
          </Link>
        </StaggerItem>
      ))}
    </Stagger>
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
      toast.success("Incident filed.");
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
      <PageShell>
        <PageHeader title="Incidents" description="Every incident you have filed, newest first." />
        <div className="flex flex-col gap-8 sm:flex-row sm:items-start">
          <section className="min-w-0 flex-1">
            {loadError && <p className="text-sm text-red-600 dark:text-red-400">{loadError}</p>}
            {incidents === null && !loadError ? (
              <div role="status" className="flex flex-col gap-2">
                <span className="sr-only">Loading…</span>
                <Skeleton className="h-16 rounded-lg" />
                <Skeleton className="h-16 rounded-lg" />
                <Skeleton className="h-16 rounded-lg" />
              </div>
            ) : (
              <IncidentList incidents={incidents ?? []} />
            )}
          </section>

          <section className="w-full rounded-xl border border-line bg-surface p-5 sm:w-80">
            <h2 className="mb-4 text-base font-semibold text-ink">File an incident</h2>
            <form onSubmit={handleCreate} className="flex flex-col gap-3">
              <label className="flex flex-col gap-1 text-sm text-ink-secondary">
                Title
                <input required value={title} onChange={(e) => setTitle(e.target.value)} className={FIELD} />
              </label>
              <label className="flex flex-col gap-1 text-sm text-ink-secondary">
                Description
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={3}
                  className={FIELD}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm text-ink-secondary">
                Severity
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as Severity)}
                  className={FIELD}
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
                  className={FIELD}
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
                  className={FIELD}
                />
              </label>
              <FormError message={formError} />
              <SubmitButton busy={submitting} busyLabel="Filing…" disabled={captures.length === 0}>
                File incident
              </SubmitButton>
            </form>
          </section>
        </div>
      </PageShell>
    </div>
  );
}
