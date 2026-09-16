import { FlaskConical, FolderSearch, LayoutDashboard, type LucideIcon } from "lucide-react";

import { ClaimGraph } from "@/components/ClaimGraph";
import { Reveal, Stagger, StaggerItem } from "@/components/motion";
import type { Claim, Dropped, TelemetryEvent } from "@/lib/api";

// The same made-up incident as the demo above, in the shape a real run has, so
// this is the incident page's own graph component and not a picture of it.
const POWERSHELL = "{5a1c0f3e-71b2-4d09-a001-000000000001}";
const RUNDLL32 = "{5a1c0f3e-71b2-4d09-a001-000000000002}";

const EVENTS: TelemetryEvent[] = [
  { ref: "e1", ts: "2026-01-15T10:09:58", event_type: "process", process_guid: POWERSHELL, image: "powershell.exe" },
  { ref: "e3", ts: "2026-01-15T10:10:00", event_type: "process", process_guid: RUNDLL32, image: "rundll32.exe" },
];

function claim(subject: string, relation: string, object_type: string, object: string, event: string): Claim {
  return { subject_type: "Process", subject, relation, object_type, object, event };
}

const CLAIMS: Claim[] = [
  claim(POWERSHELL, "spawned", "Process", RUNDLL32, "e3"),
  claim(RUNDLL32, "wrote", "File", "C:\\Temp\\lsass.dmp", "e5"),
  claim(RUNDLL32, "exhibits", "Technique", "T1003.001", "e5"),
];

const DROPPED: Dropped[] = [
  {
    kind: "claim",
    item: { ...claim(RUNDLL32, "connected_to", "Network", "10.0.0.5:445", "e9") },
    codes: ["event_missing"],
  },
];

const PAGES: { icon: LucideIcon; title: string; body: string }[] = [
  {
    icon: FolderSearch,
    title: "Incidents",
    body: "File an incident against a capture, pick baseline or guarded, and run it. Each run keeps the first answer, what the check found, and the events the model read.",
  },
  {
    icon: LayoutDashboard,
    title: "Dashboard",
    body: "Your open incidents, your runs, and how many of them had a first answer that broke a rule.",
  },
  {
    icon: FlaskConical,
    title: "Evaluation",
    body: "Baseline against guarded over every labelled scenario: technique precision and recall, verdict accuracy, and how many claims pass the check.",
  },
];

export function ProductPreview() {
  return (
    <section className="border-y border-line bg-surface">
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-10 px-6 py-20">
        <Reveal className="flex max-w-2xl flex-col gap-3">
          <h2 className="text-3xl font-semibold tracking-tight text-ink">See what the answer rests on</h2>
          <p className="text-base leading-7 text-ink-muted">
            Every accepted claim is an edge between two things the telemetry names. A claim that was
            removed stays on the page, dashed, with the rule it broke.
          </p>
        </Reveal>

        <Reveal className="rounded-xl border border-line bg-page p-4 sm:p-5">
          <ClaimGraph claims={CLAIMS} dropped={DROPPED} events={EVENTS} anchorGuid={POWERSHELL} />
        </Reveal>

        <Stagger as="ul" className="grid grid-cols-1 gap-8 md:grid-cols-3">
          {PAGES.map((page) => (
            <StaggerItem as="li" key={page.title} className="flex flex-col gap-2">
              <span className="flex items-center gap-2 text-sm font-medium text-ink">
                <page.icon aria-hidden="true" className="size-4 text-accent" />
                {page.title}
              </span>
              <p className="text-sm leading-6 text-ink-muted">{page.body}</p>
            </StaggerItem>
          ))}
        </Stagger>
      </div>
    </section>
  );
}
