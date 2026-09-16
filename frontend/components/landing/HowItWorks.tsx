import { Eraser, FileSearch, ShieldCheck, type LucideIcon } from "lucide-react";

import { Reveal, Stagger, StaggerItem } from "@/components/motion";

const STEPS: { icon: LucideIcon; title: string; body: string }[] = [
  {
    icon: FileSearch,
    title: "A model reads the telemetry",
    body: "You file an incident against a recording of Windows Sysmon events. A model reads the events that matter and returns a verdict, the ATT&CK techniques it sees, and the claims its conclusion rests on.",
  },
  {
    icon: ShieldCheck,
    title: "Every statement is checked",
    body: "With no model involved, the answer is validated against an ontology and the events it cites. A technique that does not exist, or a claim its event does not show, is a broken rule.",
  },
  {
    icon: Eraser,
    title: "What fails is removed",
    body: "A failing answer goes back to the model for repair, at most twice. Whatever still fails is removed, and the verdict changes if what is left no longer supports it.",
  },
];

export function HowItWorks() {
  return (
    <section id="how-it-works" className="mx-auto w-full max-w-5xl scroll-mt-20 px-6 py-20">
      <Reveal className="mb-10 flex max-w-2xl flex-col gap-3">
        <h2 className="text-3xl font-semibold tracking-tight text-ink">How it works</h2>
        <p className="text-base leading-7 text-ink-muted">
          Language models are good at reading security logs and bad at admitting what they did not see.
          Warrant keeps the reading and checks the rest.
        </p>
      </Reveal>
      <Stagger as="ul" className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {STEPS.map((step, i) => (
          <StaggerItem
            as="li"
            key={step.title}
            className="flex flex-col gap-3 rounded-xl border border-line bg-surface p-6 transition-colors hover:border-line-strong"
          >
            <div className="flex items-center justify-between">
              <span className="flex size-10 items-center justify-center rounded-lg bg-accent-soft text-accent">
                <step.icon aria-hidden="true" className="size-5" />
              </span>
              <span className="font-mono text-xs text-ink-muted">0{i + 1}</span>
            </div>
            <h3 className="text-base font-medium text-ink">{step.title}</h3>
            <p className="text-sm leading-6 text-ink-muted">{step.body}</p>
          </StaggerItem>
        ))}
      </Stagger>
    </section>
  );
}
