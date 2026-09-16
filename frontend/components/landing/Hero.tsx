import { Stagger, StaggerItem } from "@/components/motion";

import { AuthActions } from "./AuthActions";

export function Hero() {
  return (
    <section className="relative isolate">
      <div aria-hidden="true" className="hero-grid absolute inset-0 -z-10" />
      <Stagger className="mx-auto flex w-full max-w-3xl flex-col items-center gap-6 px-6 pb-12 pt-20 text-center sm:pt-28">
        <StaggerItem>
          <span className="rounded-full border border-line bg-surface px-3 py-1 text-xs font-medium text-ink-secondary">
            An ontology guardrail for AI incident analysis
          </span>
        </StaggerItem>
        <StaggerItem>
          <h1 className="text-balance text-4xl font-semibold tracking-tight text-ink sm:text-6xl">
            Every claim, checked against the evidence.
          </h1>
        </StaggerItem>
        <StaggerItem>
          <p className="max-w-2xl text-pretty text-lg leading-8 text-ink-muted">
            A model reads the telemetry behind a security incident and says what happened. Warrant
            checks every claim it makes against an ontology and the events themselves, and removes
            what the evidence does not support.
          </p>
        </StaggerItem>
        <StaggerItem>
          <AuthActions className="mt-2" />
        </StaggerItem>
      </Stagger>
    </section>
  );
}
