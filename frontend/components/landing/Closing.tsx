import { ArrowUpRight } from "lucide-react";

import { Reveal } from "@/components/motion";

import { AuthActions } from "./AuthActions";

const REPO = "https://github.com/ChinmayNakwa/Warrant.";

export function ClosingCta() {
  return (
    <section className="mx-auto w-full max-w-5xl px-6 py-20">
      <Reveal className="flex flex-col items-center gap-5 text-center">
        <h2 className="text-balance text-3xl font-semibold tracking-tight text-ink">
          Run it on an incident of your own.
        </h2>
        <p className="max-w-xl text-base leading-7 text-ink-muted">
          Run the same incident in baseline and in guarded mode, and see what the check changed.
        </p>
        <AuthActions className="mt-1" />
      </Reveal>
    </section>
  );
}

export function LandingFooter() {
  return (
    <footer className="border-t border-line">
      <div className="mx-auto flex w-full max-w-5xl flex-wrap items-center justify-between gap-3 px-6 py-6 text-sm text-ink-muted">
        <span>
          <span className="font-medium text-ink">Warrant</span> · MIT licence
        </span>
        <a
          href={REPO}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1 transition-colors hover:text-ink"
        >
          Source on GitHub
          <ArrowUpRight aria-hidden="true" className="size-3.5" />
        </a>
      </div>
    </footer>
  );
}
