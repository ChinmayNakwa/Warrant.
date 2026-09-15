import Link from "next/link";

export default function Home() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center px-6">
      <main className="flex w-full max-w-2xl flex-col items-center gap-8 text-center">
        <div className="flex flex-col gap-3">
          <h1 className="text-4xl font-semibold tracking-tight text-ink">Warrant</h1>
          <p className="text-lg leading-8 text-ink-muted">
            A model reads the telemetry behind a security incident and says what happened. Warrant
            checks every claim it makes against an ontology and the events themselves, and removes
            what the evidence does not support.
          </p>
        </div>
        <div className="flex flex-col gap-4 text-base font-medium sm:flex-row">
          <Link
            href="/signup"
            className="flex h-12 w-full items-center justify-center rounded-md bg-accent px-6 text-on-accent transition-opacity hover:opacity-90 sm:w-40"
          >
            Sign up
          </Link>
          <Link
            href="/login"
            className="flex h-12 w-full items-center justify-center rounded-md border border-line-strong px-6 text-ink transition-colors hover:bg-sunken sm:w-40"
          >
            Log in
          </Link>
        </div>
      </main>
    </div>
  );
}
