import Link from "next/link";

import { AuthActions } from "./AuthActions";

export function LandingHeader() {
  return (
    <header className="sticky top-0 z-20 border-b border-line bg-page/80 backdrop-blur">
      <div className="mx-auto flex h-14 w-full max-w-5xl items-center justify-between gap-4 px-6">
        <Link href="/" className="text-base font-semibold tracking-tight text-ink">
          Warrant
        </Link>
        <nav className="flex items-center gap-5">
          <a
            href="#how-it-works"
            className="hidden text-sm text-ink-secondary transition-colors hover:text-ink sm:block"
          >
            How it works
          </a>
          <AuthActions size="sm" />
        </nav>
      </div>
    </header>
  );
}
