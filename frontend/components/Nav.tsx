"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { useAuth } from "@/lib/auth";

const LINKS = [
  { href: "/incidents", label: "Incidents" },
  { href: "/evaluation", label: "Evaluation" },
];

/**
 * A sidebar on wide screens, a top bar with a scrolling link row on narrow
 * ones. `data-app-nav` is what `globals.css` keys the page's left padding on.
 */
export function Nav() {
  const { user, logout } = useAuth();
  const pathname = usePathname();

  if (!user) return null;

  return (
    <nav
      data-app-nav
      className="flex flex-col border-b border-line bg-surface md:fixed md:inset-y-0 md:left-0 md:w-60 md:border-b-0 md:border-r"
    >
      <div className="px-5 pb-2 pt-4 md:pb-6 md:pt-6">
        <span className="text-base font-semibold tracking-tight text-ink">Warrant</span>
      </div>

      <div className="flex gap-1 overflow-x-auto px-3 pb-2 md:flex-1 md:flex-col md:overflow-visible md:pb-0">
        {LINKS.map((link) => {
          const active = pathname?.startsWith(link.href);
          return (
            <Link
              key={link.href}
              href={link.href}
              aria-current={active ? "page" : undefined}
              className={
                active
                  ? "rounded-md bg-accent-soft px-3 py-2 text-sm font-medium text-accent"
                  : "rounded-md px-3 py-2 text-sm text-ink-secondary transition-colors hover:bg-sunken hover:text-ink"
              }
            >
              {link.label}
            </Link>
          );
        })}
      </div>

      <div className="flex items-center justify-between gap-3 border-t border-line px-5 py-3 md:flex-col md:items-start md:gap-1 md:py-4">
        <span className="truncate text-xs text-ink-muted md:w-full" title={user.email}>
          {user.email}
        </span>
        <button
          onClick={() => logout()}
          className="shrink-0 text-sm font-medium text-ink underline-offset-4 hover:underline"
        >
          Log out
        </button>
      </div>
    </nav>
  );
}
