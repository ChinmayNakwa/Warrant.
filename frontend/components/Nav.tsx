"use client";

import { FlaskConical, FolderSearch, LayoutDashboard, LogOut, type LucideIcon } from "lucide-react";
import { motion } from "motion/react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { Hint } from "@/components/Hint";
import { useAuth } from "@/lib/auth";

const LINKS: { href: string; label: string; icon: LucideIcon }[] = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/incidents", label: "Incidents", icon: FolderSearch },
  { href: "/evaluation", label: "Evaluation", icon: FlaskConical },
];

/**
 * A sidebar on wide screens, a top bar with a scrolling link row on narrow
 * ones. `data-app-nav` is what `globals.css` keys the page's left padding on.
 *
 * `Providers` renders it once for the whole app, so it stays mounted from one
 * page to the next and the highlight can slide between links. It shows only to
 * someone signed in, and only on the pages it links to.
 */
export function Nav() {
  const { user, logout } = useAuth();
  const pathname = usePathname();

  if (!user || !LINKS.some((link) => pathname?.startsWith(link.href))) return null;

  return (
    <nav
      data-app-nav
      className="flex flex-col border-b border-line bg-surface md:fixed md:inset-y-0 md:left-0 md:w-60 md:border-b-0 md:border-r"
    >
      <div className="px-5 pb-2 pt-4 md:pb-6 md:pt-6">
        <Link href="/" className="text-base font-semibold tracking-tight text-ink">
          Warrant
        </Link>
      </div>

      <div className="flex gap-1 overflow-x-auto px-3 pb-2 md:flex-1 md:flex-col md:overflow-visible md:pb-0">
        {LINKS.map((link) => {
          const active = pathname?.startsWith(link.href);
          return (
            <Link
              key={link.href}
              href={link.href}
              aria-current={active ? "page" : undefined}
              className={`relative flex shrink-0 items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors ${
                active ? "font-medium text-accent" : "text-ink-secondary hover:bg-sunken hover:text-ink"
              }`}
            >
              {active && (
                <motion.span
                  layoutId="nav-active"
                  className="absolute inset-0 rounded-md bg-accent-soft"
                  transition={{ type: "spring", stiffness: 500, damping: 40 }}
                />
              )}
              <link.icon aria-hidden="true" className="relative size-4" />
              <span className="relative">{link.label}</span>
            </Link>
          );
        })}
      </div>

      <div className="flex items-center justify-between gap-3 border-t border-line px-5 py-3 md:flex-col md:items-start md:gap-2 md:py-4">
        <Hint text={user.email} className="md:w-full">
          <span className="truncate text-xs text-ink-muted">{user.email}</span>
        </Hint>
        <button
          onClick={() => logout()}
          className="group inline-flex shrink-0 items-center gap-1.5 text-sm font-medium text-ink-secondary transition-colors hover:text-ink"
        >
          <LogOut aria-hidden="true" className="size-3.5 transition-transform group-hover:-translate-x-0.5" />
          Log out
        </button>
      </div>
    </nav>
  );
}
