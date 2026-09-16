"use client";

import { motion } from "motion/react";
import Link from "next/link";
import type { ReactNode } from "react";

import { EASE } from "@/components/motion";

/** The card the login and signup forms sit in, over the landing page's backdrop. */
export function AuthCard({ title, children, footer }: { title: string; children: ReactNode; footer: ReactNode }) {
  return (
    <div className="relative isolate flex flex-1 items-center justify-center px-6 py-12">
      <div aria-hidden="true" className="hero-grid absolute inset-0 -z-10" />
      <motion.div
        className="w-full max-w-sm"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: EASE }}
      >
        <Link href="/" className="mb-6 block text-center text-base font-semibold tracking-tight text-ink">
          Warrant
        </Link>
        <div className="rounded-xl border border-line bg-surface p-6 shadow-sm">
          <h1 className="mb-6 text-xl font-semibold text-ink">{title}</h1>
          {children}
        </div>
        <p className="mt-6 text-center text-sm text-ink-muted">{footer}</p>
      </motion.div>
    </div>
  );
}
