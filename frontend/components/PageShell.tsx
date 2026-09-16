"use client";

import { motion } from "motion/react";
import type { ReactNode } from "react";

import { EASE } from "@/components/motion";

const WIDTHS = {
  narrow: "max-w-4xl",
  medium: "max-w-5xl",
  wide: "max-w-6xl",
};

/** The padded column every signed-in page puts its content in. It fades up once, when the page opens. */
export function PageShell({ width = "medium", children }: { width?: keyof typeof WIDTHS; children: ReactNode }) {
  return (
    <motion.div
      className={`flex w-full flex-1 flex-col gap-6 px-6 py-8 md:px-10 ${WIDTHS[width]}`}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: EASE }}
    >
      {children}
    </motion.div>
  );
}

/** A page's title, with what sits beside it (`children`) and a line under it. */
export function PageHeader({
  title,
  description,
  children,
}: {
  title: string;
  description?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-1.5">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{title}</h1>
        {children}
      </div>
      {description && <p className="max-w-2xl text-sm text-ink-muted">{description}</p>}
    </header>
  );
}
