"use client";

import * as Tooltip from "@radix-ui/react-tooltip";
import type { ReactNode } from "react";

/**
 * A short note shown when its children are hovered. It carries its own
 * provider so it works wherever it is dropped, including in a test that
 * renders one component on its own.
 */
export function Hint({ text, children, className = "" }: { text: string; children: ReactNode; className?: string }) {
  return (
    <Tooltip.Provider delayDuration={200}>
      <Tooltip.Root>
        <Tooltip.Trigger asChild>
          <span className={`inline-flex min-w-0 ${className}`}>{children}</span>
        </Tooltip.Trigger>
        <Tooltip.Portal>
          <Tooltip.Content
            sideOffset={6}
            className="hint z-50 max-w-xs rounded-md border border-line-strong bg-surface px-2.5 py-1.5 text-xs text-ink-secondary shadow-lg"
          >
            {text}
          </Tooltip.Content>
        </Tooltip.Portal>
      </Tooltip.Root>
    </Tooltip.Provider>
  );
}
