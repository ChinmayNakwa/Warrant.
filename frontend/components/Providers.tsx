"use client";

import { MotionConfig } from "motion/react";
import type { ReactNode } from "react";
import { Toaster } from "sonner";

import { Nav } from "@/components/Nav";
import { AuthProvider } from "@/lib/auth";

/** Everything the pages share: the session, the motion settings and the toasts. */
export function Providers({ children }: { children: ReactNode }) {
  return (
    <MotionConfig reducedMotion="user">
      <AuthProvider>
        <Nav />
        {children}
      </AuthProvider>
      <Toaster
        theme="system"
        position="top-right"
        toastOptions={{
          style: {
            background: "var(--surface)",
            color: "var(--ink)",
            border: "1px solid var(--line)",
          },
        }}
      />
    </MotionConfig>
  );
}
