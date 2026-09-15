"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { useAuth } from "./auth";

/**
 * Sends a logged-out visitor to /login. Every protected page uses this, so a
 * logout button only needs to call `logout()`: this effect does the
 * navigating, and a page that also pushed a route would race it.
 */
export function useRequireAuth() {
  const { user, status } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (status === "unauthenticated") router.replace("/login");
  }, [status, router]);

  return { user, status };
}
