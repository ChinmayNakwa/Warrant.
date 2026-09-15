"use client";

import { useEffect, useState } from "react";

export type ColorScheme = "light" | "dark";

/**
 * Recharts renders raw SVG fill/stroke values, not Tailwind classes, so chart
 * color needs the OS scheme as a plain string to pick between the light/dark
 * steps in `components/charts/colors.ts`. This app has no manual theme
 * toggle (see `app/globals.css`) - `prefers-color-scheme` is the only signal.
 */
function prefersDark(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function useColorScheme(): ColorScheme {
  const [scheme, setScheme] = useState<ColorScheme>(() => (prefersDark() ? "dark" : "light"));

  useEffect(() => {
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (e: MediaQueryListEvent) => setScheme(e.matches ? "dark" : "light");
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  return scheme;
}
