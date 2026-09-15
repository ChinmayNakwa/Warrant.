import type { ColorScheme } from "@/lib/useColorScheme";
import type { Severity, Verdict } from "@/lib/api";

/** Grid, axis and text colours for charts, plus the two series colours. */
export interface ChartChrome {
  grid: string;
  axis: string;
  textMuted: string;
  textSecondary: string;
  surface: string;
  series1: string;
  series2: string;
}

const CHROME: Record<ColorScheme, ChartChrome> = {
  light: {
    grid: "#e1e0d9",
    axis: "#c3c2b7",
    textMuted: "#898781",
    textSecondary: "#52514e",
    surface: "#fcfcfb",
    series1: "#2a78d6",
    series2: "#eb6834",
  },
  dark: {
    grid: "#2c2c2a",
    axis: "#383835",
    textMuted: "#898781",
    textSecondary: "#c3c2b7",
    surface: "#1a1a19",
    series1: "#3987e5",
    series2: "#d95926",
  },
};

export function chartChrome(scheme: ColorScheme): ChartChrome {
  return CHROME[scheme];
}

// Verdicts keep the meaning their badges have: red is bad, green is good.
const VERDICT_COLORS: Record<Verdict, string> = {
  MALICIOUS: "#d03b3b",
  SUSPICIOUS: "#ec835a",
  BENIGN: "#0ca30c",
  INSUFFICIENT_EVIDENCE: "#fab219",
};

export function verdictColor(verdict: string): string {
  return VERDICT_COLORS[verdict as Verdict] ?? CHROME.light.textMuted;
}

// One blue, darker as severity rises.
const SEVERITY_COLORS: Record<Severity, string> = {
  low: "#86b6ef",
  medium: "#3987e5",
  high: "#256abf",
  critical: "#184f95",
};

export function severityColor(severity: string): string {
  return SEVERITY_COLORS[severity as Severity] ?? CHROME.light.textMuted;
}
