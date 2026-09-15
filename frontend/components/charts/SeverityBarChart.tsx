"use client";

import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { Severity } from "@/lib/api";
import { useColorScheme } from "@/lib/useColorScheme";
import { chartChrome, severityColor } from "./colors";

const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];

/** Incidents per severity, always in low-to-critical order. */
export function SeverityBarChart({ breakdown }: { breakdown: Record<string, number> }) {
  const scheme = useColorScheme();
  const chrome = chartChrome(scheme);
  const data = SEVERITY_ORDER.filter((s) => breakdown[s] !== undefined).map((severity) => ({
    severity,
    count: breakdown[severity],
  }));

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke={chrome.grid} />
        <XAxis
          dataKey="severity"
          stroke={chrome.axis}
          tick={{ fill: chrome.textMuted, fontSize: 12 }}
          tickLine={false}
        />
        <YAxis
          allowDecimals={false}
          stroke={chrome.axis}
          tick={{ fill: chrome.textMuted, fontSize: 12 }}
          tickLine={false}
          width={32}
        />
        <Tooltip
          cursor={{ fill: chrome.grid, opacity: 0.4 }}
          contentStyle={{
            background: chrome.surface,
            border: `1px solid ${chrome.grid}`,
            borderRadius: 8,
            color: chrome.textSecondary,
          }}
        />
        {/* Animation off for the same reason as VerdictPieChart: with it on
            the bars stay at zero height. */}
        <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={24} isAnimationActive={false}>
          {data.map((entry) => (
            <Cell key={entry.severity} fill={severityColor(entry.severity)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
