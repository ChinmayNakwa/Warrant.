"use client";

import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import { useColorScheme } from "@/lib/useColorScheme";
import { chartChrome, verdictColor } from "./colors";

/**
 * Share of incidents per verdict. The legend carries each slice's count, so
 * no value depends on hovering.
 */
export function VerdictPieChart({ breakdown }: { breakdown: Record<string, number> }) {
  const scheme = useColorScheme();
  const chrome = chartChrome(scheme);
  const data = Object.entries(breakdown).map(([name, value]) => ({ name, value }));

  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          innerRadius={0}
          outerRadius={90}
          // With animation on, Recharts 3.10 under React 19 leaves the
          // slices at a zero-degree sweep, so nothing is drawn.
          isAnimationActive={false}
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={verdictColor(entry.name)} stroke="none" />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: chrome.surface,
            border: `1px solid ${chrome.grid}`,
            borderRadius: 8,
            color: chrome.textSecondary,
          }}
          formatter={(value, name) => [value, String(name).replace("_", " ")]}
        />
        <Legend
          // Counts go in the legend: a function `label` on Pie renders
          // nothing in Recharts 3.10.
          formatter={(value: string) => (
            <span style={{ color: chrome.textSecondary }}>
              {value.replace("_", " ")} ({breakdown[value]})
            </span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
