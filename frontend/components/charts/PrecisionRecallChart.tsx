"use client";

import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { useColorScheme } from "@/lib/useColorScheme";
import { chartChrome } from "./colors";

export interface PrecisionRecallDatum {
  label: string;
  precision: number;
  recall: number;
}

/** Precision and recall side by side for each labelled group. */
export function PrecisionRecallChart({ data }: { data: PrecisionRecallDatum[] }) {
  const scheme = useColorScheme();
  const chrome = chartChrome(scheme);
  const surface = chrome.surface;
  const pct = (v: number) => `${Math.round(v * 100)}%`;
  const pctLabel = (v: unknown) => (typeof v === "number" ? pct(v) : "");

  return (
    <ResponsiveContainer width="100%" height={280}>
      <BarChart data={data} margin={{ top: 16, right: 8, left: 0, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke={chrome.grid} />
        <XAxis
          dataKey="label"
          stroke={chrome.axis}
          tick={{ fill: chrome.textMuted, fontSize: 12 }}
          tickLine={false}
        />
        <YAxis
          domain={[0, 1]}
          tickFormatter={pct}
          stroke={chrome.axis}
          tick={{ fill: chrome.textMuted, fontSize: 12 }}
          tickLine={false}
          width={40}
        />
        <Tooltip
          formatter={(value) => pctLabel(value)}
          contentStyle={{
            background: surface,
            border: `1px solid ${chrome.grid}`,
            borderRadius: 8,
            color: chrome.textSecondary,
          }}
        />
        <Legend formatter={(value) => <span style={{ color: chrome.textSecondary }}>{value}</span>} />
        <Bar
          dataKey="precision"
          name="Precision"
          fill={chrome.series1}
          radius={[4, 4, 0, 0]}
          maxBarSize={28}
          label={{ position: "top", formatter: pctLabel, fill: chrome.textSecondary, fontSize: 11 }}
        />
        <Bar
          dataKey="recall"
          name="Recall"
          fill={chrome.series2}
          radius={[4, 4, 0, 0]}
          maxBarSize={28}
          label={{ position: "top", formatter: pctLabel, fill: chrome.textSecondary, fontSize: 11 }}
        />
      </BarChart>
    </ResponsiveContainer>
  );
}
