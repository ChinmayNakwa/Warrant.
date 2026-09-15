"use client";

import {
  CartesianGrid,
  Label,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { useColorScheme } from "@/lib/useColorScheme";
import { chartChrome } from "./colors";

function formatDate(iso: string): string {
  return new Date(`${iso}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Runs per day. The last point is labelled with its value. */
export function RunsLineChart({ data }: { data: { date: string; count: number }[] }) {
  const scheme = useColorScheme();
  const chrome = chartChrome(scheme);
  const surface = chrome.surface;
  const lastIndex = data.length - 1;

  return (
    <ResponsiveContainer width="100%" height={260}>
      <LineChart data={data} margin={{ top: 8, right: 24, left: 0, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke={chrome.grid} />
        <XAxis
          dataKey="date"
          tickFormatter={formatDate}
          stroke={chrome.axis}
          tick={{ fill: chrome.textMuted, fontSize: 12 }}
          tickLine={false}
          minTickGap={24}
        />
        <YAxis
          allowDecimals={false}
          stroke={chrome.axis}
          tick={{ fill: chrome.textMuted, fontSize: 12 }}
          tickLine={false}
          width={32}
        />
        <Tooltip
          labelFormatter={(value) => formatDate(String(value))}
          contentStyle={{
            background: surface,
            border: `1px solid ${chrome.grid}`,
            borderRadius: 8,
            color: chrome.textSecondary,
          }}
        />
        <Line
          type="monotone"
          dataKey="count"
          stroke={chrome.series1}
          strokeWidth={2}
          dot={{ r: 4, fill: chrome.series1, stroke: surface, strokeWidth: 2 }}
          activeDot={{ r: 6, fill: chrome.series1, stroke: surface, strokeWidth: 2 }}
          isAnimationActive={false}
          label={(props) => {
            const { x, y, index, value } = props as {
              x?: number;
              y?: number;
              index?: number;
              value?: number;
            };
            if (index !== lastIndex || x === undefined || y === undefined) return <g />;
            return <Label x={x} y={y} dy={-12} value={value} fill={chrome.textSecondary} fontSize={12} />;
          }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
