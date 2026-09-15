"use client";

import { useId, useMemo, useState } from "react";

import type { Claim, Dropped, TelemetryEvent } from "@/lib/api";
import {
  type GraphClaim,
  NODE_H,
  TIP_W,
  layoutClaimGraph,
  processNamesFromEvents,
} from "@/lib/claimGraph";

type EdgeStyle = "rest" | "active" | "removed";

// Removed claims are amber and dashed, so the state never rests on colour alone.
const STROKE: Record<EdgeStyle, string> = {
  rest: "stroke-ink-muted",
  active: "stroke-ink",
  removed: "stroke-amber-700 dark:stroke-amber-400",
};

const ARROW: Record<EdgeStyle, string> = {
  rest: "fill-ink-muted",
  active: "fill-ink",
  removed: "fill-amber-700 dark:fill-amber-400",
};

/**
 * An answer's claims as a graph: one edge per accepted claim, plus one dashed
 * edge per claim guarded mode removed. Hovering or focusing a node shows its
 * claims. Node text is model text and is only ever rendered as text.
 */
export function ClaimGraph({
  claims,
  dropped,
  events,
  anchorGuid,
}: {
  claims: Claim[];
  dropped: Dropped[];
  events: TelemetryEvent[];
  anchorGuid?: string | null;
}) {
  const markerId = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const tipId = `${markerId}-tip`;
  const layout = useMemo(() => {
    const removed = dropped
      .filter((d) => d.kind === "claim")
      .map((d): GraphClaim => ({ ...(d.item as unknown as Claim), removedFor: d.codes }));
    return layoutClaimGraph([...claims, ...removed], {
      processNames: processNamesFromEvents(events),
      anchorGuid,
    });
  }, [claims, dropped, events, anchorGuid]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [scrollLeft, setScrollLeft] = useState(0);

  if (layout.edges.length === 0) return null;

  const active = layout.nodes.find((n) => n.id === activeId) ?? null;
  const touching = active
    ? layout.edges.filter((e) => e.source === active.id || e.target === active.id)
    : [];
  const lit = new Set(touching.flatMap((e) => [e.source, e.target]));
  const hasRemoved = layout.edges.some((e) => e.claim.removedFor);
  const hasAnchor = layout.nodes.some((n) => n.isAnchor);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-muted">
        <span className="flex items-center gap-1.5">
          <svg width="24" height="8" aria-hidden="true">
            <line x1="0" y1="4" x2="24" y2="4" className={STROKE.rest} strokeWidth="1.5" />
          </svg>
          accepted claim
        </span>
        {hasRemoved && (
          <span className="flex items-center gap-1.5">
            <svg width="24" height="8" aria-hidden="true">
              <line
                x1="0"
                y1="4"
                x2="24"
                y2="4"
                className={STROKE.removed}
                strokeWidth="1.5"
                strokeDasharray="4 3"
              />
            </svg>
            removed claim
          </span>
        )}
        {hasAnchor && (
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-3 w-5 rounded border-2 border-ink" />
            alerted process
          </span>
        )}
        <span className="ml-auto">Hover or focus a node for its claims.</span>
      </div>

      <div className="relative">
        <div
          className="overflow-x-auto rounded-md border border-line"
          onScroll={(e) => setScrollLeft(e.currentTarget.scrollLeft)}
        >
          <svg
            width={layout.width}
            height={layout.height}
            role="group"
            aria-label="Claim graph"
            className="block"
          >
            <defs>
              {(["rest", "active", "removed"] as const).map((style) => (
                <marker
                  key={style}
                  id={`${markerId}-${style}`}
                  markerUnits="userSpaceOnUse"
                  markerWidth="7"
                  markerHeight="7"
                  refX="7"
                  refY="3.5"
                  orient="auto"
                >
                  <path d="M0,0 L7,3.5 L0,7 Z" className={ARROW[style]} />
                </marker>
              ))}
            </defs>

            {layout.headings.map((h) => (
              <text
                key={h.text}
                x={h.x}
                y={h.y}
                dominantBaseline="central"
                className="fill-ink-muted text-[11px] font-semibold"
              >
                {h.text}
              </text>
            ))}

            {layout.edges.map((e, i) => {
              const on = active !== null && (e.source === active.id || e.target === active.id);
              const removed = e.claim.removedFor !== undefined;
              const style: EdgeStyle = removed ? "removed" : on ? "active" : "rest";
              return (
                <path
                  key={i}
                  d={e.path}
                  fill="none"
                  data-testid="claim-edge"
                  data-removed={removed}
                  className={`${STROKE[style]} transition-opacity`}
                  strokeWidth={on ? 2 : 1.25}
                  strokeDasharray={removed ? "4 3" : undefined}
                  markerEnd={`url(#${markerId}-${style})`}
                  opacity={active && !on ? 0.2 : 1}
                >
                  <title>
                    {e.claim.subject} —{e.claim.relation}→ {e.claim.object}
                  </title>
                </path>
              );
            })}

            {layout.nodes.map((n) => {
              const on = active?.id === n.id;
              return (
                <g
                  key={n.id}
                  tabIndex={0}
                  data-testid="claim-node"
                  aria-label={`${n.type} ${n.value}`}
                  aria-describedby={on ? tipId : undefined}
                  onMouseEnter={() => setActiveId(n.id)}
                  onMouseLeave={() => setActiveId(null)}
                  onFocus={() => setActiveId(n.id)}
                  onBlur={() => setActiveId(null)}
                  className="cursor-default outline-none transition-opacity"
                  opacity={active && !lit.has(n.id) ? 0.35 : 1}
                >
                  <rect
                    x={n.x}
                    y={n.y}
                    width={n.width}
                    height={NODE_H}
                    rx={6}
                    strokeWidth={n.isAnchor ? 2 : 1}
                    className={`${on ? "fill-sunken" : "fill-surface"} ${
                      n.isAnchor ? "stroke-ink" : on ? "stroke-ink-muted" : "stroke-line-strong"
                    }`}
                  />
                  <text
                    x={n.x + 8}
                    y={n.y + NODE_H / 2}
                    dominantBaseline="central"
                    className="fill-ink-secondary font-mono text-[11px]"
                  >
                    {n.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {active && (
          <div
            id={tipId}
            role="tooltip"
            className="pointer-events-none absolute z-10 rounded-md border border-line-strong bg-surface p-3 text-xs shadow-lg"
            style={{
              width: TIP_W,
              top: active.tipY,
              left: `max(0px, min(${active.tipX - scrollLeft}px, calc(100% - ${TIP_W}px)))`,
            }}
          >
            <div className="text-ink-muted">
              {active.type}
              {active.isAnchor && " · alerted process"}
            </div>
            <div className="break-all font-mono text-ink">{active.value}</div>
            <ul className="mt-2 flex flex-col gap-1">
              {touching.map(({ claim, source }, i) => (
                <li key={i} className="text-ink-secondary">
                  <span className="break-all font-mono">
                    {source === active.id
                      ? `—${claim.relation}→ ${claim.object}`
                      : `←${claim.relation}— ${claim.subject}`}
                  </span>{" "}
                  <span className="text-ink-muted">cites {claim.event}</span>
                  {claim.removedFor && (
                    <span className="text-amber-700 dark:text-amber-400">
                      {" "}
                      removed: {claim.removedFor.join(", ")}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
