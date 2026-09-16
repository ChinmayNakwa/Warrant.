/**
 * Layout for the claim graph on the incident page.
 *
 * Every claim becomes one edge, and every distinct (type, value) it names
 * becomes one node. Nothing is filtered or merged. Processes form an indented
 * tree on the left (parent above child); every other entity sits in a column
 * on the right, grouped under its type. A node's type is read from where it
 * sits, not from a colour.
 *
 * No DOM and no React, so the geometry can be tested directly.
 */
import type { Claim, TelemetryEvent } from "@/lib/api";

export const NODE_H = 22;
const ROW_H = 30;
const HEAD_H = 24;
const GROUP_GAP = 6;
const PAD_Y = 8;
// The side margins are also the lane for arcs within one column.
const MARGIN_X = 28;
const INDENT = 24;
const PROCESS_W = 180;
const ENTITY_W = 190;
const GAP = 110;
// Labels are 11px monospace, so how much fits in a node is known up front.
const CHAR_W = 6.7;
const LABEL_PAD = 16;
const PROCESS_CHARS = Math.floor((PROCESS_W - LABEL_PAD) / CHAR_W);
const ENTITY_CHARS = Math.floor((ENTITY_W - LABEL_PAD) / CHAR_W);
export const TIP_W = 300;
// A tooltip drops below neighbours in its own column only this far away.
const TIP_REACH = 8 * ROW_H;

const PROCESS = "Process";
// Fixed order, so a type keeps its place from run to run. Any other type
// follows alphabetically.
const ENTITY_ORDER = ["User", "Host", "Network", "File", "RegistryKey", "Technique"];
// For these the end of the value (the leaf name) says more than the start.
const KEEP_TAIL = new Set(["File", "RegistryKey"]);
const GUID = /^\{?[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?$/i;

/** A claim to draw. `removedFor` lists the rules it broke if guarded mode removed it. */
export interface GraphClaim extends Claim {
  removedFor?: string[];
}

export interface ClaimGraphNode {
  id: string;
  type: string;
  /** The full value from the answer. */
  value: string;
  /** `value` shortened to fit the node. */
  label: string;
  x: number;
  y: number;
  width: number;
  isAnchor: boolean;
  /** Top-left of this node's tooltip, clear of the nodes it connects to. */
  tipX: number;
  tipY: number;
}

export interface ClaimGraphEdge {
  claim: GraphClaim;
  source: string;
  target: string;
  path: string;
}

export interface ClaimGraphHeading {
  text: string;
  x: number;
  y: number;
}

export interface ClaimGraphLayout {
  nodes: ClaimGraphNode[];
  edges: ClaimGraphEdge[];
  headings: ClaimGraphHeading[];
  width: number;
  height: number;
}

export interface ClaimGraphOptions {
  /** Process GUID (lower-cased) -> image file name, for readable labels. */
  processNames?: Map<string, string>;
  anchorGuid?: string | null;
}

function nodeId(type: string, value: string): string {
  return JSON.stringify([type, value]);
}

function truncate(text: string, max: number, keep: "head" | "tail"): string {
  if (text.length <= max) return text;
  if (keep === "head") return `${text.slice(0, max - 1)}…`;
  const tail = text.slice(text.length - (max - 1));
  // Start at a path separator when one is near, so no name is cut mid-word.
  const sep = tail.search(/[\\/]/);
  return `…${sep > 0 && sep <= tail.length / 2 ? tail.slice(sep) : tail}`;
}

function processLabel(value: string, names: Map<string, string>): string {
  const bare = value.replace(/[{}]/g, "");
  const name = names.get(value.toLowerCase());
  // Two processes can share an image, so the end of the GUID stays in the label.
  if (name) return `${truncate(name, PROCESS_CHARS - 7, "head")} (${bare.slice(-4)})`;
  if (GUID.test(value)) return `…${bare.slice(-12)}`;
  return truncate(value, PROCESS_CHARS, "head");
}

/** Image file names of the processes in the telemetry, keyed by lower-cased GUID. */
export function processNamesFromEvents(events: TelemetryEvent[]): Map<string, string> {
  const names = new Map<string, string>();
  const name = (guid: unknown, image: unknown) => {
    if (typeof guid !== "string" || typeof image !== "string") return;
    const base = image.split(/[\\/]/).pop();
    if (base) names.set(guid.toLowerCase(), base);
  };
  for (const event of events) {
    if (event.event_type === "process") name(event.process_guid, event.image);
    // The process an access or thread event is aimed at was often running
    // before the capture began, so no process event names it.
    if (event.event_type === "access" || event.event_type === "thread") {
      name(event.target_process_guid, event.target_object);
    }
  }
  return names;
}

/** Parent-to-child connector inside the process tree. */
function elbowPath(parent: ClaimGraphNode, child: ClaimGraphNode): string {
  const x = parent.x + 8;
  const y = child.y + NODE_H / 2;
  const r = 5;
  return `M ${x} ${parent.y + NODE_H} V ${y - r} Q ${x} ${y} ${x + r} ${y} H ${child.x}`;
}

function curvePath(x1: number, y1: number, cx: number, x2: number, y2: number): string {
  return `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`;
}

export function layoutClaimGraph(claims: GraphClaim[], options: ClaimGraphOptions = {}): ClaimGraphLayout {
  const processNames = options.processNames ?? new Map<string, string>();
  const anchor = options.anchorGuid?.toLowerCase() ?? null;

  // Nodes, in the order the claims first name them.
  const entities = new Map<string, { type: string; value: string }>();
  for (const c of claims) {
    const ends = [
      [c.subject_type, c.subject],
      [c.object_type, c.object],
    ];
    for (const [type, value] of ends) {
      const id = nodeId(type, value);
      if (!entities.has(id)) entities.set(id, { type, value });
    }
  }
  const processIds = [...entities].filter(([, e]) => e.type === PROCESS).map(([id]) => id);

  // Process forest. A process takes the first parent that claims it, `spawned`
  // claims first. A claim that would give it a second parent or close a cycle
  // is still drawn, as an arc (below), so no claim is dropped.
  const parent = new Map<string, string>();
  const children = new Map<string, string[]>();
  const treeClaims = new Set<GraphClaim>();
  const closesCycle = (child: string, under: string) => {
    for (let cur: string | undefined = under; cur !== undefined; cur = parent.get(cur)) {
      if (cur === child) return true;
    }
    return false;
  };
  const processClaims = claims.filter((c) => c.subject_type === PROCESS && c.object_type === PROCESS);
  const spawnFirst = [
    ...processClaims.filter((c) => c.relation === "spawned"),
    ...processClaims.filter((c) => c.relation !== "spawned"),
  ];
  for (const c of spawnFirst) {
    const s = nodeId(PROCESS, c.subject);
    const t = nodeId(PROCESS, c.object);
    if (parent.has(t) || closesCycle(t, s)) continue;
    parent.set(t, s);
    children.set(s, [...(children.get(s) ?? []), t]);
    treeClaims.add(c);
  }

  // Depth-first order gives each process its row, directly under its parent.
  const row = new Map<string, number>();
  const depth = new Map<string, number>();
  const visit = (id: string, d: number) => {
    row.set(id, row.size);
    depth.set(id, d);
    for (const child of children.get(id) ?? []) visit(child, d + 1);
  };
  for (const id of processIds) if (!parent.has(id)) visit(id, 0);
  const maxDepth = Math.max(0, ...depth.values());

  // Within its type group, an entity sits near the processes it connects to.
  const neighbourRows = new Map<string, number[]>();
  for (const c of claims) {
    const s = nodeId(c.subject_type, c.subject);
    const t = nodeId(c.object_type, c.object);
    for (const [entity, process] of [
      [t, s],
      [s, t],
    ]) {
      const r = row.get(process);
      if (r !== undefined && !row.has(entity)) {
        neighbourRows.set(entity, [...(neighbourRows.get(entity) ?? []), r]);
      }
    }
  }
  const barycenter = (id: string) => {
    const rows = neighbourRows.get(id);
    return rows ? rows.reduce((a, b) => a + b, 0) / rows.length : Infinity;
  };
  const typeRank = (type: string) => {
    const i = ENTITY_ORDER.indexOf(type);
    return i === -1 ? ENTITY_ORDER.length : i;
  };
  const entityTypes = [...new Set([...entities.values()].map((e) => e.type))]
    .filter((type) => type !== PROCESS)
    .sort((a, b) => typeRank(a) - typeRank(b) || a.localeCompare(b));

  const processRight = MARGIN_X + maxDepth * INDENT + PROCESS_W;
  const entityX = processIds.length > 0 ? processRight + GAP : MARGIN_X;

  const nodes: ClaimGraphNode[] = [];
  const headings: ClaimGraphHeading[] = [];
  const place = (node: Omit<ClaimGraphNode, "tipX" | "tipY">) =>
    nodes.push({ ...node, tipX: node.x, tipY: node.y + NODE_H + 6 });

  if (processIds.length > 0) headings.push({ text: PROCESS, x: MARGIN_X, y: PAD_Y + HEAD_H / 2 });
  for (const id of processIds) {
    const { type, value } = entities.get(id)!;
    const x = MARGIN_X + depth.get(id)! * INDENT;
    place({
      id,
      type,
      value,
      label: processLabel(value, processNames),
      x,
      y: PAD_Y + HEAD_H + row.get(id)! * ROW_H + (ROW_H - NODE_H) / 2,
      // Every process node ends at the same x, so edges leave from one line.
      width: processRight - x,
      isAnchor: anchor !== null && value.toLowerCase() === anchor,
    });
  }
  const processBottom = processIds.length > 0 ? PAD_Y + HEAD_H + processIds.length * ROW_H : 0;

  let cursor = PAD_Y;
  for (const type of entityTypes) {
    headings.push({ text: type, x: entityX, y: cursor + HEAD_H / 2 });
    cursor += HEAD_H;
    const ids = [...entities]
      .filter(([, e]) => e.type === type)
      .map(([id]) => id)
      .sort((a, b) => {
        const ba = barycenter(a);
        const bb = barycenter(b);
        return ba === bb ? 0 : ba < bb ? -1 : 1;
      });
    for (const id of ids) {
      const { value } = entities.get(id)!;
      place({
        id,
        type,
        value,
        label: truncate(value, ENTITY_CHARS, KEEP_TAIL.has(type) ? "tail" : "head"),
        x: entityX,
        y: cursor + (ROW_H - NODE_H) / 2,
        width: ENTITY_W,
        isAnchor: false,
      });
      cursor += ROW_H;
    }
    cursor += GROUP_GAP;
  }

  const byId = new Map(nodes.map((n) => [n.id, n]));
  const pairKey = (a: string, b: string) => (a < b ? `${a}|${b}` : `${b}|${a}`);
  const pairTotal = new Map<string, number>();
  for (const c of claims) {
    if (treeClaims.has(c)) continue;
    const key = pairKey(nodeId(c.subject_type, c.subject), nodeId(c.object_type, c.object));
    pairTotal.set(key, (pairTotal.get(key) ?? 0) + 1);
  }
  const pairSeen = new Map<string, number>();

  const edges: ClaimGraphEdge[] = claims.map((claim) => {
    const source = nodeId(claim.subject_type, claim.subject);
    const target = nodeId(claim.object_type, claim.object);
    const s = byId.get(source)!;
    const t = byId.get(target)!;
    if (treeClaims.has(claim)) return { claim, source, target, path: elbowPath(s, t) };

    // Several claims between the same two nodes are fanned out, not stacked.
    const key = pairKey(source, target);
    const index = pairSeen.get(key) ?? 0;
    pairSeen.set(key, index + 1);
    const offset = (index - (pairTotal.get(key)! - 1) / 2) * 5;
    const loop = source === target ? 5 : 0;
    const sy = s.y + NODE_H / 2 + offset - loop;
    const ty = t.y + NODE_H / 2 + offset + loop;

    const sIsProcess = row.has(source);
    const tIsProcess = row.has(target);
    let path: string;
    if (sIsProcess !== tIsProcess) {
      const x1 = sIsProcess ? s.x + s.width : s.x;
      const x2 = tIsProcess ? t.x + t.width : t.x;
      path = curvePath(x1, sy, (x1 + x2) / 2, x2, ty);
    } else if (sIsProcess) {
      // Process to process outside the tree: an arc through the left margin.
      path = curvePath(s.x, sy, 6, t.x, ty);
    } else {
      // Entity to entity: an arc through the right margin.
      const x = s.x + s.width;
      path = curvePath(x, sy, x + MARGIN_X - 6, x, ty);
    }
    return { claim, source, target, path };
  });

  const hasEntities = entityTypes.length > 0;

  // A tooltip opens below the lowest nearby neighbour in its node's own column
  // (a process's children sit right under it), and a process's tooltip stops
  // short of the entity column, so it never hides the nodes it describes.
  for (const { source, target } of edges) {
    for (const [id, otherId] of [
      [source, target],
      [target, source],
    ]) {
      const n = byId.get(id)!;
      const other = byId.get(otherId)!;
      if (row.has(id) !== row.has(otherId) || other.y - n.y > TIP_REACH) continue;
      n.tipY = Math.max(n.tipY, other.y + NODE_H + 6);
    }
  }
  if (hasEntities) {
    for (const n of nodes) {
      if (row.has(n.id)) n.tipX = Math.max(0, Math.min(n.x, entityX - TIP_W - 8));
    }
  }

  return {
    nodes,
    edges,
    headings,
    width: (hasEntities ? entityX + ENTITY_W : processRight) + MARGIN_X,
    height: Math.max(processBottom, hasEntities ? cursor - GROUP_GAP : 0) + PAD_Y,
  };
}
