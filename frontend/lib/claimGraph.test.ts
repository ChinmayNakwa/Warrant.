import { describe, expect, it } from "vitest";

import type { TelemetryEvent } from "@/lib/api";

import { type GraphClaim, NODE_H, TIP_W, layoutClaimGraph, processNamesFromEvents } from "./claimGraph";

const P200 = "{00000000-0000-0000-0000-000000000200}";
const P201 = "{00000000-0000-0000-0000-000000000201}";
const P202 = "{00000000-0000-0000-0000-000000000202}";
const PAYLOAD = "C:\\Users\\victim\\AppData\\Local\\Temp\\payload.dat";

function claim(
  subject_type: string,
  subject: string,
  relation: string,
  object_type: string,
  object: string,
): GraphClaim {
  return { subject_type, subject, relation, object_type, object, event: "e1" };
}

// A spawn chain, a shared user, one of each other entity type, and one claim
// guarded mode removed.
function runClaims(): GraphClaim[] {
  return [
    claim("Process", P200, "spawned", "Process", P201),
    claim("Process", P201, "authenticated_as", "User", "LAB\\victim"),
    claim("Process", P201, "spawned", "Process", P202),
    claim("Process", P202, "authenticated_as", "User", "LAB\\victim"),
    claim("Process", P201, "connected_to", "Network", "127.0.0.1:8080"),
    claim("Process", P201, "wrote", "File", PAYLOAD),
    claim("Process", P201, "modified", "RegistryKey", "HKU\\S-1-5-21\\Software\\Run\\Updater"),
    { ...claim("Process", P202, "read", "Process", "lsass.exe"), removedFor: ["triple_not_allowed"] },
    claim("Process", P201, "exhibits", "Technique", "T1059.001"),
    claim("Process", P201, "exhibits", "Technique", "T1105"),
  ];
}

function node(layout: ReturnType<typeof layoutClaimGraph>, type: string, value: string) {
  const found = layout.nodes.find((n) => n.type === type && n.value === value);
  if (!found) throw new Error(`no ${type} node ${value}`);
  return found;
}

describe("layoutClaimGraph", () => {
  it("draws one edge per claim and one node per distinct (type, value)", () => {
    const claims = runClaims();
    const layout = layoutClaimGraph(claims);

    expect(layout.edges.map((e) => e.claim)).toEqual(claims);
    // 4 processes (with lsass.exe), 1 user, 1 network, 1 file, 1 key, 2 techniques
    expect(layout.nodes).toHaveLength(10);
    expect(layout.nodes.filter((n) => n.value === "LAB\\victim")).toHaveLength(1);
  });

  it("treats the same value under two types as two nodes", () => {
    const layout = layoutClaimGraph([
      claim("Process", P201, "spawned", "Process", "lsass.exe"),
      claim("Process", P201, "read", "File", "lsass.exe"),
    ]);

    expect(layout.nodes.filter((n) => n.value === "lsass.exe").map((n) => n.type)).toEqual([
      "Process",
      "File",
    ]);
  });

  it("puts a child process below and to the right of its parent", () => {
    const layout = layoutClaimGraph(runClaims());
    const [root, child, grandchild] = [P200, P201, P202].map((guid) => node(layout, "Process", guid));

    expect(child.x).toBeGreaterThan(root.x);
    expect(grandchild.x).toBeGreaterThan(child.x);
    expect(child.y).toBeGreaterThan(root.y);
    expect(grandchild.y).toBeGreaterThan(child.y);
  });

  it("keeps every node inside the canvas with no two overlapping", () => {
    const layout = layoutClaimGraph(runClaims());

    for (const n of layout.nodes) {
      expect(n.x).toBeGreaterThanOrEqual(0);
      expect(n.y).toBeGreaterThanOrEqual(0);
      expect(n.x + n.width).toBeLessThanOrEqual(layout.width);
      expect(n.y + NODE_H).toBeLessThanOrEqual(layout.height);
    }
    for (const a of layout.nodes) {
      for (const b of layout.nodes) {
        if (a === b) continue;
        const apart =
          a.x + a.width <= b.x || b.x + b.width <= a.x || a.y + NODE_H <= b.y || b.y + NODE_H <= a.y;
        expect(apart, `${a.value} overlaps ${b.value}`).toBe(true);
      }
    }
  });

  it("still draws every claim when process claims form a cycle or a self-loop", () => {
    const layout = layoutClaimGraph([
      claim("Process", "a", "spawned", "Process", "b"),
      claim("Process", "b", "spawned", "Process", "a"),
      claim("Process", "a", "spawned", "Process", "a"),
    ]);

    expect(layout.edges).toHaveLength(3);
    expect(layout.nodes).toHaveLength(2);
    expect(new Set(layout.edges.map((e) => e.path)).size).toBe(3);
  });

  it("fans out several claims between the same two nodes instead of stacking them", () => {
    const layout = layoutClaimGraph([
      claim("Process", P201, "wrote", "File", PAYLOAD),
      claim("Process", P201, "read", "File", PAYLOAD),
      claim("File", PAYLOAD, "dropped_by", "Process", P201),
    ]);

    expect(new Set(layout.edges.map((e) => e.path)).size).toBe(3);
  });

  it("lays out claims that name no process at all", () => {
    const layout = layoutClaimGraph([claim("File", "a.txt", "dropped_by", "Network", "10.0.0.1")]);

    expect(layout.nodes).toHaveLength(2);
    expect(layout.edges).toHaveLength(1);
    expect(layout.width).toBeGreaterThan(0);
  });

  it("labels a process by its image and shortens long values without changing them", () => {
    const events: TelemetryEvent[] = [
      {
        ref: "e1",
        ts: "2026-01-15T10:10:00",
        event_type: "process",
        process_guid: P201,
        image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      },
      // An event of another kind must not name a process.
      { ref: "e2", ts: "2026-01-15T10:10:01", event_type: "file", process_guid: P200, image: "C:\\x\\wrong.exe" },
    ];
    const layout = layoutClaimGraph(runClaims(), { processNames: processNamesFromEvents(events) });

    expect(node(layout, "Process", P201).label).toBe("powershell.exe (0201)");
    expect(node(layout, "Process", P200).label).toBe("…000000000200");
    expect(node(layout, "Process", "lsass.exe").label).toBe("lsass.exe");

    const file = node(layout, "File", PAYLOAD);
    expect(file.value).toBe(PAYLOAD);
    expect(file.label).toBe("…\\Local\\Temp\\payload.dat");
  });

  it("opens a process's tooltip below its children and short of the entity column", () => {
    const layout = layoutClaimGraph(runClaims());
    const parent = node(layout, "Process", P201);
    const child = node(layout, "Process", P202);
    const user = node(layout, "User", "LAB\\victim");

    expect(parent.tipY).toBeGreaterThanOrEqual(child.y + NODE_H);
    expect(parent.tipX + TIP_W).toBeLessThan(user.x);
    // An entity's neighbours are all in the other column, so its tooltip sits right below it.
    expect(user.tipY).toBe(user.y + NODE_H + 6);
    expect(user.tipX).toBe(user.x);
  });

  it("marks only the alerted process, whatever its letter case", () => {
    const layout = layoutClaimGraph(runClaims(), { anchorGuid: P201.toUpperCase() });

    expect(layout.nodes.filter((n) => n.isAnchor).map((n) => n.value)).toEqual([P201]);
    expect(layoutClaimGraph(runClaims()).nodes.some((n) => n.isAnchor)).toBe(false);
  });
});
