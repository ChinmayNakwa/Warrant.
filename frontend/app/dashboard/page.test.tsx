import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, type Mock } from "vitest";

import type { DashboardSummary } from "@/lib/api";
import { getDashboardSummary } from "@/lib/api";

import DashboardPage from "./page";

const FAKE_USER = { id: "u1", email: "analyst@example.com", created_at: "2026-01-01T00:00:00Z" };

vi.mock("@/lib/useRequireAuth", () => ({
  useRequireAuth: () => ({ user: FAKE_USER, status: "authenticated" }),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, getDashboardSummary: vi.fn() };
});

// The charts need a real layout to draw. Each stub prints its props, so the
// test can check the page hands them the backend's numbers unchanged.
vi.mock("@/components/charts/VerdictPieChart", () => ({
  VerdictPieChart: ({ breakdown }: { breakdown: Record<string, number> }) => (
    <div data-testid="verdict-chart">{JSON.stringify(breakdown)}</div>
  ),
}));
vi.mock("@/components/charts/SeverityBarChart", () => ({
  SeverityBarChart: ({ breakdown }: { breakdown: Record<string, number> }) => (
    <div data-testid="severity-chart">{JSON.stringify(breakdown)}</div>
  ),
}));
vi.mock("@/components/charts/RunsLineChart", () => ({
  RunsLineChart: ({ data }: { data: unknown }) => (
    <div data-testid="line-chart">{JSON.stringify(data)}</div>
  ),
}));

const FIXTURE: DashboardSummary = {
  open_incidents: 7,
  total_runs: 12,
  runs_with_violations: 5,
  verdict_breakdown: { MALICIOUS: 3, BENIGN: 4 },
  severity_breakdown: { high: 4, low: 3 },
  runs_over_time: [{ date: "2026-09-14", count: 2 }],
  recent_incidents: [
    {
      id: "inc-1",
      title: "Suspicious PowerShell activity",
      description: "Flagged by EDR heuristic.",
      severity: "high",
      status: "open",
      capture_id: "cap-1",
      anchor_process_guid: null,
      verdict: "MALICIOUS",
      confidence: 0.82,
      created_at: "2026-09-14T12:00:00Z",
    },
  ],
};

describe("DashboardPage", () => {
  it("renders every KPI, breakdown, and table value straight from the API response", async () => {
    (getDashboardSummary as Mock).mockResolvedValue(FIXTURE);

    render(<DashboardPage />);

    await waitFor(() => expect(getDashboardSummary).toHaveBeenCalled());

    expect(await screen.findByText("7")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();

    // Recent incidents table row, sourced from `recent_incidents[0]`.
    expect(screen.getByText("Suspicious PowerShell activity")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText("MALICIOUS")).toBeInTheDocument();

    // Chart props are the backend's breakdown objects, unmodified.
    expect(screen.getByTestId("verdict-chart")).toHaveTextContent(
      JSON.stringify(FIXTURE.verdict_breakdown),
    );
    expect(screen.getByTestId("severity-chart")).toHaveTextContent(
      JSON.stringify(FIXTURE.severity_breakdown),
    );
    expect(screen.getByTestId("line-chart")).toHaveTextContent(
      JSON.stringify(FIXTURE.runs_over_time),
    );
  });

  it("shows the empty state instead of a zeroed dashboard when there are no incidents", async () => {
    (getDashboardSummary as Mock).mockResolvedValue({
      open_incidents: 0,
      total_runs: 0,
      runs_with_violations: 0,
      verdict_breakdown: {},
      severity_breakdown: {},
      runs_over_time: [],
      recent_incidents: [],
    } satisfies DashboardSummary);

    render(<DashboardPage />);

    expect(await screen.findByText("No incidents yet")).toBeInTheDocument();
    expect(screen.queryByTestId("verdict-chart")).not.toBeInTheDocument();
  });
});
