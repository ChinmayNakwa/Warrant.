import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";

import { ApiError, type Incident, type RunDetail } from "@/lib/api";
import { createRun, getIncident, getRun, listRuns } from "@/lib/api";

import IncidentDetailPage from "./page";

const FAKE_USER = { id: "u1", email: "analyst@example.com", created_at: "2026-01-01T00:00:00Z" };

vi.mock("next/navigation", async (importOriginal) => {
  const actual = await importOriginal<typeof import("next/navigation")>();
  return { ...actual, useParams: () => ({ id: "inc-1" }), usePathname: () => "/incidents/inc-1" };
});

vi.mock("@/lib/useRequireAuth", () => ({
  useRequireAuth: () => ({ user: FAKE_USER, status: "authenticated" }),
}));

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({ user: FAKE_USER, status: "authenticated", logout: vi.fn() }),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, getIncident: vi.fn(), listRuns: vi.fn(), getRun: vi.fn(), createRun: vi.fn() };
});

const INCIDENT: Incident = {
  id: "inc-1",
  title: "LSASS dump",
  description: "",
  severity: "high",
  status: "open",
  capture_id: "cap-1",
  anchor_process_guid: null,
  verdict: "MALICIOUS",
  confidence: 0.9,
  created_at: "2026-09-20T10:00:00Z",
};

const CLAIM = {
  subject_type: "Process",
  subject: "{guid-1}",
  relation: "wrote",
  object_type: "File",
  object: "C:\\Temp\\lsass.dmp",
  event: "e2",
};

const GUARDED: RunDetail = {
  id: "run-1",
  incident_id: "inc-1",
  mode: "guarded",
  status: "completed",
  verdict: "MALICIOUS",
  confidence: 0.9,
  model: "gpt-oss:120b",
  techniques: ["T1003.001"],
  llm_calls: 2,
  violation_count: 1,
  repair_rounds: 1,
  dropped_count: 1,
  note: null,
  started_at: "2026-09-20T10:01:00Z",
  finished_at: "2026-09-20T10:02:00Z",
  answer: {
    verdict: "MALICIOUS",
    confidence: 0.9,
    techniques: [{ id: "T1003.001", events: ["e1"] }],
    claims: [CLAIM],
    summary: "rundll32 dumped LSASS memory.",
  },
  first_answer: {
    verdict: "MALICIOUS",
    confidence: 0.9,
    techniques: [
      { id: "T1003.001", events: ["e1"] },
      { id: "T9999", events: ["e1"] },
    ],
    claims: [CLAIM],
    summary: "rundll32 dumped LSASS memory.",
  },
  violations: [
    { code: "technique_unknown", path: "techniques[1]", message: "this is not a MITRE ATT&CK technique id" },
  ],
  dropped: [{ kind: "technique", item: { id: "T9999", events: ["e1"] }, codes: ["technique_unknown"] }],
  events: [
    { ref: "e1", ts: "2026-01-15T10:10:00", event_type: "process", image: "rundll32.exe" },
    { ref: "e2", ts: "2026-01-15T10:10:01", event_type: "file", target_object: "C:\\Temp\\lsass.dmp" },
  ],
};

const BASELINE: RunDetail = {
  ...GUARDED,
  id: "run-2",
  mode: "baseline",
  llm_calls: 1,
  repair_rounds: 0,
  dropped_count: 0,
  dropped: [],
  answer: GUARDED.first_answer,
};

function mockLoad(run: RunDetail | null) {
  (getIncident as Mock).mockResolvedValue(INCIDENT);
  (listRuns as Mock).mockResolvedValue(run ? [run] : []);
  (getRun as Mock).mockResolvedValue(run);
}

describe("IncidentDetailPage", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows what the check found and what a guarded run removed", async () => {
    mockLoad(GUARDED);
    render(<IncidentDetailPage />);

    expect(await screen.findByText(/broke 1 rule/)).toBeInTheDocument();
    expect(screen.getByText("techniques[1]")).toBeInTheDocument();
    expect(screen.getByText(/this is not a MITRE ATT&CK technique id/)).toBeInTheDocument();
    expect(screen.getByText(/repair it 1 time, then\s+removed or changed 1 item/)).toBeInTheDocument();
    expect(screen.getByText(/gpt-oss:120b/)).toBeInTheDocument();
    expect(screen.getByText("2 model calls")).toBeInTheDocument();
    // The accepted answer lists one technique; the first answer, kept below it, lists two.
    expect(screen.getByText("Techniques (1)")).toBeInTheDocument();
    expect(screen.getByText("Techniques (2)")).toBeInTheDocument();
    expect(screen.getByText(/Telemetry the model read \(2 events\)/)).toBeInTheDocument();
  });

  it("says a baseline run changes nothing", async () => {
    mockLoad(BASELINE);
    render(<IncidentDetailPage />);

    expect(await screen.findByText(/Baseline mode records these and changes nothing/)).toBeInTheDocument();
    expect(screen.queryByText(/repair it/)).not.toBeInTheDocument();
    expect(screen.queryByText(/First answer, before the check/)).not.toBeInTheDocument();
  });

  it("says so when the first answer passed", async () => {
    mockLoad({ ...BASELINE, violations: [], violation_count: 0 });
    render(<IncidentDetailPage />);

    expect(await screen.findByText(/passed every rule/)).toBeInTheDocument();
  });

  it("runs the chosen mode and shows the new run", async () => {
    mockLoad(null);
    (createRun as Mock).mockResolvedValue(BASELINE);
    render(<IncidentDetailPage />);

    await screen.findByText(/No runs yet/);
    fireEvent.click(screen.getByLabelText(/Baseline/));
    fireEvent.click(screen.getByRole("button", { name: "Run analysis" }));

    await waitFor(() => expect(createRun).toHaveBeenCalledWith("inc-1", "baseline"));
    expect(await screen.findByText("Accepted answer")).toBeInTheDocument();
  });

  it("shows the backend's message when a run cannot start", async () => {
    mockLoad(null);
    (createRun as Mock).mockRejectedValue(new ApiError(503, "No model is configured."));
    render(<IncidentDetailPage />);

    await screen.findByText(/No runs yet/);
    fireEvent.click(screen.getByRole("button", { name: "Run analysis" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("No model is configured.");
  });

  it("shows not found for an incident the user cannot see", async () => {
    (getIncident as Mock).mockRejectedValue(new ApiError(404, "Incident not found."));
    (listRuns as Mock).mockRejectedValue(new ApiError(404, "Incident not found."));
    render(<IncidentDetailPage />);

    expect(await screen.findByText("Incident not found.")).toBeInTheDocument();
  });
});
