import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { Claim, Dropped } from "@/lib/api";

import { ClaimGraph } from "./ClaimGraph";

const P201 = "{00000000-0000-0000-0000-000000000201}";
const P202 = "{00000000-0000-0000-0000-000000000202}";

function claim(fields: Partial<Claim>): Claim {
  return {
    subject_type: "Process",
    subject: P201,
    relation: "spawned",
    object_type: "Process",
    object: P202,
    event: "e1",
    ...fields,
  };
}

const CLAIMS: Claim[] = [
  claim({}),
  claim({ relation: "exhibits", object_type: "Technique", object: "T1059.001", event: "e2" }),
];

const DROPPED: Dropped[] = [
  { kind: "technique", item: { id: "T9999", events: ["e1"] }, codes: ["technique_unknown"] },
  {
    kind: "claim",
    item: { ...claim({ subject: P202, relation: "read", object: "lsass.exe", event: "e3" }) },
    codes: ["triple_not_allowed"],
  },
];

describe("ClaimGraph", () => {
  it("draws accepted claims and the claims guarded mode removed", () => {
    render(<ClaimGraph claims={CLAIMS} dropped={DROPPED} events={[]} />);

    const edges = screen.getAllByTestId("claim-edge");
    expect(edges.map((e) => e.getAttribute("data-removed"))).toEqual(["false", "false", "true"]);
    expect(screen.getAllByTestId("claim-node")).toHaveLength(4);
    expect(screen.getByText("removed claim")).toBeInTheDocument();
  });

  it("offers no removed or alerted key when the run has neither", () => {
    render(<ClaimGraph claims={CLAIMS} dropped={[]} events={[]} />);

    expect(screen.queryByText("removed claim")).not.toBeInTheDocument();
    expect(screen.queryByText("alerted process")).not.toBeInTheDocument();
  });

  it("shows a focused node's full value and exactly its own claims", () => {
    render(<ClaimGraph claims={CLAIMS} dropped={DROPPED} events={[]} anchorGuid={P201} />);
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();

    fireEvent.focus(screen.getByLabelText(`Process ${P202}`));

    const tip = within(screen.getByRole("tooltip"));
    expect(tip.getByText(P202)).toBeInTheDocument();
    expect(tip.getByText(`←spawned— ${P201}`)).toBeInTheDocument();
    expect(tip.getByText("—read→ lsass.exe")).toBeInTheDocument();
    expect(tip.getByText("removed: triple_not_allowed")).toBeInTheDocument();
    expect(tip.queryByText(/exhibits/)).not.toBeInTheDocument();
    expect(tip.getAllByRole("listitem")).toHaveLength(2);

    fireEvent.blur(screen.getByLabelText(`Process ${P202}`));
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("names the alerted process in the key and in its tooltip", () => {
    render(<ClaimGraph claims={CLAIMS} dropped={[]} events={[]} anchorGuid={P201} />);
    expect(screen.getByText("alerted process")).toBeInTheDocument();

    fireEvent.mouseEnter(screen.getByLabelText(`Process ${P201}`));

    expect(screen.getByRole("tooltip")).toHaveTextContent("Process · alerted process");
  });

  it("renders nothing for an answer with no claims", () => {
    const { container } = render(<ClaimGraph claims={[]} dropped={[]} events={[]} />);

    expect(container).toBeEmptyDOMElement();
  });
});
