import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ClaimDemo } from "./ClaimDemo";

// The test setup asks for reduced motion, so the demo renders its end state.
describe("ClaimDemo", () => {
  it("ends with the statements that passed and none of the ones that broke a rule", () => {
    render(<ClaimDemo />);

    expect(screen.getByText(/powershell\.exe —spawned→ rundll32\.exe/)).toBeInTheDocument();
    expect(screen.getByText(/T1003\.001/)).toBeInTheDocument();
    expect(screen.queryByText(/T9999/)).not.toBeInTheDocument();
    expect(screen.queryByText(/connected_to/)).not.toBeInTheDocument();
    expect(screen.getByText("3 of 5 statements kept, 2 removed.")).toBeInTheDocument();
  });

  it("offers no replay when nothing plays", () => {
    render(<ClaimDemo />);

    expect(screen.queryByRole("button", { name: "Replay" })).not.toBeInTheDocument();
  });
});
