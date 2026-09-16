import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Nav } from "./Nav";

const state = vi.hoisted(() => ({
  pathname: "/dashboard",
  user: { id: "u1", email: "analyst@example.com", created_at: "2026-01-01T00:00:00Z" } as object | null,
}));

vi.mock("next/navigation", async (importOriginal) => {
  const actual = await importOriginal<typeof import("next/navigation")>();
  return { ...actual, usePathname: () => state.pathname };
});

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({ user: state.user, logout: vi.fn() }),
}));

describe("Nav", () => {
  beforeEach(() => {
    state.pathname = "/dashboard";
    state.user = { id: "u1", email: "analyst@example.com", created_at: "2026-01-01T00:00:00Z" };
  });

  it("marks the link for the page being shown, including pages under it", () => {
    state.pathname = "/incidents/inc-1";
    render(<Nav />);

    expect(screen.getByRole("link", { name: "Incidents" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Dashboard" })).not.toHaveAttribute("aria-current");
    expect(screen.getByText("analyst@example.com")).toBeInTheDocument();
  });

  it("stays off the pages it does not link to", () => {
    state.pathname = "/";
    render(<Nav />);

    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });

  it("stays hidden from someone who is not signed in", () => {
    state.user = null;
    render(<Nav />);

    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });
});
