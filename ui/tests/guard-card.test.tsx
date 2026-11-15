import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { PrivacySummary } from "@/api/types";
import { GuardCard } from "@/pages/OverviewPage";

const privacy = { blocked: 0, payloads: 14, zero_leak: { checked: 31, occurrences: 0, passed: true } } as unknown as PrivacySummary;
const report = { recorded: false, invariants: [] };

describe("Overview privacy guard status", () => {
  it("does not say 'not recorded' while the evidence loads", () => {
    render(
      <MemoryRouter>
        <GuardCard loading />
      </MemoryRouter>,
    );
    expect(screen.getByText("Privacy guard status")).toBeTruthy();
    expect(screen.queryByText("not recorded")).toBeNull();
  });

  it("shows this scan's evidence once it is in", () => {
    render(
      <MemoryRouter>
        <GuardCard report={report as never} privacy={privacy} />
      </MemoryRouter>,
    );
    expect(screen.getByText("0 blocked")).toBeTruthy();
    expect(screen.getAllByText("not recorded")).toHaveLength(4);
  });
});
