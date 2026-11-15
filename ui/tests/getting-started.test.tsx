import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import GettingStartedPage from "@/pages/GettingStartedPage";
import { renderPage, serveApi } from "./support/page";

describe("Getting started", () => {
  it("walks the workflow for the selected project with the server's own state", async () => {
    await serveApi();
    renderPage(<GettingStartedPage />, "/start");
    expect(await screen.findByRole("heading", { name: "Review your first project" })).toBeTruthy();
    const steps = (await screen.findByRole("list", { name: "Review workflow" })).querySelectorAll("li");
    expect([...steps].map((li) => li.querySelector("b")?.textContent)).toEqual([
      "Add a project",
      "Run a scan",
      "Triage the findings",
      "See what the model saw",
      "Verify the egress ledger",
      "Produce the audit report",
    ]);
    // The preview project has a completed scan: its step is done and links to a new scan.
    expect(await screen.findByRole("link", { name: "Scan again" })).toBeTruthy();
    expect(await screen.findByText(/Latest scan ·/)).toBeTruthy();
  });

  it("starts at the first step on a server with no project", async () => {
    await serveApi({ "GET /projects": [] });
    renderPage(<GettingStartedPage />, "/start");
    const add = await screen.findByRole("link", { name: "Add project" });
    expect(add.getAttribute("href")).toBe("/projects/new");
    expect(add.className).toContain("pri");
    expect(screen.queryByText("Done")).toBeNull();
    expect(screen.queryByText(/Latest scan/)).toBeNull();
  });

  it("offers no action a viewer may not take", async () => {
    await serveApi({}, "viewer");
    renderPage(<GettingStartedPage />, "/start");
    await screen.findByRole("list", { name: "Review workflow" });
    expect(screen.queryByRole("link", { name: /Add/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Scan the sample application" })).toBeNull();
    expect(await screen.findByRole("link", { name: "Open Reports" })).toBeTruthy();
  });
});
