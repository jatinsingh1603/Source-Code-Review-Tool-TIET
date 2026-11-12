import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Button, CodeBlock, DataTable, Dialog, SeverityBadge, StatusBadge, Tabs, Toggle } from "@/components/ui";
import { SideBySide } from "@/components/SideBySide";
import type { LedgerDetail } from "@/api/types";

describe("primitives", () => {
  it("Button shows loading and is disabled", () => {
    const onClick = vi.fn();
    render(
      <Button loading onClick={onClick}>
        Save
      </Button>,
    );
    const b = screen.getByRole("button", { name: "Save" });
    expect(b).toBeDisabled();
    fireEvent.click(b);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("SeverityBadge pairs colour with a label", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("StatusBadge labels statuses", () => {
    render(<StatusBadge status="false_positive" />);
    expect(screen.getByText("False positive")).toBeInTheDocument();
  });

  it("Tabs move with the arrow keys", () => {
    const onChange = vi.fn();
    render(
      <Tabs
        value="a"
        onChange={onChange}
        tabs={[
          { id: "a", label: "A" },
          { id: "b", label: "B" },
        ]}
      />,
    );
    fireEvent.keyDown(screen.getByRole("tab", { name: "A" }), { key: "ArrowRight" });
    expect(onChange).toHaveBeenCalledWith("b");
  });

  it("Toggle is a switch", () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} label="Send" />);
    fireEvent.click(screen.getByRole("switch"));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it("Dialog closes on Escape", () => {
    const onClose = vi.fn();
    render(
      <Dialog open onClose={onClose} title="Confirm">
        <button>Inside</button>
      </Dialog>,
    );
    expect(screen.getByRole("dialog", { name: "Confirm" })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });

  it("DataTable sorts by a column", () => {
    const rows = [
      { id: "1", n: 2 },
      { id: "2", n: 9 },
    ];
    render(
      <MemoryRouter>
        <DataTable
          rows={rows}
          rowKey={(r) => r.id}
          columns={[{ id: "n", header: "N", cell: (r) => String(r.n), sortValue: (r) => r.n }]}
        />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole("button", { name: /N/ }));
    const cells = screen.getAllByRole("cell").map((c) => c.textContent);
    expect(cells).toEqual(["9", "2"]);
  });

  it("CodeBlock renders text with line numbers and highlights", () => {
    const { container } = render(<CodeBlock code={"a\n<b>evil</b>"} startLine={10} highlight={[{ start: 11, end: 11 }]} />);
    expect(container.querySelector("[data-line='11']")).toHaveAttribute("data-highlighted", "true");
    expect(container.querySelector("b")).toBeNull();
    expect(screen.getByText("<b>evil</b>")).toBeInTheDocument();
  });
});

const detail: LedgerDetail = {
  entry: {
    seq: 1,
    timestamp: "2026-01-01T00:00:00Z",
    provider: "mock",
    model: "m",
    level: "L3",
    payload_hash: "abc",
    entry_hash: "def",
    prev_hash: "000",
    tokens: 10,
    candidate_id: "c1",
    outcome: "sent",
  },
  original_text: "key = 'AKIA'",
  payload_text: "var_1 = '<SECRET_1>'",
  markup: [
    { kind: "secret", start: 7, end: 11, side: "original" },
    { kind: "secret", start: 9, end: 19, side: "payload" },
  ],
};

describe("SideBySide", () => {
  it("shows both sides with marks", () => {
    render(<SideBySide detail={detail} />);
    expect(screen.getByText(/stays on this machine/)).toBeInTheDocument();
    expect(screen.getByText("<SECRET_1>").tagName).toBe("MARK");
  });
  it("explains the missing original side", () => {
    render(<SideBySide detail={{ ...detail, original_text: "" }} />);
    expect(screen.getByText(/Auditor role/)).toBeInTheDocument();
    expect(screen.queryByText(/stays on this machine/)).toBeNull();
  });
});

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

describe("rendering rules", () => {
  it("never uses dangerouslySetInnerHTML in src/", () => {
    const offenders = walk(join(__dirname, "..", "src")).filter((f) =>
      readFileSync(f, "utf8").includes("dangerouslySetInner" + "HTML"),
    );
    expect(offenders).toEqual([]);
  });
});
