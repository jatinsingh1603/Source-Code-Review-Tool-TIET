import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Button, CodeBlock, DataTable, Dialog, SeverityBadge, StatusBadge, Tabs, Toggle } from "@/components/ui";
import { MarkedCode } from "@/components/Marked";
import type { LedgerDetail } from "@/api/types";

describe("primitives", () => {
  it("an action Button ignores the second click of a double click", () => {
    const onClick = vi.fn();
    render(
      <Button loading={false} onClick={onClick}>
        Start scan
      </Button>,
    );
    const b = screen.getByRole("button", { name: "Start scan" });
    fireEvent.click(b);
    fireEvent.click(b);
    expect(onClick).toHaveBeenCalledTimes(1);
  });
  it("an action Button that started nothing takes the next click after a moment", () => {
    vi.useFakeTimers();
    try {
      const onClick = vi.fn();
      render(
        <Button loading={false} onClick={onClick}>
          Create user
        </Button>,
      );
      const b = screen.getByRole("button", { name: "Create user" });
      fireEvent.click(b); // the form refused its input: no request, `loading` stays false
      vi.advanceTimersByTime(500);
      fireEvent.click(b); // the corrected form is submitted on the first try
      expect(onClick).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
  it("a plain Button passes every click through", () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Next</Button>);
    const b = screen.getByRole("button", { name: "Next" });
    fireEvent.click(b);
    fireEvent.click(b);
    expect(onClick).toHaveBeenCalledTimes(2);
  });
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

  it("Tabs keep a trailing action outside the tab list", () => {
    render(<Tabs value="a" onChange={() => {}} tabs={[{ id: "a", label: "A" }]} after={<button type="button">+ Save view</button>} />);
    const action = screen.getByRole("button", { name: "+ Save view" });
    expect(screen.getByRole("tablist")).not.toContainElement(action);
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

  it("Dialog focuses its first field, not the Close button", () => {
    render(
      <Dialog open onClose={() => undefined} title="Suppress">
        <textarea aria-label="Reason" />
      </Dialog>,
    );
    expect(document.activeElement).toBe(screen.getByRole("textbox", { name: "Reason" }));
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

describe("MarkedCode", () => {
  it("marks the payload side with the design classes, as text", () => {
    const { container } = render(<MarkedCode text={detail.payload_text} markup={detail.markup} side="payload" />);
    const mark = screen.getByText("<SECRET_1>");
    expect(mark.className).toBe("rd");
    expect(container.querySelector(".code .ln .n")?.textContent).toBe("1");
  });
  it("leaves unmarked text plain on the original side", () => {
    render(<MarkedCode text={detail.original_text} markup={detail.markup} side="original" />);
    expect(screen.getByText("AKIA").className).toBe("rd");
    expect(screen.queryByText("<SECRET_1>")).toBeNull();
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
