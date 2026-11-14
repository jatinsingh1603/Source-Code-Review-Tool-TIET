import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { FilterMenu } from "@/components/FilterMenu";

function Host() {
  const [v, setV] = useState<string[]>([]);
  return (
    <>
      <FilterMenu
        label="Severity"
        value={v}
        onChange={setV}
        options={[
          { value: "critical", label: "Critical" },
          { value: "high", label: "High" },
          { value: "low", label: "Low" },
        ]}
      />
      <button type="button">After</button>
    </>
  );
}

describe("usePopover (FilterMenu)", () => {
  it("opens from the keyboard into the first item, moves with arrows, and Escape returns to the trigger", () => {
    render(<Host />);
    const trigger = screen.getByRole("button", { name: /Severity/ });
    trigger.focus();
    fireEvent.click(trigger, { detail: 0 });
    const boxes = screen.getAllByRole("checkbox");
    expect(document.activeElement).toBe(boxes[0]);
    fireEvent.keyDown(document, { key: "ArrowDown" });
    expect(document.activeElement).toBe(boxes[1]);
    fireEvent.keyDown(document, { key: "End" });
    expect(document.activeElement).toBe(boxes[2]);
    fireEvent.keyDown(document, { key: "ArrowDown" });
    expect(document.activeElement).toBe(boxes[0]);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it("closes when focus moves out of it", () => {
    render(<Host />);
    const trigger = screen.getByRole("button", { name: /Severity/ });
    fireEvent.click(trigger, { detail: 1 });
    const box = screen.getAllByRole("checkbox")[0]!;
    expect(document.activeElement).not.toBe(box); // a mouse click does not move focus
    fireEvent.focusOut(box, { relatedTarget: screen.getByRole("button", { name: "After" }) });
    expect(screen.queryByRole("checkbox")).toBeNull();
  });
});
