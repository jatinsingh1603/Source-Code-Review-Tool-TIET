import { describe, expect, it } from "vitest";
import { render, waitFor } from "@testing-library/react";
import { act, useState } from "react";
import { useA11yShell } from "@/lib/a11y";

function Shell({ path, title }: { path: string; title: string }) {
  useA11yShell(path);
  return (
    <>
      <nav>
        <a href="/x">Findings</a>
      </nav>
      <main id="main" tabIndex={-1}>
        <h1>
          {title}
          <span className="badge">Running</span>
        </h1>
      </main>
    </>
  );
}

describe("useA11yShell", () => {
  it("titles the document after the page's h1", async () => {
    render(<Shell path="/" title="Overview" />);
    await waitFor(() => expect(document.title).toBe("Overview Running · CodeKavach"));
  });

  it("moves focus to main after a route change, not on first load", async () => {
    let go: (p: string) => void = () => {};
    function Host() {
      const [p, setP] = useState("/");
      go = setP;
      return <Shell path={p} title={p === "/" ? "Overview" : "Findings"} />;
    }
    render(<Host />);
    const link = document.querySelector("nav a") as HTMLAnchorElement;
    link.focus();
    await new Promise((r) => setTimeout(r, 100));
    expect(document.activeElement).toBe(link);
    act(() => go("/findings"));
    await waitFor(() => expect(document.activeElement?.id).toBe("main"));
    await waitFor(() => expect(document.title).toBe("Findings Running · CodeKavach"));
  });
});
