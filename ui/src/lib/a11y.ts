import { useEffect, useRef } from "react";

const APP = "CodeKavach";
/** Containers the design lets scroll sideways (wide tables, the pipeline strip). */
const SCROLLERS = ".tbl-wrap, .pipe-wrap, [data-scroll-x]";
const MARK = "data-kb-scroll";

function pageTitle(): string {
  const h1 = document.querySelector("main h1");
  // Join the h1's parts with spaces: "Scan SCN-1341F1" + a "Running" badge.
  const text = Array.from(h1?.childNodes ?? [])
    .map((n) => n.textContent?.trim() ?? "")
    .filter(Boolean)
    .join(" ")
    .replace(/\s+/g, " ");
  return text ? `${text} · ${APP}` : APP;
}

/**
 * A scroller that overflows and holds nothing focusable cannot be scrolled
 * with the keyboard (WCAG 2.1.1). Make it a named, focusable region while it
 * overflows, and undo that when it no longer does.
 */
function syncScrollers(root: ParentNode): void {
  for (const el of root.querySelectorAll<HTMLElement>(SCROLLERS)) {
    const overflows = el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1;
    const ours = el.hasAttribute(MARK);
    if (overflows && !ours && !el.hasAttribute("tabindex")) {
      // Remember which attributes are ours, so only those are taken off again.
      const set = ["tabindex"];
      el.tabIndex = 0;
      if (!el.getAttribute("role")) {
        el.setAttribute("role", "region");
        set.push("role");
      }
      if (!el.getAttribute("aria-label") && !el.getAttribute("aria-labelledby")) {
        const cap = el.querySelector("caption")?.textContent?.trim();
        el.setAttribute("aria-label", cap ? `${cap} (scrolls sideways)` : "Table (scrolls sideways)");
        set.push("aria-label");
      }
      el.setAttribute(MARK, set.join(" "));
    } else if (!overflows && ours) {
      for (const a of (el.getAttribute(MARK) ?? "").split(" ")) if (a) el.removeAttribute(a);
      el.removeAttribute(MARK);
    }
  }
}

/**
 * Shell-wide accessibility upkeep for a single-page app: a document title per
 * screen (taken from its h1), focus moved to the new page's main region after
 * a route change, so screen readers announce it and Tab continues in the
 * content, and keyboard access to sideways-scrolling tables.
 */
export function useA11yShell(pathname: string): void {
  const first = useRef(true);
  useEffect(() => {
    let frame = 0;
    const update = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const t = pageTitle();
        if (document.title !== t) document.title = t;
        syncScrollers(document);
      });
    };
    update();
    const mo = new MutationObserver(update);
    mo.observe(document.body, { childList: true, subtree: true, characterData: true });
    window.addEventListener("resize", update);
    return () => {
      cancelAnimationFrame(frame);
      mo.disconnect();
      window.removeEventListener("resize", update);
    };
  }, []);

  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    // After the new page has rendered (lazy pages may need a moment).
    const id = window.setTimeout(() => {
      const main = document.getElementById("main");
      const active = document.activeElement;
      const keep = active && active !== document.body && active.isConnected && main?.contains(active) && active !== main;
      if (main && !keep && !document.querySelector("[role=dialog][aria-modal=true]")) main.focus({ preventScroll: true });
    }, 60);
    return () => window.clearTimeout(id);
  }, [pathname]);
}
