import { useCallback, useEffect, useLayoutEffect, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";

const ITEMS = ".ck-menu button:not([disabled]), .ck-menu a[href], .ck-menu input:not([disabled])";

/**
 * Open state and keyboard behaviour for a `.ck-pop` dropdown (`.ck-menu`):
 * a click outside or Escape closes it, Escape returns focus to the trigger,
 * Tab out of it closes it, the arrow keys, Home and End move between its
 * items, and opening it from the keyboard focuses the first item.
 */
export function usePopover() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const focusFirst = useRef(false);

  const trigger = () => ref.current?.querySelector<HTMLElement>("[aria-expanded]") ?? null;
  const close = useCallback((refocus = false) => {
    setOpen(false);
    if (refocus) trigger()?.focus();
  }, []);
  /** onClick of the trigger; a keyboard "click" (detail 0) moves focus into the menu. */
  const toggle = useCallback((e?: ReactMouseEvent) => {
    focusFirst.current = e?.detail === 0;
    setOpen((x) => !x);
  }, []);

  // Keep the menu on screen, before it is painted: on a phone the top bar
  // wraps, so a right-aligned menu on a left-edge trigger opened off-screen
  // (and a menu past the right edge zoomed the whole page out).
  useLayoutEffect(() => {
    const menu = open ? ref.current?.querySelector<HTMLElement>(".ck-menu") : null;
    if (!menu) return;
    const r = menu.getBoundingClientRect();
    const room = document.documentElement.clientWidth - 8;
    const shift = r.left < 8 ? 8 - r.left : r.right > room ? room - r.right : 0;
    if (shift) menu.style.transform = `translateX(${Math.round(shift)}px)`;
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const node = ref.current;
    if (!node) return;
    const items = () => Array.from(node.querySelectorAll<HTMLElement>(ITEMS));
    if (focusFirst.current) {
      focusFirst.current = false;
      (node.querySelector<HTMLElement>(".ck-menu [aria-selected=true]") ?? items()[0])?.focus();
    }
    const onDown = (e: MouseEvent) => {
      if (!node.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      const inside = node.contains(document.activeElement);
      if (e.key === "Escape") {
        setOpen(false);
        if (inside) trigger()?.focus();
        return;
      }
      if (!inside || !["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;
      const list = items();
      if (!list.length) return;
      e.preventDefault();
      const at = list.indexOf(document.activeElement as HTMLElement);
      const next =
        e.key === "Home" ? 0
        : e.key === "End" ? list.length - 1
        : e.key === "ArrowDown" ? (at + 1) % list.length
        : at <= 0 ? list.length - 1
        : at - 1;
      list[next]?.focus();
    };
    // Tabbing to something outside closes the menu (a null target is a click
    // on a non-focusable spot, which the mousedown handler deals with).
    const onFocusOut = (e: FocusEvent) => {
      const to = e.relatedTarget as Node | null;
      if (to && !node.contains(to)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    node.addEventListener("focusout", onFocusOut);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      node.removeEventListener("focusout", onFocusOut);
    };
  }, [open]);

  return { open, setOpen, toggle, close, ref };
}
