import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { cn } from "@/lib/format";
import { IconButton } from "./Button";
import { Icon } from "./Icon";

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Traps focus inside `ref` while open and restores it to the opener on close. */
export function useFocusTrap(open: boolean, ref: React.RefObject<HTMLElement>, onClose: () => void) {
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement as HTMLElement | null;
    const node = ref.current;
    // The field to fill in first, before the header's Close button.
    const first =
      node?.querySelector<HTMLElement>("[data-autofocus]") ??
      node?.querySelector<HTMLElement>(
        ".body input:not([disabled]):not([type=hidden]), .body textarea:not([disabled]), .body select:not([disabled])",
      ) ??
      node?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? node)?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (e.key !== "Tab" || !node) return;
      const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (items.length === 0) return;
      const firstEl = items[0]!;
      const lastEl = items[items.length - 1]!;
      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault();
        lastEl.focus();
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault();
        firstEl.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
      // Back to the opener; when the dialog's action removed or disabled it
      // (a bulk bar that goes once the selection is cleared), to the page.
      if (opener?.isConnected) opener.focus?.();
      window.setTimeout(() => {
        if (document.activeElement === document.body || !document.activeElement) {
          document.getElementById("main")?.focus({ preventScroll: true });
        }
      }, 0);
    };
  }, [open, ref]);
}

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  size?: "md" | "lg";
}

/** Modal dialog: flat white panel over a dimmed page, 1 px lines. */
export function Dialog({ open, onClose, title, description, children, footer, size = "md" }: DialogProps) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const descId = useId();
  useFocusTrap(open, ref, onClose);
  if (!open) return null;
  return createPortal(
    <div
      className="ck ck-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined}
        tabIndex={-1}
        className={cn("ck-dialog", size === "lg" && "lg")}
      >
        <header>
          <div>
            <h2 id={titleId}>{title}</h2>
            {description && (
              <p id={descId} className="sub" style={{ marginTop: 4 }}>
                {description}
              </p>
            )}
          </div>
          <IconButton label="Close" onClick={onClose}>
            <Icon name="close" />
          </IconButton>
        </header>
        <div className="body">{children}</div>
        {footer && <footer>{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}
