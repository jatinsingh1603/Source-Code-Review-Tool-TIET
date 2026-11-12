import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

export type ToastKind = "success" | "error" | "info" | "warning";
export interface ToastInput {
  kind?: ToastKind;
  title: string;
  message?: string;
  /** ms before auto-dismiss; 0 keeps it until closed. */
  duration?: number;
}
interface ToastItem {
  id: number;
  kind: ToastKind;
  title: string;
  message?: string;
}

interface ToastApi {
  toast: (t: ToastInput) => void;
  success: (title: string, message?: string) => void;
  error: (title: string, message?: string) => void;
  info: (title: string, message?: string) => void;
}

const Ctx = createContext<ToastApi | null>(null);
let seq = 0;

/** Ink toasts, bottom right (COMPONENTS.md §17). Errors use the critical text colour. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const dismiss = useCallback((id: number) => setItems((xs) => xs.filter((x) => x.id !== id)), []);
  const toast = useCallback(
    (t: ToastInput) => {
      const id = ++seq;
      const kind = t.kind ?? "info";
      setItems((xs) => [...xs.slice(-3), { id, kind, title: t.title, message: t.message }]);
      const duration = t.duration ?? (kind === "error" ? 7000 : 4000);
      if (duration > 0) setTimeout(() => dismiss(id), duration);
    },
    [dismiss],
  );
  const api = useMemo<ToastApi>(
    () => ({
      toast,
      success: (title, message) => toast({ kind: "success", title, message }),
      error: (title, message) => toast({ kind: "error", title, message }),
      info: (title, message) => toast({ kind: "info", title, message }),
    }),
    [toast],
  );
  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="ck-toasts" aria-live="polite" role="status">
        {items.map((t) => (
          <div key={t.id} className={t.kind === "error" ? "toast bad" : "toast"}>
            <div>
              <b>{t.title}</b>
              {t.message && <div className="sub">{t.message}</div>}
            </div>
            <button type="button" aria-label="Dismiss notification" onClick={() => dismiss(t.id)}>
              ×
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export function useToast(): ToastApi {
  const v = useContext(Ctx);
  if (!v) throw new Error("useToast must be used inside ToastProvider");
  return v;
}
