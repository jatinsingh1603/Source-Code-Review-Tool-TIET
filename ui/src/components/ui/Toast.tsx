import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";
import { cn } from "@/lib/format";

export type ToastKind = "success" | "error" | "info" | "warning";
export interface ToastInput {
  kind?: ToastKind;
  title: string;
  message?: string;
  /** ms before auto-dismiss; 0 keeps it until closed. */
  duration?: number;
}
interface ToastItem extends Required<Omit<ToastInput, "message">> {
  id: number;
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

const icons = { success: CheckCircle2, error: XCircle, info: Info, warning: AlertTriangle };
const colours = {
  success: "text-success",
  error: "text-danger",
  info: "text-info",
  warning: "text-warning",
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const dismiss = useCallback((id: number) => setItems((xs) => xs.filter((x) => x.id !== id)), []);
  const toast = useCallback(
    (t: ToastInput) => {
      const id = ++seq;
      const item: ToastItem = {
        id,
        kind: t.kind ?? "info",
        title: t.title,
        message: t.message,
        duration: t.duration ?? (t.kind === "error" ? 7000 : 4000),
      };
      setItems((xs) => [...xs.slice(-4), item]);
      if (item.duration > 0) setTimeout(() => dismiss(id), item.duration);
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
      <div
        aria-live="polite"
        role="status"
        className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[22rem] max-w-[calc(100vw-2rem)] flex-col gap-2"
      >
        {items.map((t) => {
          const Icon = icons[t.kind];
          return (
            <div
              key={t.id}
              className="pointer-events-auto flex animate-pop-in items-start gap-3 rounded-lg border border-border bg-surface p-3.5 shadow-lg"
            >
              <Icon className={cn("mt-0.5 h-5 w-5 shrink-0", colours[t.kind])} aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-fg">{t.title}</p>
                {t.message && <p className="mt-0.5 break-words text-sm text-fg-muted">{t.message}</p>}
              </div>
              <button
                type="button"
                aria-label="Dismiss notification"
                onClick={() => dismiss(t.id)}
                className="rounded p-0.5 text-fg-subtle hover:text-fg"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          );
        })}
      </div>
    </Ctx.Provider>
  );
}

export function useToast(): ToastApi {
  const v = useContext(Ctx);
  if (!v) throw new Error("useToast must be used inside ToastProvider");
  return v;
}
