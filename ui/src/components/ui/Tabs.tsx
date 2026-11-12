import { useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import { cn } from "@/lib/format";

export interface TabItem {
  id: string;
  label: ReactNode;
  icon?: ReactNode;
  count?: number;
  disabled?: boolean;
}

export interface TabsProps {
  tabs: TabItem[];
  value: string;
  onChange: (id: string) => void;
  className?: string;
  /** Accessible name of the tab list. */
  label?: string;
}

/** WAI-ARIA tabs: arrow keys move between tabs, Home/End jump to the ends. */
export function Tabs({ tabs, value, onChange, className, label }: TabsProps) {
  const base = useId();
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const enabled = tabs.filter((t) => !t.disabled);
  const onKey = (e: KeyboardEvent) => {
    const idx = enabled.findIndex((t) => t.id === value);
    let next = -1;
    if (e.key === "ArrowRight") next = (idx + 1) % enabled.length;
    else if (e.key === "ArrowLeft") next = (idx - 1 + enabled.length) % enabled.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = enabled.length - 1;
    if (next < 0) return;
    e.preventDefault();
    const t = enabled[next]!;
    onChange(t.id);
    refs.current[tabs.indexOf(t)]?.focus();
  };
  return (
    <div
      role="tablist"
      aria-label={label}
      onKeyDown={onKey}
      className={cn("flex gap-1 overflow-x-auto border-b border-border", className)}
    >
      {tabs.map((t, i) => {
        const active = t.id === value;
        return (
          <button
            key={t.id}
            ref={(el) => {
              refs.current[i] = el;
            }}
            id={`${base}-${t.id}`}
            role="tab"
            type="button"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            disabled={t.disabled}
            onClick={() => onChange(t.id)}
            className={cn(
              "relative -mb-px inline-flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2.5 text-sm font-medium transition-colors disabled:opacity-40",
              active
                ? "border-primary text-primary"
                : "border-transparent text-fg-muted hover:border-border-strong hover:text-fg",
            )}
          >
            {t.icon}
            {t.label}
            {t.count !== undefined && (
              <span
                className={cn(
                  "rounded-full px-1.5 text-xs",
                  active ? "bg-primary-soft text-primary" : "bg-surface-3 text-fg-muted",
                )}
              >
                {t.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

/** Pill-style segmented control for small option sets. */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
}: {
  options: { value: T; label: ReactNode }[];
  value: T;
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-md bg-surface-2 p-0.5 ring-1 ring-inset ring-border">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={o.value === value}
          onClick={() => onChange(o.value)}
          className={cn(
            "rounded px-2.5 py-1 text-sm font-medium transition-colors",
            o.value === value ? "bg-surface text-fg shadow-sm" : "text-fg-muted hover:text-fg",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
