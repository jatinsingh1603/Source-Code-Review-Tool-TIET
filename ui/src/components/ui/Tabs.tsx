import { useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import { cn } from "@/lib/format";

export interface TabItem {
  id: string;
  label: ReactNode;
  count?: number | string;
  disabled?: boolean;
}

export interface TabsProps {
  tabs: TabItem[];
  value: string;
  onChange: (id: string) => void;
  className?: string;
  /** Accessible name of the tab list. */
  label?: string;
  /** Shown after the tabs on the same underline (Findings "+ Save view"). */
  after?: ReactNode;
}

function useRovingKeys<T extends { id: string; disabled?: boolean }>(
  items: T[],
  value: string,
  onChange: (id: string) => void,
) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const enabled = items.filter((t) => !t.disabled);
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
    refs.current[items.indexOf(t)]?.focus();
  };
  return { refs, onKey };
}

/** Underlined tabs with counts (COMPONENTS.md §11); arrow keys move between tabs. */
export function Tabs({ tabs, value, onChange, className, label, after }: TabsProps) {
  const base = useId();
  const { refs, onKey } = useRovingKeys(tabs, value, onChange);
  const list = (
    <div role="tablist" aria-label={label} onKeyDown={onKey} className={cn("tabs", !after && className)}>
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
            className={active ? "on" : undefined}
          >
            {t.label}
            {t.count !== undefined && <span className="cnt">{t.count}</span>}
          </button>
        );
      })}
    </div>
  );
  if (!after) return list;
  return (
    <div className={cn("tabs-row", className)}>
      {list}
      {after}
    </div>
  );
}

/** Segmented control (`.seg`). With `tabs` it behaves as a tab list (Privacy Inspect). */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
  tabs,
  className,
}: {
  options: { value: T; label: ReactNode; disabled?: boolean; title?: string }[];
  value: T;
  onChange: (v: T) => void;
  label: string;
  tabs?: boolean;
  className?: string;
}) {
  const items = options.map((o) => ({ id: o.value as string, disabled: o.disabled }));
  const { refs, onKey } = useRovingKeys(items, value, (id) => onChange(id as T));
  return (
    <div role={tabs ? "tablist" : "radiogroup"} aria-label={label} className={cn("seg", className)} onKeyDown={onKey}>
      {options.map((o, i) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role={tabs ? "tab" : "radio"}
            aria-selected={tabs ? on : undefined}
            aria-checked={tabs ? undefined : on}
            tabIndex={on ? 0 : -1}
            disabled={o.disabled}
            title={o.title}
            onClick={() => onChange(o.value)}
            className={on ? "on" : undefined}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
