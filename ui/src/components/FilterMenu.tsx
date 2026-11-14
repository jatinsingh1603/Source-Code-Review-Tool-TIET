import { cn } from "@/lib/format";
import { Icon } from "@/components/ui";
import { usePopover } from "@/components/ui/Popover";

/** A `.btn.sm` filter dropdown with checkboxes ("Severity: Critical, High ▾"). */
export function FilterMenu({
  label,
  options,
  value,
  onChange,
  all,
}: {
  label: string;
  /** Show "Label: all" when nothing is selected (Egress Ledger). */
  all?: boolean;
  options: { value: string; label: string; count?: number }[];
  value: string[];
  onChange: (v: string[]) => void;
}) {
  const { open, toggle, ref } = usePopover();
  const names = options.filter((o) => value.includes(o.value)).map((o) => o.label);
  const text = names.length ? `${label}: ${names.length > 2 ? `${names.slice(0, 2).join(", ")} +${names.length - 2}` : names.join(", ")}` : all
      ? `${label}: all`
      : label;
  return (
    <div className="ck-pop" ref={ref}>
      <button type="button" className={cn("btn sm")} aria-haspopup="true" aria-expanded={open} onClick={toggle}>
        {text}
        <Icon name="chevron-down" />
      </button>
      {open && (
        <div className="ck-menu" role="group" aria-label={label}>
          {options.length === 0 && <span className="mi faint">No values in this scan</span>}
          {options.map((o) => {
            const on = value.includes(o.value);
            return (
              <label key={o.value} className={cn("mi", on && "on")}>
                <input
                  type="checkbox"
                  className="chk"
                  checked={on}
                  onChange={() => onChange(on ? value.filter((v) => v !== o.value) : [...value, o.value])}
                />
                <span style={{ flex: 1 }}>{o.label}</span>
                {o.count !== undefined && <span className="xs faint mono">{o.count}</span>}
              </label>
            );
          })}
        </div>
      )}
    </div>
  );
}
