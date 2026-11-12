import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";
import { cn } from "@/lib/format";

export interface FieldProps {
  label: ReactNode;
  help?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  children: (id: string, describedBy: string | undefined) => ReactNode;
  className?: string;
}

/** Label + control + help/error text with the ARIA wiring done. */
export function Field({ label, help, error, required, children, className }: FieldProps) {
  const id = useId();
  const helpId = `${id}-help`;
  const describedBy = error || help ? helpId : undefined;
  return (
    <div className={className}>
      <label htmlFor={id} className="ck-label">
        {label}
        {required && (
          <span className="ml-0.5 text-danger" aria-hidden>
            *
          </span>
        )}
      </label>
      {children(id, describedBy)}
      {error ? (
        <p id={helpId} className="mt-1 text-xs text-danger" role="alert">
          {error}
        </p>
      ) : help ? (
        <p id={helpId} className="ck-help">
          {help}
        </p>
      ) : null}
    </div>
  );
}

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn("ck-input", className)} {...rest} />;
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cn("ck-input appearance-auto pr-8", className)} {...rest}>
      {children}
    </select>
  );
}

export interface ToggleProps {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: ReactNode;
  description?: ReactNode;
  disabled?: boolean;
}

export function Toggle({ checked, onChange, label, description, disabled }: ToggleProps) {
  const id = useId();
  return (
    <div className="flex items-start gap-3">
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          "relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-50",
          checked ? "bg-primary" : "bg-border-strong",
        )}
      >
        <span
          className={cn(
            "inline-block h-4 w-4 rounded-full bg-white shadow transition-transform",
            checked ? "translate-x-[18px]" : "translate-x-0.5",
          )}
        />
      </button>
      <label htmlFor={id} className="cursor-pointer select-none">
        <span className="block text-sm font-medium text-fg">{label}</span>
        {description && <span className="block text-xs text-fg-muted">{description}</span>}
      </label>
    </div>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
  indeterminate,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  indeterminate?: boolean;
}) {
  return (
    <input
      type="checkbox"
      aria-label={label}
      checked={checked}
      ref={(el) => {
        if (el) el.indeterminate = !!indeterminate;
      }}
      onChange={(e) => onChange(e.target.checked)}
      onClick={(e) => e.stopPropagation()}
      className="h-4 w-4 cursor-pointer rounded border-border-strong accent-[rgb(var(--ck-primary))]"
    />
  );
}
