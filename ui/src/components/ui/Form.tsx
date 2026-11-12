import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { cn } from "@/lib/format";

export interface FieldProps {
  label: ReactNode;
  help?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  children: (id: string, describedBy: string | undefined) => ReactNode;
  className?: string;
}

/** `.fld`: label above the control, with help or error text wired by ARIA. */
export function Field({ label, help, error, required, children, className }: FieldProps) {
  const id = useId();
  const helpId = `${id}-help`;
  const describedBy = error || help ? helpId : undefined;
  return (
    <div className={cn("fld", className)}>
      <label htmlFor={id}>
        {label}
        {required && <span aria-hidden> *</span>}
      </label>
      {children(id, describedBy)}
      {error ? (
        <span id={helpId} className="xs badc" role="alert">
          {error}
        </span>
      ) : help ? (
        <span id={helpId} className="xs faint">
          {help}
        </span>
      ) : null}
    </div>
  );
}

export function Input({ className, mono, ...rest }: InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }) {
  return <input className={cn("inp", mono && "mono", className)} {...rest} />;
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cn("inp", className)} {...rest}>
      {children}
    </select>
  );
}

export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn("inp", className)} {...rest} />;
}

export interface ToggleProps {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: ReactNode;
  description?: ReactNode;
  disabled?: boolean;
  className?: string;
}

/** Switch (`.sw` inside `.swrow`), exposed to assistive technology as a switch. */
export function Toggle({ checked, onChange, label, description, disabled, className }: ToggleProps) {
  return (
    <label className={cn("swrow", className)}>
      <input
        type="checkbox"
        role="switch"
        className="sw"
        checked={checked}
        aria-checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      {description ? (
        <span>
          <b className="sm">{label}</b>
          <br />
          <span className="xs faint">{description}</span>
        </span>
      ) : (
        label
      )}
    </label>
  );
}

/** Checkbox row (`.chk` inside `.swrow`). Without `label` text it renders the bare box. */
export function Checkbox({
  checked,
  onChange,
  label,
  indeterminate,
  bare,
  disabled,
  top,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: ReactNode;
  indeterminate?: boolean;
  /** Render only the input, with `label` as its accessible name. */
  bare?: boolean;
  disabled?: boolean;
  /** Align a multi-line label to the top (consent rows). */
  top?: boolean;
}) {
  const id = useId();
  const box = (
    <input
      id={id}
      type="checkbox"
      className="chk"
      aria-label={bare && typeof label === "string" ? label : undefined}
      checked={checked}
      disabled={disabled}
      ref={(el) => {
        if (el) el.indeterminate = !!indeterminate;
      }}
      onChange={(e) => onChange(e.target.checked)}
      onClick={(e) => e.stopPropagation()}
      style={top ? { marginTop: 3 } : undefined}
    />
  );
  if (bare) return box;
  return (
    <label className="swrow" htmlFor={id} style={top ? { alignItems: "flex-start" } : undefined}>
      {box}
      <span>{label}</span>
    </label>
  );
}
