import { forwardRef, useEffect, useRef, type ButtonHTMLAttributes, type MouseEvent, type ReactNode } from "react";
import { Link, type LinkProps } from "react-router-dom";
import { cn } from "@/lib/format";
import { Icon } from "./Icon";

/** Design buttons (COMPONENTS.md §9): ink primary, outline, ghost, danger. */
export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export type ButtonSize = "sm" | "md" | "xl";

function btnClass(variant: ButtonVariant, size: ButtonSize, extra?: string) {
  return cn(
    "btn",
    variant === "primary" && "pri",
    variant === "ghost" && "ghost",
    variant === "danger" && "danger",
    size === "sm" && "sm",
    size === "xl" && "xl",
    extra,
  );
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Disables the button and shows "…" after the label while a request runs. */
  loading?: boolean;
  /** Icon rendered before the label. */
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", loading, icon, className, children, disabled, type, onClick, ...rest },
  ref,
) {
  // A double click lands both clicks before `loading` re-renders, so an action button
  // (one that takes `loading`) ignores a second click for a moment: two scans, two
  // projects or two reports from one impatient double click is never what was meant.
  const lockedUntil = useRef(0);
  const loadingNow = useRef(loading);
  loadingNow.current = loading;
  useEffect(() => {
    if (!loading) lockedUntil.current = 0;
  }, [loading]);
  const guardedClick = (e: MouseEvent<HTMLButtonElement>) => {
    if (loading !== undefined) {
      const now = Date.now();
      if (now < lockedUntil.current) {
        e.preventDefault();
        return;
      }
      lockedUntil.current = now + 1500;
      // A click that started nothing (a form that refused its input) must not swallow the next
      // one: once a double click is over, unlock unless a request is running.
      window.setTimeout(() => {
        if (!loadingNow.current) lockedUntil.current = 0;
      }, 400);
    }
    onClick?.(e);
  };
  return (
    <button
      ref={ref}
      type={type ?? "button"}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={btnClass(variant, size, className)}
      onClick={guardedClick}
      {...rest}
    >
      {icon}
      {children}
      {loading && <span aria-hidden>…</span>}
    </button>
  );
});

export function ButtonLink({
  variant = "secondary",
  size = "md",
  icon,
  className,
  children,
  ...rest
}: LinkProps & { variant?: ButtonVariant; size?: ButtonSize; icon?: ReactNode }) {
  return (
    <Link className={btnClass(variant, size, className)} {...rest}>
      {icon}
      {children}
    </Link>
  );
}

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Accessible name; required because the button has no visible text. */
  label: string;
  children: ReactNode;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, className, children, type, ...rest },
  ref,
) {
  return (
    <button ref={ref} type={type ?? "button"} aria-label={label} title={label} className={cn("iconbtn", className)} {...rest}>
      {children}
    </button>
  );
});

/** Accent "more" link with a trailing arrow (COMPONENTS.md §4). */
export function MoreLink({ to, children, external }: { to: string; children: ReactNode; external?: boolean }) {
  if (external || /^https?:/.test(to)) {
    return (
      <a className="more" href={to} target="_blank" rel="noreferrer noopener">
        {children} <Icon name="arrow-up-right" />
      </a>
    );
  }
  return (
    <Link className="more" to={to}>
      {children} <Icon name="arrow-right" />
    </Link>
  );
}
