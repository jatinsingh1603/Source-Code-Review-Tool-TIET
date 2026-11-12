export function LogoMark({ className = "h-8 w-8" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <defs>
        <linearGradient id="ck-logo-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#6366f1" />
          <stop offset="1" stopColor="#0d9488" />
        </linearGradient>
      </defs>
      <path d="M16 2 4 6.5v8.2c0 7.4 5.1 13.4 12 15.3 6.9-1.9 12-7.9 12-15.3V6.5L16 2z" fill="url(#ck-logo-g)" />
      <path
        d="m11.5 12.5-3 3.5 3 3.5M20.5 12.5l3 3.5-3 3.5M17.5 11l-3 10"
        fill="none"
        stroke="#fff"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Wordmark({ inverted = false }: { inverted?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <LogoMark />
      <div className="leading-tight">
        <div className={inverted ? "text-[15px] font-bold tracking-tight text-white" : "text-[15px] font-bold tracking-tight text-fg"}>
          CodeKavach
        </div>
        <div className={inverted ? "text-[10.5px] text-sidebar-muted" : "text-[10.5px] text-fg-subtle"}>
          Privacy-preserving secure code review
        </div>
      </div>
    </div>
  );
}
