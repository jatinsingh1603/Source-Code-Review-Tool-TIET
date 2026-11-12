import type { CSSProperties, ReactNode } from "react";

/**
 * The design's icon set (ui/design/SCREENS.md, Icons): inline SVG, 24×24
 * viewBox, drawn with `.ico` (16 px, stroke 1.6, round caps). No icon font or
 * library.
 */
const PATHS = {
  grid: <path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z" />,
  folder: <path d="M3 7h6l2 2h10v10H3z" />,
  gauge: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 12l6-6" />
    </>
  ),
  flag: <path d="M5 21V4h11l-2 4 2 4H5" />,
  shield: <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" />,
  lines: <path d="M4 6h16M4 12h16M4 18h10" />,
  sliders: (
    <>
      <path d="M4 7h9M17 7h3M4 17h3M11 17h9" />
      <circle cx="15" cy="7" r="2" />
      <circle cx="9" cy="17" r="2" />
    </>
  ),
  doc: <path d="M6 3h9l4 4v14H6zM14 3v5h5" />,
  plug: <path d="M9 3v5M15 3v5M7 8h10v4a5 5 0 0 1-10 0zM12 17v4" />,
  chip: <path d="M7 7h10v10H7zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4" />,
  bars: <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />,
  users: (
    <>
      <circle cx="9" cy="8" r="3" />
      <path d="M3 20c0-3 3-5 6-5s6 2 6 5M16 5a3 3 0 0 1 0 6M21 20c0-2-1.5-4-4-4.6" />
    </>
  ),
  cog: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2" />
    </>
  ),
  play: <path d="M8 5v14l11-7z" />,
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-4-4" />
    </>
  ),
  bell: <path d="M6 16v-5a6 6 0 0 1 12 0v5l2 2H4zM10 21h4" />,
  "chevron-down": <path d="M6 9l6 6 6-6" />,
  "arrow-right": <path d="M5 12h14M13 6l6 6-6 6" />,
  "arrow-up-right": <path d="M7 17L17 7M9 7h8v8" />,
  "arrow-up": <path d="M12 19V5M6 11l6-6 6 6" />,
  "arrow-down": <path d="M12 5v14M6 13l6 6 6-6" />,
  "flow-right": <path d="M4 12h15M14 7l5 5-5 5" />,
  "flow-left": <path d="M20 12H5M10 7l-5 5 5 5" />,
  copy: (
    <>
      <rect x="8" y="8" width="12" height="12" rx="2" />
      <path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10" width="14" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </>
  ),
  "lock-wide": (
    <>
      <rect x="4" y="10" width="16" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v6M12 7.5v.5" />
    </>
  ),
  close: <path d="M6 6l12 12M18 6L6 18" />,
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

export function Icon({
  name,
  className,
  style,
  size,
}: {
  name: IconName;
  className?: string;
  style?: CSSProperties;
  /** Pixel size; the default is the `.ico` 16 px. */
  size?: number;
}) {
  const st = size ? { width: size, height: size, ...style } : style;
  return (
    <svg className={className ? `ico ${className}` : "ico"} viewBox="0 0 24 24" aria-hidden="true" style={st}>
      {PATHS[name]}
    </svg>
  );
}

/** The CodeKavach mark: four lines of code, one short blue segment leaves. */
export function Logo({ size, onInk }: { size?: number; onInk?: boolean }) {
  const ink = onInk ? "#FFFFFF" : "var(--text)";
  const acc = onInk ? "var(--logo-accent-on-dark)" : "var(--accent)";
  return (
    <svg className="logo" viewBox="0 0 28 28" aria-hidden="true" style={size ? { width: size, height: size } : undefined}>
      <rect x="3" y="5" width="22" height="3" rx="1" style={{ fill: ink }} />
      <rect x="7" y="11" width="10" height="3" rx="1" style={{ fill: ink }} />
      <rect x="19" y="11" width="6" height="3" rx="1" style={{ fill: acc }} />
      <rect x="7" y="17" width="15" height="3" rx="1" style={{ fill: ink }} />
      <rect x="3" y="23" width="13" height="3" rx="1" style={{ fill: ink }} />
    </svg>
  );
}
