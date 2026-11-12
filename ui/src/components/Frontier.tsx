/** A point of the privacy-utility frontier: detection F1 against identifier recovery. */
export interface FrontierPoint {
  arm: string;
  f1: number;
  /** Identifier recovery rate, 0..1. */
  recovery: number;
}

/**
 * Privacy-utility frontier (SCREENS.md §11). Scales: x = 48 + recovery% × 45.2
 * (0 to 10%), y = 200 − (F1 − 0.5) × 360 (0.5 to 1.0; the design's 0.9 top is
 * raised because measured F1 can exceed it). Points beyond 10% are noted as
 * off chart.
 */
export function Frontier({ points }: { points: FrontierPoint[] }) {
  const x = (r: number) => 48 + Math.min(10, r * 100) * 45.2;
  const y = (f: number) => 200 - (Math.max(0.5, Math.min(1, f)) - 0.5) * 360;
  const on = points.filter((p) => p.recovery * 100 <= 10);
  const off = points.filter((p) => p.recovery * 100 > 10);
  const sorted = [...on].sort((a, b) => a.recovery - b.recovery);
  const label = sorted.map((p) => `${p.arm} F1 ${p.f1.toFixed(2)} at ${(p.recovery * 100).toFixed(1)}% recovery`).join("; ");
  return (
    <svg viewBox="0 0 520 240" role="img" aria-label={label} style={{ width: "100%", height: "auto", fontFamily: "'IBM Plex Sans', sans-serif" }}>
      <line x1="48" y1="200" x2="500" y2="200" style={{ stroke: "var(--border-strong)" }} />
      <line x1="48" y1="20" x2="48" y2="200" style={{ stroke: "var(--border-strong)" }} />
      <line x1="48" y1="110" x2="500" y2="110" style={{ stroke: "var(--border)", strokeDasharray: "3 3" }} />
      <line x1="48" y1="20" x2="500" y2="20" style={{ stroke: "var(--border)", strokeDasharray: "3 3" }} />
      <text x="40" y="204" textAnchor="end" style={{ fontSize: 11, fill: "var(--faint)" }}>
        0.5
      </text>
      <text x="40" y="114" textAnchor="end" style={{ fontSize: 11, fill: "var(--faint)" }}>
        0.75
      </text>
      <text x="40" y="24" textAnchor="end" style={{ fontSize: 11, fill: "var(--faint)" }}>
        1.0
      </text>
      <text x="48" y="222" textAnchor="middle" style={{ fontSize: 11, fill: "var(--faint)" }}>
        0%
      </text>
      <text x="274" y="222" textAnchor="middle" style={{ fontSize: 11, fill: "var(--faint)" }}>
        5%
      </text>
      <text x="500" y="222" textAnchor="end" style={{ fontSize: 11, fill: "var(--faint)" }}>
        10%
      </text>
      <text x="274" y="238" textAnchor="middle" style={{ fontSize: 11, fill: "var(--muted)" }}>
        identifier recovery rate
      </text>
      <polyline
        points={sorted.map((p) => `${x(p.recovery).toFixed(0)},${y(p.f1).toFixed(0)}`).join(" ")}
        style={{ fill: "none", stroke: "var(--accent)", strokeWidth: 1.5 }}
      />
      {sorted.map((p, i) => {
        const base = /sast only/i.test(p.arm);
        const def = /L3/.test(p.arm);
        const cx = x(p.recovery);
        const cy = y(p.f1);
        // Points at the same place get their labels stacked.
        const dup = sorted.slice(0, i).filter((q) => Math.abs(x(q.recovery) - cx) < 6 && Math.abs(y(q.f1) - cy) < 6).length;
        return (
          <g key={p.arm}>
            <circle
              cx={cx}
              cy={cy}
              r={def ? 5 : 4}
              style={base ? { fill: "var(--surface)", stroke: "var(--text)", strokeWidth: 1.5 } : { fill: def ? "var(--text)" : "var(--accent)" }}
            />
            <text
              x={cx > 380 ? cx - 8 : cx + 8}
              textAnchor={cx > 380 ? "end" : "start"}
              y={base ? cy + 16 + dup * 14 : cy - 7 - dup * 14}
              style={def ? { fontSize: 12, fontWeight: 600, fill: "var(--text)" } : { fontSize: 11, fill: "var(--muted)" }}
            >
              {p.arm}
              {def ? " default" : ""} · {p.f1.toFixed(2)}
            </text>
          </g>
        );
      })}
      {off.length > 0 && (
        <text x="496" y="88" textAnchor="end" style={{ fontSize: 11, fill: "var(--faint)" }}>
          {off.map((p) => p.arm).join(", ")} at {Math.round(off[0]!.recovery * 100)}% → off chart
        </text>
      )}
    </svg>
  );
}

/** Evaluation results as the design needs them (`GET /evaluation`, an API gap). */
export interface EvaluationData {
  sample?: boolean;
  benchmarks?: { dataset: string; arm: string; precision: number; recall: number; f1: number; f1_ci?: [number, number] }[];
  frontier?: FrontierPoint[];
  attacks?: { experiment: string; description?: string; by_level?: Record<string, number | null>; reading?: string }[];
  leakage?: { level: string; recovery: number; note?: string }[];
  note?: string;
}

export function asEvaluation(d: unknown): EvaluationData | null {
  if (!d || typeof d !== "object") return null;
  return d as EvaluationData;
}
