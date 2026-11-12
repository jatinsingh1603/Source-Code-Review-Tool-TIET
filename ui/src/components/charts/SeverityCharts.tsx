import { useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Severity, SeverityCounts, TrendPoint } from "@/api/types";
import { fmtDay, SEVERITY_LABEL } from "@/lib/format";
import { Segmented } from "@/components/ui";

const chart = (name: string) => `rgb(var(--ck-chart-${name}))`;
export const SEV_CHART_COLOR: Record<Severity, string> = {
  critical: chart("critical"),
  high: chart("high"),
  medium: chart("medium"),
  low: chart("low"),
  info: chart("info"),
};

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { name: string; value: number; color?: string; payload?: { fill?: string } }[];
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border border-border bg-surface px-3 py-2 text-xs shadow-md">
      {label && <p className="mb-1 font-semibold text-fg">{label}</p>}
      {payload.map((p) => (
        <p key={p.name} className="flex items-center gap-2 text-fg-muted">
          <span
            className="inline-block h-2.5 w-2.5 rounded-sm"
            style={{ background: p.color ?? p.payload?.fill }}
          />
          <span className="text-fg">{p.name}</span>
          <span className="ml-auto pl-3 font-semibold tabular-nums text-fg">{p.value}</span>
        </p>
      ))}
    </div>
  );
}

/** Donut of findings by severity, with a legend that doubles as the table view. */
export function SeverityDonut({ counts }: { counts: SeverityCounts }) {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const data = order.map((s) => ({ name: SEVERITY_LABEL[s], key: s, value: counts[s] ?? 0 }));
  const total = data.reduce((a, d) => a + d.value, 0);
  return (
    <div className="flex flex-col items-center gap-6 sm:flex-row">
      <div className="relative h-44 w-44 shrink-0" role="img" aria-label={`Findings by severity, ${total} in total`}>
        <ResponsiveContainer>
          <PieChart>
            <Pie
              data={total ? data.filter((d) => d.value > 0) : [{ name: "None", key: "info", value: 1 }]}
              dataKey="value"
              nameKey="name"
              innerRadius="68%"
              outerRadius="100%"
              paddingAngle={total ? 2 : 0}
              stroke="rgb(var(--ck-surface))"
              strokeWidth={2}
              isAnimationActive={false}
            >
              {(total ? data.filter((d) => d.value > 0) : [{ key: "none" }]).map((d) => (
                <Cell
                  key={d.key}
                  fill={d.key === "none" ? "rgb(var(--ck-surface-3))" : SEV_CHART_COLOR[d.key as Severity]}
                />
              ))}
            </Pie>
            {total > 0 && <Tooltip content={<ChartTooltip />} />}
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-semibold tabular-nums text-fg">{total}</span>
          <span className="text-xs text-fg-subtle">open findings</span>
        </div>
      </div>
      <table className="w-full text-sm">
        <caption className="sr-only">Open findings by severity</caption>
        <tbody>
          {data.map((d) => (
            <tr key={d.key} className="border-b border-border last:border-0">
              <th scope="row" className="py-1.5 text-left font-normal">
                <span className="flex items-center gap-2 text-fg">
                  <span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEV_CHART_COLOR[d.key] }} aria-hidden />
                  {d.name}
                </span>
              </th>
              <td className="py-1.5 pl-4 text-right font-semibold tabular-nums text-fg">{d.value}</td>
              <td className="w-14 py-1.5 text-right tabular-nums text-fg-subtle">
                {total ? `${Math.round((d.value / total) * 100)}%` : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Stacked area of findings per scan over time, with a table toggle. */
export function FindingsTrend({ trend }: { trend: TrendPoint[] }) {
  const [view, setView] = useState<"chart" | "table">("chart");
  const order: Exclude<Severity, "info">[] = ["low", "medium", "high", "critical"];
  const data = trend.map((t) => ({ ...t, label: fmtDay(t.date) }));
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <ul className="flex flex-wrap gap-3 text-xs text-fg-muted" aria-label="Legend">
          {[...order].reverse().map((s) => (
            <li key={s} className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEV_CHART_COLOR[s] }} aria-hidden />
              {SEVERITY_LABEL[s]}
            </li>
          ))}
        </ul>
        <Segmented
          label="Trend view"
          value={view}
          onChange={setView}
          options={[
            { value: "chart", label: "Chart" },
            { value: "table", label: "Table" },
          ]}
        />
      </div>
      {view === "chart" ? (
        <div className="h-60" role="img" aria-label="Findings per scan over time, stacked by severity">
          <ResponsiveContainer>
            <AreaChart data={data} margin={{ top: 6, right: 8, bottom: 0, left: -18 }}>
              <CartesianGrid stroke="rgb(var(--ck-chart-grid))" vertical={false} />
              <XAxis
                dataKey="label"
                tick={{ fill: "rgb(var(--ck-chart-axis))", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "rgb(var(--ck-chart-axis))", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<ChartTooltip />} cursor={{ stroke: "rgb(var(--ck-border-strong))" }} />
              {order.map((s) => (
                <Area
                  key={s}
                  type="monotone"
                  dataKey={s}
                  name={SEVERITY_LABEL[s]}
                  stackId="1"
                  stroke={SEV_CHART_COLOR[s]}
                  strokeWidth={2}
                  fill={SEV_CHART_COLOR[s]}
                  fillOpacity={0.22}
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className="max-h-60 overflow-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">Findings per scan</caption>
            <thead>
              <tr className="text-xs uppercase text-fg-subtle">
                <th scope="col" className="py-1.5 text-left font-semibold">Scan</th>
                <th scope="col" className="py-1.5 text-left font-semibold">Date</th>
                {[...order].reverse().map((s) => (
                  <th key={s} scope="col" className="py-1.5 text-right font-semibold">
                    {SEVERITY_LABEL[s]}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.map((t) => (
                <tr key={t.scan_id} className="border-t border-border">
                  <th scope="row" className="py-1.5 text-left font-mono text-xs font-normal text-fg">{t.scan_id}</th>
                  <td className="py-1.5 text-fg-muted">{t.label}</td>
                  {[...order].reverse().map((s) => (
                    <td key={s} className="py-1.5 text-right tabular-nums text-fg">
                      {t[s]}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
