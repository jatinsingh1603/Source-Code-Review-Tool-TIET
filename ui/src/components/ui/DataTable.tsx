import { useMemo, useState, type ReactNode } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { cn } from "@/lib/format";

export interface Column<T> {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /** Value used for sorting; omit to make the column unsortable. */
  sortValue?: (row: T) => string | number;
  className?: string;
  headerClassName?: string;
  /** Marks the column whose cell names the row (rendered as a row header). */
  rowHeader?: boolean;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  initialSort?: { id: string; dir: "asc" | "desc" };
  empty?: ReactNode;
  className?: string;
  /** Row ids that should appear selected. */
  selected?: Set<string>;
  caption?: string;
  dense?: boolean;
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  initialSort,
  empty,
  className,
  selected,
  caption,
  dense,
}: DataTableProps<T>) {
  const [sort, setSort] = useState(initialSort ?? null);
  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.id === sort.id);
    if (!col?.sortValue) return rows;
    const sv = col.sortValue;
    const out = [...rows].sort((a, b) => {
      const x = sv(a);
      const y = sv(b);
      const r = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
      return sort.dir === "asc" ? r : -r;
    });
    return out;
  }, [rows, columns, sort]);

  const toggle = (id: string) =>
    setSort((s) => (s?.id === id ? { id, dir: s.dir === "asc" ? "desc" : "asc" } : { id, dir: "desc" }));

  return (
    <div className={cn("overflow-x-auto", className)}>
      <table className="w-full border-collapse text-left text-base">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr className="border-b border-border">
            {columns.map((c) => {
              const active = sort?.id === c.id;
              return (
                <th
                  key={c.id}
                  scope="col"
                  aria-sort={active ? (sort!.dir === "asc" ? "ascending" : "descending") : undefined}
                  className={cn(
                    "whitespace-nowrap bg-surface-2/60 px-4 py-2.5 text-xs font-semibold uppercase tracking-wide text-fg-subtle",
                    c.headerClassName,
                  )}
                >
                  {c.sortValue ? (
                    <button
                      type="button"
                      onClick={() => toggle(c.id)}
                      className="inline-flex items-center gap-1 uppercase hover:text-fg"
                    >
                      {c.header}
                      {active ? (
                        sort!.dir === "asc" ? (
                          <ArrowUp className="h-3 w-3" aria-hidden />
                        ) : (
                          <ArrowDown className="h-3 w-3" aria-hidden />
                        )
                      ) : (
                        <ArrowUpDown className="h-3 w-3 opacity-40" aria-hidden />
                      )}
                    </button>
                  ) : (
                    c.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => {
            const key = rowKey(r);
            return (
              <tr
                key={key}
                onClick={onRowClick ? () => onRowClick(r) : undefined}
                onKeyDown={
                  onRowClick
                    ? (e) => {
                        if (e.key === "Enter" && e.target === e.currentTarget) onRowClick(r);
                      }
                    : undefined
                }
                tabIndex={onRowClick ? 0 : undefined}
                aria-selected={selected ? selected.has(key) : undefined}
                className={cn(
                  "border-b border-border last:border-0 transition-colors",
                  onRowClick && "cursor-pointer hover:bg-surface-2 focus-visible:bg-surface-2",
                  selected?.has(key) && "bg-primary-soft/50",
                )}
              >
                {columns.map((c) => {
                  const Tag = c.rowHeader ? "th" : "td";
                  return (
                    <Tag
                      key={c.id}
                      scope={c.rowHeader ? "row" : undefined}
                      className={cn("px-4 align-middle font-normal", dense ? "py-2" : "py-3", c.className)}
                    >
                      {c.cell(r)}
                    </Tag>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
      {rows.length === 0 && empty}
    </div>
  );
}
