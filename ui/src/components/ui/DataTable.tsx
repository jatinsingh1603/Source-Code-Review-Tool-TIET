import { useMemo, useState, type ReactNode } from "react";
import { cn } from "@/lib/format";
import { SkeletonRows } from "./Feedback";

export interface Column<T> {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /** Value used for sorting; omit to make the column unsortable. */
  sortValue?: (row: T) => string | number;
  /** Class on each `td` (`num`, `mono`, `wrap`, `sm muted`…). */
  className?: string;
  headerClassName?: string;
  headerStyle?: React.CSSProperties;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  initialSort?: { id: string; dir: "asc" | "desc" };
  empty?: ReactNode;
  loading?: boolean;
  /** Row ids drawn as selected (`tr.sel`). */
  selected?: Set<string> | string | null;
  caption?: string;
  /** Drop the table frame (inside a card). */
  bare?: boolean;
  className?: string;
}

/** `.tbl` inside `.tbl-wrap` (COMPONENTS.md §12), with optional column sorting. */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  initialSort,
  empty,
  loading,
  selected,
  caption,
  bare,
  className,
}: DataTableProps<T>) {
  const [sort, setSort] = useState(initialSort ?? null);
  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.id === sort.id);
    if (!col?.sortValue) return rows;
    const sv = col.sortValue;
    return [...rows].sort((a, b) => {
      const x = sv(a);
      const y = sv(b);
      const r = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
      return sort.dir === "asc" ? r : -r;
    });
  }, [rows, columns, sort]);

  const toggle = (id: string) =>
    setSort((s) => (s?.id === id ? { id, dir: s.dir === "asc" ? "desc" : "asc" } : { id, dir: "desc" }));
  const isSel = (k: string) => (typeof selected === "string" ? selected === k : !!selected?.has(k));

  return (
    <div className={cn("tbl-wrap", className)} style={bare ? { border: 0 } : undefined}>
      <table className="tbl">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr>
            {columns.map((c) => {
              const active = sort?.id === c.id;
              return (
                <th
                  key={c.id}
                  scope="col"
                  className={c.headerClassName}
                  style={c.headerStyle}
                  aria-sort={active ? (sort!.dir === "asc" ? "ascending" : "descending") : undefined}
                >
                  {c.sortValue ? (
                    <button
                      type="button"
                      className="linkbtn"
                      style={{ color: "inherit", fontWeight: "inherit", fontSize: "inherit" }}
                      onClick={() => toggle(c.id)}
                    >
                      {c.header}
                      {active ? (sort!.dir === "asc" ? " ↑" : " ↓") : ""}
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
          {loading ? (
            <SkeletonRows cols={columns.length} />
          ) : (
            sorted.map((r) => {
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
                  aria-selected={selected ? isSel(key) : undefined}
                  className={cn(onRowClick && "click", isSel(key) && "sel")}
                >
                  {columns.map((c) => (
                    <td key={c.id} className={c.className}>
                      {c.cell(r)}
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {!loading && rows.length === 0 && empty}
    </div>
  );
}
