import type { FindingFilters } from "@/api/types";

/** Findings filters live in the URL so a view can be linked and reloaded. */
export function filtersFromParams(p: URLSearchParams): FindingFilters {
  const f: FindingFilters = {};
  for (const k of ["severity", "status", "cwe", "q"] as const) {
    const v = p.get(k);
    if (v) f[k] = v;
  }
  return f;
}

export function applyFiltersToParams(p: URLSearchParams, f: FindingFilters): URLSearchParams {
  const next = new URLSearchParams(p);
  for (const k of ["severity", "status", "cwe", "q"] as const) {
    const v = f[k];
    if (v) next.set(k, v);
    else next.delete(k);
  }
  return next;
}

export function toggleListValue(list: string | undefined, value: string): string | undefined {
  const set = new Set((list ?? "").split(",").filter(Boolean));
  if (set.has(value)) set.delete(value);
  else set.add(value);
  return set.size ? [...set].join(",") : undefined;
}
