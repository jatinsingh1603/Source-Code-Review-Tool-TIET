import type { Scan } from "@/api/types";
import { fmtDateTime } from "@/lib/format";

export function ScanPicker({
  scans,
  value,
  onChange,
}: {
  scans: Scan[];
  value: string | undefined;
  onChange: (id: string) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-sm text-fg-muted">
      <span className="whitespace-nowrap">Scan</span>
      <select
        className="ck-input h-9 w-auto min-w-[16rem]"
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
      >
        {!value && <option value="">No scans yet</option>}
        {value && !scans.some((s) => s.id === value) && <option value={value}>{value}</option>}
        {scans.map((s) => (
          <option key={s.id} value={s.id}>
            {s.id} · {fmtDateTime(s.created_at ?? s.started_at)} · {s.privacy_level} · {s.status}
          </option>
        ))}
      </select>
    </label>
  );
}
