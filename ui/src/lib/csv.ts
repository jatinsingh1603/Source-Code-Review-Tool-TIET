/**
 * Split CSV text (RFC 4180: quoted fields may hold commas, quotes and line
 * breaks) into its records, each kept as the exact source text.
 */
export function csvRecords(text: string): string[] {
  const out: string[] = [];
  let start = 0;
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') quoted = !quoted;
    else if (!quoted && (c === "\n" || c === "\r")) {
      if (i > start) out.push(text.slice(start, i));
      if (c === "\r" && text[i + 1] === "\n") i++;
      start = i + 1;
    }
  }
  if (start < text.length) out.push(text.slice(start));
  return out;
}

/** The fields of one CSV record, unquoted. */
export function csvFields(record: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < record.length; i++) {
    const c = record[i];
    if (quoted) {
      if (c === '"' && record[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (c === '"') quoted = false;
      else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") {
      out.push(cur);
      cur = "";
    } else cur += c;
  }
  out.push(cur);
  return out;
}

/**
 * Keep the header and the records whose `column` is in `keep`, in their
 * original order and text. Returns null when the column is missing.
 */
export function filterCsv(text: string, column: string, keep: ReadonlySet<string>): { text: string; rows: number } | null {
  const records = csvRecords(text.replace(/^\uFEFF/, ""));
  const header = records[0];
  if (header === undefined) return null;
  const at = csvFields(header).indexOf(column);
  if (at < 0) return null;
  const rows = records.slice(1).filter((r) => keep.has(csvFields(r)[at] ?? ""));
  const bom = text.startsWith("\uFEFF") ? "\uFEFF" : "";
  return { text: bom + [header, ...rows].join("\r\n") + "\r\n", rows: rows.length };
}
