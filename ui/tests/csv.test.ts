import { describe, expect, it } from "vitest";
import { csvFields, csvRecords, filterCsv } from "@/lib/csv";

const CSV = [
  "report_id,title,remediation,fingerprint",
  'CK-1,"SQL, built by hand","Use ""params"".\nAlways.",fp-a',
  "CK-2,Plain,Fix it,fp-b",
  'CK-3,"Third","Line one\r\nLine two",fp-c',
  "",
].join("\r\n");

describe("csv", () => {
  it("splits records on line breaks outside quotes only", () => {
    const r = csvRecords(CSV);
    expect(r).toHaveLength(4);
    expect(csvFields(r[1]!)).toEqual(["CK-1", "SQL, built by hand", 'Use "params".\nAlways.', "fp-a"]);
  });

  it("keeps the header and the matching records in their original text", () => {
    const out = filterCsv(CSV, "fingerprint", new Set(["fp-a", "fp-c"]))!;
    expect(out.rows).toBe(2);
    const r = csvRecords(out.text);
    expect(r.map((x) => csvFields(x)[0])).toEqual(["report_id", "CK-1", "CK-3"]);
    expect(csvFields(r[2]!)[2]).toBe("Line one\r\nLine two");
  });

  it("returns null without the column", () => {
    expect(filterCsv("a,b\n1,2\n", "fingerprint", new Set())).toBeNull();
  });
});
