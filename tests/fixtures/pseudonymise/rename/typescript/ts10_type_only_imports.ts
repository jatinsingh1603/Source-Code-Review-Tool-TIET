import type { ReportOptions } from "./options";
import { buildReport } from "./report";

export function run(options: ReportOptions) {
  return buildReport(options);
}
