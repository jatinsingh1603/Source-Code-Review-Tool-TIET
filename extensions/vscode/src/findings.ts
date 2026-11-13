import { execFile } from "child_process";
import { resolveExecutable } from "./executable";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  status: string;
  confidence?: string;
  cwe: number[];
  owasp?: { id: string; title?: string }[];
  description?: string;
  remediation?: string;
  fingerprint: string;
  locations: { path: string; start_line: number; end_line: number; start_col?: number; end_col?: number }[];
  evidence?: { lines: { number: number; text: string }[] }[];
  provenance?: { engines?: { rule_id: string }[] };
}

export interface ScanData {
  scan_id: string;
  summary: { findings_total: number; by_severity: Record<string, number> };
  findings: Finding[];
}

export interface Settings {
  executable: string;
  privacyLevel: string;
  provider: string;
}

interface Envelope<T> {
  ok: boolean;
  data?: T;
  errors?: { code: string; message: string; hint?: string | null }[];
}

function run(configured: string, args: string[], cwd: string): Promise<{ stdout: string; code: number }> {
  return new Promise((resolve, reject) => {
    let executable: string;
    try {
      executable = resolveExecutable(configured, cwd);
    } catch (e) {
      reject(e);
      return;
    }
    execFile(executable, args, { cwd, maxBuffer: 256 * 1024 * 1024, timeout: 30 * 60 * 1000 }, (err, stdout) => {
      if (err && (err as NodeJS.ErrnoException).code === "ENOENT") {
        reject(new Error(`Cannot run '${executable}'. Install CodeKavach or set codekavach.executable.`));
        return;
      }
      const code = err && typeof (err as { code?: unknown }).code === "number" ? ((err as { code: number }).code) : 0;
      resolve({ stdout, code });
    });
  });
}

async function json<T>(settings: Settings, args: string[], cwd: string): Promise<Envelope<T>> {
  const { stdout } = await run(settings.executable, ["--json", ...args], cwd);
  try {
    return JSON.parse(stdout) as Envelope<T>;
  } catch {
    throw new Error("CodeKavach returned no JSON. Run 'codekavach doctor' in a terminal.");
  }
}

/** Run a scan (exit code 1 only means findings exceeded the threshold) and load the findings. */
export async function scan(settings: Settings, cwd: string): Promise<ScanData> {
  const args = ["scan", cwd, "--privacy-level", settings.privacyLevel, "--fail-on", "critical"];
  if (settings.provider) {
    args.push("--provider", settings.provider);
  } else {
    args.push("--no-llm");
  }
  const result = await json<unknown>(settings, args, cwd);
  const fatal = result.errors?.find((e) => e.code !== "threshold_exceeded");
  if (fatal) {
    throw new Error(`${fatal.message}${fatal.hint ? " (" + fatal.hint + ")" : ""}`);
  }
  return load(settings, cwd);
}

/** Load the findings of the latest stored scan. */
export async function load(settings: Settings, cwd: string): Promise<ScanData> {
  const result = await json<ScanData>(settings, ["findings", cwd], cwd);
  if (!result.ok || !result.data) {
    throw new Error(result.errors?.[0]?.message ?? "No stored scan. Run a scan first.");
  }
  return result.data;
}
