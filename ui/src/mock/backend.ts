/**
 * In-browser mock of the CodeKavach REST API, used when the dashboard runs in
 * mock mode (`VITE_MOCK=1` or `?mock`). State lives in memory for the tab;
 * scans started here are simulated stage by stage and emit the same event
 * types as the real server's SSE stream.
 */
import { ApiClient, ApiError, type MockHandler, type RequestOptions } from "@/api/client";
import { setMockStream } from "@/api/events";
import type {
  Finding,
  FindingHistoryEntry,
  FindingStatus,
  LedgerEntry,
  PrivacyLevel,
  Project,
  ProviderInfo,
  Scan,
  ScanCreate,
  ScanEvent,
  Settings,
  Severity,
  User,
} from "@/api/types";
import {
  buildFinding,
  DEFAULT_POLICY,
  FINDING_TEMPLATES,
  hashish,
  ledgerDetail,
  PIPELINE_STAGES,
} from "./fixtures";

const day = 86_400_000;
const iso = (t: number) => new Date(t).toISOString();
const now = () => Date.now();
const zero = (): Record<Severity, number> => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });

interface State {
  users: (User & { password: string })[];
  tokens: Map<string, string>;
  projects: Project[];
  scans: Scan[];
  findings: Map<string, Finding[]>;
  history: Map<string, FindingHistoryEntry[]>;
  ledgers: Map<string, LedgerEntry[]>;
  settings: Settings;
  policy: string;
  live: Map<string, { events: ScanEvent[]; listeners: Set<(e: ScanEvent) => void> }>;
}

const PROVIDERS: ProviderInfo[] = [
  {
    id: "agentrouter",
    name: "AgentRouter",
    kind: "openai-responses",
    models: ["gpt-5.6-sol"],
    local: false,
    configured: true,
    default_model: "gpt-5.6-sol",
    capabilities: ["structured_output", "json_schema"],
    trust_tier: "public",
    min_level: "L3",
    host: "agentrouter.org",
  },
  {
    id: "ollama",
    name: "Ollama (local)",
    kind: "ollama",
    models: ["qwen2.5-coder:7b", "llama3.1:8b"],
    local: true,
    configured: false,
    default_model: "qwen2.5-coder:7b",
    capabilities: ["json_mode"],
  },
  {
    id: "replay",
    name: "Replay cassette",
    kind: "replay",
    models: ["recorded"],
    local: true,
    configured: true,
    default_model: "recorded",
    capabilities: ["deterministic"],
  },
  {
    id: "mock",
    name: "Mock provider",
    kind: "mock",
    models: ["mock-1"],
    local: true,
    configured: true,
    default_model: "mock-1",
    capabilities: ["deterministic"],
  },
];

function makeLedger(scan: Scan): LedgerEntry[] {
  if (scan.privacy_level === "L0" || scan.send === false) return [];
  const out: LedgerEntry[] = [];
  let prev = "sha256:" + "0".repeat(64);
  const start = new Date(scan.started_at ?? iso(now())).getTime();
  for (let seq = 1; seq <= 9; seq++) {
    const d = ledgerDetail(scan.id, seq, scan.privacy_level, scan.provider, scan.model ?? "", iso(start + seq * 4200), prev);
    out.push(d.entry);
    prev = d.entry.entry_hash;
  }
  return out;
}

function countBySeverity(fs: Finding[]): Record<Severity, number> {
  const c = zero();
  for (const f of fs) c[f.severity]++;
  return c;
}

function seed(): State {
  const t0 = now();
  const users: State["users"] = [
    { id: "u-admin", username: "admin", display_name: "Administrator", email: "admin@codekavach.local", role: "admin", active: true, created_at: iso(t0 - 40 * day), last_login: iso(t0 - 3600_000), password: "kavach-admin" },
    { id: "u-auditor", username: "auditor", display_name: "Security Auditor", email: "auditor@codekavach.local", role: "auditor", active: true, created_at: iso(t0 - 30 * day), last_login: iso(t0 - 2 * day), password: "kavach-auditor" },
    { id: "u-dev", username: "developer", display_name: "App Developer", email: "dev@codekavach.local", role: "developer", active: true, created_at: iso(t0 - 20 * day), last_login: iso(t0 - 5 * day), password: "kavach-dev" },
    { id: "u-viewer", username: "viewer", display_name: "Read-only Viewer", email: "viewer@codekavach.local", role: "viewer", active: true, created_at: iso(t0 - 10 * day), last_login: null, password: "kavach-viewer" },
  ];
  const projects: Project[] = [
    {
      id: "p-kavachbank",
      name: "KavachBank (sample)",
      description: "Deliberately vulnerable retail-banking application: Python API and Node web front end.",
      source: { type: "sample", path: "fixtures/kavachbank" },
      created_at: iso(t0 - 35 * day),
      languages: ["python", "javascript"],
      files: 18,
    },
    {
      id: "p-gateway",
      name: "payments-gateway",
      description: "Internal payment routing service.",
      source: { type: "git", url: "https://git.example.internal/fin/payments-gateway.git", ref: "main" },
      created_at: iso(t0 - 21 * day),
      languages: ["python"],
      files: 64,
    },
  ];
  const state: State = {
    users,
    tokens: new Map(),
    projects,
    scans: [],
    findings: new Map(),
    history: new Map(),
    ledgers: new Map(),
    settings: { default_provider: "agentrouter", default_model: "gpt-5.6-sol", default_privacy_level: "L3", org_name: "Thapar Institute of Engineering & Technology" },
    policy: DEFAULT_POLICY,
    live: new Map(),
  };
  // Historic scans to give the overview a trend.
  const plan: { p: string; daysAgo: number; take: number; level: PrivacyLevel; status?: Scan["status"] }[] = [
    { p: "p-kavachbank", daysAgo: 28, take: 13, level: "L3" },
    { p: "p-kavachbank", daysAgo: 21, take: 13, level: "L2" },
    { p: "p-gateway", daysAgo: 16, take: 6, level: "L3" },
    { p: "p-kavachbank", daysAgo: 12, take: 12, level: "L3" },
    { p: "p-gateway", daysAgo: 6, take: 4, level: "L0", status: "completed" },
    { p: "p-kavachbank", daysAgo: 2, take: 13, level: "L3" },
  ];
  plan.forEach((s, i) => {
    const id = `s-${1001 + i}`;
    const start = t0 - s.daysAgo * day;
    const scan: Scan = {
      id,
      project_id: s.p,
      project_name: projects.find((p) => p.id === s.p)?.name,
      status: s.status ?? "completed",
      stage: "report",
      progress: 100,
      started_at: iso(start),
      finished_at: iso(start + 74_000 + i * 9000),
      created_at: iso(start),
      privacy_level: s.level,
      provider: s.level === "L0" ? "none" : "agentrouter",
      model: s.level === "L0" ? null : "gpt-5.6-sol",
      send: s.level !== "L0",
      counts: zero(),
      files: s.p === "p-kavachbank" ? 18 : 64,
      languages: s.p === "p-kavachbank" ? ["python", "javascript"] : ["python"],
      error: null,
    };
    const tpls = s.p === "p-kavachbank" ? FINDING_TEMPLATES : FINDING_TEMPLATES.filter((_, k) => k % 2 === 0);
    const fs = tpls
      .slice(0, s.take)
      .map((tp, k) => buildFinding(tp, id, k, scan.provider, scan.model ?? "", s.level !== "L0"));
    // Older scans: some findings already triaged.
    fs.forEach((f, k) => {
      f.created_at = iso(start + 60_000);
      if (i < 3 && k % 4 === 3) f.status = "fixed";
      if (f.severity === "info") f.status = "false_positive";
    });
    if (i === plan.length - 1) {
      fs[0]!.status = "confirmed";
      fs[0]!.assignee = "developer";
      fs[0]!.comment = "Reproduced on staging with a quote in the account id.";
      state.history.set(fs[0]!.id, [
        { at: iso(start + 90_000), actor: "codekavach", action: "created", to_status: "open" },
        { at: iso(start + 3 * 3600_000), actor: "auditor", action: "status_changed", from_status: "open", to_status: "confirmed", comment: "Reproduced on staging with a quote in the account id." },
        { at: iso(start + 3 * 3600_000 + 60_000), actor: "auditor", action: "assigned", comment: "Assigned to developer" },
      ]);
    }
    scan.counts = countBySeverity(fs);
    state.scans.push(scan);
    state.findings.set(id, fs);
    state.ledgers.set(id, makeLedger(scan));
  });
  return state;
}

let state: State = seed();

function err(status: number, code: string, message: string): never {
  throw new ApiError(status, code, message);
}

function pathOf(p: string): string[] {
  return p.split("?")[0]!.split("/").filter(Boolean);
}

function delay<T>(v: T, ms = 120 + Math.random() * 180): Promise<T> {
  return new Promise((r) => setTimeout(() => r(structuredClone(v)), ms));
}

let currentToken: () => string | null = () => null;

function me(): User & { password: string } {
  const t = currentToken();
  const uid = t ? state.tokens.get(t) : undefined;
  const u = state.users.find((x) => x.id === uid);
  if (!u) err(401, "unauthorised", "Your session has ended. Please sign in again.");
  return u;
}

function publicUser(u: User & { password?: string }): User {
  const { password: _p, ...rest } = u;
  return rest;
}

function enrichProject(p: Project): Project {
  const scans = state.scans.filter((s) => s.project_id === p.id);
  const last = [...scans].sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))[0] ?? null;
  return { ...p, last_scan: last, scan_count: scans.length };
}

function allFindings(): Finding[] {
  return [...state.findings.values()].flat();
}

function latestCompletedPerProject(): Scan[] {
  const out: Scan[] = [];
  for (const p of state.projects) {
    const s = state.scans
      .filter((x) => x.project_id === p.id && x.status === "completed")
      .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))[0];
    if (s) out.push(s);
  }
  return out;
}

function stats() {
  const latest = latestCompletedPerProject();
  const fs = latest.flatMap((s) => state.findings.get(s.id) ?? []);
  const open = fs.filter((f) => f.status === "open" || f.status === "confirmed");
  const sorted = [...state.scans].sort((a, b) => (a.created_at ?? "").localeCompare(b.created_at ?? ""));
  return {
    projects: state.projects.length,
    scans: state.scans.length,
    findings_by_severity: countBySeverity(open),
    open_findings: open.length,
    last_scan: sorted[sorted.length - 1] ?? null,
    trend: sorted
      .filter((s) => s.status === "completed")
      .map((s) => {
        const f = (state.findings.get(s.id) ?? []).filter((x) => x.status !== "false_positive");
        const c = countBySeverity(f);
        return { scan_id: s.id, date: s.finished_at ?? s.created_at ?? "", critical: c.critical, high: c.high, medium: c.medium, low: c.low };
      }),
  };
}

function privacy(scanId: string) {
  const scan = state.scans.find((s) => s.id === scanId) ?? err(404, "not_found", "Scan not found.");
  const ledger = state.ledgers.get(scanId) ?? [];
  const blocked = ledger.filter((e) => e.outcome?.startsWith("blocked")).length;
  const sent = ledger.length - blocked;
  const level = scan.privacy_level;
  return {
    level,
    payloads: sent,
    blocked,
    placeholders_by_type: ledger.length
      ? { SECRET_AWS_ACCESS_KEY: 1, SECRET_AWS_SECRET_KEY: 1, SECRET_CONNECTION_STRING: 1, PII_EMAIL: 2, TABLE: 2, STRING: 6 }
      : {},
    pseudonyms: ledger.length ? 23 : 0,
    tokens_sent: ledger.filter((e) => !e.outcome?.startsWith("blocked")).reduce((a, e) => a + e.tokens, 0),
    chain_ok: true,
    zero_leak: { checked: ledger.length ? 18 : 0, occurrences: 0, passed: true },
    privacy_score: level === "L0" ? 100 : level === "L4" ? 95 : level === "L3" ? 87 : level === "L2" ? 76 : 60,
    provider: scan.provider,
    model: scan.model,
    attestation_text:
      ledger.length === 0
        ? `Scan ${scan.id} ran at privacy level ${level}. No payload was prepared for or sent to any model provider; all analysis was local.`
        : `Scan ${scan.id} ran at privacy level ${level} with provider ${scan.provider} (${scan.model}). ${sent} sanitised payloads were sent and ${blocked} were blocked before egress. Every payload is recorded in a hash-chained ledger whose chain verified intact. A zero-leak check of the ledger against 18 planted secrets and business-domain terms found 0 verbatim occurrences.`,
  };
}

// ---- scan simulation ---------------------------------------------------------

function emit(scanId: string, e: ScanEvent) {
  const l = state.live.get(scanId);
  if (!l) return;
  l.events.push(e);
  l.listeners.forEach((fn) => fn(e));
}

function simulateScan(scan: Scan) {
  state.live.set(scan.id, { events: [], listeners: new Set() });
  const project = state.projects.find((p) => p.id === scan.project_id)!;
  const templates = project.id === "p-kavachbank" || project.source.type === "sample" ? FINDING_TEMPLATES : FINDING_TEMPLATES.filter((_, k) => k % 2 === 0);
  const withLlm = scan.send !== false && scan.privacy_level !== "L0";
  const findings = templates.map((t, k) => buildFinding(t, scan.id, k, scan.provider, scan.model ?? "", withLlm));
  state.findings.set(scan.id, []);
  const steps: { at: number; fn: () => void }[] = [];
  let t = 400;
  const stageMs: Record<string, number> = { ingest: 900, parse: 1300, analyse: 2600, aggregate: 700, "privacy-prepare": 1800, "llm-review": 5200, restore: 600, rate: 800, "privacy-check": 500, report: 1200 };
  const step = (ms: number, fn: () => void) => {
    t += ms;
    steps.push({ at: t, fn });
  };
  step(0, () => {
    scan.status = "running";
    scan.started_at = iso(now());
    emit(scan.id, { type: "log", level: "info", message: `Scan ${scan.id} started at level ${scan.privacy_level}` });
  });
  PIPELINE_STAGES.forEach((name, i) => {
    const skip = (name === "llm-review" || name === "restore" || name === "privacy-check") && !withLlm;
    step(80, () => {
      scan.stage = name;
      emit(scan.id, { type: "stage", name, status: skip ? "skipped" : "started" });
    });
    if (skip) return;
    const dur = stageMs[name] ?? 800;
    if (name === "ingest") step(dur / 2, () => emit(scan.id, { type: "log", level: "info", message: `Ingested ${scan.files} files (${scan.languages?.join(", ")})` }));
    if (name === "parse") step(dur / 2, () => emit(scan.id, { type: "log", level: "info", message: "Parsed 214 functions; 0 parse errors" }));
    if (name === "analyse") {
      findings.slice(0, 8).forEach((f) =>
        step(dur / 9, () => {
          state.findings.get(scan.id)!.push(f);
          scan.counts = countBySeverity(state.findings.get(scan.id)!);
          emit(scan.id, { type: "finding", id: f.id, severity: f.severity, title: f.title });
        }),
      );
      step(0, () => emit(scan.id, { type: "log", level: "info", message: "Rules, taint and engines produced 17 raw candidates" }));
    }
    if (name === "aggregate") {
      findings.slice(8).forEach((f) =>
        step(dur / 6, () => {
          state.findings.get(scan.id)!.push(f);
          scan.counts = countBySeverity(state.findings.get(scan.id)!);
          emit(scan.id, { type: "finding", id: f.id, severity: f.severity, title: f.title });
        }),
      );
      step(0, () => emit(scan.id, { type: "log", level: "info", message: `Deduplicated to ${findings.length} findings` }));
    }
    if (name === "privacy-prepare") {
      step(dur / 2, () => emit(scan.id, { type: "log", level: "info", message: "Redacted 3 secrets and 2 PII values; 23 identifiers pseudonymised" }));
      step(dur / 4, () => emit(scan.id, { type: "log", level: "warning", message: "Payload for candidate cand-config-secrets blocked: secret_density" }));
    }
    if (name === "llm-review") {
      for (let k = 1; k <= 8; k++) step(dur / 9, () => emit(scan.id, { type: "log", level: "info", message: `Model verdict ${k}/8 received from ${scan.provider} (${scan.model})` }));
    }
    if (!["analyse", "aggregate", "llm-review"].includes(name)) step(dur / 2, () => {});
    step(0, () => {
      scan.progress = Math.round(((i + 1) / PIPELINE_STAGES.length) * 100);
      emit(scan.id, { type: "stage", name, status: "completed" });
      emit(scan.id, { type: "progress", percent: scan.progress, message: `${name} completed` });
    });
  });
  step(200, () => {
    scan.status = "completed";
    scan.progress = 100;
    scan.finished_at = iso(now());
    state.ledgers.set(scan.id, makeLedger(scan));
    emit(scan.id, { type: "log", level: "info", message: `Scan completed with ${findings.length} findings` });
    emit(scan.id, { type: "done", status: "completed" });
  });
  const timers = steps.map((s) =>
    setTimeout(() => {
      if (scan.status === "cancelled") return;
      s.fn();
    }, s.at),
  );
  cancellers.set(scan.id, () => timers.forEach(clearTimeout));
}

const cancellers = new Map<string, () => void>();

// ---- request router ------------------------------------------------------------

async function handle(method: string, path: string, opts: RequestOptions): Promise<unknown> {
  const seg = pathOf(path);
  const body = (opts.body ?? {}) as Record<string, unknown>;
  const q = opts.query ?? {};
  const [a, b, c, d] = seg;

  if (a === "health") return delay({ status: "ok", mode: "mock" });
  if (a === "version") return delay({ version: "0.9.0-demo", api: "v1" });

  if (a === "auth" && b === "login" && method === "POST") {
    const u = state.users.find((x) => x.username === body.username && x.password === body.password && x.active !== false);
    if (!u) {
      await delay(null, 400);
      err(401, "invalid_credentials", "The username or password is not correct.");
    }
    const token = `mock-${hashish(u.id + now(), 24)}`;
    state.tokens.set(token, u.id);
    u.last_login = iso(now());
    return delay({ token, user: publicUser(u) }, 350);
  }

  const user = me();
  const role = user.role;
  const requireRole = (...roles: string[]) => {
    if (!roles.includes(role)) err(403, "forbidden", "You do not have permission to do this.");
  };

  if (a === "auth" && b === "me") return delay(publicUser(user));
  if (a === "me" && b === "password" && method === "POST") {
    const stored = state.users.find((x) => x.id === user.id);
    if (!stored || stored.password !== body.current_password) err(400, "wrong_password", "The current password is not correct.");
    else stored.password = String(body.new_password);
    return delay({ ok: true, revoked: 0 });
  }
  if (a === "auth" && b === "logout") {
    return delay(null);
  }
  if (a === "stats") return delay(stats());

  if (a === "projects") {
    if (!b && method === "GET") return delay(state.projects.map(enrichProject));
    if (!b && method === "POST") {
      requireRole("admin", "auditor");
      const name = String(body.name ?? "").trim();
      if (!name) err(422, "validation_error", "name: Field required");
      const src = body.source as Project["source"];
      const p: Project = {
        id: `p-${hashish(name + now(), 8)}`,
        name,
        description: (body.description as string) || null,
        source: src,
        created_at: iso(now()),
        languages: src.type === "sample" ? ["python", "javascript"] : ["python"],
        files: src.type === "sample" ? 18 : 42,
      };
      state.projects.push(p);
      return delay(enrichProject(p), 300);
    }
    const p = state.projects.find((x) => x.id === b) ?? err(404, "not_found", "Project not found.");
    if (c === "scans" && method === "POST") {
      requireRole("admin", "auditor", "developer");
      const sc = body as unknown as ScanCreate;
      const scan: Scan = {
        id: `s-${hashish(p.id + now(), 6)}`,
        project_id: p.id,
        project_name: p.name,
        status: "queued",
        stage: null,
        progress: 0,
        started_at: null,
        finished_at: null,
        created_at: iso(now()),
        privacy_level: sc.privacy_level,
        provider: sc.privacy_level === "L0" ? "none" : sc.provider,
        model: sc.privacy_level === "L0" ? null : (sc.model ?? null),
        send: sc.send,
        counts: zero(),
        files: p.files,
        languages: p.languages,
        error: null,
      };
      state.scans.push(scan);
      simulateScan(scan);
      return delay(scan, 250);
    }
    if (c === "upload") return delay(enrichProject(p), 200);
    if (method === "GET") return delay(enrichProject(p));
    if (method === "PATCH") {
      requireRole("admin", "auditor");
      Object.assign(p, body);
      return delay(enrichProject(p));
    }
    if (method === "DELETE") {
      requireRole("admin");
      state.projects = state.projects.filter((x) => x.id !== p.id);
      return delay(null);
    }
  }

  if (a === "scans") {
    if (!b) {
      const list = state.scans
        .filter((s) => !q.project_id || s.project_id === q.project_id)
        .sort((x, y) => (y.created_at ?? "").localeCompare(x.created_at ?? ""));
      return delay(list);
    }
    const scan = state.scans.find((s) => s.id === b) ?? err(404, "not_found", "Scan not found.");
    if (!c) return delay(scan, 60);
    if (c === "cancel") {
      if (scan.status === "running" || scan.status === "queued") {
        cancellers.get(scan.id)?.();
        scan.status = "cancelled";
        scan.finished_at = iso(now());
        emit(scan.id, { type: "log", level: "warning", message: "Scan cancelled by user" });
        emit(scan.id, { type: "done", status: "cancelled" });
      }
      return delay(scan);
    }
    if (c === "findings") {
      let fs = state.findings.get(scan.id) ?? [];
      const sev = q.severity ? String(q.severity).split(",") : null;
      const st = q.status ? String(q.status).split(",") : null;
      if (sev) fs = fs.filter((f) => sev.includes(f.severity));
      if (st) fs = fs.filter((f) => st.includes(f.status));
      if (q.cwe) fs = fs.filter((f) => (f.cwe ?? "").toLowerCase().includes(String(q.cwe).toLowerCase()));
      if (q.q) {
        const needle = String(q.q).toLowerCase();
        fs = fs.filter((f) => `${f.title} ${f.locations[0]?.path} ${f.rule_id} ${f.cwe}`.toLowerCase().includes(needle));
      }
      return delay(fs);
    }
    if (c === "privacy") {
      requireRole("admin", "auditor", "developer");
      return delay(privacy(scan.id));
    }
    if (c === "ledger") {
      requireRole("admin", "auditor", "developer");
      const entries = state.ledgers.get(scan.id) ?? [];
      if (!d) return delay({ entries });
      if (d === "verify") {
        return delay({ ok: true, entries: entries.length, first_bad_seq: null, message: "Hash chain intact", verified_at: iso(now()) }, 700);
      }
      const seq = Number(d);
      const entry = entries.find((e) => e.seq === seq) ?? err(404, "not_found", "Ledger entry not found.");
      const det = ledgerDetail(scan.id, seq, scan.privacy_level, scan.provider, scan.model ?? "", entry.timestamp, entry.prev_hash);
      if (role === "developer") return delay({ ...det, original_text: "", markup: det.markup.filter((m) => m.side === "payload") });
      return delay(det);
    }
    if (c === "reports") {
      if (!d) {
        return delay({
          formats: [
            { format: "html", available: true },
            { format: "pdf", available: true },
            { format: "docx", available: true },
            { format: "xlsx", available: true },
            { format: "sarif", available: true },
            { format: "json", available: true },
            { format: "csv", available: true },
            { format: "md", available: true },
          ],
        });
      }
      return delay(reportBlob(scan, d), 400);
    }
    if (c === "sync" && d === "github") {
      requireRole("admin", "auditor");
      const fs = (state.findings.get(scan.id) ?? []).filter((f) => ["critical", "high", "medium"].includes(f.severity) && f.status !== "false_positive");
      const dry = body.dry_run !== false;
      return delay(
        {
          created: fs.length - 2,
          updated: 1,
          closed: 1,
          items: fs.map((f, i) => ({
            finding_id: f.id,
            action: i === 0 ? "update" : i === fs.length - 1 ? "close" : "create",
            title: `[CodeKavach] ${f.title}`,
            issue_number: dry ? null : 40 + i,
            url: dry ? null : `https://github.com/${String(body.repo)}/issues/${40 + i}`,
          })),
        },
        900,
      );
    }
  }

  if (a === "findings" && b) {
    const all = allFindings();
    const f = all.find((x) => x.id === b) ?? err(404, "not_found", "Finding not found.");
    if (c === "history") {
      return delay(
        state.history.get(f.id) ?? [{ at: f.created_at ?? iso(now()), actor: "codekavach", action: "created", to_status: "open" as FindingStatus }],
      );
    }
    if (method === "PATCH") {
      requireRole("admin", "auditor", "developer");
      const h = state.history.get(f.id) ?? [{ at: f.created_at ?? iso(now()), actor: "codekavach", action: "created", to_status: "open" as FindingStatus }];
      if (body.status && body.status !== f.status) {
        h.push({ at: iso(now()), actor: user.username, action: "status_changed", from_status: f.status, to_status: body.status as FindingStatus, comment: (body.comment as string) || null });
        f.status = body.status as FindingStatus;
      } else if (body.comment) {
        h.push({ at: iso(now()), actor: user.username, action: "commented", comment: body.comment as string });
      }
      if (body.assignee !== undefined && body.assignee !== f.assignee) {
        h.push({ at: iso(now()), actor: user.username, action: "assigned", comment: body.assignee ? `Assigned to ${String(body.assignee)}` : "Unassigned" });
        f.assignee = (body.assignee as string) || null;
      }
      if (body.comment) f.comment = body.comment as string;
      state.history.set(f.id, h);
      return delay(f, 250);
    }
    return delay(f);
  }

  if (a === "providers") {
    if (!b) return delay(PROVIDERS);
    if (c === "test") {
      const p = PROVIDERS.find((x) => x.id === b) ?? err(404, "not_found", "Provider not found.");
      if (!p.configured) return delay({ ok: false, latency_ms: 0, model: p.default_model, message: "Provider is not configured: no endpoint reachable at http://127.0.0.1:11434" }, 600);
      return delay({ ok: true, latency_ms: p.local ? 12 : 3870 + Math.round(Math.random() * 600), model: (body.model as string) || p.default_model, message: "Structured-output probe answered correctly; probe recorded in the egress ledger." }, p.local ? 300 : 1800);
    }
  }

  if (a === "settings") {
    if (method === "PUT") {
      requireRole("admin");
      state.settings = { ...state.settings, ...body } as Settings;
    }
    return delay(state.settings);
  }

  if (a === "policy") {
    if (method === "PUT") {
      requireRole("admin");
      const toml = String(body.toml ?? "");
      const bad = toml.split("\n").findIndex((l) => /^\s*\[[^\]]*$/.test(l));
      if (bad >= 0) err(422, "policy_invalid", `Line ${bad + 1}: unterminated table header`);
      state.policy = toml;
    }
    return delay({ toml: state.policy, parsed: { policy: { default_level: "L3" } } });
  }

  if (a === "users") {
    requireRole("admin");
    if (!b && method === "GET") return delay(state.users.map(publicUser));
    if (!b && method === "POST") {
      if (state.users.some((u) => u.username === body.username)) err(409, "conflict", "A user with this username already exists.");
      const u = { id: `u-${hashish(String(body.username), 6)}`, username: String(body.username), display_name: (body.display_name as string) || null, email: (body.email as string) || null, role: body.role as User["role"], active: true, created_at: iso(now()), last_login: null, password: String(body.password) };
      state.users.push(u);
      return delay(publicUser(u));
    }
    const u = state.users.find((x) => x.id === b) ?? err(404, "not_found", "User not found.");
    if (method === "PATCH") {
      if (u.id === user.id && body.role && body.role !== "admin") err(409, "conflict", "You cannot remove your own administrator role.");
      Object.assign(u, body);
      return delay(publicUser(u));
    }
    if (method === "DELETE") {
      if (u.id === user.id) err(409, "conflict", "You cannot delete your own account.");
      state.users = state.users.filter((x) => x.id !== u.id);
      return delay(null);
    }
  }

  err(404, "not_found", `No mock route for ${method} ${path}`);
}

function reportBlob(scan: Scan, fmt: string): Blob {
  const fs = state.findings.get(scan.id) ?? [];
  if (fmt === "html") {
    const rows = fs
      .map((f) => `<tr><td>${f.severity.toUpperCase()}</td><td>${esc(f.title)}</td><td>${esc(f.cwe ?? "")}</td><td>${esc(f.locations[0]?.path ?? "")}:${f.locations[0]?.start_line ?? ""}</td></tr>`)
      .join("");
    return new Blob(
      [
        `<!doctype html><html><head><meta charset="utf-8"><title>CodeKavach report</title><style>body{font-family:system-ui;margin:2rem;color:#111}h1{margin:0}table{border-collapse:collapse;width:100%;margin-top:1rem}td,th{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left;font-size:13px}</style></head><body><h1>Security assessment: ${esc(scan.project_name ?? scan.project_id)}</h1><p>Scan ${scan.id} · privacy level ${scan.privacy_level} · ${fs.length} findings (demo data)</p><table><tr><th>Severity</th><th>Title</th><th>CWE</th><th>Location</th></tr>${rows}</table></body></html>`,
      ],
      { type: "text/html" },
    );
  }
  if (fmt === "json" || fmt === "sarif") return new Blob([JSON.stringify(fmt === "json" ? { scan, findings: fs } : { version: "2.1.0", runs: [] }, null, 2)], { type: "application/json" });
  if (fmt === "csv") return new Blob([["severity,title,cwe,path,line", ...fs.map((f) => `${f.severity},"${f.title}",${f.cwe},${f.locations[0]?.path},${f.locations[0]?.start_line}`)].join("\n")], { type: "text/csv" });
  if (fmt === "md") return new Blob([`# CodeKavach report\n\n${fs.map((f) => `- **${f.severity}** ${f.title}`).join("\n")}\n`], { type: "text/markdown" });
  return new Blob([`Demo ${fmt} report for ${scan.id}`], { type: "application/octet-stream" });
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

export function installMockBackend(client: ApiClient): MockHandler {
  state = seed();
  currentToken = () => client.getToken();
  // A token from a previous mock session in this tab maps to the admin user.
  const existing = client.getToken();
  if (existing?.startsWith("mock-")) state.tokens.set(existing, "u-admin");
  const handler: MockHandler = (method, path, opts) => handle(method.toUpperCase(), path, opts);
  client.setMockHandler(handler);
  setMockStream((scanId, emitFn) => {
    const scan = state.scans.find((s) => s.id === scanId);
    const live = state.live.get(scanId);
    if (!live) {
      // Not simulated in this tab: replay a finished scan as a single done event.
      const t = setTimeout(() => {
        if (scan) {
          PIPELINE_STAGES.forEach((name) => emitFn({ type: "stage", name, status: "completed" }));
          emitFn({ type: "progress", percent: 100 });
          emitFn({ type: "done", status: scan.status });
        }
      }, 50);
      return () => clearTimeout(t);
    }
    const replay = [...live.events];
    const t = setTimeout(() => replay.forEach(emitFn), 0);
    live.listeners.add(emitFn);
    return () => {
      clearTimeout(t);
      live.listeners.delete(emitFn);
    };
  });
  return handler;
}
