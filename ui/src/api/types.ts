/**
 * Types of the CodeKavach REST API (`/api/v1`).
 *
 * These mirror the shared server contract. Fields the server may add later are
 * tolerated (extra JSON keys are ignored); optional fields are marked so the
 * views degrade gracefully when a server build does not provide them.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type FindingStatus = "open" | "confirmed" | "false_positive" | "accepted_risk" | "fixed";
export const FINDING_STATUSES: FindingStatus[] = [
  "open",
  "confirmed",
  "false_positive",
  "accepted_risk",
  "fixed",
];

export type PrivacyLevel = "L0" | "L1" | "L2" | "L3" | "L4";
export const PRIVACY_LEVELS: PrivacyLevel[] = ["L0", "L1", "L2", "L3", "L4"];

export type Role = "admin" | "auditor" | "developer" | "viewer";
export const ROLES: Role[] = ["admin", "auditor", "developer", "viewer"];

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export type SeverityCounts = Record<Severity, number>;

export interface User {
  id: string;
  username: string;
  display_name?: string | null;
  full_name?: string | null;
  email?: string | null;
  role: Role;
  active?: boolean;
  created_at?: string;
  last_login?: string | null;
  /** Server permission names, e.g. `privacy:read_original`. */
  permissions?: string[];
}

export interface LoginResponse {
  token: string;
  user: User;
}

export interface Health {
  status: string;
  database?: string;
  active_scans?: number;
  /** Network posture for the top-bar pill (API gap; optional). */
  network?: "offline" | "online" | string;
  /** Invariant suite results (API gap; optional). */
  invariants?: { id: string; title?: string; passed: boolean; run_at?: string; tests?: number }[];
  /** System health checks (API gap; optional). */
  checks?: { name: string; ok: boolean; detail?: string; level?: string }[];
  [k: string]: unknown;
}

export interface AuditEvent {
  id: number | string;
  at: string;
  actor: string;
  action: string;
  resource?: string;
  outcome?: string;
  client?: string;
  detail?: Record<string, unknown>;
}

export interface AuditLog {
  chain_intact?: boolean;
  checked?: number;
  events: AuditEvent[];
}

export interface VersionInfo {
  version: string;
  [k: string]: unknown;
}

export interface TrendPoint {
  scan_id: string;
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
  project_id?: string;
}

export interface Stats {
  projects: number;
  scans: number;
  findings_by_severity: SeverityCounts;
  open_findings: number;
  last_scan: Scan | null;
  trend: TrendPoint[];
  findings_total?: number;
  /** API gaps (optional). */
  mttr_days?: number | null;
  mttr_delta_days?: number | null;
}

export type SourceType = "path" | "git" | "upload" | "sample";

export interface ProjectSource {
  type: SourceType;
  path?: string | null;
  url?: string | null;
  ref?: string | null;
}

export interface Project {
  id: string;
  name: string;
  description?: string | null;
  source: ProjectSource;
  created_at: string;
  updated_at?: string | null;
  last_scan?: Scan | null;
  scan_count?: number;
  languages?: string[];
  files?: number;
  scans?: number;
}

export interface ProjectCreate {
  name: string;
  description?: string;
  source: ProjectSource;
}

export interface ScanCreate {
  privacy_level: PrivacyLevel;
  provider: string;
  model?: string;
  send: boolean;
  rules?: string[];
}

export interface Scan {
  id: string;
  project_id: string;
  project_name?: string;
  status: ScanStatus;
  stage?: string | null;
  progress: number;
  started_at?: string | null;
  finished_at?: string | null;
  created_at?: string | null;
  privacy_level: PrivacyLevel;
  provider: string;
  model?: string | null;
  send?: boolean;
  counts: SeverityCounts;
  files?: number;
  languages?: string[];
  error?: string | null;
  findings_total?: number;
  lines?: number;
  rules?: string[];
  /** API gaps (optional until the server provides them). */
  mode?: "branch" | "diff" | string | null;
  ref?: string | null;
  payloads?: number | null;
  engines?: string[] | null;
  eta_seconds?: number | null;
  privacy_summary?: {
    payloads: number;
    blocked: number;
    chain_ok: boolean;
    zero_leak?: { checked: number; occurrences: number; passed: boolean };
    tokens_sent?: number;
    bytes_sent?: number;
  } | null;
}

export interface Location {
  path: string;
  start_line: number;
  end_line?: number;
  start_col?: number;
  end_col?: number;
}

export interface CodeLine {
  number: number;
  text: string;
}

export interface CodeSnippet {
  path: string;
  start_line: number;
  lines: CodeLine[];
  highlight: { start: number; end: number }[];
  language?: string;
}

export interface TaintStep {
  index?: number;
  kind: "source" | "propagation" | "sanitiser" | "sink" | string;
  label: string;
  path: string;
  line: number;
  code?: string;
}

export interface Evidence {
  snippet?: string | null;
  code?: CodeSnippet | null;
  taint_path?: TaintStep[];
}

export interface LlmVerdict {
  is_vulnerable: boolean;
  confidence: number | string;
  reasoning: string;
  impact?: string | null;
  remediation?: string | null;
  model?: string;
  provider?: string;
  /** API gaps (optional). */
  exploit_scenario?: string | null;
  temperature?: number | null;
  runs?: { verdict?: string; is_vulnerable?: boolean; confidence?: number | string; ledger_seq?: number }[] | null;
}

export interface ComplianceRef {
  framework: string;
  clause: string;
  title?: string;
}

export interface Reference {
  title: string;
  url?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description?: string | null;
  severity: Severity;
  confidence: number | string;
  cwe?: string | null;
  cwe_name?: string | null;
  owasp?: string | null;
  asvs?: string | null;
  capec?: string | null;
  cvss4_vector?: string | null;
  cvss4_score?: number | null;
  cvss31_vector?: string | null;
  cvss31_score?: number | null;
  likelihood?: string | null;
  impact?: string | null;
  compliance?: ComplianceRef[];
  locations: Location[];
  evidence?: Evidence | null;
  llm?: LlmVerdict | null;
  remediation?: string | null;
  references?: (Reference | string)[];
  status: FindingStatus;
  engine?: string | null;
  rule_id?: string | null;
  fingerprint?: string | null;
  assignee?: string | null;
  comment?: string | null;
  created_at?: string;
  updated_at?: string;
  path?: string;
  line?: number;
  language?: string;
  llm_reviewed?: boolean;
  cwes?: string[];
  asvs_refs?: string[];
  capec_refs?: string[];
  impact_detail?: { level?: number; narrative?: string } | null;
  likelihood_detail?: { level?: number; rationale?: string } | null;
  provenance?: {
    origin?: string;
    engines?: { engine: string; rule_id?: string }[];
    llm_reviews?: {
      provider: string;
      model: string;
      level?: PrivacyLevel;
      ledger_seq?: number | null;
      is_vulnerable?: boolean;
      confidence?: number | string;
      reasoning?: string;
      task?: string;
    }[];
  } | null;
  scan?: { id: string; project_id?: string; project_name?: string; privacy_level?: PrivacyLevel; provider?: string; model?: string } | null;
  history?: FindingHistoryEntry[];
  /** API gaps (optional). */
  baseline_state?: "new" | "unchanged" | "fixed" | string | null;
  engines?: string[] | null;
  due_at?: string | null;
  remediation_diff?: string | null;
}

export interface FindingPatch {
  status?: FindingStatus;
  comment?: string;
  assignee?: string;
}

export interface FindingHistoryEntry {
  id?: string;
  at: string;
  actor: string;
  action: string;
  from_status?: FindingStatus | null;
  to_status?: FindingStatus | null;
  comment?: string | null;
}

export interface FindingFilters {
  severity?: string;
  status?: string;
  cwe?: string;
  q?: string;
}

export interface PrivacySummary {
  level: PrivacyLevel;
  payloads: number;
  blocked: number;
  placeholders_by_type: Record<string, number>;
  pseudonyms: number;
  tokens_sent: number;
  chain_ok: boolean;
  zero_leak: { checked: number; occurrences: number; passed: boolean };
  privacy_score?: number | null;
  provider: string;
  model?: string | null;
  attestation_text: string;
  sent?: number;
  withheld?: number;
  chain_entries?: number;
  ledger_head?: string | null;
  ledger_head_hash?: string | null;
  ledger_entries?: number;
  attestation_digest?: string | null;
  send?: boolean;
  provider_tier?: string;
  levels_by_candidate?: Record<string, number>;
  policy_rules?: Record<string, number>;
  score_components?: { name: string; value: number | null; raw?: string; unit?: string; kind?: string; basis?: string }[];
  score_formula?: string;
  disclosure?: Record<string, string | number>;
  /** API gap (optional): bytes of payload sent. */
  bytes_sent?: number | null;
}

export interface LedgerEntry {
  seq: number;
  timestamp: string;
  provider: string;
  model: string;
  level: PrivacyLevel;
  payload_hash: string;
  entry_hash: string;
  prev_hash: string;
  tokens: number;
  candidate_id: string;
  finding_id?: string | null;
  outcome?: string;
  task?: string;
  block_code?: string | null;
  ref_seq?: number | null;
  tokens_prompt?: number | null;
  tokens_completion?: number | null;
  /** API gap (optional). */
  bytes?: number | null;
}

export type MarkupKind = "secret" | "pii" | "identifier" | "literal";

export interface Markup {
  kind: MarkupKind;
  start: number;
  end: number;
  side: "original" | "payload";
  label?: string;
}

export interface LedgerDetail {
  entry: LedgerEntry;
  payload_text: string;
  original_text: string;
  markup: Markup[];
  original_start_line?: number | null;
  /** API gaps (optional). */
  path?: string | null;
  start_line?: number | null;
  slice_lines?: number[] | null;
  source_line?: number | null;
  sink_line?: number | null;
}

export interface LedgerVerifyResult {
  ok: boolean;
  entries: number;
  first_bad_seq?: number | null;
  message?: string;
  verified_at?: string;
  hashes_ok?: number;
  blocked?: number;
  terms_checked?: number;
  terms_found?: number;
  head_hash?: string;
}

export interface ReportFormat {
  format: string;
  label?: string;
  available: boolean;
  reason?: string | null;
  media_type?: string;
}

export interface ProviderInfo {
  id: string;
  name: string;
  kind: string;
  models: string[];
  local: boolean;
  configured: boolean;
  default_model: string | null;
  capabilities?: string[] | Record<string, unknown>;
  /** Strictest-of floor for this provider's trust tier (L1 < L2 < L3 < L4 < L0). */
  min_level?: PrivacyLevel | null;
  trust_tier?: string | null;
  host?: string | null;
  key_refs?: string[];
}

export interface ProviderTestResult {
  ok: boolean;
  latency_ms: number;
  model: string;
  message: string;
}

export interface Settings {
  default_provider: string;
  default_model?: string | null;
  default_privacy_level: PrivacyLevel;
  org_name: string;
  [k: string]: unknown;
}

export interface Policy {
  toml: string;
  parsed?: unknown;
}

export interface UserCreate {
  username: string;
  password: string;
  role: Role;
  display_name?: string;
  email?: string;
}

export interface GithubSyncRequest {
  repo: string;
  token_ref: string;
  dry_run: boolean;
}

export interface GithubSyncItem {
  finding_id: string;
  action: "create" | "update" | "close" | "skip" | string;
  title: string;
  issue_number?: number | null;
  url?: string | null;
}

export interface GithubSyncResult {
  created: number;
  updated: number;
  closed: number;
  items: GithubSyncItem[];
}

/** Server-sent event payloads of `GET /scans/{id}/events`. */
export type ScanEvent = (
  | { type: "stage"; name: string; status: "started" | "completed" | "skipped" | "failed" | string }
  | { type: "progress"; percent: number; message?: string }
  | { type: "log"; level: string; message: string }
  | {
      type: "finding";
      id: string;
      severity: Severity;
      title: string;
      /** "verdict": a live model verdict on a candidate (id is the candidate id), not a finding. */
      phase?: "verdict";
    }
  | { type: "done"; status: ScanStatus }
) & { /** Server timestamp of the event (ISO 8601), when sent. */ at?: string };
