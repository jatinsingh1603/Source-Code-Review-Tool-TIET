import { useMemo, useState } from "react";
import { useOptional, useProviders, useScans, useSettings, useTestProvider } from "@/api/queries";
import { endpoints } from "@/api/endpoints";
import type { ProviderInfo, ProviderTestResult } from "@/api/types";
import { useSession } from "@/app/session";
import { fmtInt } from "@/lib/display";
import { Button, Content, Empty, ErrorBanner, PageHeader, Skeleton, StatusDot, useToast } from "@/components/ui";

const WIRE: Record<string, string> = {
  mock: "internal",
  replay: "recorded JSONL",
  anthropic: "messages",
  openai: "openai responses",
  "openai-compatible": "openai-compatible",
  ollama: "openai-compatible",
  vllm: "openai-compatible",
  gemini: "generateContent",
  bedrock: "converse",
  azure: "chat completions",
};

const CAP_LABEL: Record<string, string> = {
  structured_output: "Structured output",
  tool_calling: "Tool use",
  batch: "Batch",
  local: "Local",
};

function logo(name: string): string {
  const w = name.replace(/[^A-Za-z ]/g, " ").trim().split(/\s+/);
  return (w[0]?.[0] ?? "?").toUpperCase();
}

function caps(p: ProviderInfo): string[] {
  const c = p.capabilities;
  if (!c) return [];
  if (Array.isArray(c)) return c.map((x) => CAP_LABEL[x] ?? x);
  return Object.entries(c)
    .filter(([k, v]) => v === true && CAP_LABEL[k])
    .map(([k]) => CAP_LABEL[k]!);
}

/** Providers (SCREENS.md §14): configured LLM providers, health and usage. */
export default function ProvidersPage() {
  const q = useProviders();
  const settings = useSettings().data;
  const scans = useScans().data;
  const test = useTestProvider();
  const toast = useToast();
  const { can } = useSession();
  const [health, setHealth] = useState<Record<string, ProviderTestResult | "running">>({});

  const runAll = async () => {
    for (const p of q.data ?? []) {
      if (!p.configured) continue;
      setHealth((h) => ({ ...h, [p.id]: "running" }));
      try {
        const r = await test.mutateAsync({ id: p.id });
        setHealth((h) => ({ ...h, [p.id]: r }));
      } catch (e) {
        setHealth((h) => ({ ...h, [p.id]: { ok: false, latency_ms: 0, model: "", message: e instanceof Error ? e.message : "failed" } }));
      }
    }
    toast.info("Health checks finished");
  };

  const month = new Date().toISOString().slice(0, 7);
  const month0 = month;
  const usageQ = useOptional(`usage-${month0}`, () => endpoints.providerUsage(month0));
  const usage = useMemo(() => {
    const m = new Map<string, number>();
    for (const s of scans ?? []) {
      if ((s.created_at ?? s.started_at ?? "").slice(0, 7) !== month) continue;
      const t = s.privacy_summary?.tokens_sent ?? 0;
      if (t) m.set(s.provider, (m.get(s.provider) ?? 0) + t);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [scans, month]);
  const maxUse = usage[0]?.[1] ?? 1;
  const monthName = new Date().toLocaleString("en-GB", { month: "long" });

  return (
    <Content>
      <PageHeader
        crumbs={[{ label: "Organisation" }, { label: "Providers" }]}
        title="Providers"
        sub="Bring your own keys. Keys are stored as references, never as plaintext."
        actions={
          <>
            <Button onClick={() => void runAll()} loading={test.isPending}>
              Run health checks
            </Button>
            <Button variant="primary" disabled title={can("settings:write") ? "Providers are added in the server configuration (codekavach.toml)." : "Admins add providers."}>
              + Add provider
            </Button>
          </>
        }
      />
      {q.isError && <ErrorBanner what="Providers could not be loaded." error={q.error} onRetry={() => void q.refetch()} />}
      <section className="g g-3">
        {q.isLoading
          ? [0, 1, 2].map((i) => (
              <div key={i} className="card">
                <Skeleton rows={2} />
              </div>
            ))
          : (q.data ?? []).map((p) => {
              const h = health[p.id];
              const st =
                h === "running"
                  ? { tone: "acc" as const, label: "Checking" }
                  : h
                    ? h.ok
                      ? { tone: "ok" as const, label: `Healthy · ${h.latency_ms} ms` }
                      : { tone: "warn" as const, label: "Unreachable" }
                    : !p.configured
                      ? { tone: "bad" as const, label: "Key missing" }
                      : { tone: "neutral" as const, label: "Not checked" };
              return (
                <div key={p.id} className="card stack">
                  <div className="row between">
                    <div className="row" style={{ gap: 10 }}>
                      <span className="provlogo">{logo(p.name)}</span>
                      <div>
                        <b>{p.name}</b>
                        <div className="xs faint mono">wire: {p.wire ?? WIRE[p.kind] ?? p.kind}</div>
                      </div>
                    </div>
                    <span title={h && h !== "running" ? h.message : undefined}>
                      <StatusDot tone={st.tone} className="sm">
                        {st.label}
                      </StatusDot>
                    </span>
                  </div>
                  <div className="row">
                    {caps(p).map((c) => (
                      <span key={c} className="chip">
                        {c}
                      </span>
                    ))}
                    {settings?.default_provider === p.id && <span className="chip fixed">Default</span>}
                  </div>
                  <dl className="dl sm">
                    <dt>Key</dt>
                    <dd>
                      {p.key_ref_status?.length
                        ? p.key_ref_status.map((k) => (
                            <div key={k.ref}>
                              <span className="mono xs">{k.ref}</span> · {k.present ? "present" : k.state === "not-set" ? "missing" : k.state}
                            </div>
                          ))
                        : p.key_refs?.length
                        ? p.key_refs.map((r) => (
                            <span key={r}>
                              <span className="mono xs">{r}</span> · {p.configured ? "present" : "missing"}
                            </span>
                          ))
                        : p.local
                          ? "Offline · no key"
                          : "—"}
                    </dd>
                    {p.models.length > 0 && (
                      <>
                        <dt>Models</dt>
                        <dd className="mono xs">{p.models.join(" · ")}</dd>
                      </>
                    )}
                    {(p.endpoint || p.host) && (
                      <>
                        <dt>Endpoint</dt>
                        <dd className="mono xs" style={{ wordBreak: "break-all" }}>
                          {p.endpoint ?? p.host}
                        </dd>
                      </>
                    )}
                    <dt>Trust tier</dt>
                    <dd>
                      {p.trust_tier ?? (p.local ? "local" : "remote")}
                      {p.min_level ? ` · needs ${p.min_level} or stricter` : ""}
                    </dd>
                    <dt>Cost</dt>
                    <dd className={p.local ? undefined : "faint"}>{p.kind === "mock" || p.kind === "replay" ? "None" : p.local ? "Your hardware" : "[set by admin]"}</dd>
                  </dl>
                </div>
              );
            })}
      </section>

      <section className="g g-2">
        <div className="card">
          <div className="card-h">
            <div>
              <h2>Auto-selection rules</h2>
              <p className="sub">Evaluated top to bottom for every scan</p>
            </div>
          </div>
          <div className="tbl-wrap" style={{ border: 0 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>#</th>
                  <th>When</th>
                  <th>Use</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="mono">1</td>
                  <td className="sm">Level is L0</td>
                  <td className="sm">No model · local engines only</td>
                </tr>
                <tr>
                  <td className="mono">2</td>
                  <td className="sm">Level below the provider's floor</td>
                  <td className="sm">Not allowed · choose a stricter level</td>
                </tr>
                <tr>
                  <td className="mono">3</td>
                  <td className="sm">Otherwise</td>
                  <td className="sm">{q.data?.find((p) => p.id === settings?.default_provider)?.name ?? "Default provider"}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div className="card">
          <div className="card-h">
            <div>
              <h2>Token usage, {monthName}</h2>
              <p className="sub">Input and output tokens recorded in the egress ledger</p>
            </div>
          </div>
          {usageQ.data?.usage.length ? (
            <div className="stack" style={{ gap: 12 }}>
              <div className="legend">
                <span>
                  <i style={{ background: "var(--text)" }} />
                  Input
                </span>
                <span>
                  <i style={{ background: "var(--accent)" }} />
                  Output
                </span>
              </div>
              {(() => {
                const max = Math.max(1, ...usageQ.data.usage.map((u) => u.input_tokens + u.output_tokens));
                return usageQ.data.usage.map((u) => (
                  <div key={u.provider}>
                    <div className="row between sm">
                      <span>
                        {q.data?.find((p) => p.id === u.provider)?.name ?? u.provider}
                        <span className="xs faint"> · {fmtInt(u.requests)} requests</span>
                      </span>
                      <span className="mono">
                        {fmtInt(u.input_tokens)} · {fmtInt(u.output_tokens)}
                      </span>
                    </div>
                    <div className="tokbar">
                      <i style={{ width: `${(u.input_tokens / max) * 100}%` }} />
                      <i className="out" style={{ width: `${(u.output_tokens / max) * 100}%` }} />
                    </div>
                  </div>
                ));
              })()}
            </div>
          ) : usage.length === 0 ? (
            <Empty title="No usage this month">Payloads sent this month appear here.</Empty>
          ) : (
            <div className="stack" style={{ gap: 12 }}>
              {usage.map(([id, n]) => (
                <div key={id}>
                  <div className="row between sm">
                    <span>{q.data?.find((p) => p.id === id)?.name ?? id}</span>
                    <span className="mono">{fmtInt(n)}</span>
                  </div>
                  <div className="tokbar">
                    <i style={{ width: `${(n / maxUse) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
          <p className="xs faint" style={{ marginTop: 12 }}>
            Costs appear once an admin sets a rate card for each paid provider.
          </p>
        </div>
      </section>

      <section className="stack">
        <div className="row">
          <h2 style={{ fontSize: 14, fontWeight: 600 }}>Conformance tests</h2>
          <span className="xs faint">schema, refusal handling, pseudonym round-trip, timeout, fail-closed</span>
        </div>
        <div className="card">
          <Empty title="No conformance results on this server">
            Run <span className="mono">codekavach providers --help</span> to test a provider from the command line.
          </Empty>
        </div>
      </section>
    </Content>
  );
}
