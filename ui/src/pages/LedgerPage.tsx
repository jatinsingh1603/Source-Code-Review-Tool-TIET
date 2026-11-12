import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useSelectedScan } from "@/app/useSelectedScan";
import { useLedger, useLedgerEntry, usePrivacy, useProviders, useVerifyLedger } from "@/api/queries";
import { downloadApiFile } from "@/api/endpoints";
import type { LedgerEntry, LedgerVerifyResult } from "@/api/types";
import { providerName } from "@/lib/domain";
import { byteLength, fmtHash, fmtInt, fmtSeq, fmtTime, findingLabel, scanLabel } from "@/lib/display";
import { FilterMenu } from "@/components/FilterMenu";
import { MarkedCode } from "@/components/Marked";
import {
  Button,
  Content,
  Empty,
  ErrorBanner,
  Hash,
  Icon,
  IconButton,
  LevelBadge,
  MoreLink,
  Skeleton,
  SkeletonRows,
  StatusDot,
  useToast,
  type DotTone,
} from "@/components/ui";

const STATUS: Record<string, { tone: DotTone; label: string }> = {
  sent: { tone: "ok", label: "Sent" },
  completed: { tone: "ok", label: "Response" },
  blocked: { tone: "bad", label: "Blocked" },
  "dry-run": { tone: "neutral", label: "Dry-run" },
  recorded: { tone: "neutral", label: "Dry-run" },
  genesis: { tone: "neutral", label: "Genesis" },
};

function statusOf(e: LedgerEntry): { tone: DotTone; label: string } {
  const o = e.outcome ?? "sent";
  if (o.startsWith("blocked")) {
    const why = e.block_code ?? o.split(":")[1];
    return { tone: "bad", label: `Blocked${why ? ` · ${why.replace(/_/g, " ")}` : ""}` };
  }
  return STATUS[o] ?? { tone: "neutral", label: o };
}

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/** Egress Ledger (SCREENS.md §12): every outbound payload, hash-chained. */
export default function LedgerPage() {
  const [params, setParams] = useSearchParams();
  const { scanId, scans } = useSelectedScan();
  const scan = scans.find((s) => s.id === scanId);
  const ledgerQ = useLedger(scanId);
  const privacy = usePrivacy(scanId).data;
  const providers = useProviders().data;
  const verify = useVerifyLedger();
  const toast = useToast();
  const [result, setResult] = useState<LedgerVerifyResult | null>(null);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<string[]>([]);
  const [prov, setProv] = useState<string[]>([]);
  const [shown, setShown] = useState(10);
  const seq = params.get("seq") ? Number(params.get("seq")) : null;
  const detail = useLedgerEntry(scanId, seq);

  const entries = useMemo(() => [...(ledgerQ.data ?? [])].sort((a, b) => b.seq - a.seq), [ledgerQ.data]);
  const hasBytes = entries.some((e) => e.bytes !== undefined && e.bytes !== null);
  const filtered = entries.filter((e) => {
    const st = (e.outcome ?? "sent").split(":")[0]!;
    if (status.length && !status.includes(st)) return false;
    if (prov.length && !prov.includes(e.provider)) return false;
    if (q) {
      const t = q.toLowerCase().replace(/^#/, "");
      const hay = `${fmtSeq(e.seq)} ${e.seq} ${e.payload_hash} ${e.entry_hash} ${e.finding_id ?? ""} ${findingLabel(e.finding_id)}`.toLowerCase();
      if (!hay.includes(t)) return false;
    }
    return true;
  });
  const sent = entries.filter((e) => (e.outcome ?? "sent") === "sent").length;
  const blocked = entries.filter((e) => e.outcome?.startsWith("blocked")).length;
  const chainOk = result ? result.ok : privacy?.chain_ok;
  const head = result?.head_hash ?? privacy?.ledger_head ?? privacy?.ledger_head_hash ?? entries[0]?.entry_hash;
  const setSeq = (s: number | null) => {
    const n = new URLSearchParams(params);
    if (s === null) n.delete("seq");
    else n.set("seq", String(s));
    setParams(n, { replace: true });
  };

  const runVerify = () => {
    if (!scanId) return;
    verify.mutate(scanId, {
      onSuccess: (r) => {
        setResult(r);
        if (r.ok) toast.success("Ledger chain verified", `${fmtInt(r.entries)} records · chain, payload hash and zero-leak checks passed`);
        else toast.error("Ledger chain broken", r.first_bad_seq ? `First bad record: ${fmtSeq(r.first_bad_seq)}` : r.message);
      },
      onError: (e) => toast.error("Verification failed", e.message),
    });
  };

  const mock = scan?.provider === "mock" || scan?.send === false;
  const z = privacy?.zero_leak;

  return (
    <Content>
      <div className="ph">
        <div>
          <div className="crumb">
            <Link to="/privacy">Privacy</Link>
            <span>/</span>
            <span>Egress Ledger</span>
          </div>
          <h1>Egress Ledger</h1>
          <p className="sub" style={{ marginTop: 4 }}>
            Every outbound payload, hash-chained in order.{" "}
            {scanId && (
              <>
                Scan <span className="mono">{scanLabel(scanId)}</span>.
              </>
            )}
          </p>
        </div>
        <div className="row">
          <Button onClick={runVerify} loading={verify.isPending} disabled={!scanId}>
            Verify again
          </Button>
          <Button
            disabled={!entries.length}
            onClick={() =>
              void downloadApiFile(`/scans/${scanId}/ledger`, { format: "jsonl" }, `codekavach-ledger-${scanId}.jsonl`).catch(() =>
                download(
                  `codekavach-ledger-${scanId}.jsonl`,
                  [...entries].reverse().map((e) => JSON.stringify(e)).join("\n") + "\n",
                  "application/x-ndjson",
                ),
              )
            }
          >
            Export ledger (JSONL)
          </Button>
          <Button
            disabled={!privacy}
            onClick={() =>
              void downloadApiFile(`/scans/${scanId}/ledger-verification`, { format: "txt" }, `codekavach-verification-${scanId}.txt`).catch(() =>
                download(
                  `codekavach-verification-${scanId}.json`,
                  JSON.stringify({ scan_id: scanId, verified: result ?? null, chain_ok: privacy?.chain_ok, entries: entries.length, head, zero_leak: privacy?.zero_leak }, null, 2),
                  "application/json",
                ),
              )
            }
          >
            Export verification report
          </Button>
        </div>
      </div>

      {privacy && (
        <div className={`banner ${chainOk === false ? "bad" : "info"} split`}>
          <div>
            <div className="sm" style={{ fontWeight: 600 }}>
              {chainOk === false
                ? `Chain broken${result?.first_bad_seq ? ` at record ${fmtSeq(result.first_bad_seq)}` : ""}`
                : `Chain verified · ${fmtInt(result?.entries ?? privacy.chain_entries ?? entries.length)} records · ${
                    (result?.terms_checked ?? z?.checked) ? `${fmtInt(result?.terms_found ?? z?.occurrences)} listed terms found` : "no listed terms to check"
                  }`}
            </div>
            <div className="xs faint" style={{ marginTop: 2 }}>
              {result?.verified_at ? `Verified offline at ${fmtTime(result.verified_at)} IST` : "Checked when the scan finished"}
              {head ? ` against head ${fmtHash(head)}` : ""}
            </div>
          </div>
          <div>
            <div className="xs faint">Chain links</div>
            <StatusDot tone={chainOk === false ? "bad" : "ok"} className="sm">
              {chainOk === false ? "broken" : `${fmtInt(result?.entries ?? entries.length)} of ${fmtInt(result?.entries ?? entries.length)} valid`}
            </StatusDot>
          </div>
          <div>
            <div className="xs faint">Payload hashes</div>
            <StatusDot tone={chainOk === false ? "bad" : "ok"} className="sm">
              {result?.hashes_ok !== undefined ? `${fmtInt(result.hashes_ok)} unique payloads match` : `${fmtInt(sent)} sent`} · {fmtInt(result?.blocked ?? blocked)} blocked
            </StatusDot>
          </div>
          <div>
            <div className="xs faint">Zero-leak check</div>
            <StatusDot tone={z?.passed ? "ok" : z?.checked ? "bad" : "neutral"} className="sm">
              {result?.terms_checked !== undefined
                ? `${fmtInt(result.terms_found ?? 0)} of ${fmtInt(result.terms_checked)} terms, verbatim`
                : z?.checked
                  ? `${fmtInt(z.occurrences)} of ${fmtInt(z.checked)} terms, verbatim`
                  : "no listed terms"}
            </StatusDot>
          </div>
        </div>
      )}
      {mock && (
        <div className="banner warn sm">
          <span>
            <b>{scan?.provider === "mock" ? "Mock provider" : "Dry run"}:</b> the ledger shows what <i>would</i> have been sent. Nothing left this laptop.
          </span>
        </div>
      )}

      <section className={seq !== null ? "g g-side" : "g"} style={seq !== null ? undefined : { gridTemplateColumns: "minmax(0, 1fr)" }}>
        <div className="stack">
          <div className="row">
            <label className="search" style={{ maxWidth: 280, background: "var(--surface)", cursor: "text" }}>
              <Icon name="search" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Hash, finding or sequence"
                aria-label="Filter by hash, finding or sequence"
                style={{ border: 0, outline: 0, background: "transparent", font: "inherit", color: "var(--text)", flex: 1, minWidth: 0 }}
              />
            </label>
            <FilterMenu
              all
              label="Status"
              value={status}
              onChange={setStatus}
              options={[...new Set(entries.map((e) => (e.outcome ?? "sent").split(":")[0]!))].map((s) => ({
                value: s,
                label: STATUS[s]?.label ?? s,
                count: entries.filter((e) => (e.outcome ?? "sent").startsWith(s)).length,
              }))}
            />
            <FilterMenu
              all
              label="Provider"
              value={prov}
              onChange={setProv}
              options={[...new Set(entries.map((e) => e.provider))].map((p) => ({ value: p, label: providerName(p, providers) }))}
            />
          </div>
          {ledgerQ.isError ? (
            <ErrorBanner what="The ledger could not be loaded." error={ledgerQ.error} onRetry={() => void ledgerQ.refetch()} />
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Seq</th>
                    <th>Time</th>
                    <th>Provider · model</th>
                    <th>Payload hash</th>
                    <th className="num">{hasBytes ? "Bytes" : "Tokens"}</th>
                    <th>Chain hash</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {ledgerQ.isLoading || !scanId ? (
                    scans.length || !scanId ? <SkeletonRows cols={7} /> : null
                  ) : (
                    filtered.slice(0, shown).map((e) => {
                      const st = statusOf(e);
                      return (
                        <tr
                          key={e.seq}
                          className={`click${e.seq === seq ? " sel" : ""}`}
                          tabIndex={0}
                          aria-selected={e.seq === seq}
                          onClick={() => setSeq(e.seq)}
                          onKeyDown={(k) => k.key === "Enter" && setSeq(e.seq)}
                        >
                          <td className="mono">{fmtSeq(e.seq)}</td>
                          <td className="mono sm">{fmtTime(e.timestamp)}</td>
                          <td className="sm">
                            {providerName(e.provider, providers)} · {e.model}
                          </td>
                          <td>{e.outcome?.startsWith("blocked") ? <span className="faint sm">none</span> : <Hash value={e.payload_hash} copy={false} />}</td>
                          <td className="num mono">{fmtInt(hasBytes ? e.bytes ?? 0 : e.tokens)}</td>
                          <td>
                            <Hash value={e.entry_hash} copy={false} />
                          </td>
                          <td>
                            <StatusDot tone={st.tone}>{st.label}</StatusDot>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
              {!ledgerQ.isLoading && scanId && entries.length === 0 && (
                <Empty title="No payloads left this machine">
                  {scan?.privacy_level === "L0" ? "This scan ran at L0. The ledger holds no payloads." : "This scan recorded no payloads."}
                </Empty>
              )}
              {!scanId && !scans.length && <Empty title="No scans yet" action="Run a scan" to="/projects/new" />}
            </div>
          )}
          <div className="row between sm muted">
            <span>
              Showing {Math.min(shown, filtered.length)} of {filtered.length}
            </span>
            {shown < filtered.length && (
              <Button size="sm" onClick={() => setShown((s) => s + 20)}>
                Load more
                <Icon name="arrow-down" />
              </Button>
            )}
          </div>
        </div>

        {seq !== null && (
          <div className="card stack">
            <div className="row between">
              <h2>Record {fmtSeq(seq)}</h2>
              <IconButton label="Close record" onClick={() => setSeq(null)}>
                <Icon name="close" />
              </IconButton>
            </div>
            {detail.isLoading ? (
              <Skeleton rows={2} />
            ) : detail.isError || !detail.data ? (
              <ErrorBanner what="This record could not be loaded." error={detail.error} />
            ) : (
              <>
                <dl className="dl sm">
                  <dt>Finding</dt>
                  <dd>
                    {detail.data.entry.finding_id ? (
                      <Link className="acc mono" to={`/findings/${detail.data.entry.finding_id}`} style={{ textDecoration: "none" }}>
                        {findingLabel(detail.data.entry.finding_id)}
                      </Link>
                    ) : (
                      <span className="faint">—</span>
                    )}
                  </dd>
                  <dt>Level</dt>
                  <dd>
                    <LevelBadge level={detail.data.entry.level} name />
                  </dd>
                  <dt>Payload</dt>
                  <dd>
                    <Hash value={detail.data.entry.payload_hash} />
                  </dd>
                  <dt>Previous</dt>
                  <dd>
                    <Hash value={detail.data.entry.prev_hash} />
                  </dd>
                  <dt>Chain</dt>
                  <dd>
                    <Hash value={detail.data.entry.entry_hash} />
                  </dd>
                  <dt>Leak check</dt>
                  <dd>{z?.checked ? `${fmtInt(z.occurrences)} of ${fmtInt(z.checked)} terms` : "no listed terms"}</dd>
                </dl>
                {detail.data.payload_text ? (
                  <div>
                    <div className="code-h">
                      <span className="sm">Payload · read-only</span>
                      <span className="xs faint">{fmtInt(detail.data.entry.bytes ?? byteLength(detail.data.payload_text))} B</span>
                    </div>
                    <MarkedCode
                      text={detail.data.payload_text}
                      markup={detail.data.markup}
                      side="payload"
                      style={{ fontSize: 11.5, lineHeight: "19px", maxHeight: 420, overflow: "auto", borderTopLeftRadius: 0, borderTopRightRadius: 0 }}
                    />
                  </div>
                ) : (
                  <p className="sm muted">No payload body for this record.</p>
                )}
                {detail.data.entry.outcome === "completed" && detail.data.entry.ref_seq ? (
                  <MoreLink to={`/privacy/inspect/${scanId}/${detail.data.entry.ref_seq}`}>Open request in Privacy Inspect</MoreLink>
                ) : (
                  <MoreLink to={`/privacy/inspect/${scanId}/${seq}`}>Open in Privacy Inspect</MoreLink>
                )}
              </>
            )}
          </div>
        )}
      </section>
    </Content>
  );
}
