import { useMemo, useState } from "react";
import { Check, Copy, FileCheck2, Fingerprint, Link2, Link2Off, ListTree, Lock, ScrollText, ShieldCheck, Tags } from "lucide-react";
import { useLedger, useLedgerEntry, usePrivacy, useVerifyLedger } from "@/api/queries";
import type { LedgerEntry, LedgerVerifyResult } from "@/api/types";
import { PageHeader } from "@/components/layout/PageHeader";
import {
  Badge,
  Button,
  Callout,
  Card,
  CardBody,
  CardHeader,
  DataTable,
  Drawer,
  EmptyState,
  ErrorState,
  PrivacyLevelBadge,
  Skeleton,
  SkeletonRows,
  Tabs,
  type Column,
} from "@/components/ui";
import { ScanPicker } from "@/components/ScanPicker";
import { PrivacyFacts } from "@/components/PrivacyPosture";
import { SideBySide } from "@/components/SideBySide";
import { useSelectedScan } from "@/app/useSelectedScan";
import { useSession } from "@/app/session";
import { fmtDateTime, fmtNum, shortHash } from "@/lib/format";

function placeholderLabel(type: string): string {
  return type
    .toLowerCase()
    .split("_")
    .map((w, i) => (i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(" ");
}

function PlaceholderBars({ counts }: { counts: Record<string, number> }) {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (!entries.length) return <p className="text-sm text-fg-muted">No placeholders were needed for this scan.</p>;
  return (
    <table className="w-full text-sm">
      <caption className="sr-only">Placeholders by type</caption>
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k}>
            <th scope="row" className="w-[45%] py-1 pr-3 text-left font-normal">
              <span className="font-mono text-xs text-fg">{`<${k}>`}</span>
              <span className="block text-[11px] text-fg-subtle">{placeholderLabel(k)}</span>
            </th>
            <td className="py-1">
              <div className="flex items-center gap-2">
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-surface-3" aria-hidden>
                  <div
                    className={k.startsWith("SECRET") ? "h-full rounded-full bg-mark-secret" : k.startsWith("PII") ? "h-full rounded-full bg-mark-pii" : "h-full rounded-full bg-mark-literal"}
                    style={{ width: `${(v / max) * 100}%` }}
                  />
                </div>
                <span className="w-8 text-right font-semibold tabular-nums text-fg">{v}</span>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function outcomeBadge(e: LedgerEntry) {
  const o = e.outcome ?? "sent";
  if (o.startsWith("blocked")) return <Badge tone="danger">{o}</Badge>;
  if (o.includes("local")) return <Badge tone="success">{o}</Badge>;
  return <Badge tone="info">{o}</Badge>;
}

function CopyHash({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="inline-flex items-center gap-1 rounded px-1 text-xs text-fg-subtle hover:text-fg"
      aria-label="Copy full hash"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* ignore */
        }
      }}
    >
      {done ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

function LedgerDrawer({ scanId, entry, onClose }: { scanId: string; entry: LedgerEntry | null; onClose: () => void }) {
  const q = useLedgerEntry(scanId, entry?.seq ?? null);
  return (
    <Drawer
      open={!!entry}
      onClose={onClose}
      width="max-w-6xl"
      title={entry ? `Ledger entry #${entry.seq}` : ""}
      subtitle={entry && (
        <span className="flex flex-wrap items-center gap-2">
          <PrivacyLevelBadge level={entry.level} />
          {outcomeBadge(entry)}
          <span className="font-mono text-xs">{entry.candidate_id}</span>
        </span>
      )}
    >
      {q.isLoading ? (
        <Skeleton className="h-80" />
      ) : q.error ? (
        <ErrorState error={q.error} title="This entry could not be loaded" />
      ) : q.data ? (
        <div className="space-y-5">
          <dl className="grid gap-x-6 gap-y-2 rounded-lg bg-surface-2 p-4 text-sm sm:grid-cols-2">
            {[
              ["Timestamp", fmtDateTime(q.data.entry.timestamp)],
              ["Provider · model", `${q.data.entry.provider} · ${q.data.entry.model}`],
              ["Tokens", fmtNum(q.data.entry.tokens)],
              ["Finding", q.data.entry.finding_id ?? "—"],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between gap-3">
                <dt className="text-fg-muted">{k}</dt>
                <dd className="text-right text-fg">{v}</dd>
              </div>
            ))}
            {[
              ["Payload hash", q.data.entry.payload_hash],
              ["Entry hash", q.data.entry.entry_hash],
              ["Previous hash", q.data.entry.prev_hash],
            ].map(([k, v]) => (
              <div key={k} className="sm:col-span-2">
                <dt className="text-fg-muted">{k}</dt>
                <dd className="flex items-center gap-1 break-all font-mono text-xs text-fg">
                  {v}
                  <CopyHash value={v ?? ""} />
                </dd>
              </div>
            ))}
          </dl>
          <SideBySide detail={q.data} />
          <p className="text-xs text-fg-subtle">
            The pseudonym mapping stays in the local vault and is never shown or exported here. The payload hash above is the one recorded in the ledger, so this is the
            recorded payload, not a re-render.
          </p>
        </div>
      ) : null}
    </Drawer>
  );
}

export default function PrivacyPage() {
  const { scanId, setScanId, scans } = useSelectedScan();
  const privacy = usePrivacy(scanId);
  const ledger = useLedger(scanId);
  const verify = useVerifyLedger();
  const { can } = useSession();
  const [tab, setTab] = useState("ledger");
  const [selected, setSelected] = useState<LedgerEntry | null>(null);
  const [verifyResult, setVerifyResult] = useState<LedgerVerifyResult | null>(null);
  const [outcome, setOutcome] = useState<"all" | "sent" | "blocked">("all");

  const entries = useMemo(() => {
    const list = ledger.data ?? [];
    if (outcome === "all") return list;
    return list.filter((e) => (outcome === "blocked" ? e.outcome?.startsWith("blocked") : !e.outcome?.startsWith("blocked")));
  }, [ledger.data, outcome]);

  const runVerify = async () => {
    if (!scanId) return;
    setVerifyResult(null);
    try {
      setVerifyResult(await verify.mutateAsync(scanId));
    } catch (e) {
      setVerifyResult({ ok: false, entries: 0, message: e instanceof Error ? e.message : "Verification failed" });
    }
  };

  const cols: Column<LedgerEntry>[] = [
    { id: "seq", header: "#", rowHeader: true, cell: (e) => <span className="font-mono text-sm text-fg">{e.seq}</span>, sortValue: (e) => e.seq },
    { id: "ts", header: "Time", cell: (e) => <span className="whitespace-nowrap text-sm text-fg-muted">{fmtDateTime(e.timestamp)}</span>, sortValue: (e) => e.timestamp },
    {
      id: "candidate",
      header: "Candidate",
      cell: (e) => (
        <span className="block max-w-[11rem] truncate font-mono text-xs text-fg" title={e.candidate_id}>
          {e.candidate_id}
        </span>
      ),
    },
    { id: "level", header: "Level", cell: (e) => <PrivacyLevelBadge level={e.level} /> },
    { id: "tokens", header: "Tokens", cell: (e) => <span className="tabular-nums text-sm text-fg">{fmtNum(e.tokens)}</span>, sortValue: (e) => e.tokens },
    {
      id: "hash",
      header: "Payload hash",
      cell: (e) => (
        <span className="font-mono text-xs text-fg-muted" title={e.payload_hash}>
          {shortHash(e.payload_hash, 12)}
        </span>
      ),
    },
    {
      id: "chain",
      header: "Chain",
      cell: (e) => (
        <span className="inline-flex items-center gap-1 font-mono text-xs text-fg-subtle" title={`prev ${e.prev_hash}\nentry ${e.entry_hash}`}>
          <Link2 className="h-3 w-3" aria-hidden />
          {shortHash(e.prev_hash, 6)}→{shortHash(e.entry_hash, 6)}
        </span>
      ),
    },
    { id: "outcome", header: "Outcome", cell: outcomeBadge, sortValue: (e) => e.outcome ?? "" },
  ];

  const p = privacy.data;
  return (
    <>
      <PageHeader
        title="Privacy Centre"
        description="Exactly what left this machine, for each scan: the attestation, every payload in the hash-chained ledger, and a side-by-side view against the original code."
        actions={<ScanPicker scans={scans} value={scanId} onChange={setScanId} />}
      />
      {!scanId ? (
        <Card>
          <EmptyState icon={<Lock className="h-6 w-6" />} title="No scans yet" description="Run a scan to see its privacy attestation and egress ledger." />
        </Card>
      ) : privacy.error ? (
        <Card>
          <ErrorState error={privacy.error} onRetry={() => void privacy.refetch()} title="Privacy summary unavailable" />
        </Card>
      ) : (
        <>
          <div className="grid gap-6 xl:grid-cols-3">
            <Card className="xl:col-span-2">
              <CardHeader icon={<FileCheck2 className="h-4 w-4" />} title="Privacy attestation" description="Generated from the ledger of this scan" />
              <CardBody>
                {p ? (
                  <div className="grid gap-6 lg:grid-cols-[1fr_17rem]">
                    <blockquote className="rounded-lg border-l-4 border-primary bg-primary-soft/40 px-4 py-3 text-base leading-relaxed text-fg">
                      {p.attestation_text}
                    </blockquote>
                    <PrivacyFacts p={p} />
                  </div>
                ) : (
                  <Skeleton className="h-48" />
                )}
                <p className="mt-4 text-xs text-fg-subtle">
                  These are measured disclosure volumes for this scan. They do not measure what a determined reader could infer from what was sent.
                </p>
              </CardBody>
            </Card>
            <Card>
              <CardHeader icon={<Tags className="h-4 w-4" />} title="Placeholders by type" description={p ? `${fmtNum(p.pseudonyms)} identifiers pseudonymised` : undefined} />
              <CardBody>{p ? <PlaceholderBars counts={p.placeholders_by_type ?? {}} /> : <Skeleton className="h-40" />}</CardBody>
            </Card>
          </div>

          <Card className="mt-6">
            <div className="px-5 pt-3">
              <Tabs
                label="Privacy views"
                value={tab}
                onChange={setTab}
                tabs={[
                  { id: "ledger", label: "Egress ledger", icon: <ScrollText className="h-4 w-4" />, count: ledger.data?.length },
                  { id: "integrity", label: "Integrity", icon: <Fingerprint className="h-4 w-4" /> },
                ]}
              />
            </div>
            {tab === "ledger" && (
              <>
                <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
                  <p className="text-sm text-fg-muted">
                    Select an entry to compare the payload with the original code.
                    {ledger.data?.[0] ? ` All entries: ${ledger.data[0].provider} · ${ledger.data[0].model}.` : ""}
                  </p>
                  <div className="flex gap-1.5" role="group" aria-label="Outcome filter">
                    {(["all", "sent", "blocked"] as const).map((o) => (
                      <Button key={o} size="sm" variant={outcome === o ? "secondary" : "ghost"} aria-pressed={outcome === o} onClick={() => setOutcome(o)}>
                        {o === "all" ? "All" : o === "sent" ? "Sent" : "Blocked"}
                      </Button>
                    ))}
                  </div>
                </div>
                {ledger.isLoading ? (
                  <div className="p-5">
                    <SkeletonRows rows={6} />
                  </div>
                ) : ledger.error ? (
                  <ErrorState error={ledger.error} />
                ) : (
                  <DataTable
                    className="max-h-[38rem] overflow-y-auto"
                    columns={cols}
                    rows={entries}
                    rowKey={(e) => String(e.seq)}
                    onRowClick={setSelected}
                    initialSort={{ id: "seq", dir: "asc" }}
                    caption="Egress ledger"
                    empty={
                      <EmptyState
                        icon={<ShieldCheck className="h-6 w-6" />}
                        title="The ledger is empty"
                        description={
                          p?.level === "L0"
                            ? "This scan ran at level L0: no payload was prepared for or sent to any model."
                            : "No payload was recorded for this scan."
                        }
                      />
                    }
                  />
                )}
              </>
            )}
            {tab === "integrity" && (
              <CardBody className="pt-5">
                <div className="grid gap-6 lg:grid-cols-2">
                  <div className="space-y-3">
                    <div className="flex items-center gap-3">
                      {(verifyResult ? verifyResult.ok : p?.chain_ok) ? (
                        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-success-soft text-success">
                          <Link2 className="h-6 w-6" aria-hidden />
                        </div>
                      ) : (
                        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-danger-soft text-danger">
                          <Link2Off className="h-6 w-6" aria-hidden />
                        </div>
                      )}
                      <div>
                        <p className="text-lg font-semibold text-fg">
                          {(verifyResult ? verifyResult.ok : p?.chain_ok) ? "Hash chain intact" : "Hash chain broken"}
                        </p>
                        <p className="text-sm text-fg-muted">
                          {verifyResult
                            ? `${verifyResult.message ?? ""} · ${fmtNum(verifyResult.entries)} entries verified${verifyResult.verified_at ? ` at ${fmtDateTime(verifyResult.verified_at)}` : ""}`
                            : `${fmtNum(ledger.data?.length ?? 0)} entries, first #${ledger.data?.[0]?.seq ?? "—"}, last #${ledger.data?.[ledger.data.length - 1]?.seq ?? "—"}`}
                        </p>
                      </div>
                    </div>
                    {verifyResult && !verifyResult.ok && verifyResult.first_bad_seq != null && (
                      <Callout tone="danger" title={`First inconsistent entry: #${verifyResult.first_bad_seq}`}>
                        An entry's recorded hash does not match its content or its predecessor. The ledger has been altered after it was written.
                      </Callout>
                    )}
                    {can("privacy:read_original") && (
                      <Button icon={<ListTree className="h-4 w-4" />} loading={verify.isPending} onClick={runVerify}>
                        Re-verify the chain
                      </Button>
                    )}
                  </div>
                  <div className="rounded-lg bg-surface-2 p-4 text-sm text-fg-muted">
                    <p className="font-semibold text-fg">What this checks</p>
                    <p className="mt-1">
                      Each ledger entry stores the hash of its payload and the hash of the previous entry. Verification recomputes every hash in order. An intact chain
                      means no entry was edited, removed or reordered after it was written; a broken chain names the first entry that does not match.
                    </p>
                  </div>
                </div>
              </CardBody>
            )}
          </Card>
          {scanId && <LedgerDrawer scanId={scanId} entry={selected} onClose={() => setSelected(null)} />}
        </>
      )}
    </>
  );
}
