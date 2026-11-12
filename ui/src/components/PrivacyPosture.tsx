import { Link } from "react-router-dom";
import { CheckCircle2, Link2, Lock, ShieldCheck, XCircle } from "lucide-react";
import { usePrivacy } from "@/api/queries";
import type { PrivacySummary } from "@/api/types";
import { Card, CardBody, CardHeader, ErrorState, PrivacyLevelBadge, Skeleton } from "@/components/ui";
import { cn, fmtNum, LEVEL_INFO } from "@/lib/format";

export function ScoreRing({ score, size = 76 }: { score: number; size?: number }) {
  const r = (size - 10) / 2;
  const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(100, score));
  const tone = v >= 85 ? "rgb(var(--ck-success))" : v >= 70 ? "rgb(var(--ck-warning))" : "rgb(var(--ck-danger))";
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={`Privacy score ${v} of 100`}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgb(var(--ck-surface-3))" strokeWidth={7} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={tone}
          strokeWidth={7}
          strokeLinecap="round"
          strokeDasharray={`${(v / 100) * c} ${c}`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-semibold tabular-nums text-fg">{v}</span>
        <span className="text-[10px] uppercase tracking-wide text-fg-subtle">score</span>
      </div>
    </div>
  );
}

function Check({ ok, label, detail }: { ok: boolean; label: string; detail?: string }) {
  return (
    <li className="flex items-start gap-2">
      {ok ? (
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
      ) : (
        <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" aria-hidden />
      )}
      <span className="text-sm">
        <span className="font-medium text-fg">{label}</span>
        {detail && <span className="text-fg-muted"> · {detail}</span>}
        <span className="sr-only">{ok ? " (passed)" : " (failed)"}</span>
      </span>
    </li>
  );
}

export function PrivacyFacts({ p }: { p: PrivacySummary }) {
  const placeholders = Object.values(p.placeholders_by_type ?? {}).reduce((a, b) => a + b, 0);
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        {typeof p.privacy_score === "number" && <ScoreRing score={Math.round(p.privacy_score)} />}
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <PrivacyLevelBadge level={p.level} withName />
          </div>
          <p className="mt-1 text-sm text-fg-muted">{LEVEL_INFO[p.level]?.short}</p>
          <p className="mt-0.5 text-xs text-fg-subtle">
            {p.provider && p.provider !== "none" ? `${p.provider}${p.model ? ` · ${p.model}` : ""}` : "No model provider"}
          </p>
        </div>
      </div>
      <dl className="grid grid-cols-3 gap-2 text-center">
        {[
          ["Payloads sent", p.payloads],
          ["Blocked", p.blocked],
          ["Tokens sent", p.tokens_sent],
          ["Placeholders", placeholders],
          ["Pseudonyms", p.pseudonyms],
          ["Leak checks", p.zero_leak?.checked ?? 0],
        ].map(([k, v]) => (
          <div key={k as string} className="rounded-md bg-surface-2 px-2 py-2">
            <dt className="text-[11px] text-fg-subtle">{k}</dt>
            <dd className="text-base font-semibold tabular-nums text-fg">{fmtNum(v as number)}</dd>
          </div>
        ))}
      </dl>
      <ul className="space-y-1.5">
        <Check
          ok={p.zero_leak?.passed ?? true}
          label={p.zero_leak?.passed ? "Zero-leak check passed" : "Zero-leak check failed"}
          detail={`${p.zero_leak?.occurrences ?? 0} verbatim occurrences of ${p.zero_leak?.checked ?? 0} protected values`}
        />
        <Check ok={p.chain_ok} label={p.chain_ok ? "Ledger hash chain intact" : "Ledger hash chain broken"} />
      </ul>
    </div>
  );
}

export function PrivacyPostureCard({ scanId }: { scanId: string | undefined }) {
  const q = usePrivacy(scanId);
  return (
    <Card className="flex flex-col">
      <CardHeader
        icon={<ShieldCheck className="h-4 w-4" />}
        title="Privacy posture"
        description="What left this machine in the latest scan"
        actions={
          scanId && (
            <Link to={`/privacy?scan=${scanId}`} className="inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline">
              <Link2 className="h-3.5 w-3.5" aria-hidden /> Ledger
            </Link>
          )
        }
      />
      <CardBody className={cn("flex-1")}>
        {!scanId ? (
          <p className="text-sm text-fg-muted">Run a scan to see its privacy attestation.</p>
        ) : q.isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-24 w-full" />
          </div>
        ) : q.error ? (
          <ErrorState error={q.error} title="Privacy summary unavailable" />
        ) : q.data ? (
          <PrivacyFacts p={q.data} />
        ) : null}
        <p className="mt-4 flex items-start gap-1.5 text-xs text-fg-subtle">
          <Lock className="mt-0.5 h-3 w-3 shrink-0" aria-hidden /> Measured disclosure for this scan, not a guarantee of
          secrecy.
        </p>
      </CardBody>
    </Card>
  );
}
