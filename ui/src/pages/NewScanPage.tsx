import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { CheckCircle2, Cloud, Cpu, Loader2, Play, PlugZap, XCircle } from "lucide-react";
import { useProject, useProviders, useSettings, useStartScan, useTestProvider } from "@/api/queries";
import { PRIVACY_LEVELS, type PrivacyLevel, type ProviderTestResult } from "@/api/types";
import { PageHeader } from "@/components/layout/PageHeader";
import { Badge, Button, Card, CardBody, CardHeader, Field, Input, PrivacyLevelBadge, Select, Skeleton, Toggle, useToast } from "@/components/ui";
import { EgressPreview } from "@/components/EgressPreview";
import { cn, LEVEL_INFO } from "@/lib/format";
import { sourceText } from "./ProjectsPage";

const lvlBar: Record<PrivacyLevel, string> = {
  L0: "bg-lvl-0",
  L1: "bg-lvl-1",
  L2: "bg-lvl-2",
  L3: "bg-lvl-3",
  L4: "bg-lvl-4",
};

function Step({ n, title, children, description }: { n: number; title: string; description?: string; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-3">
            <span className="flex h-7 w-7 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-fg">{n}</span>
            {title}
          </span>
        }
        description={description}
      />
      <CardBody>{children}</CardBody>
    </Card>
  );
}

export default function NewScanPage() {
  const { id } = useParams();
  const project = useProject(id);
  const providers = useProviders();
  const settings = useSettings();
  const start = useStartScan();
  const test = useTestProvider();
  const toast = useToast();
  const navigate = useNavigate();

  const [level, setLevel] = useState<PrivacyLevel>("L3");
  const [providerId, setProviderId] = useState<string>("");
  const [model, setModel] = useState<string>("");
  const [send, setSend] = useState(true);
  const [rules, setRules] = useState("");
  const [testResult, setTestResult] = useState<ProviderTestResult | null>(null);
  const [defaultsApplied, setDefaultsApplied] = useState(false);

  const list = useMemo(() => providers.data ?? [], [providers.data]);
  const provider = list.find((p) => p.id === providerId);

  useEffect(() => {
    if (defaultsApplied || !list.length || settings.isLoading) return;
    const s = settings.data;
    const def = list.find((p) => p.id === s?.default_provider) ?? list.find((p) => p.configured) ?? list[0]!;
    setProviderId(def.id);
    setModel(s?.default_provider === def.id && s?.default_model ? s.default_model : def.default_model);
    if (s?.default_privacy_level) setLevel(s.default_privacy_level);
    setDefaultsApplied(true);
  }, [list, settings.data, settings.isLoading, defaultsApplied]);

  const chooseProvider = (pid: string) => {
    const p = list.find((x) => x.id === pid);
    setProviderId(pid);
    setModel(p?.default_model ?? "");
    setTestResult(null);
  };

  const runTest = async () => {
    setTestResult(null);
    try {
      const r = await test.mutateAsync({ id: providerId, model });
      setTestResult(r);
    } catch (e) {
      setTestResult({ ok: false, latency_ms: 0, model, message: e instanceof Error ? e.message : "Test failed" });
    }
  };

  const submit = async () => {
    if (!id) return;
    try {
      const scan = await start.mutateAsync({
        projectId: id,
        body: {
          privacy_level: level,
          provider: level === "L0" ? "none" : providerId,
          model: level === "L0" ? undefined : model || undefined,
          send: level === "L0" ? false : send,
          rules: rules.trim() ? rules.split(/[\s,]+/).filter(Boolean) : undefined,
        },
      });
      toast.success("Scan started", `Scan ${scan.id} is running.`);
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      toast.error("Could not start the scan", e instanceof Error ? e.message : undefined);
    }
  };

  const p = project.data;
  return (
    <>
      <PageHeader
        crumbs={[{ label: "Projects", to: "/projects" }, { label: p?.name ?? "…", to: `/projects/${id}` }, { label: "New scan" }]}
        title="New scan"
        description="Choose how much may leave this machine and which model reviews the candidates. Deterministic analysis always runs locally."
      />
      <div className="grid gap-6 xl:grid-cols-[1fr_22rem]">
        <div className="space-y-6">
          <Step n={1} title="Source" description="The code base to analyse">
            {p ? (
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-lg font-semibold text-fg">{p.name}</span>
                <Badge>{p.source.type}</Badge>
                <span className="font-mono text-xs text-fg-subtle">{sourceText(p)}</span>
                {(p.languages ?? []).map((l) => (
                  <Badge key={l} tone="accent">
                    {l}
                  </Badge>
                ))}
              </div>
            ) : (
              <Skeleton className="h-8 w-80" />
            )}
          </Step>

          <Step n={2} title="Privacy level" description="Decides what, if anything, is sent to a model provider">
            <div role="radiogroup" aria-label="Privacy level" className="grid gap-2 sm:grid-cols-5">
              {PRIVACY_LEVELS.map((l) => (
                <button
                  key={l}
                  type="button"
                  role="radio"
                  aria-checked={level === l}
                  onClick={() => setLevel(l)}
                  className={cn(
                    "relative overflow-hidden rounded-lg border p-3 text-left transition-colors",
                    level === l ? "border-primary bg-primary-soft/50 ring-1 ring-primary" : "border-border hover:bg-surface-2",
                  )}
                >
                  <span className={cn("absolute inset-x-0 top-0 h-1", lvlBar[l])} aria-hidden />
                  <span className="flex items-center justify-between">
                    <span className="text-base font-bold text-fg">{l}</span>
                    {level === l && <CheckCircle2 className="h-4 w-4 text-primary" aria-hidden />}
                  </span>
                  <span className="mt-0.5 block text-sm font-medium text-fg">{LEVEL_INFO[l].name}</span>
                  <span className="mt-1 block text-xs leading-snug text-fg-muted">{LEVEL_INFO[l].short}</span>
                </button>
              ))}
            </div>
            <div className="mt-3 flex items-center gap-2 text-xs text-fg-subtle">
              <span>Less disclosed</span>
              <span className="h-1.5 flex-1 rounded-full bg-gradient-to-r from-[rgb(var(--ck-lvl-0))] via-[rgb(var(--ck-lvl-2))] to-[rgb(var(--ck-lvl-4))]" aria-hidden />
              <span>More context for the model</span>
            </div>
            <div className="mt-4 rounded-lg bg-surface-2 p-4">
              <p className="text-sm font-semibold text-fg">What leaves this machine at {level}</p>
              <p className="mt-1 text-sm text-fg-muted">{LEVEL_INFO[level].leaves}</p>
              <ul className="mt-2 list-disc space-y-0.5 pl-5 text-sm text-fg-muted">
                {LEVEL_INFO[level].detail.map((d) => (
                  <li key={d}>{d}</li>
                ))}
              </ul>
            </div>
          </Step>

          <Step n={3} title="Model provider" description={level === "L0" ? "Not used at level L0" : "The model that reviews sanitised candidates"}>
            <fieldset disabled={level === "L0"} className={cn(level === "L0" && "opacity-50")}>
              {providers.isLoading ? (
                <Skeleton className="h-24" />
              ) : (
                <div className="grid gap-2 sm:grid-cols-2">
                  {list.map((pr) => (
                    <button
                      key={pr.id}
                      type="button"
                      aria-pressed={providerId === pr.id}
                      onClick={() => chooseProvider(pr.id)}
                      className={cn(
                        "flex items-start gap-3 rounded-lg border p-3 text-left transition-colors",
                        providerId === pr.id ? "border-primary bg-primary-soft/50 ring-1 ring-primary" : "border-border hover:bg-surface-2",
                      )}
                    >
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-surface-3 text-fg-muted">
                        {pr.local ? <Cpu className="h-4 w-4" aria-hidden /> : <Cloud className="h-4 w-4" aria-hidden />}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-semibold text-fg">{pr.name}</span>
                          <Badge tone={pr.local ? "success" : "info"}>{pr.local ? "local" : "hosted"}</Badge>
                          {!pr.configured && <Badge tone="warning">not configured</Badge>}
                        </div>
                        <p className="mt-0.5 truncate text-xs text-fg-muted">
                          {pr.kind} · {pr.default_model}
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              )}
              <div className="mt-4 grid gap-4 sm:grid-cols-[1fr_auto] sm:items-end">
                <Field label="Model">
                  {(fid) =>
                    provider && provider.models.length > 0 ? (
                      <Select id={fid} value={model} onChange={(e) => setModel(e.target.value)}>
                        {provider.models.map((m) => (
                          <option key={m} value={m}>
                            {m}
                          </option>
                        ))}
                      </Select>
                    ) : (
                      <Input id={fid} value={model} onChange={(e) => setModel(e.target.value)} />
                    )
                  }
                </Field>
                <Button variant="outline" icon={<PlugZap className="h-4 w-4" />} loading={test.isPending} onClick={runTest} disabled={!providerId}>
                  Test connection
                </Button>
              </div>
              {test.isPending && (
                <p className="mt-2 flex items-center gap-2 text-sm text-fg-muted">
                  <Loader2 className="h-4 w-4 animate-spin" /> Sending a fixed probe through the egress transport…
                </p>
              )}
              {testResult && (
                <p className={cn("mt-2 flex items-start gap-2 text-sm", testResult.ok ? "text-success" : "text-danger")} role="status">
                  {testResult.ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0" />}
                  <span>
                    {testResult.ok ? `Reachable in ${testResult.latency_ms} ms (${testResult.model}).` : "Not reachable."}{" "}
                    <span className="text-fg-muted">{testResult.message}</span>
                  </span>
                </p>
              )}
              <div className="mt-5 border-t border-border pt-4">
                <Toggle
                  checked={send}
                  onChange={setSend}
                  label="Send payloads to the provider"
                  description="Off: payloads are prepared and recorded in the ledger for inspection, but nothing is sent."
                />
              </div>
            </fieldset>
          </Step>

          <Step n={4} title="Rules (optional)" description="Restrict the scan to specific rule ids or packs">
            <Field label="Rule ids" help="Comma or space separated. Leave empty to run the default rule pack.">
              {(fid) => <Input id={fid} value={rules} onChange={(e) => setRules(e.target.value)} placeholder="e.g. py.sqli.string-format, B602" />}
            </Field>
          </Step>
        </div>

        <div className="xl:sticky xl:top-[calc(var(--ck-topbar-height)+1.5rem)] xl:self-start">
          <Card>
            <CardHeader title="Egress preview" description="Read this before starting" />
            <CardBody className="space-y-4">
              <EgressPreview level={level} provider={provider} send={send} />
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between gap-3">
                  <dt className="text-fg-muted">Privacy level</dt>
                  <dd>
                    <PrivacyLevelBadge level={level} withName />
                  </dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-fg-muted">Provider</dt>
                  <dd className="truncate font-medium text-fg">{level === "L0" ? "None" : (provider?.name ?? "—")}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-fg-muted">Model</dt>
                  <dd className="truncate font-mono text-xs text-fg">{level === "L0" ? "—" : model || "—"}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-fg-muted">Egress</dt>
                  <dd className="font-medium text-fg">{level === "L0" || !send ? "Nothing sent" : provider?.local ? "Local model" : "Hosted model"}</dd>
                </div>
              </dl>
              <Button size="lg" className="w-full" icon={<Play className="h-4 w-4" />} loading={start.isPending} onClick={submit} disabled={!p || (level !== "L0" && !providerId)}>
                Start scan
              </Button>
              {provider && !provider.configured && level !== "L0" && send && (
                <p className="text-xs text-warning">This provider is not configured on the server; the model review step will fail closed.</p>
              )}
            </CardBody>
          </Card>
        </div>
      </div>
    </>
  );
}
