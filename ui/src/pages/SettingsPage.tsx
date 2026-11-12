import { useEffect, useRef, useState } from "react";
import { CheckCircle2, Cloud, Cpu, FileCode2, PlugZap, Save, Settings2, SlidersHorizontal, XCircle } from "lucide-react";
import { usePolicy, useProviders, useSavePolicy, useSaveSettings, useSettings, useTestProvider } from "@/api/queries";
import { type PrivacyLevel, type ProviderInfo, type ProviderTestResult, type Settings } from "@/api/types";
import { ApiError } from "@/api/client";
import { PageHeader } from "@/components/layout/PageHeader";
import { Badge, Button, Callout, Card, CardBody, CardHeader, ErrorState, Field, Input, Select, Skeleton, Tabs, useToast } from "@/components/ui";
import { useSession } from "@/app/session";
import { cn, LEVEL_INFO, LEVELS_BY_STRICTNESS } from "@/lib/format";

function capabilityList(c: ProviderInfo["capabilities"]): string[] {
  if (!c) return [];
  if (Array.isArray(c)) return c;
  return Object.entries(c)
    .filter(([, v]) => v === true)
    .map(([k]) => k);
}

function ProviderCard({ p }: { p: ProviderInfo }) {
  const test = useTestProvider();
  const [model, setModel] = useState(p.default_model ?? p.models[0] ?? "");
  const [result, setResult] = useState<ProviderTestResult | null>(null);
  const run = async () => {
    setResult(null);
    try {
      setResult(await test.mutateAsync({ id: p.id, model: model || undefined }));
    } catch (e) {
      setResult({ ok: false, latency_ms: 0, model, message: e instanceof Error ? e.message : "Test failed" });
    }
  };
  return (
    <Card className="flex flex-col">
      <div className="flex items-start gap-3 p-5 pb-3">
        <div className={cn("flex h-10 w-10 shrink-0 items-center justify-center rounded-lg", p.local ? "bg-success-soft text-success" : "bg-info-soft text-info")}>
          {p.local ? <Cpu className="h-5 w-5" aria-hidden /> : <Cloud className="h-5 w-5" aria-hidden />}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <h3 className="font-semibold text-fg">{p.name}</h3>
            <Badge tone={p.local ? "success" : "info"}>{p.local ? "local" : "hosted"}</Badge>
          </div>
          <p className="font-mono text-xs text-fg-subtle">
            {p.id} · {p.kind}
            {p.host ? ` · ${p.host}` : ""}
          </p>
          {(p.trust_tier || p.min_level) && (
            <p className="mt-0.5 text-xs text-fg-muted">
              {p.trust_tier ? `Trust tier: ${p.trust_tier}` : ""}
              {p.trust_tier && p.min_level ? " · " : ""}
              {p.min_level ? `Privacy floor: ${p.min_level}` : ""}
            </p>
          )}
        </div>
        {p.configured ? (
          <Badge tone="success" icon={<CheckCircle2 className="h-3 w-3" />}>
            Configured
          </Badge>
        ) : (
          <Badge tone="warning" icon={<XCircle className="h-3 w-3" />}>
            Not configured
          </Badge>
        )}
      </div>
      <div className="flex-1 space-y-3 px-5">
        <div className="flex flex-wrap gap-1.5">
          {capabilityList(p.capabilities).map((c) => (
            <Badge key={c} tone="neutral">
              {c.replace(/_/g, " ")}
            </Badge>
          ))}
        </div>
        <Field label="Model">
          {(id) => (
            <Select id={id} value={model} onChange={(e) => setModel(e.target.value)}>
              {(p.models.length ? p.models : [p.default_model ?? ""]).map((m) => (
                <option key={m} value={m}>
                  {m || "Provider default"}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {result && (
          <p className={cn("flex items-start gap-2 text-sm", result.ok ? "text-success" : "text-danger")} role="status">
            {result.ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0" />}
            <span>
              {result.ok ? `OK in ${result.latency_ms} ms` : "Failed"} <span className="text-fg-muted">· {result.message}</span>
            </span>
          </p>
        )}
      </div>
      <div className="mt-4 flex items-center justify-between gap-3 border-t border-border px-5 py-3">
        <p className="text-xs text-fg-subtle">{p.local ? "Calls stay on this machine or network" : "Keys are held server-side only"}</p>
        <Button size="sm" variant="outline" icon={<PlugZap className="h-3.5 w-3.5" />} loading={test.isPending} onClick={run}>
          Test
        </Button>
      </div>
    </Card>
  );
}

function DefaultsForm() {
  const settings = useSettings();
  const providers = useProviders();
  const save = useSaveSettings();
  const toast = useToast();
  const { can } = useSession();
  const [form, setForm] = useState<Settings | null>(null);
  useEffect(() => {
    if (settings.data) setForm(settings.data);
  }, [settings.data]);
  if (settings.error) return <ErrorState error={settings.error} />;
  if (!form) return <Skeleton className="h-64" />;
  const prov = (providers.data ?? []).find((p) => p.id === form.default_provider);
  const disabled = !can("settings:write");
  return (
    <Card>
      <CardHeader icon={<SlidersHorizontal className="h-4 w-4" />} title="Scan defaults" description="Pre-filled in the new scan wizard" />
      <CardBody>
        <form
          className="grid gap-4 md:grid-cols-2"
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await save.mutateAsync({
                default_provider: form.default_provider,
                default_model: form.default_model,
                default_privacy_level: form.default_privacy_level,
                org_name: form.org_name,
              });
              toast.success("Settings saved");
            } catch (err) {
              toast.error("Settings were not saved", err instanceof Error ? err.message : undefined);
            }
          }}
        >
          <Field label="Default provider">
            {(id) => (
              <Select
                id={id}
                disabled={disabled}
                value={form.default_provider}
                onChange={(e) => {
                  const p = providers.data?.find((x) => x.id === e.target.value);
                  setForm({ ...form, default_provider: e.target.value, default_model: p?.default_model ?? null });
                }}
              >
                {(providers.data ?? []).map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Default model">
            {(id) => (
              <Select id={id} disabled={disabled} value={form.default_model ?? ""} onChange={(e) => setForm({ ...form, default_model: e.target.value })}>
                {(prov?.models.length ? prov.models : [form.default_model ?? ""]).map((m) => (
                  <option key={m} value={m}>
                    {m || "Provider default"}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Default privacy level" help={LEVEL_INFO[form.default_privacy_level]?.short}>
            {(id, d) => (
              <Select id={id} aria-describedby={d} disabled={disabled} value={form.default_privacy_level} onChange={(e) => setForm({ ...form, default_privacy_level: e.target.value as PrivacyLevel })}>
                {LEVELS_BY_STRICTNESS.map((l) => (
                  <option key={l} value={l}>
                    {l} · {LEVEL_INFO[l].name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Organisation name" help="Printed on report covers">
            {(id, d) => <Input id={id} aria-describedby={d} disabled={disabled} value={form.org_name ?? ""} onChange={(e) => setForm({ ...form, org_name: e.target.value })} />}
          </Field>
          <div className="md:col-span-2">
            <Button type="submit" icon={<Save className="h-4 w-4" />} loading={save.isPending} disabled={disabled}>
              Save defaults
            </Button>
          </div>
        </form>
      </CardBody>
    </Card>
  );
}

function PolicyEditor() {
  const policy = usePolicy();
  const save = useSavePolicy();
  const toast = useToast();
  const { can } = useSession();
  const [text, setText] = useState("");
  const [error, setError] = useState<{ message: string; line?: number; code?: string } | null>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (policy.data) setText(policy.data.toml ?? "");
  }, [policy.data]);
  if (policy.error) return <ErrorState error={policy.error} title="Policy unavailable" />;
  if (!policy.data) return <Skeleton className="h-96" />;
  const lines = text.split("\n").length;
  const dirty = text !== (policy.data.toml ?? "");
  const disabled = !can("settings:write");
  const submit = async () => {
    setError(null);
    try {
      await save.mutateAsync(text);
      toast.success("Policy saved", "New scans use the updated policy.");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Validation failed";
      const m = /line (\d+)/i.exec(msg);
      setError({ message: msg, line: m ? Number(m[1]) : undefined, code: e instanceof ApiError ? e.code : undefined });
    }
  };
  return (
    <Card>
      <CardHeader
        icon={<FileCode2 className="h-4 w-4" />}
        title="Privacy policy"
        description="TOML document deciding the privacy level per path and provider. Validated by the server on save."
        actions={
          <>
            {dirty && (
              <Button variant="ghost" size="sm" onClick={() => setText(policy.data!.toml ?? "")}>
                Revert
              </Button>
            )}
            <Button size="sm" icon={<Save className="h-3.5 w-3.5" />} loading={save.isPending} disabled={!dirty || disabled} onClick={submit}>
              Validate and save
            </Button>
          </>
        }
      />
      <CardBody className="space-y-3">
        {error && (
          <Callout tone="danger" title={`Policy rejected${error.code ? ` (${error.code})` : ""}`}>
            {error.message}
          </Callout>
        )}
        {disabled && <Callout tone="info">Only administrators can change the policy. You can read it here.</Callout>}
        <div className="flex max-h-[34rem] overflow-hidden rounded-lg border border-border bg-code-bg font-mono text-[12.5px] leading-[21px] focus-within:ring-2 focus-within:ring-primary/30">
          <div ref={gutterRef} aria-hidden className="select-none overflow-hidden py-2 pl-3 pr-3 text-right text-code-gutter">
            {Array.from({ length: lines }, (_, i) => (
              <div key={i} className={cn(error?.line === i + 1 && "rounded bg-danger-soft font-bold text-danger")}>
                {i + 1}
              </div>
            ))}
          </div>
          <textarea
            aria-label="Policy TOML"
            spellCheck={false}
            readOnly={disabled}
            value={text}
            onChange={(e) => setText(e.target.value)}
            onScroll={(e) => {
              if (gutterRef.current) gutterRef.current.scrollTop = e.currentTarget.scrollTop;
            }}
            rows={Math.min(Math.max(lines, 12), 26)}
            className="flex-1 resize-none overflow-auto whitespace-pre bg-transparent py-2 pr-3 text-fg outline-none"
          />
        </div>
      </CardBody>
    </Card>
  );
}

export default function SettingsPage() {
  const providers = useProviders();
  const [tab, setTab] = useState("providers");
  return (
    <>
      <PageHeader title="Providers & settings" description="Model providers available to this server, scan defaults and the privacy policy." />
      <Tabs
        label="Settings sections"
        value={tab}
        onChange={setTab}
        className="mb-6"
        tabs={[
          { id: "providers", label: "Model providers", icon: <Cloud className="h-4 w-4" /> },
          { id: "defaults", label: "Defaults", icon: <Settings2 className="h-4 w-4" /> },
          { id: "policy", label: "Privacy policy", icon: <FileCode2 className="h-4 w-4" /> },
        ]}
      />
      {tab === "providers" &&
        (providers.error ? (
          <ErrorState error={providers.error} onRetry={() => void providers.refetch()} />
        ) : (
          <>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {providers.isLoading
                ? Array.from({ length: 3 }, (_, i) => <Skeleton key={i} className="h-60" />)
                : providers.data!.map((p) => <ProviderCard key={p.id} p={p} />)}
            </div>
            <p className="mt-4 text-xs text-fg-subtle">
              A test sends a fixed, minimal probe through the single egress transport, so each test is itself recorded in the egress ledger. API keys are configured on
              the server (environment or key file) and are never returned to the browser.
            </p>
          </>
        ))}
      {tab === "defaults" && <DefaultsForm />}
      {tab === "policy" && <PolicyEditor />}
    </>
  );
}
