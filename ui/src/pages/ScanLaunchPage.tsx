import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useCurrentProject } from "@/app/project-context";
import { useProject, useProviders, useSettings, useStartScan, useTestProvider } from "@/api/queries";
import { PRIVACY_LEVELS, type PrivacyLevel, type ProviderTestResult } from "@/api/types";
import { atLeastAsStrict } from "@/lib/format";
import { LEVEL_NAME } from "@/lib/display";
import { egressSummary } from "@/lib/egress";
import { shortProviderName } from "@/lib/domain";
import { Button, Content, PageHeader, Skeleton, useToast } from "@/components/ui";
import { ENGINE_GROUPS, STAGES } from "@/lib/pipeline";

/** Scan launch: the live view's left form, unlocked (SCREENS.md §07). */
export default function ScanLaunchPage() {
  const { id } = useParams();
  const project = useProject(id);
  const { projects, setCurrentId } = useCurrentProject();
  const providers = useProviders();
  const settings = useSettings();
  const start = useStartScan();
  const test = useTestProvider();
  const toast = useToast();
  const navigate = useNavigate();

  const [level, setLevel] = useState<PrivacyLevel>("L3");
  const [providerId, setProviderId] = useState("");
  const [model, setModel] = useState("");
  const [dryRun, setDryRun] = useState(false);
  // Quick review for remote providers (serial gateways answer one request at a time); every
  // candidate for a local model. The rest keep their deterministic evidence and can be reviewed
  // one by one from the finding page.
  const [reviewLimit, setReviewLimit] = useState<number | null>(null);
  const [testResult, setTestResult] = useState<ProviderTestResult | null>(null);
  const [ready, setReady] = useState(false);
  const list = useMemo(() => providers.data ?? [], [providers.data]);
  const provider = list.find((p) => p.id === providerId);

  useEffect(() => {
    if (ready || !list.length || settings.isLoading) return;
    const s = settings.data;
    const def = list.find((p) => p.id === s?.default_provider) ?? list.find((p) => p.configured) ?? list[0]!;
    setProviderId(def.id);
    setModel(s?.default_provider === def.id && s?.default_model ? s.default_model : def.default_model ?? def.models[0] ?? "");
    if (s?.default_privacy_level) setLevel(s.default_privacy_level);
    setReady(true);
  }, [list, settings.data, settings.isLoading, ready]);

  useEffect(() => {
    if (id) setCurrentId(id);
  }, [id, setCurrentId]);

  const floorBlocked = !!provider?.min_level && level !== "L0" && !atLeastAsStrict(level, provider.min_level);
  const summary = egressSummary(level, provider, !dryRun);
  const limit = reviewLimit ?? (provider && !provider.local ? 8 : 0);

  const submit = async () => {
    if (!id) return;
    try {
      const scan = await start.mutateAsync({
        projectId: id,
        body: {
          privacy_level: level,
          provider: level === "L0" ? "none" : providerId,
          model: level === "L0" ? undefined : model || undefined,
          send: level === "L0" ? false : !dryRun,
          ...(level === "L0" ? {} : { review_limit: limit }),
        },
      });
      toast.success("Scan started", "Opening the live view.");
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      toast.error("Could not start the scan", e instanceof Error ? e.message : undefined);
    }
  };

  const p = project.data;
  return (
    <Content>
      <PageHeader crumbs={[{ label: p?.name ?? "Project", to: "/" }, { label: "Scans", to: "/scans" }, { label: "New scan" }]} title="New scan" />
      <section className="g g-side-l">
        <form
          className="card stack s16"
          aria-label="Scan configuration"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <div className="row between">
            <h2>Launch settings</h2>
          </div>
          <div className="fld">
            <label htmlFor="sc-t">Target</label>
            <select id="sc-t" className="inp" value={id} onChange={(e) => navigate(`/projects/${e.target.value}/scan`)}>
              {projects.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.name}
                </option>
              ))}
            </select>
          </div>
          <div className="fld">
            <span className="lbl">Mode</span>
            <div className="seg">
              <button className="on" type="button">
                Branch
              </button>
              <button type="button" disabled title="Diff scans need server support for a base ref.">
                Diff
              </button>
            </div>
          </div>
          <div className="fld">
            <label htmlFor="sc-b">Source</label>
            <input
              id="sc-b"
              className="inp mono"
              readOnly
              value={p ? p.source.ref ?? (p.source as { upload_name?: string }).upload_name ?? p.source.path ?? p.source.url ?? p.source.type : ""}
            />
          </div>
          <div className="fld">
            <label htmlFor="sc-l">Privacy level</label>
            <select id="sc-l" className="inp" value={level} onChange={(e) => setLevel(e.target.value as PrivacyLevel)}>
              {PRIVACY_LEVELS.map((l) => (
                <option key={l} value={l}>
                  {l} · {LEVEL_NAME[l]}
                  {l === "L3" ? " (default)" : ""}
                </option>
              ))}
            </select>
          </div>
          <div className="g" style={{ gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 10 }}>
            <div className="fld">
              <label htmlFor="sc-p">Provider</label>
              <select
                id="sc-p"
                className="inp"
                value={providerId}
                disabled={level === "L0"}
                onChange={(e) => {
                  const x = list.find((y) => y.id === e.target.value);
                  setProviderId(e.target.value);
                  setModel(x?.default_model ?? x?.models[0] ?? "");
                  setTestResult(null);
                }}
              >
                {list.map((x) => (
                  <option key={x.id} value={x.id} disabled={!x.configured} title={x.name}>
                    {shortProviderName(x.name)}
                    {x.configured ? "" : " · no key"}
                  </option>
                ))}
              </select>
            </div>
            <div className="fld">
              <label htmlFor="sc-m">Model</label>
              <select id="sc-m" className="inp" value={model} disabled={level === "L0" || !provider?.models.length} onChange={(e) => setModel(e.target.value)}>
                {!provider?.models.length && <option value="">default</option>}
                {provider?.models.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="fld">
            <label htmlFor="sc-r">Model review</label>
            <select id="sc-r" className="inp" value={limit} disabled={level === "L0"} onChange={(e) => setReviewLimit(Number(e.target.value))}>
              <option value={3}>Live demo · the 3 most severe candidates</option>
              <option value={8}>Quick · the 8 most severe candidates</option>
              <option value={20}>The 20 most severe candidates</option>
              <option value={0}>Every candidate</option>
            </select>
            <span className="xs faint">
              {level === "L0"
                ? "No model at L0."
                : "Candidates not sent keep their engine evidence; review any of them later from the finding page."}
            </span>
          </div>
          {floorBlocked && (
            <div className="banner warn sm">
              {provider?.name} needs {provider?.min_level} or stricter. Choose a stricter level or another provider.
            </div>
          )}
          <div className="stack s6">
            <span className="lbl">Engines</span>
            {ENGINE_GROUPS.map((g) => (
              <label key={g} className="swrow" title="Every installed engine runs on each scan.">
                <input type="checkbox" className="chk" checked readOnly disabled /> {g}
              </label>
            ))}
          </div>
          <div className="hr" />
          <label className="swrow">
            <input type="checkbox" className="sw" checked={dryRun || level === "L0"} disabled={level === "L0"} onChange={(e) => setDryRun(e.target.checked)} />{" "}
            No-send (dry run)
          </label>
          <div className="row">
            <Button variant="primary" type="submit" loading={start.isPending} disabled={!ready || floorBlocked || !id}>
              Start scan
            </Button>
            {level !== "L0" && provider && (
              <Button
                size="sm"
                variant="ghost"
                loading={test.isPending}
                onClick={async () => {
                  setTestResult(null);
                  try {
                    setTestResult(await test.mutateAsync({ id: providerId, model: model || undefined }));
                  } catch (err) {
                    setTestResult({ ok: false, latency_ms: 0, model, message: err instanceof Error ? err.message : "Test failed" });
                  }
                }}
              >
                Test provider
              </Button>
            )}
          </div>
          {testResult && (
            <span className={`xs ${testResult.ok ? "okc" : "badc"}`}>
              {testResult.ok ? `Reachable · ${testResult.latency_ms} ms` : `Not reachable · ${testResult.message}`}
            </span>
          )}
        </form>

        <div className="stack s16">
          <div className="card stack s16">
            <div className="row between">
              <h2>Pipeline</h2>
              <span className="sub">Not started</span>
            </div>
            <div className="bar">
              <i style={{ width: "0%" }} />
            </div>
            <div className="pipe-wrap" tabIndex={0} role="region" aria-label="Pipeline stages">
              <div className="pipe">
                {STAGES.map((s) => (
                  <div key={s.n} className={`stage wait${s.guard ? " guardz" : ""}`}>
                    <span className="sn">{s.n}</span>
                    <span className="st-t">{s.title}</span>
                    <span className={`loc${s.n === "05" ? " rem" : ""}`}>{s.n === "05" ? (level === "L0" ? "Off at L0" : provider?.local ? "Local model" : "Remote or local") : s.n === "09" ? "Optional" : "Local"}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="card stack">
            <h2>What leaves at {level}</h2>
            {!ready ? (
              <Skeleton />
            ) : (
              <>
                <p className="sm">
                  <b>{summary.title}.</b> <span className="muted">{summary.body}</span>
                </p>
                {summary.remains && <p className="xs faint">{summary.remains}</p>}
              </>
            )}
            <div className="note">
              <b>What this does not cover.</b>
              <ul>
                <li>At L2 and L3, control flow, literal shapes and public API names are still visible to the model.</li>
                <li>The leak check is verbatim only.</li>
              </ul>
            </div>
          </div>
        </div>
      </section>
    </Content>
  );
}
