import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { useCurrentProject } from "@/app/project-context";
import { useShell } from "@/app/shell-context";
import { qk, useCreateProject, useOptional, usePolicy, useProject, useProviders, useSettings, useStartScan } from "@/api/queries";
import { endpoints, uploadArchive } from "@/api/endpoints";
import type { PrivacyLevel, Project, ProviderInfo, SourceType } from "@/api/types";
import { atLeastAsStrict } from "@/lib/format";
import { fmtInt, LEVEL_BARS, LEVEL_NAME } from "@/lib/display";
import { ENGINE_GROUPS } from "@/lib/pipeline";
import { policyDoc } from "@/lib/policy";
import { validateGitUrl } from "@/lib/validate";
import { Button, Content, ErrorBanner, Icon, useToast } from "@/components/ui";

const STEPS = ["Connect repository", "Detect inventory", "Privacy level", "Provider", "Consent and launch"];
const MAX_UPLOAD_MB = 200;

const LEVEL_CARDS: { l: PrivacyLevel; title: string; sub: string }[] = [
  { l: "L0", title: "Local only", sub: "Nothing leaves. Local model or deterministic engines." },
  { l: "L1", title: "Redacted", sub: "Code with secrets and PII redacted." },
  { l: "L2", title: "Pseudonymised", sub: "L1, plus identifiers, strings and comments renamed." },
  { l: "L3", title: "Minimal slice", sub: "L2, but only the vulnerability-relevant slice." },
  { l: "L4", title: "Facts only", sub: "No code. Abstract data-flow facts and questions." },
];

const LEAVES: Record<PrivacyLevel, [string, string]> = {
  L0: ["Nothing. No network connection is opened.", "All code, secrets, identifiers and comments.\nVault and ledger."],
  L1: ["Source files with secrets and PII replaced by typed placeholders.\nReal identifiers, strings and comments.", "Secret values and PII.\nVault and ledger."],
  L2: ["Source files with identifiers, strings and comments pseudonymised.\nControl flow and literal shapes.", "Secrets, PII, real names and business terms.\nVault mapping pseudonyms back."],
  L3: ["Only the lines on the source-to-sink slice, pseudonymised.\nControl flow and public API names in that slice.", "Whole files, secrets, PII, real names and business terms.\nEverything outside the slice."],
  L4: ["Abstract data-flow facts and questions. No code.", "All source code, names and literals.\nVault and ledger."],
};

const FULL = new Set(["python", "javascript", "typescript"]);

function providerChip(p: ProviderInfo, def?: string): string {
  if (p.id === def) return "Default";
  if (p.kind === "mock" || p.kind === "replay") return "Offline";
  if (p.local) return "Self-hosted";
  return "BYO key";
}

function providerSub(p: ProviderInfo): string {
  if (p.kind === "mock") return "Offline · no key. Deterministic verdicts for demos and CI.";
  if (p.kind === "replay") return "Replays recorded verdicts. No key.";
  if (p.key_refs?.length) return `Key reference: ${p.key_refs.join(", ")}${p.configured ? "" : " · missing"}`;
  if (p.local) return `${p.models.slice(0, 4).join(", ") || "Models"} on your hardware.`;
  return p.host ?? p.kind;
}

/** Set up a project (SCREENS.md §05): a five-step wizard ending in a scan. */
export default function OnboardingPage() {
  const [params, setParams] = useSearchParams();
  const step = Math.min(5, Math.max(1, Number(params.get("step") ?? 1) || 1));
  const setStep = (n: number) => {
    const p = new URLSearchParams(params);
    p.set("step", String(n));
    setParams(p, { replace: true });
  };
  const navigate = useNavigate();
  const toast = useToast();
  const qc = useQueryClient();
  const { setCurrentId } = useCurrentProject();
  const settings = useSettings().data;
  const providersQ = useProviders();
  const policy = usePolicy().data;
  const create = useCreateProject();
  const start = useStartScan();

  const [type, setType] = useState<SourceType>("path");
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [url, setUrl] = useState("");
  const [ref, setRef] = useState("main");
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [projectId, setProjectId] = useState<string | null>(params.get("project"));
  const project = useProject(projectId ?? undefined).data;
  const [level, setLevel] = useState<PrivacyLevel>("L3");
  const [providerId, setProviderId] = useState("");
  const [consent, setConsent] = useState(false);
  const [dryRun, setDryRun] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (settings?.default_privacy_level) setLevel(settings.default_privacy_level);
    if (settings?.default_provider) setProviderId((p) => p || settings.default_provider);
  }, [settings]);
  useShell({ projectPill: project?.name ?? "New project", projectIcon: true, levelPill: `${level} · ${LEVEL_NAME[level]}` });

  const providers = providersQ.data ?? [];
  const provider = providers.find((p) => p.id === providerId);
  const belowFloor = !!provider?.min_level && level !== "L0" && !atLeastAsStrict(level, provider.min_level);
  const doc = policyDoc(policy);

  /** Step 1 → 2 creates the project (and uploads the archive). */
  const connect = async () => {
    setErr(null);
    const finalName = name.trim();
    if (!finalName) return setErr("Give the project a name.");
    if (type === "git") {
      const g = validateGitUrl(url);
      if (g) return setErr(g);
    }
    if (type === "path" && !path.trim()) return setErr("Enter the folder's absolute path on the server.");
    if (type === "upload") {
      if (!file) return setErr("Choose an archive to upload.");
      if (file.size > MAX_UPLOAD_MB * 1024 * 1024) return setErr(`The limit is ${MAX_UPLOAD_MB} MB.`);
      if (!/\.(zip|tar|tar\.gz|tgz)$/i.test(file.name)) return setErr("Use a .zip, .tar or .tar.gz archive.");
    }
    try {
      const p: Project = await create.mutateAsync({
        name: finalName,
        source: type === "git" ? { type, url: url.trim(), ref: ref.trim() || undefined } : type === "path" ? { type, path: path.trim() } : { type },
      });
      if (type === "upload" && file) {
        setProgress(0);
        await uploadArchive(p.id, file, setProgress);
        setProgress(null);
        void qc.invalidateQueries({ queryKey: qk.project(p.id) });
      }
      setProjectId(p.id);
      setCurrentId(p.id);
      const n = new URLSearchParams(params);
      n.set("project", p.id);
      n.set("step", "2");
      setParams(n, { replace: true });
    } catch (e) {
      setProgress(null);
      setErr(e instanceof Error ? e.message : "The project could not be created.");
    }
  };

  const launch = async () => {
    if (!projectId) return;
    try {
      const scan = await start.mutateAsync({
        projectId,
        body: {
          privacy_level: level,
          provider: level === "L0" ? "none" : providerId,
          model: level === "L0" ? undefined : provider?.default_model ?? undefined,
          send: level === "L0" ? false : !dryRun,
        },
      });
      toast.success("Scan started");
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      toast.error("Could not start the scan", e instanceof Error ? e.message : undefined);
    }
  };

  const canLaunch = !!projectId && (consent || level === "L0" || dryRun) && !belowFloor && (level === "L0" || !!provider?.configured);
  const next = () => {
    if (step === 1 && !projectId) return void connect();
    setStep(step + 1);
  };

  const langs = useMemo(() => project?.languages ?? [], [project]);
  const inventory = useOptional(`inventory-${projectId}`, () => endpoints.inventory(projectId!), !!projectId).data;
  const engines = useOptional("engines", endpoints.engines).data;

  return (
    <Content maxWidth={1180}>
      <div className="ph">
        <div>
          <div className="crumb">
            <Link to="/projects">Projects</Link>
            <span>/</span>
            <span>New project</span>
          </div>
          <h1>Set up a project</h1>
        </div>
        <span className="sub">Step {step} of 5</span>
      </div>
      <nav className="steps" aria-label="Setup steps">
        {STEPS.map((s, i) => (
          <button
            key={s}
            type="button"
            className={`step ${i + 1 < step ? "done" : i + 1 === step ? "on" : ""}`}
            aria-current={i + 1 === step ? "step" : undefined}
            disabled={i === 1 && !projectId}
            onClick={() => setStep(i + 1)}
          >
            <span className="sc">{i + 1}</span>
            {s}
          </button>
        ))}
      </nav>

      {step === 1 && (
        <section className="card stack s16" style={{ padding: 24 }}>
          <div>
            <h2 style={{ fontSize: 16 }}>Connect a repository</h2>
            <p className="sub">The code is read in place on the server. Nothing is sent anywhere until you start a scan.</p>
          </div>
          {projectId && project ? (
            <div className="banner sm">
              Project <b>{project.name}</b> is connected. Continue to the inventory.
            </div>
          ) : (
            <>
              <div className="g g-4" role="radiogroup" aria-label="Source">
                {(
                  [
                    ["path", "Local path", "A folder on this machine"],
                    ["git", "Git URL", "SSH or HTTPS, cloned locally"],
                    ["upload", "Archive upload", ".zip or .tar.gz"],
                    ["github", "GitHub", "Via the GitHub App · not configured"],
                  ] as const
                ).map(([t, title, sub]) => (
                  <button
                    key={t}
                    type="button"
                    role="radio"
                    aria-checked={type === t}
                    disabled={t === "github"}
                    className={`lvlcard${type === t ? " on" : ""}`}
                    style={t === "github" ? { opacity: 0.55, cursor: "not-allowed" } : undefined}
                    onClick={() => t !== "github" && setType(t as SourceType)}
                  >
                    <b>{title}</b>
                    <span className="sub">{sub}</span>
                  </button>
                ))}
              </div>
              <div className="g g-2">
                {type === "path" && (
                  <div className="fld">
                    <label htmlFor="ob-path">Folder</label>
                    <input id="ob-path" className="inp mono" value={path} placeholder="/srv/repos/kavachbank-core" onChange={(e) => setPath(e.target.value)} />
                  </div>
                )}
                {type === "git" && (
                  <div className="fld">
                    <label htmlFor="ob-url">Repository URL</label>
                    <input id="ob-url" className="inp mono" value={url} placeholder="https://github.com/org/repo.git" onChange={(e) => setUrl(e.target.value)} />
                  </div>
                )}
                {type === "upload" && (
                  <div className="fld">
                    <span className="lbl">Archive</span>
                    <div className="dropzone">
                      <span className="sm muted">{file ? file.name : "No file chosen"}</span>
                      <button className="btn sm" type="button" onClick={() => fileRef.current?.click()}>
                        {file ? "Replace" : "Choose file"}
                      </button>
                      <input ref={fileRef} type="file" accept=".zip,.tar,.tgz,.gz" hidden onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
                    </div>
                  </div>
                )}
                <div className="fld">
                  <label htmlFor="ob-name">Project name</label>
                  <input id="ob-name" className="inp" value={name} placeholder="kavachbank-core" onChange={(e) => setName(e.target.value)} />
                </div>
              </div>
              {type === "git" && (
                <div className="fld">
                  <label htmlFor="ob-br">Branch</label>
                  <input id="ob-br" className="inp mono" value={ref} onChange={(e) => setRef(e.target.value)} />
                </div>
              )}
              {progress !== null && (
                <div className="bar" aria-label="Upload progress">
                  <i style={{ width: `${Math.round(progress * 100)}%` }} />
                </div>
              )}
              {err && <ErrorBanner what={err} />}
            </>
          )}
        </section>
      )}

      {step === 2 && (
        <section className="g g-side">
          <div className="card stack">
            <div className="card-h" style={{ margin: 0 }}>
              <h2 style={{ fontSize: 16 }}>Languages and inventory</h2>
              <span className="sub">
                {inventory?.totals?.files
                  ? `${fmtInt(inventory.totals.files)} files · ${fmtInt(inventory.totals.lines)} lines`
                  : project?.files
                    ? `${project.files} files`
                    : "Counted on the first scan"}
              </span>
            </div>
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Language</th>
                    <th className="num">Files</th>
                    <th className="num">Lines</th>
                    <th>Share</th>
                    <th>Support</th>
                  </tr>
                </thead>
                <tbody>
                  {(inventory?.languages ?? langs.map((l) => ({ language: l, files: 0, lines: 0, support: FULL.has(l) ? "full" : "partial" }))).map((l) => {
                    const total = inventory?.totals?.lines || 1;
                    return (
                      <tr key={l.language}>
                        <td>{l.language === "unknown" ? "Other" : l.language.charAt(0).toUpperCase() + l.language.slice(1)}</td>
                        <td className="num mono">{l.files ? fmtInt(l.files) : "—"}</td>
                        <td className="num mono">{l.lines ? fmtInt(l.lines) : "—"}</td>
                        <td style={{ width: 200 }}>
                          <div className="bar">
                            <i style={{ width: `${(l.lines / total) * 100}%` }} />
                          </div>
                        </td>
                        <td>{l.support === "full" ? <span className="chip fixed">Full</span> : <span className="chip">{l.support === "basic" ? "Secrets only" : "Emerging"}</span>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {!inventory?.languages?.length && langs.length === 0 && (
                <div className="empty">
                  <b style={{ color: "var(--text)" }}>Inventory appears after the first scan</b>
                  <span className="sm">Languages, files and lines are counted when the code is ingested.</span>
                </div>
              )}
            </div>
          </div>
          <div className="card stack">
            <h2 style={{ fontSize: 16 }}>Engines available</h2>
            {(engines ?? []).length
              ? engines!.map((e) => (
                  <label key={e.id} className="swrow" title={e.summary}>
                    <input type="checkbox" className="chk" checked={e.installed} readOnly aria-readonly="true" onClick={(ev) => ev.preventDefault()} />{" "}
                    <span>
                      {e.name}
                      {!e.installed && <span className="xs faint"> · {e.status.replace(/_/g, " ")}</span>}
                    </span>
                  </label>
                ))
              : ENGINE_GROUPS.map((g) => (
                  <label key={g} className="swrow">
                    <input type="checkbox" className="chk" checked readOnly aria-readonly="true" onClick={(e) => e.preventDefault()} /> {g}
                  </label>
                ))}
            <p className="xs faint">Every installed engine runs on each scan.</p>
          </div>
        </section>
      )}

      {step === 3 && (
        <section className="stack s16">
          <div className="g" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))" }} role="radiogroup" aria-label="Privacy level">
            {LEVEL_CARDS.map((c) => (
              <button key={c.l} type="button" role="radio" aria-checked={level === c.l} className={`lvlcard${level === c.l ? " on" : ""}`} onClick={() => setLevel(c.l)}>
                <span className="lvl">
                  {c.l}
                  {c.l === "L3" ? " · default" : ""}
                  <span className="meter">
                    {[0, 1, 2, 3, 4].map((i) => (
                      <i key={i} className={i < LEVEL_BARS[c.l] ? "f" : undefined} />
                    ))}
                  </span>
                </span>
                <b>{c.title}</b>
                <span className="sub">{c.sub}</span>
              </button>
            ))}
          </div>
          <div className="g g-2">
            <div className="card stack" style={{ borderColor: "var(--high)" }}>
              <div className="row">
                <Icon name="arrow-right" style={{ color: "var(--high)" }} />
                <h3>What leaves at {level}</h3>
              </div>
              <p className="sm" style={{ whiteSpace: "pre-line" }}>
                {LEAVES[level][0]}
              </p>
            </div>
            <div className="card stack" style={{ borderColor: "var(--ok)" }}>
              <div className="row">
                <Icon name="lock" className="okc" />
                <h3>What stays local</h3>
              </div>
              <p className="sm" style={{ whiteSpace: "pre-line" }}>
                {LEAVES[level][1]}
              </p>
            </div>
          </div>
          <div className="note">
            <b>What this does not cover.</b> At L2 and L3, control flow, literal shapes and public API names are still visible to the model. The
            leak check is verbatim only.
          </div>
        </section>
      )}

      {step === 4 && (
        <section className="g g-3" role="radiogroup" aria-label="Provider">
          {providers.map((p) => (
            <button
              key={p.id}
              type="button"
              role="radio"
              aria-checked={providerId === p.id}
              className={`lvlcard${providerId === p.id ? " on" : ""}`}
              onClick={() => setProviderId(p.id)}
            >
              <div className="row between">
                <span className="provlogo">{p.name.replace(/[^A-Za-z]/g, "").charAt(0).toUpperCase()}</span>
                <span className={providerChip(p, settings?.default_provider) === "Default" ? "chip fixed" : "chip"}>{providerChip(p, settings?.default_provider)}</span>
              </div>
              <b>{p.name}</b>
              <span className="sub">{providerSub(p)}</span>
            </button>
          ))}
          {belowFloor && (
            <div className="banner warn sm">
              {provider?.name} needs {provider?.min_level} or stricter; go back and choose a stricter level.
            </div>
          )}
        </section>
      )}

      {step === 5 && (
        <section className="g g-side">
          <div className="card stack s16">
            <h2 style={{ fontSize: 16 }}>Review and consent</h2>
            <dl className="dl">
              <dt>Repository</dt>
              <dd className="mono">
                {project?.name ?? "—"} · {project?.source.ref ?? project?.source.type}
              </dd>
              <dt>Privacy level</dt>
              <dd>
                <span className="lvl">
                  {level} · {LEVEL_NAME[level]}
                </span>
              </dd>
              <dt>Provider</dt>
              <dd>{level === "L0" ? "None · local engines only" : `${provider?.name ?? "—"}${provider?.local ? " · no key" : ""}`}</dd>
              <dt>Engines</dt>
              <dd>Rules, external engines when installed, Secrets, SCA, IaC, Taint</dd>
              <dt>Policy</dt>
              <dd>
                {doc.path.length
                  ? `${doc.path.length} path rule${doc.path.length === 1 ? "" : "s"} · ${doc.path
                      .filter((r) => r.never_send)
                      .map((r) => r.pattern)
                      .join(", ") || "no never-send paths"}${doc.path.some((r) => r.never_send) ? " never-send" : ""}`
                  : "No path rules"}
              </dd>
            </dl>
            <label className="swrow" style={{ alignItems: "flex-start" }}>
              <input type="checkbox" className="chk" checked={consent} onChange={(e) => setConsent(e.target.checked)} style={{ marginTop: 3 }} /> I understand that
              sanitised slices may be sent to the selected provider and that every payload is recorded in the egress ledger.
            </label>
            <label className="swrow">
              <input type="checkbox" className="sw" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} /> No-send (dry run): build payloads, send
              nothing
            </label>
            {provider && !provider.configured && level !== "L0" && <div className="banner warn sm">{provider.name} has no key configured. Choose another provider.</div>}
          </div>
          <div className="note">
            <b>Before you launch.</b>
            <ul>
              <li>Secrets are redacted before anything is sliced.</li>
              <li>If any privacy step fails, the request is aborted (I4).</li>
              <li>You can inspect every payload afterwards.</li>
            </ul>
          </div>
        </section>
      )}

      <div className="row between">
        <Button variant="ghost" disabled={step === 1} onClick={() => setStep(step - 1)}>
          Back
        </Button>
        <div className="row">
          <Link className="btn" to={projectId ? `/projects/${projectId}` : "/projects"}>
            Save and exit
          </Link>
          {step < 5 ? (
            <Button variant="primary" onClick={next} loading={create.isPending || progress !== null}>
              Continue
            </Button>
          ) : (
            <Button variant="primary" onClick={() => void launch()} disabled={!canLaunch} loading={start.isPending}>
              Launch scan
            </Button>
          )}
        </div>
      </div>
    </Content>
  );
}
