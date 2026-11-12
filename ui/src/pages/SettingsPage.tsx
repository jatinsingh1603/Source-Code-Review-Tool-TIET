import { useEffect, useState } from "react";
import { useSession } from "@/app/session";
import { useProviders, useSaveSettings, useSettings, useUpdateUser } from "@/api/queries";
import { PRIVACY_LEVELS, type PrivacyLevel, type Settings } from "@/api/types";
import { roleLabel } from "@/lib/permissions";
import { LEVEL_NAME } from "@/lib/display";
import { readPrefs, writePrefs, type Prefs } from "@/lib/prefs";
import { Avatar, Button, Content, Segmented, Skeleton, useToast } from "@/components/ui";

const SECTIONS: [string, string][] = [
  ["profile", "Profile"],
  ["appearance", "Appearance"],
  ["notifications", "Notifications"],
  ["tokens", "CLI and API tokens"],
  ["language", "Language and region"],
];

const EVENTS: [string, string][] = [
  ["crit", "New Critical or High finding"],
  ["assigned", "Finding assigned to me"],
  ["privacy", "Privacy step failed or payload blocked"],
  ["budget", "Exposure budget above 80%"],
  ["scan", "Scan completed"],
];

const NOTIF_KEY = "ck-notifications";
type Notif = Record<string, { app: boolean; email: boolean }>;
function readNotif(): Notif {
  try {
    return JSON.parse(localStorage.getItem(NOTIF_KEY) ?? "{}") as Notif;
  } catch {
    return {};
  }
}

/** Settings (SCREENS.md §19): personal sections as anchors, plus organisation defaults for admins. */
export default function SettingsPage() {
  const { user, can } = useSession();
  const toast = useToast();
  const update = useUpdateUser();
  const [active, setActive] = useState("profile");
  const [prefs, setPrefs] = useState<Prefs>(readPrefs);
  const [name, setName] = useState(user?.display_name ?? user?.full_name ?? "");
  const [notif, setNotif] = useState<Notif>(readNotif);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    const els = SECTIONS.map(([id]) => document.getElementById(id)).filter((x): x is HTMLElement => !!x);
    const obs = new IntersectionObserver(
      (entries) => {
        const vis = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (vis) setActive(vis.target.id);
      },
      { rootMargin: "-10% 0px -60% 0px" },
    );
    els.forEach((e) => obs.observe(e));
    return () => obs.disconnect();
  }, []);

  const save = async () => {
    writePrefs(prefs);
    try {
      localStorage.setItem(NOTIF_KEY, JSON.stringify(notif));
    } catch {
      /* storage unavailable */
    }
    if (user && can("users:admin") && name.trim() && name !== (user.display_name ?? "")) {
      try {
        await update.mutateAsync({ id: user.id, body: { display_name: name.trim() } });
      } catch (e) {
        toast.error("Name not saved", e instanceof Error ? e.message : undefined);
        return;
      }
    }
    setDirty(false);
    toast.success("Settings saved", "Display preferences are kept in this browser.");
  };

  const set = (p: Partial<Prefs>) => {
    setPrefs((x) => ({ ...x, ...p }));
    setDirty(true);
  };
  const ev = (k: string) => notif[k] ?? { app: true, email: k !== "budget" && k !== "scan" };

  return (
    <Content maxWidth={1100}>
      <div className="ph">
        <div>
          <h1>Settings</h1>
        </div>
        <Button variant="primary" onClick={() => void save()} loading={update.isPending}>
          Save changes{dirty ? " ·" : ""}
        </Button>
      </div>
      <section className="g g-side-l">
        <nav className="subnav-list" aria-label="Settings sections">
          {SECTIONS.map(([id, label]) => (
            <a key={id} className={`btn ghost${active === id ? " on" : ""}`} href={`#${id}`} aria-current={active === id ? "true" : undefined} onClick={() => setActive(id)}>
              {label}
            </a>
          ))}
        </nav>
        <div className="stack s16">
          <div className="card stack s16" id="profile">
            <h2>Profile</h2>
            <div className="row" style={{ gap: 14 }}>
              <Avatar name={name || user?.username || "?"} size="lg" />
              <button className="btn sm" type="button" disabled title="Profile photos are not stored on this server.">
                Change photo
              </button>
            </div>
            <div className="g g-2">
              <div className="fld">
                <label htmlFor="st-n">Name</label>
                <input
                  id="st-n"
                  className="inp"
                  value={name}
                  disabled={!can("users:admin")}
                  title={can("users:admin") ? undefined : "Ask an administrator to change your name."}
                  onChange={(e) => {
                    setName(e.target.value);
                    setDirty(true);
                  }}
                />
              </div>
              <div className="fld">
                <label htmlFor="st-e">Email</label>
                <input id="st-e" className="inp" value={user?.email || user?.username || ""} disabled />
              </div>
            </div>
            <div className="g g-2">
              <div className="fld">
                <label htmlFor="st-r">Role</label>
                <input id="st-r" className="inp" value={user ? `${roleLabel(user.role)} · set by admin` : ""} disabled />
              </div>
              <div className="fld">
                <label htmlFor="st-u">Username</label>
                <input id="st-u" className="inp mono" value={user?.username ?? ""} disabled />
              </div>
            </div>
          </div>

          <div className="card stack" id="appearance">
            <h2>Appearance</h2>
            <div className="fld">
              <span className="lbl">Density</span>
              <Segmented
                label="Density"
                value={prefs.density}
                onChange={(v) => set({ density: v })}
                options={[
                  { value: "comfortable", label: "Comfortable" },
                  { value: "compact", label: "Compact" },
                ]}
              />
            </div>
            <label className="swrow">
              <input type="checkbox" className="sw" checked={prefs.severityShapes} onChange={(e) => set({ severityShapes: e.target.checked })} /> Show
              severity shapes as well as colour
            </label>
            <label className="swrow">
              <input type="checkbox" className="sw" checked={prefs.reduceMotion} onChange={(e) => set({ reduceMotion: e.target.checked })} /> Reduce
              motion
            </label>
          </div>

          <div className="card" id="notifications">
            <h2 style={{ marginBottom: 8 }}>Notifications</h2>
            <div className="tbl-wrap" style={{ border: 0 }}>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Event</th>
                    <th>In app</th>
                    <th>Email</th>
                  </tr>
                </thead>
                <tbody>
                  {EVENTS.map(([k, label]) => (
                    <tr key={k}>
                      <td className="sm">{label}</td>
                      {(["app", "email"] as const).map((ch) => (
                        <td key={ch}>
                          <input
                            type="checkbox"
                            className="chk"
                            aria-label={`${label}: ${ch === "app" ? "in app" : "email"}`}
                            checked={ev(k)[ch]}
                            onChange={(e) => {
                              setNotif((n) => ({ ...n, [k]: { ...ev(k), [ch]: e.target.checked } }));
                              setDirty(true);
                            }}
                          />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="xs faint" style={{ marginTop: 8 }}>
              Kept in this browser. Email delivery needs a mail relay configured on the server.
            </p>
          </div>

          <div className="card stack" id="tokens">
            <div className="row between">
              <h2>CLI and API tokens</h2>
              <button className="btn sm" type="button" disabled title="Personal tokens need server support; sign in from the CLI with your account.">
                + New personal token
              </button>
            </div>
            <p className="sm muted">
              The command line runs scans on this machine without a token. To use the REST API from a script, sign in with{" "}
              <span className="mono">POST /api/v1/auth/login</span> and send the token as a bearer header.
            </p>
            <div className="code cmd" style={{ padding: "10px 14px", fontSize: 12, whiteSpace: "pre-wrap" }}>
              {"codekavach scan . --privacy-level L3 --provider mock\ncodekavach privacy ledger --help"}
            </div>
          </div>

          <div className="card stack" id="language">
            <h2>Language and region</h2>
            <div className="g g-2">
              <div className="fld">
                <label htmlFor="st-l">Language</label>
                <select id="st-l" className="inp" value={prefs.language} onChange={(e) => set({ language: e.target.value as Prefs["language"] })}>
                  <option value="en-GB">English (United Kingdom)</option>
                  <option value="hi" disabled>
                    हिन्दी (coming)
                  </option>
                </select>
              </div>
              <div className="fld">
                <label htmlFor="st-z">Time zone</label>
                <select id="st-z" className="inp" value={prefs.timeZone} onChange={(e) => set({ timeZone: e.target.value })}>
                  <option value="Asia/Kolkata">Asia/Kolkata · IST</option>
                  <option value="UTC">UTC</option>
                  <option value="Australia/Sydney">Australia/Sydney</option>
                  <option value="Europe/London">Europe/London</option>
                </select>
              </div>
            </div>
            <div className="fld">
              <label htmlFor="st-d">Date format</label>
              <select id="st-d" className="inp" value={prefs.dateFormat} onChange={(e) => set({ dateFormat: e.target.value as Prefs["dateFormat"] })}>
                <option value="long">12 Nov 2026</option>
                <option value="iso">2026-11-12</option>
              </select>
            </div>
          </div>

          {can("settings:write") && <OrgDefaults />}
        </div>
      </section>
    </Content>
  );
}

/** Organisation defaults, shown to admins: pre-filled in every new scan. */
function OrgDefaults() {
  const settings = useSettings();
  const providers = useProviders();
  const save = useSaveSettings();
  const toast = useToast();
  const [form, setForm] = useState<Settings | null>(null);
  useEffect(() => {
    if (settings.data) setForm(settings.data);
  }, [settings.data]);
  const prov = (providers.data ?? []).find((p) => p.id === form?.default_provider);
  return (
    <form
      className="card stack"
      id="organisation"
      onSubmit={async (e) => {
        e.preventDefault();
        if (!form) return;
        try {
          await save.mutateAsync({
            default_provider: form.default_provider,
            default_model: form.default_model,
            default_privacy_level: form.default_privacy_level,
            org_name: form.org_name,
          });
          toast.success("Organisation defaults saved");
        } catch (err) {
          toast.error("Defaults were not saved", err instanceof Error ? err.message : undefined);
        }
      }}
    >
      <div className="row between">
        <h2>Organisation defaults</h2>
        <span className="xs faint">Admins only · used by every new scan</span>
      </div>
      {!form ? (
        <Skeleton />
      ) : (
        <>
          <div className="g g-2">
            <div className="fld">
              <label htmlFor="od-p">Default provider</label>
              <select
                id="od-p"
                className="inp"
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
              </select>
            </div>
            <div className="fld">
              <label htmlFor="od-m">Default model</label>
              <select id="od-m" className="inp" value={form.default_model ?? ""} onChange={(e) => setForm({ ...form, default_model: e.target.value })}>
                {(prov?.models.length ? prov.models : [form.default_model ?? ""]).map((m) => (
                  <option key={m} value={m}>
                    {m || "Provider default"}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="g g-2">
            <div className="fld">
              <label htmlFor="od-l">Default privacy level</label>
              <select id="od-l" className="inp" value={form.default_privacy_level} onChange={(e) => setForm({ ...form, default_privacy_level: e.target.value as PrivacyLevel })}>
                {PRIVACY_LEVELS.map((l) => (
                  <option key={l} value={l}>
                    {l} · {LEVEL_NAME[l]}
                  </option>
                ))}
              </select>
            </div>
            <div className="fld">
              <label htmlFor="od-o">Organisation name</label>
              <input id="od-o" className="inp" value={form.org_name ?? ""} onChange={(e) => setForm({ ...form, org_name: e.target.value })} />
            </div>
          </div>
          <div>
            <Button type="submit" loading={save.isPending}>
              Save defaults
            </Button>
          </div>
        </>
      )}
    </form>
  );
}
