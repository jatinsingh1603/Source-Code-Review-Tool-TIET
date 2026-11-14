import { useEffect, useMemo, useState } from "react";
import { useSession } from "@/app/session";
import { useQueryClient } from "@tanstack/react-query";
import { useOptional, useProviders, useSaveSettings, useSettings } from "@/api/queries";
import { endpoints } from "@/api/endpoints";
import { PRIVACY_LEVELS, type PersonalToken, type PrivacyLevel, type Settings } from "@/api/types";
import { roleLabel } from "@/lib/permissions";
import { fmtDate, LEVEL_NAME } from "@/lib/display";
import { readPrefs, writePrefs, type Prefs } from "@/lib/prefs";
import { Avatar, Button, Content, Segmented, Skeleton, useToast } from "@/components/ui";

const SECTIONS: [string, string][] = [
  ["profile", "Profile"],
  ["appearance", "Appearance"],
  ["notifications", "Notifications"],
  ["password", "Password"],
  ["tokens", "CLI and API tokens"],
  ["language", "Language and region"],
];
const ORG_SECTION: [string, string] = ["organisation", "Organisation defaults"];
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

const EVENTS: [string, string][] = [
  ["critical_finding", "New Critical or High finding"],
  ["finding_assigned", "Finding assigned to me"],
  ["scan_failed", "Privacy step failed or scan aborted"],
  ["ledger_verification_failed", "Ledger verification failed"],
  ["scan_completed", "Scan completed"],
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
  const qc = useQueryClient();
  const serverPrefs = useOptional("me-prefs", endpoints.myPreferences).data;
  const serverNotif = useOptional("me-notif", endpoints.myNotifications).data;
  const tokensQ = useOptional("me-tokens", endpoints.myTokens);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [tokenName, setTokenName] = useState("");
  const [busy, setBusy] = useState(false);
  const [active, setActive] = useState("profile");
  const [prefs, setPrefs] = useState<Prefs>(readPrefs);
  const [name, setName] = useState(user?.display_name ?? user?.full_name ?? "");
  const [email, setEmail] = useState(user?.email ?? "");
  const orgAdmin = can("settings:write");
  const sections = useMemo(() => (orgAdmin ? [...SECTIONS, ORG_SECTION] : SECTIONS), [orgAdmin]);
  const [notif, setNotif] = useState<Notif>(readNotif);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (!serverPrefs) return;
    setPrefs((p) => ({
      ...p,
      density: serverPrefs.density === "comfortable" || serverPrefs.density === "compact" ? serverPrefs.density : p.density,
      reduceMotion: typeof serverPrefs.reduce_motion === "boolean" ? serverPrefs.reduce_motion : p.reduceMotion,
      timeZone: typeof serverPrefs.time_zone === "string" ? serverPrefs.time_zone : p.timeZone,
      dateFormat: serverPrefs.date_format === "iso" ? "iso" : p.dateFormat,
    }));
  }, [serverPrefs]);
  useEffect(() => {
    if (!serverNotif?.events) return;
    setNotif(Object.fromEntries(Object.entries(serverNotif.events).map(([k, v]) => [k, { app: v.in_app, email: v.email }])));
  }, [serverNotif]);

  // Arriving with a #section (Admin's "+ New token" links to #tokens): the shell scrolls to it;
  // mark it in the section list straight away.
  useEffect(() => {
    const id = window.location.hash.slice(1);
    if (id && document.getElementById(id)) setActive(id);
  }, []);

  useEffect(() => {
    const els = sections.map(([id]) => document.getElementById(id)).filter((x): x is HTMLElement => !!x);
    const obs = new IntersectionObserver(
      (entries) => {
        const vis = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (vis) setActive(vis.target.id);
      },
      { rootMargin: "-10% 0px -60% 0px" },
    );
    els.forEach((e) => obs.observe(e));
    return () => obs.disconnect();
  }, [sections]);

  const save = async () => {
    const mail = email.trim();
    if (mail && !EMAIL_RE.test(mail)) {
      toast.error("Settings not saved", "The email address does not look right, for example name@thapar.edu.");
      return;
    }
    writePrefs(prefs);
    setBusy(true);
    try {
      localStorage.setItem(NOTIF_KEY, JSON.stringify(notif));
    } catch {
      /* storage unavailable */
    }
    try {
      if (user && name.trim() && name !== (user.display_name ?? "")) await endpoints.patchMe({ display_name: name.trim() });
      if (user && mail !== (user.email ?? "")) await endpoints.patchMe({ email: mail });
      if (serverPrefs) {
        await endpoints.patchPreferences({
          density: prefs.density,
          reduce_motion: prefs.reduceMotion,
          time_zone: prefs.timeZone,
          date_format: prefs.dateFormat,
        });
      }
      if (serverNotif) {
        await endpoints.patchMyNotifications({
          events: Object.fromEntries(Object.entries(notif).map(([k, v]) => [k, { in_app: v.app, email: v.email }])),
        });
      }
      setDirty(false);
      toast.success("Settings saved");
    } catch (e) {
      toast.error("Settings not saved", e instanceof Error ? e.message : undefined);
    } finally {
      setBusy(false);
    }
  };

  const [creatingToken, setCreatingToken] = useState(false);
  const createToken = async () => {
    if (creatingToken) return;
    setCreatingToken(true);
    try {
      const t = await endpoints.createMyToken(tokenName.trim() || "cli");
      setNewToken(t.token);
      setTokenName("");
      void qc.invalidateQueries({ queryKey: ["optional", "me-tokens"] });
    } catch (e) {
      toast.error("Token not created", e instanceof Error ? e.message : undefined);
    } finally {
      setCreatingToken(false);
    }
  };

  const set = (p: Partial<Prefs>) => {
    setPrefs((x) => ({ ...x, ...p }));
    setDirty(true);
  };
  const ev = (k: string) => notif[k] ?? { app: true, email: false };

  return (
    <Content maxWidth={1100}>
      <div className="ph">
        <div>
          <h1>Settings</h1>
        </div>
        <Button variant="primary" onClick={() => void save()} loading={busy}>
          Save changes{dirty ? " ·" : ""}
        </Button>
      </div>
      <section className="g g-side-l">
        <nav className="subnav-list" aria-label="Settings sections">
          {sections.map(([id, label]) => (
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
                  maxLength={128}
                  className="inp"
                  value={name}
                  onChange={(e) => {
                    setName(e.target.value);
                    setDirty(true);
                  }}
                />
              </div>
              <div className="fld">
                <label htmlFor="st-e">Email</label>
                <input
                  id="st-e"
                  className="inp"
                  type="email"
                  autoComplete="email"
                  value={email}
                  placeholder="Not set"
                  onChange={(e) => {
                    setEmail(e.target.value);
                    setDirty(true);
                  }}
                />
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
              {serverNotif ? "Stored on the server. In-app notifications appear under the bell; the server sends no e-mail." : "Kept in this browser."}
            </p>
          </div>

          <PasswordCard />

          <div className="card stack" id="tokens">
            <div className="row between">
              <h2>CLI and API tokens</h2>
              <div className="row">
                <input
                  className="inp sm"
                  style={{ width: 160 }}
                  placeholder="laptop-cli"
                  aria-label="Token name"
                  maxLength={128}
                  value={tokenName}
                  onChange={(e) => setTokenName(e.target.value)}
                />
                <Button size="sm" loading={creatingToken} onClick={() => void createToken()} disabled={!tokensQ.data && !tokensQ.isLoading}>
                  + New personal token
                </Button>
              </div>
            </div>
            {newToken && (
              <div className="banner sm" role="status">
                <span>
                  <b>Copy this token now; it is shown once.</b> <span className="mono" style={{ wordBreak: "break-all" }}>{newToken}</span>
                </span>
                <button
                  className="btn sm"
                  type="button"
                  onClick={() =>
                    void navigator.clipboard.writeText(newToken).then(
                      () => toast.success("Copied", "Paste it where your CLI or script reads it."),
                      () => toast.error("Copy failed", "Select the token and copy it by hand."),
                    )
                  }
                >
                  Copy
                </button>
              </div>
            )}
            {((Array.isArray(tokensQ.data) ? tokensQ.data : []) as PersonalToken[])
              .filter((t) => !t.revoked)
              .map((t) => (
                <div className="guard" key={t.id}>
                  <span className="gt">
                    <b className="sm" style={{ color: "var(--text)" }}>
                      {t.name}
                    </b>
                    <br />
                    <span className="xs">
                      {t.prefix ? `${t.prefix}… · ` : ""}created {fmtDate(t.created_at)}
                      {t.expires_at ? ` · expires ${fmtDate(t.expires_at)}` : ""}
                    </span>
                  </span>
                  <Button
                    size="sm"
                    onClick={() =>
                      void endpoints.deleteMyToken(t.id).then(
                        () => {
                          toast.success("Token revoked", `${t.name} no longer works.`);
                          void qc.invalidateQueries({ queryKey: ["optional", "me-tokens"] });
                        },
                        (e: Error) => toast.error("Not revoked", e.message),
                      )
                    }
                  >
                    Revoke
                  </Button>
                </div>
              ))}
            <div className="code cmd" style={{ padding: "10px 14px", fontSize: 12, whiteSpace: "pre-wrap" }}>
              {"curl -H 'Authorization: Bearer <token>' " + (typeof window !== "undefined" ? window.location.origin : "") + "/api/v1/stats\ncodekavach scan . --privacy-level L3 --provider mock"}
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

          {orgAdmin && <OrgDefaults />}
        </div>
      </section>
    </Content>
  );
}

/** The caller's own password; the server keeps this session and signs out the others. */
function PasswordCard() {
  const toast = useToast();
  const [form, setForm] = useState({ current: "", next: "", again: "" });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setErr(null);
    if (!form.current) return setErr("Enter your current password.");
    if (form.next.length < 10) return setErr("The new password needs at least 10 characters.");
    if (form.next !== form.again) return setErr("The two new passwords are not the same.");
    setBusy(true);
    try {
      const r = await endpoints.changeMyPassword({ current_password: form.current, new_password: form.next });
      setForm({ current: "", next: "", again: "" });
      toast.success("Password changed", r.revoked ? `Signed out elsewhere: ${r.revoked} other session(s) and token(s).` : "This session stays signed in.");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "The password was not changed.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      className="card stack"
      id="password"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <h2>Password</h2>
      <div className="fld">
        <label htmlFor="pw-c">Current password</label>
        <input id="pw-c" className="inp" type="password" autoComplete="current-password" value={form.current} onChange={(e) => setForm({ ...form, current: e.target.value })} />
      </div>
      <div className="g g-2">
        <div className="fld">
          <label htmlFor="pw-n">New password</label>
          <input id="pw-n" className="inp" type="password" autoComplete="new-password" value={form.next} onChange={(e) => setForm({ ...form, next: e.target.value })} />
        </div>
        <div className="fld">
          <label htmlFor="pw-a">New password again</label>
          <input id="pw-a" className="inp" type="password" autoComplete="new-password" value={form.again} onChange={(e) => setForm({ ...form, again: e.target.value })} />
        </div>
      </div>
      <p className="xs faint">At least 10 characters. Your other sessions and personal tokens are signed out; this one stays.</p>
      {err && (
        <div className="banner bad sm" role="alert">
          {err}
        </div>
      )}
      <div>
        <Button type="submit" loading={busy}>
          Change password
        </Button>
      </div>
    </form>
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
              <input id="od-o" className="inp" maxLength={200} value={form.org_name ?? ""} onChange={(e) => setForm({ ...form, org_name: e.target.value })} />
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
