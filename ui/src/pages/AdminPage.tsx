import { useState } from "react";
import { Navigate, useNavigate, useParams } from "react-router-dom";
import { useSession } from "@/app/session";
import { useShell } from "@/app/shell-context";
import { Link } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useAudit, useCreateUser, useHealth, useOptional, useProviders, useSettings, useUsers, useVersion } from "@/api/queries";
import { endpoints } from "@/api/endpoints";
import { ROLES, type AuditEvent, type PersonalToken, type Role, type User } from "@/api/types";
import { roleLabel } from "@/lib/permissions";
import { fmtBytesText, fmtDate, fmtInt, fmtShort, LEVEL_NAME } from "@/lib/display";
import {
  Avatar,
  Button,
  Content,
  Dialog,
  Empty,
  ErrorBanner,
  Field,
  Guard,
  Input,
  MoreLink,
  PageHeader,
  Skeleton,
  SkeletonRows,
  StatusDot,
  Tabs,
  useToast,
} from "@/components/ui";

const TABS = [
  { id: "users", label: "Users and roles" },
  { id: "orgs", label: "Organisations" },
  { id: "tokens", label: "API tokens" },
  { id: "keys", label: "Provider keys" },
  { id: "audit", label: "Audit log" },
  { id: "retention", label: "Retention" },
  { id: "health", label: "System health" },
];

/** Admin (SCREENS.md §18): users and roles, keys, audit log, retention, health. */
export default function AdminPage() {
  const { tab = "users" } = useParams();
  const navigate = useNavigate();
  const settings = useSettings().data;
  const [invite, setInvite] = useState(false);
  // An auditor reads the audit log here; everything else on this page is the admin's.
  const isAdmin = useSession().can("users:admin");
  useShell({
    projectPill: settings?.org_name ?? "Organisation",
    levelPill: settings ? `Default ${settings.default_privacy_level} · ${LEVEL_NAME[settings.default_privacy_level]}` : undefined,
    hideProvider: true,
  });
  if (!isAdmin && tab !== "audit") return <Navigate to="/admin/audit" replace />;
  return (
    <Content>
      <PageHeader
        crumbs={[{ label: "Organisation" }, { label: "Admin" }]}
        title={isAdmin ? "Admin" : "Audit log"}
        sub={isAdmin ? undefined : "Read-only for auditors. Users, keys and retention are managed by an admin."}
        actions={
          isAdmin ? (
            <Button variant="primary" onClick={() => setInvite(true)}>
              Invite user
            </Button>
          ) : undefined
        }
      />
      {isAdmin && <Tabs label="Admin sections" value={tab} onChange={(t) => navigate(t === "users" ? "/admin" : `/admin/${t}`)} tabs={TABS} />}
      {tab === "users" ? (
        <section className="g g-side">
          <div className="stack s16">
            <UsersTable />
            <div className="g g-2">
              <TokensCard />
              <KeysCard />
            </div>
            <AuditPanel limit={6} />
          </div>
          <div className="stack s16">
            <RetentionCard />
            <HealthCard />
          </div>
        </section>
      ) : tab === "orgs" ? (
        <OrgsPanel />
      ) : tab === "tokens" ? (
        <TokensCard />
      ) : tab === "keys" ? (
        <KeysCard />
      ) : tab === "audit" ? (
        <AuditPanel />
      ) : tab === "retention" ? (
        <RetentionCard />
      ) : (
        <HealthCard />
      )}
      <InviteDialog open={invite} onClose={() => setInvite(false)} />
    </Content>
  );
}

function UsersTable() {
  const q = useUsers();
  const qc = useQueryClient();
  const setRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) => endpoints.setRole(id, role),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["users"] }),
  });
  const revokeM = useMutation({
    mutationFn: (id: string) => endpoints.revokeUser(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["users"] }),
  });
  const { user: me } = useSession();
  const toast = useToast();
  const [revoke, setRevoke] = useState<User | null>(null);
  const [reset, setReset] = useState<User | null>(null);
  const restoreM = useMutation({
    mutationFn: (id: string) => endpoints.updateUser(id, { active: true }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["users"] }),
  });
  if (q.isError) return <ErrorBanner what="Users could not be loaded." error={q.error} onRetry={() => void q.refetch()} />;
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead>
          <tr>
            <th>User</th>
            <th>Role</th>
            <th>Status</th>
            <th>Sign-in</th>
            <th>Last active</th>
            <th><span className="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {q.isLoading ? (
            <SkeletonRows cols={6} rows={3} />
          ) : (
            (q.data ?? []).map((u) => {
              const name = u.display_name || u.full_name || u.username;
              return (
                <tr key={u.id}>
                  <td>
                    <div className="row">
                      <Avatar name={name} size="sm" />
                      <div>
                        <b className="sm">{name}</b>
                        <div className="xs faint">
                          <span className="mono">{u.username}</span>
                          {u.email ? ` · ${u.email}` : ""}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td>
                    <select
                      className="inp sm"
                      aria-label={`Role of ${name}`}
                      style={{ width: 120 }}
                      value={u.role}
                      disabled={u.id === me?.id || u.active === false || setRole.isPending}
                      title={u.id === me?.id ? "You cannot change your own role." : u.active === false ? "Access revoked; the account is disabled." : undefined}
                      onChange={(e) => {
                        // Read the choice now: the controlled select snaps back to the old role
                        // until the list reloads, so e.target.value is stale by onSuccess.
                        const next = e.target.value as Role;
                        setRole.mutate(
                          { id: u.id, role: next },
                          {
                            onSuccess: () => toast.success("Role changed", `${name} is now ${roleLabel(next)}. Their sessions and tokens were signed out.`),
                            onError: (err) => toast.error("Role not changed", err.message),
                          },
                        );
                      }}
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {roleLabel(r)}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="sm">{u.active === false ? <StatusDot tone="neutral">Revoked</StatusDot> : <StatusDot tone="ok">Active</StatusDot>}</td>
                  <td className="sm">Local</td>
                  <td className="sm muted">{u.last_login ? fmtShort(u.last_login) : "Never"}</td>
                  <td>
                    {u.id !== me?.id && (
                      <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 2 }}>
                        <button className="btn sm ghost" type="button" onClick={() => setReset(u)}>
                          Reset password
                        </button>
                        {u.active === false ? (
                          <button
                            className="btn sm ghost"
                            type="button"
                            disabled={restoreM.isPending}
                            onClick={() =>
                              restoreM.mutate(u.id, {
                                onSuccess: () => toast.success("Access restored", `${name} can sign in again.`),
                                onError: (e) => toast.error("Not restored", e.message),
                              })
                            }
                          >
                            Restore
                          </button>
                        ) : (
                          <button className="btn sm ghost" type="button" onClick={() => setRevoke(u)}>
                            Revoke
                          </button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      <Dialog
        open={!!revoke}
        onClose={() => setRevoke(null)}
        title="Revoke access?"
        description={revoke ? `${revoke.display_name || revoke.username} is signed out everywhere and the account is disabled. Their triage history stays.` : undefined}
        footer={
          <>
            <Button variant="ghost" onClick={() => setRevoke(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={revokeM.isPending}
              onClick={() =>
                revoke &&
                revokeM.mutate(revoke.id, {
                  onSuccess: () => {
                    toast.success("Access revoked");
                    setRevoke(null);
                  },
                  onError: (e) => toast.error("Not revoked", e.message),
                })
              }
            >
              Revoke
            </Button>
          </>
        }
      />
      <ResetPasswordDialog user={reset} onClose={() => setReset(null)} />
    </div>
  );
}

function ResetPasswordDialog({ user, onClose }: { user: User | null; onClose: () => void }) {
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const m = useMutation({ mutationFn: (v: { id: string; password: string }) => endpoints.updateUser(v.id, { password: v.password }) });
  const close = () => {
    setPassword("");
    setErr(null);
    onClose();
  };
  const submit = () => {
    if (!user) return;
    setErr(null);
    if (password.length < 10) return setErr("Password: at least 10 characters.");
    m.mutate(
      { id: user.id, password },
      {
        onSuccess: () => {
          toast.success("Password reset", `${user.display_name || user.username} is signed out everywhere; share the new password through a separate channel.`);
          close();
        },
        onError: (e) => setErr(e.message),
      },
    );
  };
  return (
    <Dialog
      open={!!user}
      onClose={close}
      title="Reset password"
      description={user ? `Sets a new password for ${user.display_name || user.username} (${user.username}). Their sessions and personal tokens are revoked.` : undefined}
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            Cancel
          </Button>
          <Button variant="primary" loading={m.isPending} onClick={submit}>
            Reset password
          </Button>
        </>
      }
    >
      <Field label="New password" required help="At least 10 characters">
        {(id, d) => <Input id={id} aria-describedby={d} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />}
      </Field>
      {err && <div className="banner bad sm">{err}</div>}
    </Dialog>
  );
}

function TokensCard() {
  const q = useOptional("admin-tokens", endpoints.tokens);
  const qc = useQueryClient();
  const toast = useToast();
  const tokens = (Array.isArray(q.data) ? q.data : []) as PersonalToken[];
  const [confirm, setConfirm] = useState<PersonalToken | null>(null);
  const [busy, setBusy] = useState(false);
  const revoke = (t: PersonalToken) => {
    setBusy(true);
    void endpoints
      .revokeToken(t.id)
      .then(
        () => {
          toast.success("Token revoked", `${t.name}${t.username ? ` (${t.username})` : ""} no longer works.`);
          void qc.invalidateQueries({ queryKey: ["optional", "admin-tokens"] });
        },
        (e: Error) => toast.error("Not revoked", e.message),
      )
      .finally(() => {
        setBusy(false);
        setConfirm(null);
      });
  };
  return (
    <div className="card">
      <Dialog
        open={!!confirm}
        onClose={() => setConfirm(null)}
        title="Revoke token?"
        description={confirm ? `${confirm.name}${confirm.username ? `, owned by ${confirm.username},` : ""} stops working at once: scripts and CI jobs that use it get 401. This cannot be undone; the owner can create a new token in Settings.` : undefined}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirm(null)}>
              Cancel
            </Button>
            <Button variant="danger" loading={busy} onClick={() => confirm && revoke(confirm)}>
              Revoke token
            </Button>
          </>
        }
      />
      <div className="card-h">
        <h2>API tokens</h2>
        <Link className="btn sm" to="/settings#tokens">
          + New token
        </Link>
      </div>
      {q.isLoading ? (
        <Skeleton />
      ) : tokens.filter((t) => !t.revoked).length === 0 ? (
        <Empty title="No API tokens">Users create personal tokens in Settings; they appear here.</Empty>
      ) : (
        tokens
          .filter((t) => !t.revoked)
          .map((t) => (
            <div className="guard" key={t.id}>
              <span className="gt">
                <b className="sm" style={{ color: "var(--text)" }}>
                  {t.name}
                </b>
                <br />
                <span className="xs">
                  {t.username ?? ""} · {t.expires_at ? `expires ${fmtDate(t.expires_at)}` : "no expiry"}
                  {t.last_used_at ? ` · used ${fmtShort(t.last_used_at)}` : ""}
                </span>
              </span>
              <span className="mono xs faint">{t.prefix ? `${t.prefix}…` : ""}</span>
              <button
                className="btn sm ghost"
                type="button"
                onClick={() => setConfirm(t)}
              >
                Revoke
              </button>
            </div>
          ))
      )}
    </div>
  );
}

function KeysCard() {
  const providers = useProviders().data;
  const refs = (providers ?? []).flatMap((p) => (p.key_refs ?? []).map((r) => ({ p, r })));
  return (
    <div className="card">
      <div className="card-h">
        <h2>Provider keys</h2>
        <MoreLink to="/providers">Providers</MoreLink>
      </div>
      {!providers ? (
        <Skeleton />
      ) : refs.length === 0 ? (
        <Empty title="No key references">Local and mock providers need no key.</Empty>
      ) : (
        refs.map(({ p, r }) => (
          <div className="guard" key={`${p.id}-${r}`}>
            <span className="gt">
              <b className="sm" style={{ color: "var(--text)" }}>
                {p.name}
              </b>
              <br />
              <span className="mono xs">{r}</span>
            </span>
            <StatusDot tone={p.configured ? "ok" : "bad"} className="xs">
              {p.configured ? "present" : "missing"}
            </StatusDot>
          </div>
        ))
      )}
      <p className="xs faint" style={{ marginTop: 8 }}>
        Only references are stored. Values are read at request time and never written to logs or the ledger.
      </p>
    </div>
  );
}

function AuditPanel({ limit }: { limit?: number }) {
  const q = useAudit();
  const events = (q.data?.events ?? []).slice(0, limit ?? 200);
  const toast = useToast();
  const [exporting, setExporting] = useState(false);
  // The table shows the newest events; the export pages through the whole log.
  const exportLog = async () => {
    setExporting(true);
    const all: AuditEvent[] = [];
    try {
      for (;;) {
        const page = await endpoints.audit(1000, all.length);
        all.push(...page.events);
        if (!page.events.length || all.length >= (page.total ?? 0)) break;
      }
    } catch (e) {
      toast.error("Audit log export failed", e instanceof Error ? e.message : undefined);
      return;
    } finally {
      setExporting(false);
    }
    const blob = new Blob([all.map((e) => JSON.stringify(e)).join("\n") + "\n"], { type: "application/x-ndjson" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "codekavach-audit.jsonl";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };
  return (
    <div className="stack">
      <div className="row between">
        <div className="row">
          <h2 style={{ fontSize: 14, fontWeight: 600 }}>Audit log</h2>
          {q.data?.chain_intact !== undefined && (
            <StatusDot tone={q.data.chain_intact ? "ok" : "bad"} className="xs">
              {q.data.chain_intact ? "chain ok" : "chain broken"}
            </StatusDot>
          )}
        </div>
        <Button size="sm" onClick={() => void exportLog()} loading={exporting} disabled={!q.data?.events.length} title="Download every audit event as JSON Lines">
          Export
        </Button>
      </div>
      {q.isError ? (
        <ErrorBanner what="The audit log could not be loaded." error={q.error} />
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {q.isLoading ? (
                <SkeletonRows cols={5} rows={3} />
              ) : (
                events.map((e: AuditEvent) => (
                  <tr key={e.id}>
                    <td className="mono sm">{fmtShort(e.at)}</td>
                    <td className="sm">{e.actor}</td>
                    <td className="sm">
                      {e.action}
                      {e.outcome && e.outcome !== "allowed" ? <span className="badc"> · {e.outcome}</span> : null}
                    </td>
                    <td className="mono xs">{e.resource || "—"}</td>
                    <td className="mono xs">{e.client || "local"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          {!q.isLoading && events.length === 0 && <Empty title="No audit events yet" />}
          {!!q.data?.total && q.data.total > events.length && (
            <p className="xs faint" style={{ padding: "8px 12px" }}>
              Showing the newest {fmtInt(events.length)} of {fmtInt(q.data.total)} events. Export downloads all of them.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function RetentionCard() {
  const vault = useOptional("vault", endpoints.vault).data;
  const ret = useOptional("retention", endpoints.retention).data;
  const rotated = vault?.vaults.map((v) => v.rotated_at).filter((x): x is string => !!x).sort().pop();
  return (
    <div className="card stack">
      <h2>Data retention and vault</h2>
      {!vault && !ret ? (
        <p className="sm muted">Scans, findings and ledgers are kept until a project is deleted.</p>
      ) : (
        <dl className="dl sm">
          {ret && (
            <>
              <dt>Scans kept</dt>
              <dd>
                {fmtInt(ret.scans)} · {fmtBytesText((ret.scans_bytes ?? 0) + (ret.uploads_bytes ?? 0) + (ret.database_bytes ?? 0))}
              </dd>
              <dt>Oldest scan</dt>
              <dd>{fmtDate(ret.oldest_scan_at)}</dd>
              <dt>Vault retention</dt>
              <dd>{ret.vault_retention_days ? `${ret.vault_retention_days} days, then purge` : "kept with each scan"}</dd>
            </>
          )}
          {vault && (
            <>
              <dt>Vault key</dt>
              <dd className="mono xs">{vault.key_source ?? vault.vaults[0]?.key_source ?? "—"} · AES-256-GCM</dd>
              <dt>Last rotated</dt>
              <dd>{rotated ? fmtDate(rotated) : "never"}</dd>
              <dt>Vault size</dt>
              <dd>
                {fmtInt(vault.records)} mappings · {fmtInt(vault.count)} scans
              </dd>
            </>
          )}
        </dl>
      )}
      <p className="xs faint">
        {ret?.how_to_purge ? `Purging is an API action, kept out of the dashboard on purpose: ${ret.how_to_purge}. ` : ""}Purging a vault means old verdicts can no longer be mapped back to real names.
        Reports already generated are unaffected.
      </p>
    </div>
  );
}

function HealthCard() {
  const sys = useOptional("system-health", endpoints.systemHealth);
  const h = useHealth();
  const v = useVersion().data;
  const checks = (sys.data?.checks ?? []).filter((c) => c.status !== "skip");
  return (
    <div className="card">
      <div className="card-h">
        <h2>System health</h2>
        <span className="mono xs faint">codekavach doctor{v ? ` · v${v.version}` : ""}</span>
      </div>
      {sys.isLoading || h.isLoading ? (
        <Skeleton />
      ) : checks.length ? (
        checks.slice(0, 10).map((c) => (
          <Guard key={c.name} result={c.status === "pass" ? "pass" : <span className="note-w">{c.status === "warn" ? "Low" : c.status}</span>}>
            {c.name.replace(/^server:/, "").replace(/_/g, " ")}
            {c.summary ? ` · ${c.summary}` : ""}
          </Guard>
        ))
      ) : h.data ? (
        <>
          <Guard result={h.data.status === "ok" ? "pass" : <span className="note-w">{h.data.status}</span>}>API server</Guard>
          <Guard result={h.data.database === "ok" ? "pass" : <span className="note-w">{String(h.data.database ?? "unknown")}</span>}>Database and migrations</Guard>
        </>
      ) : (
        <ErrorBanner what="Health could not be read." error={h.error} />
      )}
    </div>
  );
}

function OrgsPanel() {
  const settings = useSettings().data;
  return (
    <div className="card">
      <div className="card-h">
        <h2>Organisations</h2>
      </div>
      {settings ? (
        <dl className="dl">
          <dt>Name</dt>
          <dd>{settings.org_name}</dd>
          <dt>Default level</dt>
          <dd>
            {settings.default_privacy_level} · {LEVEL_NAME[settings.default_privacy_level]}
          </dd>
          <dt>Default provider</dt>
          <dd>{settings.default_provider}</dd>
        </dl>
      ) : (
        <Skeleton />
      )}
      <p className="xs faint" style={{ marginTop: 12 }}>
        This server hosts one organisation. Edit its defaults in Settings.
      </p>
    </div>
  );
}

function InviteDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const create = useCreateUser();
  const toast = useToast();
  const [form, setForm] = useState({ username: "", display_name: "", email: "", password: "", role: "developer" as Role });
  const [err, setErr] = useState<string | null>(null);
  const submit = async () => {
    setErr(null);
    if (!/^[a-z0-9._-]{3,}$/i.test(form.username)) return setErr("Username: at least 3 letters, digits, dots, dashes or underscores.");
    if (form.email.trim() && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(form.email.trim())) return setErr("Email: enter a full address, for example name@thapar.edu, or leave it empty.");
    if (form.password.length < 10) return setErr("Password: at least 10 characters.");
    try {
      await create.mutateAsync({ ...form, email: form.email.trim() });
      toast.success("User created", `${form.username} can sign in now.`);
      setForm({ username: "", display_name: "", email: "", password: "", role: "developer" });
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "The user was not created.");
    }
  };
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Invite user"
      description="Creates a local account. Share the initial password through a separate channel."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={create.isPending} onClick={() => void submit()}>
            Create user
          </Button>
        </>
      }
    >
      <div className="g g-2" style={{ gap: 12 }}>
        <Field label="Username" required>
          {(id) => <Input id={id} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} autoComplete="off" />}
        </Field>
        <Field label="Display name">
          {(id) => <Input id={id} value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />}
        </Field>
        <Field label="Email">
          {(id) => <Input id={id} type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />}
        </Field>
        <Field label="Role">
          {(id) => (
            <select id={id} className="inp" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {roleLabel(r)}
                </option>
              ))}
            </select>
          )}
        </Field>
      </div>
      <Field label="Initial password" required help="At least 10 characters">
        {(id, d) => <Input id={id} aria-describedby={d} type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />}
      </Field>
      {err && <div className="banner bad sm">{err}</div>}
    </Dialog>
  );
}
