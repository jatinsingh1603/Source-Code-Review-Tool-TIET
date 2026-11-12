import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useSession } from "@/app/session";
import { useShell } from "@/app/shell-context";
import { useAudit, useCreateUser, useDeleteUser, useHealth, useProviders, useSettings, useUpdateUser, useUsers, useVersion } from "@/api/queries";
import { ROLES, type AuditEvent, type Role, type User } from "@/api/types";
import { roleLabel } from "@/lib/permissions";
import { fmtShort, LEVEL_NAME } from "@/lib/display";
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
  useShell({
    projectPill: settings?.org_name ?? "Organisation",
    levelPill: settings ? `Default ${settings.default_privacy_level} · ${LEVEL_NAME[settings.default_privacy_level]}` : undefined,
    hideProvider: true,
  });
  return (
    <Content>
      <PageHeader
        crumbs={[{ label: "Organisation" }, { label: "Admin" }]}
        title="Admin"
        actions={
          <Button variant="primary" onClick={() => setInvite(true)}>
            Invite user
          </Button>
        }
      />
      <Tabs label="Admin sections" value={tab} onChange={(t) => navigate(t === "users" ? "/admin" : `/admin/${t}`)} tabs={TABS} />
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
  const update = useUpdateUser();
  const del = useDeleteUser();
  const { user: me } = useSession();
  const toast = useToast();
  const [revoke, setRevoke] = useState<User | null>(null);
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
            <th />
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
                        <div className="xs faint">{u.email || u.username}</div>
                      </div>
                    </div>
                  </td>
                  <td>
                    <select
                      className="inp sm"
                      aria-label={`Role of ${name}`}
                      style={{ width: 120 }}
                      value={u.role}
                      disabled={u.id === me?.id || update.isPending}
                      title={u.id === me?.id ? "You cannot change your own role." : undefined}
                      onChange={(e) =>
                        update.mutate(
                          { id: u.id, body: { role: e.target.value as Role } },
                          {
                            onSuccess: () => toast.success("Role changed", `${name} is now ${roleLabel(e.target.value as Role)}.`),
                            onError: (err) => toast.error("Role not changed", err.message),
                          },
                        )
                      }
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {roleLabel(r)}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="sm">{u.active === false ? <StatusDot tone="neutral">Disabled</StatusDot> : <StatusDot tone="ok">Active</StatusDot>}</td>
                  <td className="sm">Local</td>
                  <td className="sm muted">{u.last_login ? fmtShort(u.last_login) : "Never"}</td>
                  <td>
                    {u.id !== me?.id && (
                      <button className="btn sm ghost" type="button" onClick={() => setRevoke(u)}>
                        Revoke
                      </button>
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
        description={revoke ? `${revoke.display_name || revoke.username} will no longer be able to sign in. Their triage history stays.` : undefined}
        footer={
          <>
            <Button variant="ghost" onClick={() => setRevoke(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={del.isPending}
              onClick={() =>
                revoke &&
                del.mutate(revoke.id, {
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
    </div>
  );
}

function TokensCard() {
  return (
    <div className="card">
      <div className="card-h">
        <h2>API tokens</h2>
        <button className="btn sm" type="button" disabled title="Long-lived API tokens need server support.">
          + New token
        </button>
      </div>
      <Empty title="No API tokens">Scripts sign in with a user account; sessions expire on their own.</Empty>
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
  const exportLog = () => {
    const blob = new Blob([(q.data?.events ?? []).map((e) => JSON.stringify(e)).join("\n") + "\n"], { type: "application/x-ndjson" });
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
        <Button size="sm" onClick={exportLog} disabled={!q.data?.events.length}>
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
        </div>
      )}
    </div>
  );
}

function RetentionCard() {
  return (
    <div className="card stack">
      <h2>Data retention and vault</h2>
      <p className="sm muted">
        Scans, findings and ledgers are kept until a project is deleted. The pseudonym vault stays on this machine and is managed with the
        command line:
      </p>
      <div className="code cmd" style={{ whiteSpace: "pre-wrap" }}>
        {"codekavach vault --help"}
      </div>
      <p className="xs faint">
        Purging the vault means old verdicts can no longer be mapped back to real names. Reports already generated are unaffected.
      </p>
    </div>
  );
}

function HealthCard() {
  const h = useHealth();
  const v = useVersion().data;
  return (
    <div className="card">
      <div className="card-h">
        <h2>System health</h2>
        <span className="mono xs faint">GET /health{v ? ` · v${v.version}` : ""}</span>
      </div>
      {h.isLoading ? (
        <Skeleton />
      ) : h.isError || !h.data ? (
        <ErrorBanner what="Health could not be read." error={h.error} />
      ) : (
        <>
          <Guard result={h.data.status === "ok" ? "pass" : <span className="note-w">{h.data.status}</span>}>API server</Guard>
          <Guard result={h.data.database === "ok" ? "pass" : <span className="note-w">{String(h.data.database ?? "unknown")}</span>}>
            Database and migrations
          </Guard>
          <Guard result={<span className="xs faint">{h.data.active_scans ?? 0} running</span>}>Scan workers</Guard>
          {(h.data.checks ?? []).map((c) => (
            <Guard key={c.name} result={c.ok ? "pass" : <span className="note-w">{c.detail ?? "Check"}</span>}>
              {c.name}
            </Guard>
          ))}
          <p className="xs faint" style={{ marginTop: 8 }}>
            Engine, mirror and disk checks: run <span className="mono">codekavach doctor</span> on the server.
          </p>
        </>
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
    if (form.password.length < 10) return setErr("Password: at least 10 characters.");
    try {
      await create.mutateAsync(form);
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
