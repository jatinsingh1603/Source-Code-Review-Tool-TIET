import { useState, type FormEvent } from "react";
import { Trash2, UserPlus } from "lucide-react";
import { useCreateUser, useDeleteUser, useUpdateUser, useUsers } from "@/api/queries";
import { ROLES, type Role, type User } from "@/api/types";
import { PageHeader } from "@/components/layout/PageHeader";
import { Badge, Button, Card, DataTable, Dialog, ErrorState, Field, IconButton, Input, Select, SkeletonRows, Toggle, useToast, type Column } from "@/components/ui";
import { useSession } from "@/app/session";
import { fmtRelative, initials } from "@/lib/format";
import { roleLabel } from "@/lib/permissions";

const ROLE_DESC: Record<Role, string> = {
  admin: "Everything, including users, settings and policy",
  auditor: "Everything a developer can do, plus original code in the Privacy Centre and the audit trail",
  developer: "Projects, scans, triage, ledger and payloads (not original code), GitHub sync",
  viewer: "Read findings and download reports",
};

function CreateUserDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const create = useCreateUser();
  const toast = useToast();
  const [form, setForm] = useState({ username: "", display_name: "", email: "", password: "", role: "developer" as Role });
  const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    if (!/^[a-z0-9._-]{3,32}$/i.test(form.username)) return setErr("Username: 3 to 32 letters, digits, dots, dashes or underscores.");
    if (form.password.length < 10) return setErr("Password: at least 10 characters.");
    try {
      await create.mutateAsync({ ...form, display_name: form.display_name || undefined, email: form.email || undefined });
      toast.success("User created", form.username);
      setForm({ username: "", display_name: "", email: "", password: "", role: "developer" });
      onClose();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Could not create the user");
    }
  };
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Add user"
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="create-user" loading={create.isPending}>
            Add user
          </Button>
        </>
      }
    >
      <form id="create-user" onSubmit={submit} className="grid gap-4 sm:grid-cols-2" noValidate>
        <Field label="Username" required>
          {(id) => <Input id={id} value={form.username} autoComplete="off" onChange={(e) => setForm({ ...form, username: e.target.value })} />}
        </Field>
        <Field label="Display name">
          {(id) => <Input id={id} value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />}
        </Field>
        <Field label="Email">
          {(id) => <Input id={id} type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />}
        </Field>
        <Field label="Initial password" required help="At least 10 characters">
          {(id, d) => <Input id={id} aria-describedby={d} type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />}
        </Field>
        <Field label="Role" className="sm:col-span-2" help={ROLE_DESC[form.role]}>
          {(id, d) => (
            <Select id={id} aria-describedby={d} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {roleLabel(r)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {err && (
          <p className="text-sm text-danger sm:col-span-2" role="alert">
            {err}
          </p>
        )}
      </form>
    </Dialog>
  );
}

export default function UsersPage() {
  const users = useUsers();
  const update = useUpdateUser();
  const del = useDeleteUser();
  const toast = useToast();
  const { user: me } = useSession();
  const [open, setOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<User | null>(null);

  const change = async (u: User, body: { role?: Role; active?: boolean }) => {
    try {
      await update.mutateAsync({ id: u.id, body });
      toast.success("User updated", u.username);
    } catch (e) {
      toast.error("Update failed", e instanceof Error ? e.message : undefined);
    }
  };

  const cols: Column<User>[] = [
    {
      id: "user",
      header: "User",
      rowHeader: true,
      sortValue: (u) => u.username,
      cell: (u) => (
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary-soft text-xs font-bold text-primary">{initials(u.display_name || u.username)}</span>
          <div>
            <p className="font-medium text-fg">
              {u.display_name || u.username} {u.id === me?.id && <Badge tone="primary">you</Badge>}
            </p>
            <p className="text-xs text-fg-subtle">
              {u.username}
              {u.email ? ` · ${u.email}` : ""}
            </p>
          </div>
        </div>
      ),
    },
    {
      id: "role",
      header: "Role",
      sortValue: (u) => u.role,
      cell: (u) => (
        <Select aria-label={`Role of ${u.username}`} className="h-8 w-36" value={u.role} disabled={u.id === me?.id} onChange={(e) => change(u, { role: e.target.value as Role })}>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {roleLabel(r)}
            </option>
          ))}
        </Select>
      ),
    },
    {
      id: "active",
      header: "Active",
      cell: (u) => (
        <Toggle checked={u.active !== false} disabled={u.id === me?.id} onChange={(v) => change(u, { active: v })} label={<span className="sr-only">Active</span>} />
      ),
    },
    { id: "login", header: "Last sign-in", sortValue: (u) => u.last_login ?? "", cell: (u) => <span className="text-sm text-fg-muted">{u.last_login ? fmtRelative(u.last_login) : "Never"}</span> },
    {
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (u) =>
        u.id !== me?.id && (
          <IconButton label={`Delete ${u.username}`} onClick={() => setConfirmDelete(u)}>
            <Trash2 className="h-4 w-4" />
          </IconButton>
        ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Users"
        description="People who can sign in to this CodeKavach server and what each role may do."
        actions={
          <Button icon={<UserPlus className="h-4 w-4" />} onClick={() => setOpen(true)}>
            Add user
          </Button>
        }
      />
      <div className="mb-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {ROLES.map((r) => (
          <div key={r} className="rounded-lg border border-border bg-surface p-4">
            <p className="font-semibold text-fg">{roleLabel(r)}</p>
            <p className="mt-1 text-sm text-fg-muted">{ROLE_DESC[r]}</p>
          </div>
        ))}
      </div>
      <Card>
        {users.isLoading ? (
          <div className="p-5">
            <SkeletonRows />
          </div>
        ) : users.error ? (
          <ErrorState error={users.error} onRetry={() => void users.refetch()} />
        ) : (
          <DataTable columns={cols} rows={users.data ?? []} rowKey={(u) => u.id} caption="Users" initialSort={{ id: "user", dir: "asc" }} />
        )}
      </Card>
      <CreateUserDialog open={open} onClose={() => setOpen(false)} />
      <Dialog
        open={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        size="sm"
        title={`Delete ${confirmDelete?.username ?? ""}?`}
        description="The account can no longer sign in. Triage history keeps the username."
        footer={
          <>
            <Button variant="outline" onClick={() => setConfirmDelete(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={del.isPending}
              onClick={async () => {
                try {
                  await del.mutateAsync(confirmDelete!.id);
                  toast.success("User deleted");
                } catch (e) {
                  toast.error("Could not delete the user", e instanceof Error ? e.message : undefined);
                }
                setConfirmDelete(null);
              }}
            >
              Delete user
            </Button>
          </>
        }
      />
    </>
  );
}
