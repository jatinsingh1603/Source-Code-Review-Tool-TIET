import type { Role } from "@/api/types";

/**
 * Role-to-permission map used for presentation only (navigation and guards).
 * The server remains the enforcement point for every request.
 */
export type Permission =
  | "projects:write"
  | "scans:run"
  | "findings:triage"
  | "findings:review"
  | "privacy:read"
  | "privacy:read_original"
  | "reports:read"
  | "settings:write"
  | "users:admin"
  | "github:sync"
  | "providers:test"
  | "audit:read";

const DEVELOPER: Permission[] = [
  "projects:write",
  "scans:run",
  "findings:triage",
  "privacy:read",
  "reports:read",
  "github:sync",
  "providers:test",
];

/** Mirrors codekavach.server.rbac; used when the session carries no permission list. */
const MAP: Record<Role, Permission[]> = {
  admin: [...DEVELOPER, "privacy:read_original", "audit:read", "findings:review", "settings:write", "users:admin"],
  auditor: [...DEVELOPER, "privacy:read_original", "audit:read", "findings:review"],
  developer: DEVELOPER,
  viewer: ["reports:read"],
};

/** Server permission names (codekavach.server.rbac.Permission) to interface permissions. */
const FROM_SERVER: Record<string, Permission> = {
  "project:write": "projects:write",
  "scan:run": "scans:run",
  "finding:triage": "findings:triage",
  "finding:review": "findings:review",
  "privacy:read_ledger": "privacy:read",
  "privacy:read_original": "privacy:read_original",
  "report:read": "reports:read",
  "settings:write": "settings:write",
  "users:admin": "users:admin",
  "sync:github": "github:sync",
  "provider:test": "providers:test",
  "audit:read": "audit:read",
};

export function permissionsFor(role: Role | undefined, serverPermissions?: string[] | null): Set<Permission> {
  if (serverPermissions && serverPermissions.length) {
    return new Set(serverPermissions.map((p) => FROM_SERVER[p]).filter((p): p is Permission => !!p));
  }
  return new Set(role ? (MAP[role] ?? []) : []);
}

export function roleLabel(role: Role): string {
  return role.charAt(0).toUpperCase() + role.slice(1);
}

/** The least-privileged role that holds a permission, for "requires X" messages. */
export function minimumRoleFor(p: Permission): Role {
  for (const r of ["viewer", "developer", "auditor", "admin"] as Role[]) {
    if (MAP[r].includes(p)) return r;
  }
  return "admin";
}

/** The role a permission needs, in words, for refusals. */
const PERMISSION_WORDS: Record<string, string> = {
  "privacy:read_original": "the Auditor role, because it shows original code or payload text",
  "audit:read": "the Auditor role",
  "finding:review": "the Auditor role",
  "privacy:read_ledger": "the Developer role",
  "finding:triage": "the Developer role",
  "scan:run": "the Developer role",
  "project:write": "the Developer role",
  "provider:test": "the Developer role",
  "sync:github": "the Developer role",
  "settings:write": "the Admin role",
  "users:admin": "the Admin role",
};

/**
 * A refusal (HTTP 403) worded for a person: the server's "the role viewer lacks the permission
 * settings:write" becomes "Your role (Viewer) cannot do this: it needs the Admin role. ...".
 * Text that is already worded is kept.
 */
export function forbiddenText(message: string): string {
  const m = /role (\w+) lacks the permission ([\w:]+)/i.exec(message);
  if (!m) {
    return message.startsWith("Your role")
      ? message
      : "Your role cannot do this. Ask an administrator if you need access.";
  }
  const need = PERMISSION_WORDS[m[2]!] ?? "a role with more access";
  return `Your role (${roleLabel(m[1]!.toLowerCase() as Role)}) cannot do this: it needs ${need}. Ask an administrator if you need access.`;
}

/**
 * The refusal the server would give ``role`` for a server permission, worded the same way, for a
 * page that does not send a request it knows is refused (the server writes each refusal to the
 * audit log as a denied access).
 */
export function refusalText(role: Role | undefined, permission: string): string {
  return forbiddenText(`the role ${role ?? "viewer"} lacks the permission ${permission}`);
}
