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
