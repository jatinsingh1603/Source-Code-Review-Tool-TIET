import type { Role } from "@/api/types";

/**
 * Role-to-permission map used for presentation only (navigation and guards).
 * The server remains the enforcement point for every request.
 */
export type Permission =
  | "projects:write"
  | "scans:run"
  | "findings:triage"
  | "privacy:read"
  | "privacy:read_original"
  | "reports:read"
  | "settings:write"
  | "users:admin"
  | "github:sync";

const MAP: Record<Role, Permission[]> = {
  admin: [
    "projects:write",
    "scans:run",
    "findings:triage",
    "privacy:read",
    "privacy:read_original",
    "reports:read",
    "settings:write",
    "users:admin",
    "github:sync",
  ],
  auditor: [
    "projects:write",
    "scans:run",
    "findings:triage",
    "privacy:read",
    "privacy:read_original",
    "reports:read",
    "github:sync",
  ],
  developer: ["scans:run", "findings:triage", "privacy:read", "reports:read"],
  viewer: ["reports:read"],
};

export function permissionsFor(role: Role | undefined): Set<Permission> {
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
