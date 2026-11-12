import type { Policy, PrivacyLevel } from "@/api/types";
import { atLeastAsStrict } from "./format";

/** A path rule of the privacy policy, as `GET /policy → parsed.document.path[]`. */
export interface PathRule {
  pattern: string;
  level?: PrivacyLevel | null;
  never_send?: boolean;
  language?: string | null;
  id?: string;
}

export interface PolicyDoc {
  policy_version?: number;
  path: PathRule[];
  language: { language?: string; name?: string; level?: PrivacyLevel | null; never_send?: boolean }[];
  floor?: PrivacyLevel | null;
  default_level?: PrivacyLevel | null;
}

export function policyDoc(p?: Policy | null): PolicyDoc {
  const parsed = (p?.parsed ?? {}) as { document?: Partial<PolicyDoc> };
  const d = parsed.document ?? {};
  return {
    policy_version: d.policy_version,
    path: Array.isArray(d.path) ? d.path : [],
    language: Array.isArray(d.language) ? d.language : [],
    floor: d.floor ?? null,
    default_level: d.default_level ?? null,
  };
}

/** Glob to RegExp: `**` any path, `*` within a segment, `?` one character. */
export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        const slash = glob[i + 2] === "/";
        re += slash ? "(?:.*/)?" : ".*";
        i += slash ? 2 : 1;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

export function matches(pattern: string, path: string): boolean {
  try {
    return globToRegExp(pattern).test(path);
  } catch {
    return false;
  }
}

/** The strictest of a list of levels (never-send counts as strictest of all). */
export function strictest(levels: (PrivacyLevel | "never-send")[]): PrivacyLevel | "never-send" | null {
  if (levels.includes("never-send")) return "never-send";
  let best: PrivacyLevel | null = null;
  for (const l of levels as PrivacyLevel[]) if (!best || atLeastAsStrict(l, best)) best = l;
  return best;
}

/** Serialise rules back to the policy TOML the server reads. */
export function rulesToToml(doc: PolicyDoc, rules: PathRule[]): string {
  const lines = [
    "# CodeKavach privacy policy, applied to every server scan.",
    "# Rules can only tighten the privacy level chosen for a scan; never_send keeps a path local.",
    `policy_version = ${doc.policy_version ?? 1}`,
  ];
  for (const r of rules) {
    lines.push("", "[[path]]", `pattern = ${JSON.stringify(r.pattern)}`);
    if (r.never_send) lines.push("never_send = true");
    else if (r.level) lines.push(`level = ${JSON.stringify(r.level)}`);
  }
  return lines.join("\n") + "\n";
}
