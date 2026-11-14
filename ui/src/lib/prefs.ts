/**
 * Per-user display preferences (Settings → Appearance, Language and region).
 * Kept in this browser (and on the server when it stores preferences); the time zone and date
 * form apply to every date the dashboard shows.
 */
import { setDisplayPrefs } from "@/lib/display";

export interface Prefs {
  density: "comfortable" | "compact";
  severityShapes: boolean;
  reduceMotion: boolean;
  language: "en-GB" | "hi";
  timeZone: string;
  dateFormat: "long" | "iso";
}

const KEY = "ck-prefs";
// Preferences belong to a user: two people sharing a browser keep their own time zone.
let owner = "";
const keyOf = (who: string) => (who ? `${KEY}:${who}` : KEY);
export const DEFAULT_PREFS: Prefs = {
  density: "compact",
  severityShapes: true,
  reduceMotion: false,
  language: "en-GB",
  timeZone: "Asia/Kolkata",
  dateFormat: "long",
};

export function readPrefs(): Prefs {
  try {
    const raw = localStorage.getItem(keyOf(owner)) ?? localStorage.getItem(KEY);
    if (!raw) return DEFAULT_PREFS;
    return { ...DEFAULT_PREFS, ...(JSON.parse(raw) as Partial<Prefs>) };
  } catch {
    return DEFAULT_PREFS;
  }
}

export function writePrefs(p: Prefs): void {
  try {
    localStorage.setItem(keyOf(owner), JSON.stringify(p));
  } catch {
    /* storage may be unavailable (private mode); the choice then lasts for this page only */
  }
  applyPreferences(p);
}

/** Reflect preferences as classes on <body class="ck">. */
export function applyPreferences(p: Prefs = readPrefs()): void {
  if (typeof document === "undefined") return;
  const b = document.body;
  b.classList.toggle("reduce-motion", p.reduceMotion);
  b.classList.toggle("no-shapes", !p.severityShapes);
  b.classList.toggle("comfortable", p.density === "comfortable");
  setDisplayPrefs(p.timeZone, p.dateFormat === "iso");
}

/** The server's copy of the preferences (GET /me/preferences) laid over `base`. */
export function prefsFromServer(server: Record<string, unknown>, base: Prefs): Prefs {
  const density = server.density;
  return {
    ...base,
    density: density === "comfortable" || density === "compact" ? density : base.density,
    reduceMotion: typeof server.reduce_motion === "boolean" ? server.reduce_motion : base.reduceMotion,
    timeZone: typeof server.time_zone === "string" && server.time_zone ? server.time_zone : base.timeZone,
    dateFormat: server.date_format === "iso" ? "iso" : server.date_format === "long" ? "long" : base.dateFormat,
  };
}

/**
 * Switch to the preferences of the user who just signed in (or none, after signing out): their
 * copy in this browser at once, then the server's, which follows them from browser to browser.
 */
export async function loadPrefsFor(
  username: string | null,
  fetchServer: () => Promise<Record<string, unknown> | null>,
): Promise<void> {
  owner = username ?? "";
  if (!username) {
    applyPreferences(DEFAULT_PREFS);
    return;
  }
  applyPreferences();
  const server = await fetchServer().catch(() => null);
  if (!server) return;
  // Only the region follows the user from the server: density stays this browser's choice (the
  // server's default, comfortable, would otherwise override the compact layout of the design).
  const mine = readPrefs();
  const region = prefsFromServer(server, mine);
  writePrefs({ ...mine, timeZone: region.timeZone, dateFormat: region.dateFormat });
}
