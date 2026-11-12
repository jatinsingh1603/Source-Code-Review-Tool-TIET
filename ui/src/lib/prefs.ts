/**
 * Per-user display preferences (Settings → Appearance, Language and region).
 * The API has no preferences endpoint yet, so they live in this browser only.
 */
export interface Prefs {
  density: "comfortable" | "compact";
  severityShapes: boolean;
  reduceMotion: boolean;
  language: "en-GB" | "hi";
  timeZone: string;
  dateFormat: "long" | "iso";
}

const KEY = "ck-prefs";
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
    const raw = localStorage.getItem(KEY);
    if (!raw) return DEFAULT_PREFS;
    return { ...DEFAULT_PREFS, ...(JSON.parse(raw) as Partial<Prefs>) };
  } catch {
    return DEFAULT_PREFS;
  }
}

export function writePrefs(p: Prefs): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(p));
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
}
