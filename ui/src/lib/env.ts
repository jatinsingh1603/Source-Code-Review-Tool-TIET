/**
 * Mock mode serves the dashboard from in-browser fixture data so it can be
 * developed and demonstrated without a running server. Enable it with
 * `VITE_MOCK=1` at build or dev time, or by opening any page with `?mock`
 * (persisted for the tab; `?mock=0` turns it off again).
 */
const KEY = "ck-mock";

export function isMockMode(): boolean {
  if (import.meta.env.VITE_MOCK === "1" || import.meta.env.VITE_MOCK === "true") return true;
  if (typeof window === "undefined") return false;
  try {
    const params = new URLSearchParams(window.location.search);
    if (params.has("mock")) {
      const v = params.get("mock");
      const on = v !== "0" && v !== "false";
      if (on) window.sessionStorage.setItem(KEY, "1");
      else window.sessionStorage.removeItem(KEY);
      return on;
    }
    return window.sessionStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}
