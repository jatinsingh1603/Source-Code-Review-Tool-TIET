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

/**
 * The path the dashboard is served under, without a trailing slash: "" for
 * `codekavach serve` at "/", "/Source-Code-Review-Tool-TIET" for the GitHub
 * Pages demo (set with `VITE_BASE` at build time). The router uses it as its
 * basename; raw URLs that bypass the router (window.open, window.location)
 * go through `withBase` and `routerPath`.
 */
export const BASE_PATH = import.meta.env.BASE_URL.replace(/\/+$/, "");

/** An in-app path ("/findings/F-1") as a URL the browser can open. */
export function withBase(path: string): string {
  return `${BASE_PATH}${path}`;
}

/** The current browser path as the router sees it, without the base. */
export function routerPath(pathname: string = window.location.pathname, base: string = BASE_PATH): string {
  if (!base) return pathname;
  if (pathname === base) return "/";
  return pathname.startsWith(`${base}/`) ? pathname.slice(base.length) : pathname;
}

/**
 * A static build of mock mode with no CodeKavach server behind it (the GitHub
 * Pages demo), so the dashboard says plainly that it shows sample data.
 */
export const HOSTED_DEMO =
  import.meta.env.PROD && (import.meta.env.VITE_MOCK === "1" || import.meta.env.VITE_MOCK === "true");

/** Where a visitor of the hosted demo learns to install the real thing. */
export const INSTALL_DOCS_URL =
  "https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/blob/main/docs/demo/install.md";
