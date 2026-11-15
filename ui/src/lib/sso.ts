/**
 * Google sign-in helpers.
 *
 * Real server: `GET /api/v1/auth/google/login` runs the OpenID Connect flow and
 * returns the browser to `/login#sso_token=<session token>` (a fragment, so the
 * token is never sent to a server or written to an access log), or to
 * `/login?sso_error=<code>` when the sign-in failed.
 *
 * Hosted mock demo: with `VITE_GOOGLE_CLIENT_ID` set at build time the login
 * page shows a Google Identity Services button; the ID token is decoded in the
 * browser only to greet the visitor by name. Nothing is verified or stored.
 */

/** The public OAuth client ID for the hosted demo's Google button ("" = off). */
export const GOOGLE_CLIENT_ID: string = String(import.meta.env.VITE_GOOGLE_CLIENT_ID ?? "").trim();

/** Where the server starts the Google sign-in (same origin as the API). */
export const GOOGLE_LOGIN_PATH = "/api/v1/auth/google/login";

export const GSI_SCRIPT_URL = "https://accounts.google.com/gsi/client";

type LocationLike = Pick<Location, "hash" | "pathname" | "search">;
type HistoryLike = Pick<History, "replaceState">;

/**
 * The session token a completed Google sign-in left in the URL fragment, or
 * null. The fragment is removed from the address bar and the history entry so
 * the token cannot be bookmarked, shared or read back later.
 */
export function consumeSsoToken(
  loc: LocationLike = window.location,
  history: HistoryLike = window.history,
): string | null {
  const hash = loc.hash.startsWith("#") ? loc.hash.slice(1) : loc.hash;
  if (!hash.includes("sso_token=")) return null;
  const token = new URLSearchParams(hash).get("sso_token");
  history.replaceState(null, "", `${loc.pathname}${loc.search}`);
  return token && /^[A-Za-z0-9._~-]{16,512}$/.test(token) ? token : null;
}

const SSO_ERRORS: Record<string, string> = {
  state: "The Google sign-in expired or was started in another window. Try again.",
  denied: "Google sign-in was cancelled.",
  exchange: "Google could not be reached to finish the sign-in. Try again.",
  token: "Google's answer could not be verified. Try again.",
  unverified: "That Google account's email address is not verified.",
  not_allowed: "That Google account is not allowed on this server. Ask an administrator.",
  rate_limited: "Too many Google sign-in attempts. Wait a minute and try again.",
  disabled: "Your account on this server is disabled. Ask an administrator.",
};

/** A sentence for `?sso_error=<code>`, or null when the URL carries none. */
export function ssoErrorMessage(search: string): string | null {
  const code = new URLSearchParams(search).get("sso_error");
  if (code === null) return null;
  return SSO_ERRORS[code] ?? "Google sign-in failed. Try again or use a local account.";
}

export interface GoogleProfile {
  name: string;
  email: string;
}

/** Name and email from a Google ID token (JWT), read without verifying it; null if unreadable. */
export function decodeGoogleCredential(credential: string): GoogleProfile | null {
  const part = credential.split(".")[1];
  if (!part) return null;
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const bytes = Uint8Array.from(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
    const claims = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    const email = typeof claims.email === "string" ? claims.email.trim().toLowerCase() : "";
    if (!email.includes("@")) return null;
    const name = typeof claims.name === "string" && claims.name.trim() ? claims.name.trim() : email;
    return { name: name.slice(0, 128), email: email.slice(0, 256) };
  } catch {
    return null;
  }
}
