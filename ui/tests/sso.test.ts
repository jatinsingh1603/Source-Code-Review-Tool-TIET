import { describe, expect, it, vi } from "vitest";
import { consumeSsoToken, decodeGoogleCredential, ssoErrorMessage } from "@/lib/sso";

const TOKEN = "ckt_abcDEF0123456789-_abcDEF0123456789";

function b64url(value: unknown): string {
  return btoa(unescape(encodeURIComponent(JSON.stringify(value))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

describe("consumeSsoToken", () => {
  it("returns the token from the fragment and clears the fragment", () => {
    const replaceState = vi.fn();
    const token = consumeSsoToken({ hash: `#sso_token=${TOKEN}`, pathname: "/login", search: "" }, { replaceState });
    expect(token).toBe(TOKEN);
    expect(replaceState).toHaveBeenCalledWith(null, "", "/login");
  });

  it("keeps the query string when it clears the fragment", () => {
    const replaceState = vi.fn();
    consumeSsoToken({ hash: `#sso_token=${TOKEN}`, pathname: "/base/login", search: "?x=1" }, { replaceState });
    expect(replaceState).toHaveBeenCalledWith(null, "", "/base/login?x=1");
  });

  it("leaves other fragments alone", () => {
    const replaceState = vi.fn();
    expect(consumeSsoToken({ hash: "#section", pathname: "/login", search: "" }, { replaceState })).toBeNull();
    expect(consumeSsoToken({ hash: "", pathname: "/login", search: "" }, { replaceState })).toBeNull();
    expect(replaceState).not.toHaveBeenCalled();
  });

  it("drops a malformed token but still clears the fragment", () => {
    const replaceState = vi.fn();
    const hash = "#sso_token=<script>alert(1)</script>";
    expect(consumeSsoToken({ hash, pathname: "/login", search: "" }, { replaceState })).toBeNull();
    expect(replaceState).toHaveBeenCalledTimes(1);
  });

  it("never reads a token from the query string", () => {
    const replaceState = vi.fn();
    const loc = { hash: "", pathname: "/login", search: `?sso_token=${TOKEN}` };
    expect(consumeSsoToken(loc, { replaceState })).toBeNull();
  });
});

describe("ssoErrorMessage", () => {
  it("is null without the parameter", () => {
    expect(ssoErrorMessage("")).toBeNull();
    expect(ssoErrorMessage("?mock=1")).toBeNull();
  });
  it("words known codes and falls back for unknown ones", () => {
    expect(ssoErrorMessage("?sso_error=not_allowed")).toMatch(/not allowed/);
    expect(ssoErrorMessage("?sso_error=state")).toMatch(/Try again/);
    expect(ssoErrorMessage("?sso_error=%3Cb%3E")).toBe("Google sign-in failed. Try again or use a local account.");
  });
});

describe("decodeGoogleCredential", () => {
  it("reads name and email from the payload", () => {
    const jwt = `${b64url({ alg: "RS256" })}.${b64url({ email: "Asha@Example.edu", name: "Asha Rao ✓" })}.sig`;
    expect(decodeGoogleCredential(jwt)).toEqual({ name: "Asha Rao ✓", email: "asha@example.edu" });
  });
  it("uses the email as the name when there is none", () => {
    const jwt = `h.${b64url({ email: "a@b.co" })}.s`;
    expect(decodeGoogleCredential(jwt)).toEqual({ name: "a@b.co", email: "a@b.co" });
  });
  it("is null for anything unreadable", () => {
    expect(decodeGoogleCredential("")).toBeNull();
    expect(decodeGoogleCredential("a.b.c")).toBeNull();
    expect(decodeGoogleCredential(`h.${b64url({ name: "No Email" })}.s`)).toBeNull();
  });
});
