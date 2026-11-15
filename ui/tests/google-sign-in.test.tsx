import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";
import { GoogleSignIn } from "@/components/GoogleSignIn";

const noop = () => undefined;

function show() {
  return render(<GoogleSignIn onSignedIn={noop} onError={noop} fallback={<button disabled>Continue with SSO</button>} />);
}

describe("GoogleSignIn on a real server", () => {
  afterEach(() => vi.restoreAllMocks());

  it("links to the server's Google sign-in when the server has it switched on", async () => {
    vi.spyOn(api, "isMock", "get").mockReturnValue(false);
    vi.spyOn(endpoints, "authProviders").mockResolvedValue({ google: { enabled: true } });
    show();
    const link = await screen.findByTestId("google-sign-in");
    expect(link.getAttribute("href")).toBe("/api/v1/auth/google/login");
    expect(link.textContent).toContain("Sign in with Google");
    expect(screen.queryByText("Continue with SSO")).toBeNull();
  });

  it.each([{ google: { enabled: false } }, null])("keeps the fallback when the server answers %j", async (answer) => {
    vi.spyOn(api, "isMock", "get").mockReturnValue(false);
    const asked = vi.spyOn(endpoints, "authProviders").mockResolvedValue(answer);
    show();
    await waitFor(() => expect(asked).toHaveBeenCalled());
    expect(screen.getByText("Continue with SSO")).toBeTruthy();
    expect(screen.queryByTestId("google-sign-in")).toBeNull();
  });

  it("keeps the fallback when the server cannot be asked", async () => {
    vi.spyOn(api, "isMock", "get").mockReturnValue(false);
    vi.spyOn(endpoints, "authProviders").mockRejectedValue(new Error("offline"));
    show();
    await waitFor(() => expect(screen.getByText("Continue with SSO")).toBeTruthy());
    expect(screen.queryByTestId("google-sign-in")).toBeNull();
  });
});
