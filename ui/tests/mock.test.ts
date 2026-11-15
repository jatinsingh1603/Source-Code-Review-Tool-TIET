import { describe, expect, it } from "vitest";
import { ApiClient } from "@/api/client";
import { optional } from "@/api/endpoints";
import { installMockBackend } from "@/mock/backend";

async function signedIn(): Promise<ApiClient> {
  const client = new ApiClient(() => Promise.reject(new Error("mock mode must not fetch")), null);
  installMockBackend(client);
  // pragma: allowlist nextline secret - the documented preview sign-in of the mock backend
  const { token } = await client.post<{ token: string }>("/auth/login", { username: "admin", password: "kavach-admin" });
  client.setToken(token);
  return client;
}

describe("mock backend policy routes", () => {
  it("serves the policy document at /policy", async () => {
    const client = await signedIn();
    const policy = await client.get<{ toml: string }>("/policy");
    expect(typeof policy.toml).toBe("string");
  });

  it("leaves /policy/explain, /policy/templates and /policy/validate unanswered", async () => {
    // The Privacy Centre and Policy pages crashed when these returned the policy document.
    const client = await signedIn();
    expect(await optional(client.get("/policy/explain", { path: "src/app.py" }))).toBeNull();
    expect(await optional(client.get("/policy/templates"))).toBeNull();
    expect(await optional(client.post("/policy/validate", { toml: "" }))).toBeNull();
  });
});

describe("mock backend audit log", () => {
  it("lists a seeded trail, newest first, and records sign-ins", async () => {
    const client = await signedIn();
    const log = await client.get<{ chain_intact: boolean; total: number; events: { at: string; actor: string; action: string }[] }>(
      "/audit",
      { limit: 50, offset: 0 },
    );
    expect(log.chain_intact).toBe(true);
    expect(log.total).toBeGreaterThan(5);
    expect(log.events[0]).toMatchObject({ actor: "admin", action: "auth.login" });
    const times = log.events.map((e) => e.at);
    expect([...times].sort().reverse()).toEqual(times);
  });

  it("pages through the log with limit and offset", async () => {
    const client = await signedIn();
    const all = await client.get<{ total: number; events: unknown[] }>("/audit", { limit: 1000, offset: 0 });
    const tail = await client.get<{ events: unknown[] }>("/audit", { limit: 1000, offset: all.total });
    expect(all.events).toHaveLength(all.total);
    expect(tail.events).toHaveLength(0);
  });
});
