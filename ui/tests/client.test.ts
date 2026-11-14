import { describe, expect, it, vi } from "vitest";
import { ApiClient, ApiError, humanizeValidation, parseErrorEnvelope } from "@/api/client";
import { normaliseFormats, unwrapList } from "@/api/endpoints";

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("parseErrorEnvelope", () => {
  it("reads the {error:{code,message}} envelope", () => {
    expect(parseErrorEnvelope(409, { error: { code: "scan_active", message: "cancel first" } })).toMatchObject({
      code: "scan_active",
      message: "cancel first",
    });
  });
  it("reads FastAPI validation errors", () => {
    const env = parseErrorEnvelope(422, { detail: [{ loc: ["body", "name"], msg: "Field required" }] });
    expect(env.code).toBe("validation_error");
    expect(env.message).toBe("Name is required.");
  });
  it("words the server's validation messages for people", () => {
    const env = parseErrorEnvelope(422, {
      error: { code: "validation_error", message: "body.username: String should have at most 64 characters" },
    });
    expect(env.message).toBe("Username is too long (64 characters at most).");
    expect(humanizeValidation("path.seq: Input should be a valid integer, unable to parse string as an integer")).toBe(
      "Payload number must be a whole number.",
    );
    expect(humanizeValidation("body.name: Value error, name is empty")).toBe("Name: name is empty.");
  });
  it("falls back to a status message", () => {
    expect(parseErrorEnvelope(500, null).message).toMatch(/server/);
  });
});

describe("ApiClient", () => {
  it("sends the bearer token and JSON body", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(200, { ok: true }));
    const c = new ApiClient(fetchImpl as unknown as typeof fetch, null);
    c.setToken("tok");
    await c.post("/projects", { name: "x" });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/projects");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok");
    expect(init.body).toBe(JSON.stringify({ name: "x" }));
  });

  it("builds query strings without empty values", () => {
    const c = new ApiClient(vi.fn() as unknown as typeof fetch, null);
    expect(c.url("/scans/s1/findings", { severity: "high", q: "", cwe: undefined })).toBe(
      "/api/v1/scans/s1/findings?severity=high",
    );
  });

  it("maps errors to ApiError", async () => {
    const c = new ApiClient((async () =>
      jsonResponse(404, { error: { code: "not_found", message: "scan not found" } })) as unknown as typeof fetch, null);
    await expect(c.get("/scans/x")).rejects.toMatchObject({ status: 404, code: "not_found", message: "Scan not found." });
  });

  it("clears the token and calls the handler on 401", async () => {
    const c = new ApiClient((async () => jsonResponse(401, { detail: "expired" })) as unknown as typeof fetch, null);
    c.setToken("tok");
    const onUnauth = vi.fn();
    c.onUnauthorised(onUnauth);
    await expect(c.get("/auth/me")).rejects.toBeInstanceOf(ApiError);
    expect(onUnauth).toHaveBeenCalledOnce();
    expect(c.getToken()).toBeNull();
  });

  it("does not treat a failed login as an expired session", async () => {
    const c = new ApiClient((async () => jsonResponse(401, { detail: "bad" })) as unknown as typeof fetch, null);
    const onUnauth = vi.fn();
    c.onUnauthorised(onUnauth);
    await expect(c.post("/auth/login", {})).rejects.toBeInstanceOf(ApiError);
    expect(onUnauth).not.toHaveBeenCalled();
  });

  it("surfaces the Retry-After hint on 429", async () => {
    const c = new ApiClient((async () => jsonResponse(429, { detail: "slow down" }, { "Retry-After": "7" })) as unknown as typeof fetch, null);
    await expect(c.get("/stats")).rejects.toMatchObject({ retryAfter: 7, message: "Slow down. Try again in 7 s." });
  });

  it("reports a network failure as status 0", async () => {
    const c = new ApiClient((async () => {
      throw new TypeError("failed");
    }) as unknown as typeof fetch, null);
    await expect(c.get("/health")).rejects.toMatchObject({ status: 0, code: "network_error" });
  });
});

describe("response normalisation", () => {
  it("unwraps bare and wrapped lists", () => {
    expect(unwrapList([1, 2])).toEqual([1, 2]);
    expect(unwrapList({ entries: [3] }, "entries")).toEqual([3]);
    expect(unwrapList({ items: [4] })).toEqual([4]);
    expect(unwrapList(null)).toEqual([]);
  });
  it("normalises report formats from strings and objects", () => {
    expect(normaliseFormats(["html"])).toEqual([{ format: "html", label: "HTML report", available: true }]);
    expect(normaliseFormats(["md", "markdown", "html"]).map((f) => f.format)).toEqual(["html", "md"]);
    const [f] = normaliseFormats({ formats: [{ format: "pdf", available: false, reason: "no renderer" }] });
    expect(f).toMatchObject({ format: "pdf", available: false, reason: "no renderer" });
  });
});
