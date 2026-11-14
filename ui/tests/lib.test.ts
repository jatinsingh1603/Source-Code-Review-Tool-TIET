import { describe, expect, it } from "vitest";
import { countPlaceholders, segmentLines } from "@/lib/markup";
import { applyFiltersToParams, filtersFromParams, toggleListValue } from "@/lib/filters";
import { cvssRating, parseVector } from "@/lib/cvss";
import { atLeastAsStrict, confidenceFraction, LEVELS_BY_STRICTNESS } from "@/lib/format";
import { egressSummary } from "@/lib/egress";
import { suggestName, validateGitUrl } from "@/lib/validate";
import { permissionsFor } from "@/lib/permissions";
import { fmtDate, fmtLong, languageLabel, setDisplayPrefs } from "@/lib/display";
import { pathRulesOf } from "@/lib/policy";
import { ApiError } from "@/api/client";
import { errorText } from "@/components/ui/Feedback";
import { providerName } from "@/lib/domain";
import type { ProviderInfo } from "@/api/types";

describe("providerName", () => {
  it("names built-in providers before the provider list has loaded", () => {
    expect(providerName("mock")).toBe("Mock (offline)");
    expect(providerName("agentrouter", undefined)).toBe("AgentRouter (OpenAI Responses)");
    expect(providerName("custom-gw")).toBe("custom-gw");
  });
});

describe("segmentLines", () => {
  it("applies markup ranges and splits across lines", () => {
    const text = "a = SECRET\nb";
    const lines = segmentLines(text, [{ kind: "secret", start: 4, end: 12, side: "original" }]);
    expect(lines[0]).toEqual([{ text: "a = " }, { text: "SECRET", kind: "secret", label: undefined }]);
    expect(lines[1]).toEqual([{ text: "b", kind: "secret", label: undefined }]);
  });
  it("lets the first overlapping range win", () => {
    const lines = segmentLines("abcdef", [
      { kind: "pii", start: 0, end: 4, side: "payload" },
      { kind: "identifier", start: 2, end: 6, side: "payload" },
    ]);
    expect(lines[0]!.map((s) => s.kind)).toEqual(["pii", "identifier"]);
  });
  it("counts placeholders by type once each", () => {
    expect(countPlaceholders("<SECRET_AWS_1> <SECRET_AWS_1> <PII_EMAIL_2> <SECRET_AWS_3>")).toEqual({
      SECRET_AWS: 2,
      PII_EMAIL: 1,
    });
  });
});

describe("filters in the URL", () => {
  it("round-trips every filter", () => {
    const f = { severity: "critical,high", status: "open", cwe: "CWE-89", q: "sql" };
    const p = applyFiltersToParams(new URLSearchParams("scan=s1"), f);
    expect(p.get("scan")).toBe("s1");
    expect(filtersFromParams(p)).toEqual(f);
    expect(filtersFromParams(applyFiltersToParams(p, {}))).toEqual({});
  });
  it("toggles list values", () => {
    expect(toggleListValue(undefined, "high")).toBe("high");
    expect(toggleListValue("high,low", "high")).toBe("low");
    expect(toggleListValue("high", "high")).toBeUndefined();
  });
});

describe("CVSS", () => {
  it("parses a v4 vector", () => {
    const v = parseVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    expect(v?.version).toBe("4.0");
    expect(v?.metrics[0]).toMatchObject({ name: "Attack vector", label: "Network" });
  });
  it("rates scores", () => {
    expect(cvssRating(9.3)).toBe("Critical");
    expect(cvssRating(7)).toBe("High");
    expect(cvssRating(0)).toBe("None");
    expect(parseVector("garbage")).toBeNull();
  });
});

describe("privacy levels", () => {
  it("orders by strictness, not by digit", () => {
    expect(LEVELS_BY_STRICTNESS).toEqual(["L0", "L4", "L3", "L2", "L1"]);
    expect(atLeastAsStrict("L4", "L3")).toBe(true);
    expect(atLeastAsStrict("L1", "L3")).toBe(false);
    expect(atLeastAsStrict("L0", "L4")).toBe(true);
  });
  const hosted = { id: "agentrouter", name: "AgentRouter", local: false } as ProviderInfo;
  const local = { id: "ollama", name: "Ollama", local: true } as ProviderInfo;
  it("says nothing is sent at L0 or when sending is off", () => {
    expect(egressSummary("L0", hosted, true).title).toMatch(/Nothing leaves/);
    expect(egressSummary("L3", hosted, false).title).toMatch(/not sent/);
  });
  it("names the local model case", () => {
    expect(egressSummary("L3", local, true).body).toMatch(/nothing is sent to a third party/);
  });
  it("still explains the level with a local model or a dry run", () => {
    expect(egressSummary("L1", local, true).body).toMatch(/only secrets and personal data/);
    expect(egressSummary("L3", local, true).body).toMatch(/minimal slice/);
    expect(egressSummary("L2", hosted, false).body).toMatch(/pseudonymised/);
  });
  it("describes the hosted levels and what remains visible", () => {
    const l3 = egressSummary("L3", hosted, true);
    expect(l3.body).toMatch(/minimal slice/);
    expect(l3.remains).toMatch(/Still visible/);
    expect(egressSummary("L4", hosted, true).body).toMatch(/no code/);
    expect(egressSummary("L4", hosted, true).body).toMatch(/fails closed/);
    expect(egressSummary("L1", hosted, true).tone).toBe("warning");
  });
});

describe("misc helpers", () => {
  it("validates git URLs", () => {
    expect(validateGitUrl("https://github.com/o/r.git")).toBeNull();
    expect(validateGitUrl("git@github.com:o/r.git")).toBeNull();
    expect(validateGitUrl("https://user:pw@host/r.git")).toMatch(/credentials/);
    expect(validateGitUrl("ftp://x")).toMatch(/https/);
  });
  it("maps confidence words", () => {
    expect(confidenceFraction("medium")).toBe(0.6);
    expect(confidenceFraction(0.9)).toBe(0.9);
    expect(confidenceFraction(80)).toBe(0.8);
  });
  it("hides privacy and admin from viewers", () => {
    const v = permissionsFor("viewer");
    expect(v.has("privacy:read")).toBe(false);
    expect(v.has("users:admin")).toBe(false);
    expect(permissionsFor("admin").has("users:admin")).toBe(true);
  });
});

describe("languageLabel", () => {
  it("writes inventory language ids the way people do", () => {
    expect(languageLabel("javascript")).toBe("JavaScript");
    expect(languageLabel("yaml")).toBe("YAML");
    expect(languageLabel("python")).toBe("Python");
    expect(languageLabel("unknown")).toBe("Other");
    expect(languageLabel(null)).toBe("");
  });
});

describe("pathRulesOf", () => {
  it("reads a path-only policy and refuses other axes", () => {
    const toml =
      'policy_version = 1\n\n[[path]]\npattern = "**/secrets/**"\nnever_send = true\n\n[[path]]\npattern = "**/payments/**"\nlevel = "L3"\n';
    expect(pathRulesOf(toml)).toEqual([
      { pattern: "**/secrets/**", never_send: true, level: null },
      { pattern: "**/payments/**", never_send: false, level: "L3" },
    ]);
    expect(pathRulesOf(toml + '\n[[language]]\nlanguage = "sql"\nlevel = "L4"\n')).toBeNull();
    expect(pathRulesOf('[privacy]\nlevel = "L3"\n')).toBeNull();
  });
});

describe("suggestName", () => {
  it("takes the folder, repository or archive name", () => {
    expect(suggestName("path", "fixtures/polyglot/", "", null)).toBe("polyglot");
    expect(suggestName("git", "", "https://github.com/octocat/Hello-World.git", null)).toBe("Hello-World");
    expect(suggestName("git", "", "git@github.com:org/repo.git", null)).toBe("repo");
    expect(suggestName("upload", "", "", new File(["x"], "demo-shopfront.zip"))).toBe("demo-shopfront");
    expect(suggestName("path", "", "", null)).toBe("");
    expect(validateGitUrl("github.com/octocat/Hello-World")).toMatch(/^Add https:\/\//);
  });
});

describe("errorText", () => {
  it("words a 403 for a person, not as a permission code", () => {
    const e = new ApiError(403, "forbidden", "the role developer lacks the permission privacy:read_original");
    const text = errorText(e);
    expect(text).toMatch(/^Your role \(developer\) cannot open this: it needs the Auditor role/);
    expect(text).not.toContain("privacy:read_original");
  });
});

describe("display preferences", () => {
  it("dates follow the chosen time zone and date form", () => {
    const at = "2026-11-14T11:46:00Z";
    try {
      expect(fmtLong(at)).toBe("14 Nov 2026, 17:16 IST");
      setDisplayPrefs("Australia/Sydney", false);
      expect(fmtLong(at)).toBe("14 Nov 2026, 22:46 AEDT");
      setDisplayPrefs("UTC", true);
      expect(fmtDate(at)).toBe("2026-11-14");
      expect(fmtLong(at)).toMatch(/^2026-11-14 11:46/);
    } finally {
      setDisplayPrefs("Asia/Kolkata", false);
    }
  });
});
