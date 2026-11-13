import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { resolveExecutable } from "../src/executable.ts";

function tree(): { ws: string; bin: string } {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "ck-exe-"));
  const ws = path.join(base, "ws");
  const bin = path.join(base, "bin");
  fs.mkdirSync(path.join(ws, "tools"), { recursive: true });
  fs.mkdirSync(bin);
  for (const p of [path.join(ws, "codekavach"), path.join(ws, "tools", "x.sh"), path.join(bin, "codekavach")]) {
    fs.writeFileSync(p, "#!/bin/sh\n", { mode: 0o755 });
  }
  return { ws, bin };
}

test("bare name resolves on an absolute PATH entry outside the workspace", () => {
  const { ws, bin } = tree();
  assert.equal(resolveExecutable("codekavach", ws, { PATH: bin }, "linux"), path.join(bin, "codekavach"));
});

test("relative and empty PATH entries never pick the workspace copy", () => {
  const { ws, bin } = tree();
  const env = { PATH: ["", ".", "tools", bin].join(path.delimiter) };
  assert.equal(resolveExecutable("codekavach", ws, env, "linux"), path.join(bin, "codekavach"));
});

test("PATH entries inside the workspace are skipped", () => {
  const { ws } = tree();
  assert.throws(() => resolveExecutable("codekavach", ws, { PATH: ws }, "linux"), /Cannot find/);
});

test("relative executable paths are refused", () => {
  const { ws, bin } = tree();
  assert.throws(() => resolveExecutable("./tools/x.sh", ws, { PATH: bin }, "linux"), /relative paths/);
  assert.throws(() => resolveExecutable("tools/x.sh", ws, { PATH: bin }, "linux"), /relative paths/);
});

test("absolute executable inside the workspace is refused", () => {
  const { ws, bin } = tree();
  assert.throws(() => resolveExecutable(path.join(ws, "tools", "x.sh"), ws, { PATH: bin }, "linux"), /inside the workspace/);
});

test("absolute executable outside the workspace is used as is", () => {
  const { ws, bin } = tree();
  const exe = path.join(bin, "codekavach");
  assert.equal(resolveExecutable(exe, ws, { PATH: "" }, "linux"), exe);
});

test("settings that run code or send it out cannot be set by a workspace", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "..", "package.json"), "utf8"));
  const props = pkg.contributes.configuration.properties;
  for (const key of ["codekavach.executable", "codekavach.provider", "codekavach.privacyLevel"]) {
    assert.equal(props[key].scope, "machine", key);
  }
  assert.equal(pkg.capabilities.untrustedWorkspaces.supported, false);
});
