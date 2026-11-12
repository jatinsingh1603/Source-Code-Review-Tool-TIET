import * as vscode from "vscode";
import { Finding } from "./findings";

function esc(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

export function findingHtml(f: Finding): string {
  const loc = f.locations[0];
  const rule = f.provenance?.engines?.[0]?.rule_id ?? "";
  const code = (f.evidence?.[0]?.lines ?? [])
    .map((l) => {
      const hot = loc && l.number >= loc.start_line && l.number <= loc.end_line;
      return `<div class="line${hot ? " hot" : ""}"><span class="n">${l.number}</span>${esc(l.text)}</div>`;
    })
    .join("");
  const chips = [
    ...f.cwe.map((c) => `CWE-${c}`),
    ...(f.owasp ?? []).map((o) => o.id),
    rule,
  ]
    .filter(Boolean)
    .map((c) => `<span class="chip">${esc(c)}</span>`)
    .join("");
  return `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<style>
body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);padding:16px;line-height:1.5}
h1{font-size:1.25em;margin:.2em 0 .6em}
.sev{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.8em;font-weight:600;color:#fff;text-transform:uppercase}
.critical{background:#b60205}.high{background:#d93f0b}.medium{background:#b08800}.low{background:#2d7d46}.info{background:#5a6c8c}
.chip{display:inline-block;border:1px solid var(--vscode-panel-border);border-radius:4px;padding:0 6px;margin:0 6px 6px 0;font-size:.85em}
pre,.code{font-family:var(--vscode-editor-font-family);background:var(--vscode-textCodeBlock-background);border-radius:4px;padding:8px 0;overflow:auto}
.line{white-space:pre;padding:0 10px}.hot{background:rgba(255,80,60,.18)}.n{display:inline-block;width:3.2em;opacity:.55}
h2{font-size:1em;margin:1.2em 0 .3em;opacity:.8}
</style></head><body>
<span class="sev ${esc(f.severity)}">${esc(f.severity)}</span>
<h1>${esc(f.title)}</h1>
<div>${chips}</div>
<div>${esc(loc?.path ?? "")}:${loc?.start_line ?? ""} &middot; status ${esc(f.status)} &middot; confidence ${esc(f.confidence ?? "n/a")}</div>
${f.description ? `<h2>Description</h2><p>${esc(f.description)}</p>` : ""}
${code ? `<h2>Code</h2><div class="code">${code}</div>` : ""}
${f.remediation ? `<h2>Remediation</h2><p>${esc(f.remediation)}</p>` : ""}
</body></html>`;
}

let panel: vscode.WebviewPanel | undefined;

export function showFinding(f: Finding): void {
  if (!panel) {
    panel = vscode.window.createWebviewPanel("codekavachFinding", "CodeKavach finding", vscode.ViewColumn.Beside, {
      enableScripts: false,
    });
    panel.onDidDispose(() => (panel = undefined));
  }
  panel.title = `${f.severity.toUpperCase()}: ${f.title.slice(0, 40)}`;
  panel.webview.html = findingHtml(f);
  panel.reveal(vscode.ViewColumn.Beside, true);
}
