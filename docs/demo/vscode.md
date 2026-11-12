# VS Code extension runbook

Surface: the CodeKavach extension (`extensions/vscode`), installed from the `.vsix` attached to a release. About five minutes.

## What to say

"The review runs where the code is. The extension is a thin client: it calls the local `codekavach` command, reads the result and shows findings as ordinary VS Code diagnostics. With no provider configured nothing leaves the laptop; with one, the privacy level decides what may leave and the egress ledger records it."

## Before the demo

- [ ] `codekavach --version` works in the terminal VS Code will use (install: [`install.md`](install.md), path 2 or 3).
- [ ] The release's `.vsix` is downloaded (draft releases are visible to repository writers only), or build it yourself:
  ```console
  $ cd extensions/vscode && npm ci && npm run build
  $ npx @vscode/vsce package --no-dependencies     # writes codekavach-0.1.0.vsix
  ```
- [ ] A sample project is open: `fixtures/kavachbank` from the repository (copy it somewhere writable first; a scan writes state next to the project).

## Steps

1. **Install.** `code --install-extension codekavach-0.1.0.vsix`, or Extensions view, "..." menu, "Install from VSIX...". Expected: a CodeKavach shield icon appears in the activity bar.
2. **Configure.** Settings, search "CodeKavach":
   - `codekavach.executable`: leave `codekavach`, or give the full path (for example the `uv tool` shim or `.venv/bin/codekavach`).
   - `codekavach.provider`: leave empty for the offline deterministic scan (safest default for the room). `agentrouter` or `ollama` add LLM review.
   - `codekavach.privacyLevel`: `L3` by default; change via the command palette, "CodeKavach: Set Privacy Level".
   - `codekavach.dashboardUrl`: `http://127.0.0.1:8080`, the Docker/`codekavach serve` dashboard.
3. **Scan.** Command palette, "CodeKavach: Scan Workspace". Expected: a progress notification, then the Findings tree fills (grouped by severity) and the Problems panel (Ctrl+Shift+M) lists the same findings with file and line; squiggles appear in the editor.
4. **Finding detail.** Click a finding in the tree (or "CodeKavach: Show Finding Details"): a panel shows the code, taxonomy references (CWE/OWASP) and remediation. Click a Problems entry to jump to the line.
5. **Dashboard.** "CodeKavach: Open Dashboard" opens `codekavach.dashboardUrl` in the browser for the full view, reports and privacy ledger. Start it first with `docker compose up -d` (see [`install.md`](install.md)).
6. **Reload.** "CodeKavach: Reload Findings From Last Scan" re-reads the stored scan without scanning, useful if the scan was run from the terminal.

## Server URL vs CLI

Today the extension talks to the **CLI only** (`codekavach scan --json`, `codekavach findings`). There is no setting for a REST server URL: `dashboardUrl` is used only to open the dashboard. Say so if asked; REST mode, quick-fix code actions and Marketplace publishing are listed as not implemented in the extension README.

## Fallback

- `codekavach` not found: set `codekavach.executable` to the absolute path, or open the terminal and run `codekavach scan <dir>` then use "Reload Findings From Last Scan".
- Extension will not install: show the same findings with `codekavach findings` in the terminal and in the dashboard.
- No network: all of the above works offline when `codekavach.provider` is empty.

## What was verified for this runbook

The `.vsix` was built locally and by the release workflow (contents: `package.json`, `dist/extension.js`, `media/shield.svg`, readme, licence). The installation into a VS Code profile was not exercised on the build machine (its `code` is the Windows launcher and hung under WSL), so rehearse steps 1 to 4 once on the demo machine.
