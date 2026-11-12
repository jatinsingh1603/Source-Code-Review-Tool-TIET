# CodeKavach for VS Code

Scans the open workspace with the local `codekavach` command and shows the findings in the
Problems panel and in a CodeKavach tree view. Click a finding to open a detail page with the
code, taxonomy references and remediation.

By default the extension runs deterministic analysis only, so nothing leaves your machine. Set
`codekavach.provider` (for example `agentrouter` or `ollama`) to add LLM review; what is sent is
governed by `codekavach.privacyLevel` (command: *CodeKavach: Set Privacy Level*) and recorded in
the egress ledger.

## Commands

| Command | What it does |
|---|---|
| CodeKavach: Scan Workspace | Runs `codekavach scan` then loads the findings |
| CodeKavach: Reload Findings From Last Scan | Reads the stored scan without scanning |
| CodeKavach: Set Privacy Level | Chooses L0 to L4 for this workspace |
| CodeKavach: Show Finding Details | Detail webview (also opens from the tree) |
| CodeKavach: Open Dashboard | Opens the web dashboard (`codekavach.dashboardUrl`) |

Requires the `codekavach` command on the PATH (or set `codekavach.executable`). The extension
calls the CLI with `--json` and uses `codekavach findings`; it never reads the vault.

## Build

```bash
cd extensions/vscode
npm install
npm run typecheck && npm run build
npx @vscode/vsce package --no-dependencies   # produces codekavach-0.1.0.vsix (not committed)
```

Install the file with `code --install-extension codekavach-0.1.0.vsix`.

Not implemented: REST-server mode, quick-fix code actions, marketplace publishing (needs a
publisher account).
