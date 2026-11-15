# VS Code extension guide

The CodeKavach extension (`extensions/vscode`) runs the review where the code is. It is a thin client: it calls the local `codekavach` command, reads the result and shows the findings as ordinary VS Code diagnostics and in its own tree view. With no provider configured nothing leaves the machine; with one, the privacy level decides what may leave and the egress ledger records it.

## Requirements

- The `codekavach` command on the machine ([Installation](install.md)); check with `codekavach --version` in the terminal VS Code uses.
- The extension file, `codekavach-<version>.vsix`, from the release, or built from a checkout:

```console
$ cd extensions/vscode && npm ci && npm run build
$ npx @vscode/vsce package --no-dependencies     # writes codekavach-0.1.0.vsix
```

## Install

```console
$ code --install-extension codekavach-0.1.0.vsix
```

Or in VS Code: Extensions view, "..." menu, **Install from VSIX...**. A CodeKavach shield icon appears in the activity bar. The extension is not published on the Marketplace.

## Configure

Settings, search "CodeKavach":

| Setting | Meaning |
|---------|---------|
| `codekavach.executable` | `codekavach` by default. Give the full path when the command is not on VS Code's PATH (for example the `uv tool` shim or `.venv/bin/codekavach`). |
| `codekavach.provider` | Empty by default: the deterministic engines only, nothing is sent. `agentrouter`, `ollama` or another configured provider adds model review. |
| `codekavach.privacyLevel` | `L3` by default. Change it with the command **CodeKavach: Set Privacy Level**. |
| `codekavach.dashboardUrl` | Address of the dashboard that **CodeKavach: Open Dashboard** opens, for example `http://127.0.0.1:8080`. |

The code under review is untrusted, so the extension runs only in trusted workspaces, and `codekavach.executable`, `codekavach.provider` and `codekavach.privacyLevel` are read from user settings only: a repository's `.vscode/settings.json` cannot change them.

## Use

1. **Scan.** Command palette, **CodeKavach: Scan Workspace**. A progress notification appears; then the Findings tree fills, grouped by severity, the Problems panel (Ctrl+Shift+M) lists the same findings with file and line, and the affected lines are underlined in the editor. A scan writes its state next to the project, so the folder must be writable.
2. **Read a finding.** Click a finding in the tree (or run **CodeKavach: Show Finding Details**): a panel shows the code, the CWE and OWASP references and the remediation. Click a Problems entry to jump to the line.
3. **Open the dashboard.** **CodeKavach: Open Dashboard** opens `codekavach.dashboardUrl` in the browser for the full view, the reports and the egress ledger. The server must be running ([Quickstart](quickstart.md)).
4. **Reload.** **CodeKavach: Reload Findings From Last Scan** re-reads the stored scan without scanning, for example after a scan run from the terminal.

To try it on known findings, open a writable copy of the sample project `fixtures/kavachbank`.

## What the extension does not do

- It talks to the command line only (`codekavach scan --json`, `codekavach findings`). There is no setting for a REST server address: `dashboardUrl` is used only to open the dashboard.
- It offers no quick-fix code actions.
- It does not read the vault.

## Troubleshooting

| Symptom | What to do |
|---------|------------|
| "`codekavach` not found" | Set `codekavach.executable` to the absolute path. Or run `codekavach scan <dir>` in a terminal and use **Reload Findings From Last Scan**. |
| The extension will not install | The extension needs VS Code 1.85 or newer. The same findings are available from `codekavach findings` in a terminal and in the dashboard. |
| No findings after a scan | Run `codekavach scan <dir>` in a terminal to see the scan's own messages, then **Reload Findings From Last Scan**. |

## Verification status

The `.vsix` is built by the release workflow and was built locally; its contents are `package.json`, `dist/extension.js`, `media/shield.svg`, the readme and the licence. Installation into a VS Code profile and the steps under "Use" have not been exercised on the build machine, which has no desktop VS Code. Run them once on your machine before you rely on the extension.
