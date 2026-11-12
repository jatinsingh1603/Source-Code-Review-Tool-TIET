import * as vscode from "vscode";
import * as path from "path";
import { Finding, ScanData, Settings, Severity, load, scan } from "./findings";
import { showFinding } from "./webview";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function settings(): Settings {
  const c = vscode.workspace.getConfiguration("codekavach");
  return {
    executable: c.get<string>("executable", "codekavach"),
    privacyLevel: c.get<string>("privacyLevel", "L3"),
    provider: c.get<string>("provider", ""),
  };
}

function diagSeverity(s: Severity): vscode.DiagnosticSeverity {
  if (s === "critical" || s === "high") return vscode.DiagnosticSeverity.Error;
  if (s === "medium") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

type Node = { kind: "severity"; severity: Severity; items: Finding[] } | { kind: "finding"; finding: Finding };

class FindingsTree implements vscode.TreeDataProvider<Node> {
  private emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.emitter.event;
  data: ScanData | undefined;

  set(data: ScanData | undefined): void {
    this.data = data;
    this.emitter.fire();
  }

  getChildren(node?: Node): Node[] {
    if (!this.data) return [];
    if (!node) {
      return ORDER.map((severity) => ({
        kind: "severity" as const,
        severity,
        items: this.data!.findings.filter((f) => f.severity === severity),
      })).filter((n) => n.items.length > 0);
    }
    return node.kind === "severity" ? node.items.map((finding) => ({ kind: "finding" as const, finding })) : [];
  }

  getTreeItem(node: Node): vscode.TreeItem {
    if (node.kind === "severity") {
      const item = new vscode.TreeItem(`${node.severity} (${node.items.length})`, vscode.TreeItemCollapsibleState.Expanded);
      item.iconPath = new vscode.ThemeIcon(
        node.severity === "critical" || node.severity === "high" ? "error" : node.severity === "medium" ? "warning" : "info",
      );
      return item;
    }
    const f = node.finding;
    const loc = f.locations[0];
    const item = new vscode.TreeItem(f.title, vscode.TreeItemCollapsibleState.None);
    item.description = `${path.basename(loc.path)}:${loc.start_line}`;
    item.tooltip = `${f.severity}: ${f.title}\n${loc.path}:${loc.start_line}`;
    item.command = { command: "codekavach.showFinding", title: "Show", arguments: [f] };
    return item;
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("codekavach");
  const tree = new FindingsTree();
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
  status.command = "codekavach.scan";
  status.text = "$(shield) CodeKavach";
  status.show();
  context.subscriptions.push(diagnostics, status, vscode.window.registerTreeDataProvider("codekavach.findings", tree));

  const root = (): string | undefined => vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

  const publish = (root_: string, data: ScanData): void => {
    diagnostics.clear();
    const byFile = new Map<string, vscode.Diagnostic[]>();
    for (const f of data.findings) {
      const loc = f.locations[0];
      if (!loc) continue;
      const range = new vscode.Range(
        Math.max(0, loc.start_line - 1),
        Math.max(0, (loc.start_col ?? 1) - 1),
        Math.max(0, loc.end_line - 1),
        loc.end_col ? loc.end_col - 1 : Number.MAX_SAFE_INTEGER,
      );
      const d = new vscode.Diagnostic(range, `${f.title} [${f.severity}]`, diagSeverity(f.severity));
      d.source = "CodeKavach";
      d.code = f.cwe.length ? `CWE-${f.cwe[0]}` : (f.provenance?.engines?.[0]?.rule_id ?? f.id);
      const file = path.join(root_, loc.path);
      byFile.set(file, [...(byFile.get(file) ?? []), d]);
    }
    for (const [file, list] of byFile) diagnostics.set(vscode.Uri.file(file), list);
    tree.set(data);
    const s = data.summary.by_severity;
    status.text = `$(shield) CodeKavach: ${data.summary.findings_total} (${s.critical ?? 0}C ${s.high ?? 0}H)`;
  };

  const guarded = async (fn: (r: string) => Promise<void>): Promise<void> => {
    const r = root();
    if (!r) {
      void vscode.window.showWarningMessage("Open a folder to use CodeKavach.");
      return;
    }
    try {
      await fn(r);
    } catch (e) {
      void vscode.window.showErrorMessage(String((e as Error).message));
    }
  };

  context.subscriptions.push(
    vscode.commands.registerCommand("codekavach.scan", () =>
      guarded((r) =>
        Promise.resolve(
          vscode.window.withProgress(
            { location: vscode.ProgressLocation.Notification, title: "CodeKavach: scanning workspace" },
            async () => {
              const data = await scan(settings(), r);
              publish(r, data);
              void vscode.window.showInformationMessage(`CodeKavach: ${data.summary.findings_total} findings.`);
            },
          ),
        ),
      ),
    ),
    vscode.commands.registerCommand("codekavach.refresh", () =>
      guarded(async (r) => publish(r, await load(settings(), r))),
    ),
    vscode.commands.registerCommand("codekavach.showFinding", (f?: Finding) => {
      if (f) showFinding(f);
    }),
    vscode.commands.registerCommand("codekavach.setPrivacyLevel", async () => {
      const levels = [
        { label: "L0", description: "Local only, nothing leaves the machine" },
        { label: "L1", description: "Heavily abstracted" },
        { label: "L2", description: "Pseudonymised, minimal slices" },
        { label: "L3", description: "Pseudonymised slices (default)" },
        { label: "L4", description: "Redacted code with more context" },
      ];
      const pick = await vscode.window.showQuickPick(levels, { placeHolder: "Privacy level for LLM requests" });
      if (pick) {
        await vscode.workspace.getConfiguration("codekavach").update("privacyLevel", pick.label, vscode.ConfigurationTarget.Workspace);
      }
    }),
    vscode.commands.registerCommand("codekavach.openDashboard", () => {
      const url = vscode.workspace.getConfiguration("codekavach").get<string>("dashboardUrl", "http://127.0.0.1:8080");
      return vscode.env.openExternal(vscode.Uri.parse(url));
    }),
  );

  // Show the last stored scan without re-scanning; silent when there is none.
  const r = root();
  if (r) {
    load(settings(), r).then((data) => publish(r, data), () => undefined);
  }
}

export function deactivate(): void {}
