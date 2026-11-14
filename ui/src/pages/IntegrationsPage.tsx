import { useState } from "react";
import { useSelectedScan } from "@/app/useSelectedScan";
import { useSession } from "@/app/session";
import { useFindings, usePrivacy } from "@/api/queries";
import { isOpen } from "@/lib/domain";
import { GithubSyncDialog } from "@/components/GithubSyncDialog";
import { Button, Content, Icon, PageHeader, Skeleton, useToast } from "@/components/ui";

const ACTION_YML = `name: CodeKavach
on:
  pull_request:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jatinsingh1603/Source-Code-Review-Tool-TIET/action@main
        id: ck
        with:
          privacy-level: L3
          provider: none
          fail-on: high
          upload-sarif: true`;

const PRECOMMIT = `repos:
  - repo: https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET
    rev: main
    hooks:
      - id: codekavach
        args: ["--fail-on", "high"]`;

function Snippet({ title, path, text }: { title: string; path: string; text: string }) {
  const toast = useToast();
  return (
    <div>
      <div className="code-h">
        <span>
          <b>{title}</b> <span className="mono muted">{path}</span>
        </span>
        <Button
          size="sm"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(text + "\n");
              toast.success("Copied");
            } catch {
              toast.error("Copy failed", "The clipboard is not available here.");
            }
          }}
        >
          Copy
        </Button>
      </div>
      <div className="code" style={{ fontSize: 12, lineHeight: "20px" }} tabIndex={0} role="region" aria-label={title}>
        {text.split("\n").map((l, i) => (
          <div key={i} className="ln">
            <span className="n" aria-hidden="true">
              {i + 1}
            </span>
            {l}
          </div>
        ))}
      </div>
    </div>
  );
}

/** Integrations (SCREENS.md §16): GitHub, VS Code, MCP, CI badge and snippets. */
export default function IntegrationsPage() {
  const { scanId, project } = useSelectedScan();
  const findings = useFindings(scanId).data;
  const privacy = usePrivacy(scanId).data;
  const { can } = useSession();
  const [sync, setSync] = useState(false);
  const open = (findings ?? []).filter(isOpen);
  const crit = open.filter((f) => f.severity === "critical").length;
  const rows: [string, string, number][] = [
    ["Open · Critical or High", "Fix now", open.filter((f) => f.status === "open" && (f.severity === "critical" || f.severity === "high")).length],
    ["Open · Medium or Low", "Backlog", open.filter((f) => f.status === "open" && !(f.severity === "critical" || f.severity === "high")).length],
    ["Confirmed", "In progress", open.filter((f) => f.status === "confirmed").length],
    ["Fixed · awaiting rescan", "Verify", (findings ?? []).filter((f) => f.status === "fixed").length],
  ];

  return (
    <Content>
      <PageHeader crumbs={[{ label: project?.name ?? "Project", to: "/" }, { label: "Integrations" }]} title="Integrations" />
      <section className="g g-side">
        <div className="card stack s16">
          <div className="row between">
            <div className="row" style={{ gap: 10 }}>
              <span className="provlogo">GH</span>
              <div>
                <b>GitHub</b>
                <div className="xs faint">Issues through the REST API · token reference on the server</div>
              </div>
            </div>
            <div className="row">
              <span className="st sm">
                <span className="dot" />
                Manual sync
              </span>
              {can("github:sync") && (
                <Button size="sm" disabled={!scanId} onClick={() => setSync(true)}>
                  Sync findings
                </Button>
              )}
            </div>
          </div>
          <div className="swgrid">
            {(
              [
                ["Issue sync", "One issue per finding; fixed findings close their issue", true],
                ["Dry-run preview", "See what would change before calling GitHub", true],
                ["SARIF upload", "Through the GitHub Action below", true],
                ["PR check runs", "Fail the job on new findings at or above a severity", true],
                ["Review comments", "Inline on the changed line · not available yet", false],
                ["Include payload hash", "Adds the ledger record to each issue · not available yet", false],
              ] as const
            ).map(([t, d, on]) => (
              <label key={t} className="swrow">
                <input type="checkbox" className="sw" checked={on} readOnly disabled aria-readonly="true" />{" "}
                <span>
                  <b className="sm">{t}</b>
                  <br />
                  <span className="xs faint">{d}</span>
                </span>
              </label>
            ))}
          </div>
          <div>
            <div className="sub" style={{ marginBottom: 8 }}>
              Kanban column mapping · {project?.name ?? "this project"}
            </div>
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Finding status</th>
                    <th><span className="sr-only">Maps to</span></th>
                    <th>Board column</th>
                    <th className="num">Cards</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(([s, col, n]) => (
                    <tr key={s}>
                      <td className="sm">{s}</td>
                      <td className="faint">
                        <Icon name="arrow-right" />
                      </td>
                      <td className="sm">{col}</td>
                      <td className="num mono">{findings ? n : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="stack s16">
          <div className="card stack">
            <div className="row between">
              <b>VS Code extension</b>
              <span className="chip">v0.1.0</span>
            </div>
            <p className="sub">See findings inline, open Privacy Inspect for the current file and run L0 scans before you commit.</p>
            <p className="xs faint">
              Build it from <span className="mono">extensions/vscode</span> in the repository and install the VSIX.
            </p>
          </div>
          <div className="card stack">
            <div className="row between">
              <b>Local MCP server</b>
              <span className="st sm">
                <span className="dot" />
                stdio · start locally
              </span>
            </div>
            <p className="sub">Lets a local coding assistant query findings and the ledger. Read-only, no vault access (I3).</p>
            <div className="code cmd">codekavach-mcp</div>
          </div>
          <div className="card stack">
            <b>CI badge</b>
            {!findings ? (
              <Skeleton />
            ) : (
              <div className="row">
                <span className="ci-badge">
                  <span>codekavach</span>
                  <span className={crit ? "bad" : "ok"}>{crit} critical</span>
                </span>
                {privacy && (
                  <span className="ci-badge">
                    <span>privacy</span>
                    <span className={privacy.zero_leak.occurrences ? "bad" : "ok"}>
                      {privacy.level} · {privacy.zero_leak.occurrences} leaks
                    </span>
                  </span>
                )}
              </div>
            )}
            <p className="xs faint">From the latest scan. The GitHub Action exposes the same counts as step outputs.</p>
          </div>
        </div>
      </section>

      <section className="g g-2">
        <Snippet title="GitHub Action" path=".github/workflows/codekavach.yml" text={ACTION_YML} />
        <div>
          <Snippet title="Pre-commit hook" path=".pre-commit-config.yaml" text={PRECOMMIT} />
          <p className="xs faint" style={{ marginTop: 8 }}>
            Runs deterministic engines only: nothing leaves the developer's machine on commit.
          </p>
        </div>
      </section>
      {scanId && sync && <GithubSyncDialog scanId={scanId} open onClose={() => setSync(false)} />}
    </Content>
  );
}
