import { useState } from "react";
import { useGithubSync } from "@/api/queries";
import type { GithubSyncResult } from "@/api/types";
import { Button, Chip, Dialog, Field, Icon, Input, Toggle, useToast } from "@/components/ui";

/** Sync findings to GitHub issues: preview first (dry run), then sync. */
export function GithubSyncDialog({
  scanId,
  open,
  onClose,
  findingIds,
}: {
  scanId: string;
  open: boolean;
  onClose: () => void;
  /** Sync only these findings (the whole scan when omitted). */
  findingIds?: string[];
}) {
  const [repo, setRepo] = useState("");
  const [tokenRef, setTokenRef] = useState("env:GITHUB_TOKEN");
  const [dryRun, setDryRun] = useState(true);
  const [result, setResult] = useState<GithubSyncResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sync = useGithubSync();
  const toast = useToast();
  // A pasted https://github.com/owner/name(.git) URL is taken as owner/name.
  const repoName = repo
    .trim()
    .replace(/^(https?:\/\/)?(www\.)?github\.com\//i, "")
    .replace(/\.git$/i, "")
    .replace(/\/+$/, "");
  const repoOk = /^[\w.-]+\/[\w.-]+$/.test(repoName);
  const only = !!findingIds?.length;
  const one = findingIds?.length === 1;

  const run = async () => {
    setError(null);
    setResult(null);
    try {
      const r = await sync.mutateAsync({ scanId, body: { repo: repoName, token_ref: tokenRef.trim(), dry_run: dryRun, ...(only ? { finding_ids: findingIds } : {}) } });
      setResult(r);
      if (!dryRun) toast.success("GitHub issues synchronised", `${r.created} created, ${r.updated} updated, ${r.closed} closed.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sync failed");
    }
  };
  const items = result?.items ?? [];

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="lg"
      title={one ? "Create GitHub issue" : "Sync to GitHub"}
      description={`${one ? "Creates or updates the issue for this finding" : only ? `Creates or updates one issue for each of the ${findingIds!.length} selected findings` : "Creates or updates one issue per finding of the scan and closes issues for fixed findings"}. CodeKavach does not change code or open pull requests.`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          <Button variant="primary" onClick={run} loading={sync.isPending} disabled={!repoOk || !tokenRef.trim()}>
            {dryRun ? "Preview" : "Sync now"}
          </Button>
        </>
      }
    >
      <div className="g g-2" style={{ gap: 12 }}>
        <Field label="Repository" required help="owner/name" error={repo && !repoOk ? "Use the owner/name form, for example kavachbank/core." : undefined}>
          {(id, d) => (
            <Input id={id} mono aria-describedby={d} value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="kavachbank/core" />
          )}
        </Field>
        <Field label="Token reference" required help="Resolved on the server, e.g. env:GITHUB_TOKEN. Do not paste a token.">
          {(id, d) => <Input id={id} mono aria-describedby={d} value={tokenRef} onChange={(e) => setTokenRef(e.target.value)} />}
        </Field>
      </div>
      <Toggle checked={dryRun} onChange={setDryRun} label="Dry run: list what would change, call nothing" />
      <div className="banner info sm">
        <Icon name="info" />
        <span>Issue bodies carry the title, rule, CWE, location and remediation, with secrets masked. Vault contents are never exported (I3).</span>
      </div>
      {error && <div className="banner bad sm">Sync failed. {error}</div>}
      {result && (
        <div className="stack s6">
          <div className="row">
            <Chip tone="fixed">{result.created} to create</Chip>
            <Chip tone="new">{result.updated} to update</Chip>
            <Chip>{result.closed} to close</Chip>
          </div>
          {result.notes?.map((n) => (
            <p key={n} className="xs faint">
              {n}
            </p>
          ))}
          <div className="tbl-wrap" style={{ maxHeight: 240, overflowY: "auto" }}>
            <table className="tbl">
              <tbody>
                {items.map((it) => (
                  <tr key={`${it.finding_id}-${it.action}`}>
                    <td className="sm mono">{it.action}</td>
                    <td className="wrap sm">{it.title}</td>
                    <td>
                      {it.url && (
                        <a className="more" href={it.url} target="_blank" rel="noreferrer noopener">
                          #{it.issue_number} <Icon name="arrow-up-right" />
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Dialog>
  );
}
