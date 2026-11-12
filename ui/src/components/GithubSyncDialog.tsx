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
  /** Limit the preview to these findings (the server syncs the whole scan). */
  findingIds?: string[];
}) {
  const [repo, setRepo] = useState("");
  const [tokenRef, setTokenRef] = useState("env:GITHUB_TOKEN");
  const [dryRun, setDryRun] = useState(true);
  const [result, setResult] = useState<GithubSyncResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sync = useGithubSync();
  const toast = useToast();
  const repoOk = /^[\w.-]+\/[\w.-]+$/.test(repo.trim());

  const run = async () => {
    setError(null);
    setResult(null);
    try {
      const r = await sync.mutateAsync({ scanId, body: { repo: repo.trim(), token_ref: tokenRef.trim(), dry_run: dryRun } });
      setResult(r);
      if (!dryRun) toast.success("GitHub issues synchronised", `${r.created} created, ${r.updated} updated, ${r.closed} closed.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sync failed");
    }
  };
  const items = result ? result.items.filter((i) => !findingIds?.length || findingIds.includes(i.finding_id)) : [];

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="lg"
      title="Sync to GitHub"
      description="Creates or updates one issue per finding and closes issues for fixed findings. CodeKavach does not change code or open pull requests."
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
        <Field label="Repository" required help="owner/name" error={repo && !repoOk ? "Use the owner/name form." : undefined}>
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
