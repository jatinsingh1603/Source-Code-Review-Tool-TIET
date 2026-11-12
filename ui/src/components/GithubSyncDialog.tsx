import { useState } from "react";
import { ExternalLink, Github, Info } from "lucide-react";
import { useGithubSync } from "@/api/queries";
import type { GithubSyncResult } from "@/api/types";
import { Badge, Button, Callout, Dialog, Field, Input, Toggle, useToast } from "@/components/ui";

export function GithubSyncDialog({ scanId, open, onClose }: { scanId: string; open: boolean; onClose: () => void }) {
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

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="lg"
      title={
        <span className="flex items-center gap-2">
          <Github className="h-5 w-5" aria-hidden /> Sync findings to GitHub issues
        </span>
      }
      description="Creates or updates one issue per finding and closes issues for findings that are fixed. CodeKavach never modifies code or opens pull requests."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          <Button onClick={run} loading={sync.isPending} disabled={!repoOk || !tokenRef.trim()}>
            {dryRun ? "Preview" : "Sync now"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Repository" required help="owner/name" error={repo && !repoOk ? "Use the owner/name form." : undefined}>
            {(id, d) => <Input id={id} aria-describedby={d} value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="thapar-cs/kavachbank" />}
          </Field>
          <Field label="Token reference" required help="A reference resolved on the server, e.g. env:GITHUB_TOKEN. Never paste a token here.">
            {(id, d) => <Input id={id} aria-describedby={d} value={tokenRef} onChange={(e) => setTokenRef(e.target.value)} />}
          </Field>
        </div>
        <Toggle checked={dryRun} onChange={setDryRun} label="Dry run" description="Lists what would change without calling the GitHub API." />
        <Callout tone="info" icon={<Info className="h-4 w-4" />}>
          Issue bodies carry the finding title, rule, CWE, location and remediation with secrets masked. Model reasoning is included as text only.
        </Callout>
        {error && <Callout tone="danger" title="Sync failed">{error}</Callout>}
        {result && (
          <div>
            <div className="mb-2 flex flex-wrap gap-2">
              <Badge tone="success">{result.created} to create</Badge>
              <Badge tone="info">{result.updated} to update</Badge>
              <Badge tone="neutral">{result.closed} to close</Badge>
            </div>
            <ul className="max-h-60 divide-y divide-border overflow-y-auto rounded-md border border-border">
              {result.items.map((it) => (
                <li key={`${it.finding_id}-${it.action}`} className="flex items-center gap-3 px-3 py-2 text-sm">
                  <Badge tone={it.action === "create" ? "success" : it.action === "close" ? "neutral" : "info"}>{it.action}</Badge>
                  <span className="min-w-0 flex-1 truncate text-fg">{it.title}</span>
                  {it.url && (
                    <a href={it.url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-primary hover:underline">
                      #{it.issue_number} <ExternalLink className="h-3 w-3" aria-hidden />
                    </a>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Dialog>
  );
}
