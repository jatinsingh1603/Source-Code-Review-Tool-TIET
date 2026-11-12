import { useEffect, useState } from "react";
import { Download, Eye, FileCode2, FileJson, FileSpreadsheet, FileText, FileType2, Github, Globe, RefreshCw } from "lucide-react";
import { useReports } from "@/api/queries";
import { fetchReport, formatLabel, saveBlob } from "@/api/endpoints";
import { PageHeader } from "@/components/layout/PageHeader";
import { Button, Card, CardBody, CardHeader, EmptyState, ErrorState, Skeleton, useToast } from "@/components/ui";
import { ScanPicker } from "@/components/ScanPicker";
import { GithubSyncDialog } from "@/components/GithubSyncDialog";
import { useSelectedScan } from "@/app/useSelectedScan";
import { useSession } from "@/app/session";
import { cn } from "@/lib/format";

const ICON: Record<string, typeof FileText> = {
  html: Globe,
  pdf: FileText,
  docx: FileType2,
  xlsx: FileSpreadsheet,
  csv: FileSpreadsheet,
  sarif: FileCode2,
  json: FileJson,
  md: FileText,
};

const DESC: Record<string, string> = {
  html: "Interactive audit report for browsers",
  pdf: "Print-ready audit report for sign-off",
  docx: "Editable report for the client deliverable",
  xlsx: "Findings workbook for tracking",
  csv: "Flat findings list",
  sarif: "SARIF 2.1.0 for GitHub code scanning and IDEs",
  json: "Complete machine-readable results",
  md: "Markdown summary for pull requests and wikis",
};

export default function ReportsPage() {
  const { scanId, setScanId, scans } = useSelectedScan();
  const reports = useReports(scanId);
  const toast = useToast();
  const { can } = useSession();
  const [busy, setBusy] = useState<string | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [syncOpen, setSyncOpen] = useState(false);

  const htmlAvailable = reports.data?.some((r) => r.format === "html" && r.available);

  const loadPreview = async () => {
    if (!scanId) return;
    setPreviewLoading(true);
    try {
      const { blob } = await fetchReport(scanId, "html");
      setPreview(await blob.text());
    } catch (e) {
      setPreview(null);
      toast.error("Preview unavailable", e instanceof Error ? e.message : undefined);
    } finally {
      setPreviewLoading(false);
    }
  };

  useEffect(() => {
    setPreview(null);
    if (htmlAvailable) void loadPreview();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, htmlAvailable]);

  const download = async (fmt: string) => {
    if (!scanId) return;
    setBusy(fmt);
    try {
      const { blob, filename } = await fetchReport(scanId, fmt);
      saveBlob(blob, filename);
      toast.success("Report downloaded", filename);
    } catch (e) {
      toast.error(`The ${formatLabel(fmt)} could not be generated`, e instanceof Error ? e.message : undefined);
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <PageHeader
        title="Reports"
        description="Professional audit reports generated from the scan results. Secrets are masked in every format."
        actions={
          <>
            <ScanPicker scans={scans} value={scanId} onChange={setScanId} />
            {can("github:sync") && scanId && (
              <Button variant="outline" icon={<Github className="h-4 w-4" />} onClick={() => setSyncOpen(true)}>
                GitHub sync
              </Button>
            )}
          </>
        }
      />
      {!scanId ? (
        <Card>
          <EmptyState title="No scans yet" description="Reports become available when a scan completes." />
        </Card>
      ) : reports.error ? (
        <Card>
          <ErrorState error={reports.error} onRetry={() => void reports.refetch()} />
        </Card>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {reports.isLoading
              ? Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-36" />)
              : reports.data!.map((r) => {
                  const Icon = ICON[r.format] ?? FileText;
                  return (
                    <Card key={r.format} className={cn("flex flex-col p-4", !r.available && "opacity-60")}>
                      <div className="flex items-start gap-3">
                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary-soft text-primary">
                          <Icon className="h-5 w-5" aria-hidden />
                        </div>
                        <div className="min-w-0">
                          <p className="font-semibold text-fg">{r.label ?? formatLabel(r.format)}</p>
                          <p className="text-xs uppercase tracking-wide text-fg-subtle">.{r.format}</p>
                        </div>
                      </div>
                      <p className="mt-2 flex-1 text-sm text-fg-muted">{r.available ? (DESC[r.format] ?? "") : (r.reason ?? "Not available on this server")}</p>
                      <Button
                        className="mt-3"
                        variant="outline"
                        size="sm"
                        icon={<Download className="h-3.5 w-3.5" />}
                        disabled={!r.available}
                        loading={busy === r.format}
                        onClick={() => download(r.format)}
                      >
                        Download
                      </Button>
                    </Card>
                  );
                })}
          </div>

          {htmlAvailable && (
            <Card className="mt-6">
              <CardHeader
                icon={<Eye className="h-4 w-4" />}
                title="HTML report preview"
                description="Rendered in a sandbox with scripts disabled"
                actions={
                  <Button size="sm" variant="ghost" icon={<RefreshCw className="h-3.5 w-3.5" />} loading={previewLoading} onClick={loadPreview}>
                    Reload
                  </Button>
                }
              />
              <CardBody>
                {previewLoading && !preview ? (
                  <Skeleton className="h-[40rem]" />
                ) : preview ? (
                  <iframe
                    title="HTML report preview"
                    sandbox=""
                    srcDoc={preview}
                    className="h-[48rem] w-full rounded-lg border border-border bg-white"
                  />
                ) : (
                  <p className="text-sm text-fg-muted">The preview could not be loaded.</p>
                )}
              </CardBody>
            </Card>
          )}
          <GithubSyncDialog scanId={scanId} open={syncOpen} onClose={() => setSyncOpen(false)} />
        </>
      )}
    </>
  );
}
