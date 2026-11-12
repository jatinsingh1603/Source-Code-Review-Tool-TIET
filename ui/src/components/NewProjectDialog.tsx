import { useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Archive, FlaskConical, FolderOpen, GitBranch, UploadCloud, X } from "lucide-react";
import { useCreateProject, qk } from "@/api/queries";
import { uploadArchive } from "@/api/endpoints";
import type { SourceType } from "@/api/types";
import { Button, Dialog, Field, Input, ProgressBar, useToast } from "@/components/ui";
import { useCurrentProject } from "@/app/project-context";
import { cn } from "@/lib/format";

export const MAX_UPLOAD_MB = 200;

const SOURCES: { type: SourceType; label: string; icon: typeof GitBranch; hint: string }[] = [
  { type: "sample", label: "Sample app", icon: FlaskConical, hint: "KavachBank, a deliberately vulnerable banking app" },
  { type: "git", label: "Git URL", icon: GitBranch, hint: "Clone a repository over HTTPS" },
  { type: "path", label: "Local path", icon: FolderOpen, hint: "A directory on the CodeKavach server" },
  { type: "upload", label: "Upload archive", icon: Archive, hint: `.zip or .tar.gz up to ${MAX_UPLOAD_MB} MB` },
];

export function validateGitUrl(url: string): string | null {
  if (!url.trim()) return "Enter a repository URL.";
  if (/^git@[\w.-]+:[\w./-]+(\.git)?$/.test(url.trim())) return null;
  try {
    const u = new URL(url.trim());
    if (u.protocol !== "https:" && u.protocol !== "http:") return "Use an https:// or git@ URL.";
    if (u.username || u.password) return "Do not put credentials in the URL; configure a token on the server.";
    return null;
  } catch {
    return "This is not a valid URL.";
  }
}

export function NewProjectDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [type, setType] = useState<SourceType>("sample");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [url, setUrl] = useState("");
  const [ref, setRef] = useState("main");
  const [path, setPath] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const abortRef = useRef<AbortController | null>(null);
  const create = useCreateProject();
  const toast = useToast();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { setCurrentId } = useCurrentProject();

  const reset = () => {
    setName("");
    setDescription("");
    setUrl("");
    setPath("");
    setFile(null);
    setProgress(null);
    setErrors({});
  };

  const close = () => {
    abortRef.current?.abort();
    reset();
    onClose();
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const errs: Record<string, string> = {};
    const finalName = name.trim() || (type === "sample" ? "KavachBank (sample)" : "");
    if (!finalName) errs.name = "Give the project a name.";
    if (type === "git") {
      const g = validateGitUrl(url);
      if (g) errs.url = g;
    }
    if (type === "path" && !path.trim()) errs.path = "Enter an absolute path on the server.";
    if (type === "upload") {
      if (!file) errs.file = "Choose an archive to upload.";
      else if (file.size > MAX_UPLOAD_MB * 1024 * 1024)
        errs.file = `This file is ${(file.size / 1024 / 1024).toFixed(0)} MB; the limit is ${MAX_UPLOAD_MB} MB.`;
      else if (!/\.(zip|tar|tar\.gz|tgz)$/i.test(file.name)) errs.file = "Use a .zip, .tar or .tar.gz archive.";
    }
    setErrors(errs);
    if (Object.keys(errs).length) return;
    try {
      const project = await create.mutateAsync({
        name: finalName,
        description: description.trim() || undefined,
        source:
          type === "git"
            ? { type, url: url.trim(), ref: ref.trim() || undefined }
            : type === "path"
              ? { type, path: path.trim() }
              : { type },
      });
      if (type === "upload" && file) {
        abortRef.current = new AbortController();
        setProgress(0);
        await uploadArchive(project.id, file, setProgress, abortRef.current.signal);
        void qc.invalidateQueries({ queryKey: qk.projects });
      }
      toast.success("Project created", `${project.name} is ready to scan.`);
      setCurrentId(project.id);
      close();
      navigate(`/projects/${project.id}`);
    } catch (err) {
      setProgress(null);
      if (err instanceof DOMException && err.name === "AbortError") return;
      toast.error("Could not create the project", err instanceof Error ? err.message : undefined);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={close}
      size="lg"
      title="New project"
      description="Connect a code base. Source code stays on the CodeKavach server; nothing is sent anywhere until you start a scan."
      footer={
        <>
          <Button variant="outline" onClick={close}>
            Cancel
          </Button>
          <Button type="submit" form="new-project" loading={create.isPending || progress !== null}>
            Create project
          </Button>
        </>
      }
    >
      <form id="new-project" onSubmit={submit} className="space-y-5" noValidate>
        <fieldset>
          <legend className="ck-label">Source</legend>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {SOURCES.map((s) => (
              <button
                key={s.type}
                type="button"
                aria-pressed={type === s.type}
                onClick={() => setType(s.type)}
                className={cn(
                  "flex flex-col items-start gap-1.5 rounded-lg border p-3 text-left transition-colors",
                  type === s.type ? "border-primary bg-primary-soft/60 ring-1 ring-primary" : "border-border hover:bg-surface-2",
                )}
              >
                <s.icon className={cn("h-5 w-5", type === s.type ? "text-primary" : "text-fg-subtle")} aria-hidden />
                <span className="text-sm font-semibold text-fg">{s.label}</span>
                <span className="text-xs leading-snug text-fg-muted">{s.hint}</span>
              </button>
            ))}
          </div>
        </fieldset>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" required={type !== "sample"} error={errors.name}>
            {(id, d) => (
              <Input
                id={id}
                aria-describedby={d}
                value={name}
                placeholder={type === "sample" ? "KavachBank (sample)" : "e.g. payments-api"}
                onChange={(e) => setName(e.target.value)}
              />
            )}
          </Field>
          <Field label="Description">
            {(id) => <Input id={id} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" />}
          </Field>
        </div>

        {type === "git" && (
          <div className="grid gap-4 sm:grid-cols-[1fr_10rem]">
            <Field label="Repository URL" required error={errors.url} help="Public HTTPS URL, or a host the server holds credentials for.">
              {(id, d) => (
                <Input id={id} aria-describedby={d} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/org/repo.git" />
              )}
            </Field>
            <Field label="Branch or tag">
              {(id) => <Input id={id} value={ref} onChange={(e) => setRef(e.target.value)} />}
            </Field>
          </div>
        )}
        {type === "path" && (
          <Field label="Server path" required error={errors.path} help="An absolute directory path readable by the CodeKavach server.">
            {(id, d) => <Input id={id} aria-describedby={d} value={path} onChange={(e) => setPath(e.target.value)} placeholder="/srv/code/payments-api" />}
          </Field>
        )}
        {type === "upload" && (
          <Field label="Archive" required error={errors.file}>
            {(id, d) => (
              <div>
                <label
                  htmlFor={id}
                  className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-border bg-surface-2/50 px-4 py-6 text-center hover:border-primary"
                >
                  <UploadCloud className="h-7 w-7 text-fg-subtle" aria-hidden />
                  <span className="text-sm text-fg">
                    {file ? (
                      <span className="font-medium">
                        {file.name} · {(file.size / 1024 / 1024).toFixed(1)} MB
                      </span>
                    ) : (
                      <>
                        <span className="font-medium text-primary">Choose a file</span> or drop it here
                      </>
                    )}
                  </span>
                  <span className="text-xs text-fg-subtle">.zip, .tar or .tar.gz, at most {MAX_UPLOAD_MB} MB</span>
                </label>
                <input
                  id={id}
                  aria-describedby={d}
                  type="file"
                  accept=".zip,.tar,.gz,.tgz"
                  className="sr-only"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
                {progress !== null && (
                  <div className="mt-3 flex items-center gap-3">
                    <ProgressBar value={progress * 100} label="Upload progress" />
                    <span className="w-10 text-right text-xs tabular-nums text-fg-muted">{Math.round(progress * 100)}%</span>
                    <button type="button" aria-label="Cancel upload" onClick={() => abortRef.current?.abort()} className="text-fg-subtle hover:text-danger">
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                )}
              </div>
            )}
          </Field>
        )}
      </form>
    </Dialog>
  );
}
