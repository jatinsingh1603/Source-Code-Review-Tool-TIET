/** A git URL the server can clone, without embedded credentials; null when valid. */
export function validateGitUrl(url: string): string | null {
  if (!url.trim()) return "Enter a repository URL.";
  if (/^git@[\w.-]+:[\w./-]+(\.git)?$/.test(url.trim())) return null;
  try {
    const u = new URL(url.trim());
    if (u.protocol !== "https:" && u.protocol !== "http:") return "Use an https:// or git@ URL.";
    if (u.username || u.password) return "Do not put credentials in the URL; configure a token on the server.";
    return null;
  } catch {
    if (/^[\w.-]+\.[a-z]{2,}\//i.test(url.trim())) return `Add https:// at the start, for example https://${url.trim()}`;
    return "This is not a valid URL.";
  }
}

/** The last path segment of a folder, repository URL or archive, as a project name. */
export function suggestName(type: string, path: string, url: string, file: File | null): string {
  if (type === "sample") return "KavachBank sample";
  const raw = type === "path" ? path : type === "git" ? url : type === "upload" ? file?.name ?? "" : "";
  const last = raw.trim().replace(/[\\/]+$/, "").split(/[\\/:]/).pop() ?? "";
  return last.replace(/\.(git|zip|tar\.gz|tgz|tar)$/i, "");
}
