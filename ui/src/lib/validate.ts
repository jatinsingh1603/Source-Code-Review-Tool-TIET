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
    return "This is not a valid URL.";
  }
}
