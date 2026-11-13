import * as fs from "fs";
import * as path from "path";

function inside(dir: string, file: string): boolean {
  const rel = path.relative(path.resolve(dir), path.resolve(file));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/**
 * Resolve the configured codekavach executable to an absolute path outside the
 * workspace under review. The workspace is untrusted input: a repo must not be
 * able to make the extension run a binary it ships, either through a relative
 * path or (on Windows) through the current-directory search execFile does for a
 * bare command name.
 */
export function resolveExecutable(
  executable: string,
  workspace: string,
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  const exe = executable.trim() || "codekavach";
  const refuse = (why: string): never => {
    throw new Error(
      `Refusing to run '${exe}': ${why}. Set codekavach.executable in your user settings to an absolute path.`,
    );
  };
  if (path.isAbsolute(exe)) {
    if (inside(workspace, exe)) refuse("it is inside the workspace");
    return exe;
  }
  if (exe.includes("/") || exe.includes("\\")) refuse("relative paths are not allowed");
  const pathVar = (platform === "win32" ? (env.Path ?? env.PATH) : env.PATH) ?? "";
  const exts =
    platform === "win32" ? ["", ...(env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean)] : [""];
  for (const dir of pathVar.split(path.delimiter)) {
    // Empty and relative PATH entries resolve against the workspace: skip them.
    if (!dir || !path.isAbsolute(dir) || inside(workspace, dir)) continue;
    for (const ext of exts) {
      const candidate = path.join(dir, exe + ext);
      if (isFile(candidate)) return candidate;
    }
  }
  throw new Error(`Cannot find '${exe}' on PATH. Install CodeKavach or set codekavach.executable.`);
}
