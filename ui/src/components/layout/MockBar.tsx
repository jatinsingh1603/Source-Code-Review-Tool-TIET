import { api } from "@/api/client";
import { HOSTED_PREVIEW, INSTALL_DOCS_URL } from "@/lib/env";

/**
 * The slim strip that says the dashboard is showing sample data. The hosted
 * preview (a static mock build, such as GitHub Pages) also links to the install
 * guide, because nothing there scans real code.
 */
export function MockBar() {
  if (!api.isMock) return null;
  if (HOSTED_PREVIEW) {
    return (
      <div className="mockbar" role="note">
        Hosted preview · sample data, runs in your browser ·{" "}
        <a href={INSTALL_DOCS_URL} target="_blank" rel="noreferrer noopener">
          install for real scans
        </a>
      </div>
    );
  }
  return (
    <div className="mockbar" role="note">
      Sample data mode: the dashboard is showing built-in sample data, not a live server.
    </div>
  );
}
