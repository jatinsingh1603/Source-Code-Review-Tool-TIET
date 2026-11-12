import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { useCurrentProject } from "@/app/project-context";
import { useSession } from "@/app/session";
import type { Permission } from "@/lib/permissions";
import { pickDefault } from "@/app/useSelectedScan";
import { useFindings, useScans } from "@/api/queries";
import { scanLabel } from "@/lib/display";
import { Icon, SEV_CLASS, useFocusTrap } from "@/components/ui";

interface Item {
  key: string;
  lead: ReactNode;
  text: string;
  go: () => void;
}

/** ⌘K / Ctrl+K command palette (COMPONENTS.md §23): findings, scans and actions. */
const PAGES: [string, string, Permission?][] = [
  ["Overview", "/"],
  ["Projects", "/projects"],
  ["Scans", "/scans"],
  ["Findings", "/findings"],
  ["Privacy Centre", "/privacy", "privacy:read"],
  ["Egress Ledger", "/privacy/ledger", "privacy:read"],
  ["Privacy policy", "/privacy/policy", "privacy:read"],
  ["Reports", "/reports", "reports:read"],
  ["Integrations", "/integrations"],
  ["Providers", "/providers"],
  ["Evaluation", "/evaluation"],
  ["Admin", "/admin", "users:admin"],
  ["Audit log", "/admin/audit", "audit:read"],
  ["Settings", "/settings"],
];

export function CommandPalette({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const navigate = useNavigate();
  const ref = useRef<HTMLDivElement>(null);
  useFocusTrap(true, ref, onClose);
  const { current } = useCurrentProject();
  const scans = useScans(current?.id).data ?? [];
  const allScansQ = useScans().data;
  const latest = pickDefault(scans);
  const term = q.trim();
  const findingsQ = useFindings(term.length >= 2 ? latest?.id : undefined, term.length >= 2 ? { q: term } : {}).data;

  const { can } = useSession();

  const items = useMemo<Item[]>(() => {
    const go = (to: string) => () => {
      onClose();
      navigate(to);
    };
    const t = term.toLowerCase();
    const findings = term.length >= 2 ? findingsQ ?? [] : [];
    const allScans = allScansQ ?? [];
    const out: Item[] = [];
    for (const f of findings.slice(0, 6)) {
      out.push({
        key: `f-${f.id}`,
        lead: <span className={`sev ${SEV_CLASS[f.severity] ?? "i"}`} />,
        text: `${f.title}${f.locations?.[0] ? ` · ${f.locations[0].path}` : ""}`,
        go: go(`/findings/${f.id}`),
      });
    }
    if (t) {
      for (const s of allScans.filter((s) => s.id.toLowerCase().includes(t) || scanLabel(s.id).toLowerCase().includes(t)).slice(0, 4)) {
        out.push({
          key: `s-${s.id}`,
          lead: <span className="pal-k">SCAN</span>,
          text: `${scanLabel(s.id)} · ${s.project_name ?? ""} ${s.privacy_level}`.trim(),
          go: go(`/scans/${s.id}`),
        });
      }
    }
    const actions: [string, string][] = [
      ["Run KavachBank demo (offline)", "/demo"],
      ["Verify egress ledger chain", latest ? `/privacy/ledger?scan=${latest.id}` : "/privacy/ledger"],
      ["Open Privacy Inspect", "/privacy/inspect"],
      ["Open findings", "/findings"],
      ["Set up a project", "/projects/new"],
      ["How CodeKavach works", "/how-it-works"],
      ["Settings", "/settings"],
    ];
    for (const [label, to] of actions) {
      if (!t || label.toLowerCase().includes(t)) {
        out.push({ key: `a-${label}`, lead: <span className="pal-k">ACTION</span>, text: label, go: go(to) });
      }
    }
    if (t) {
      // Every screen by name, so "admin" or "providers" + Enter goes there.
      for (const [label, to, perm] of PAGES) {
        if ((!perm || can(perm)) && label.toLowerCase().includes(t) && !out.some((o) => o.text === label)) {
          out.push({ key: `p-${to}`, lead: <span className="pal-k">PAGE</span>, text: label, go: go(to) });
        }
      }
    }
    return out;
  }, [findingsQ, allScansQ, term, latest, navigate, onClose, can]);

  useEffect(() => setSel(0), [term]);

  return createPortal(
    <div
      className="ck ck-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div ref={ref} className="palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <div className="pal-in">
          <Icon name="search" className="faint" />
          <input
            data-autofocus
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search findings, scans, actions"
            aria-label="Search findings, scans and actions"
            role="combobox"
            aria-expanded="true"
            aria-controls="pal-list"
            aria-activedescendant={items[sel] ? `pal-${sel}` : undefined}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setSel((s) => Math.min(items.length - 1, s + 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setSel((s) => Math.max(0, s - 1));
              } else if (e.key === "Enter") {
                e.preventDefault();
                items[sel]?.go();
              }
            }}
          />
          <span className="kbd">esc</span>
        </div>
        <div className="pal-list" id="pal-list" role="listbox">
          {items.map((it, i) => (
            <div
              key={it.key}
              id={`pal-${i}`}
              role="option"
              aria-selected={i === sel}
              className={i === sel ? "pal-i on" : "pal-i"}
              onMouseEnter={() => setSel(i)}
              onClick={it.go}
            >
              {it.lead}
              <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {it.text}
              </span>
              {i === sel && <span className="kbd">↵</span>}
            </div>
          ))}
          {items.length === 0 && <div className="pal-i faint">No matches</div>}
        </div>
      </div>
    </div>,
    document.body,
  );
}
