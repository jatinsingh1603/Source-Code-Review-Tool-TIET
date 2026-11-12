import { useState } from "react";
import { ChevronDown, ChevronRight, CloudOff, Send, ShieldCheck } from "lucide-react";
import type { PrivacyLevel, ProviderInfo } from "@/api/types";
import { LEVEL_INFO } from "@/lib/format";
import { Callout } from "@/components/ui";

/**
 * Plain-language statement of what will leave the machine for a given
 * level / provider / send combination. The wording is measured: it says what
 * is removed, what remains visible and what is recorded, and claims no secrecy.
 */
export function egressSummary(level: PrivacyLevel, provider: ProviderInfo | undefined, send: boolean): {
  tone: "success" | "info" | "warning";
  title: string;
  body: string;
  remains?: string;
} {
  if (level === "L0") {
    return {
      tone: "success",
      title: "Nothing leaves this machine",
      body: "At level L0 CodeKavach runs deterministic rules, taint analysis and engines locally and calls no model. Findings carry deterministic evidence only.",
    };
  }
  if (!send) {
    return {
      tone: "success",
      title: "Payloads are prepared but not sent",
      body: `Sanitised payloads for level ${level} are built and recorded in the ledger so you can inspect them, but no request is made to ${provider?.name ?? "the provider"}. Use this to review exactly what would be disclosed before allowing egress.`,
    };
  }
  if (provider?.local) {
    return {
      tone: "success",
      title: `Sent only to a local model (${provider.name})`,
      body: `Payloads at level ${level} go to a model running on this machine or network; nothing is sent to a third party. The ledger still records every local call so the review remains auditable.`,
    };
  }
  const base: Record<Exclude<PrivacyLevel, "L0">, string> = {
    L1: "At level L1 CodeKavach sends only finding metadata: the rule, CWE, source and sink categories and the abstract shape of the data flow. No source code, identifiers or literals are sent.",
    L2: "At level L2 CodeKavach sends an abstracted skeleton of each relevant function. Secrets and personal data become typed placeholders, every internal name becomes a neutral pseudonym and string literals keep only their shape.",
    L3: "At level L3 CodeKavach sends a minimal slice of the code around each candidate finding. Before sending, detected secrets and personal data are replaced by typed placeholders, internal names are replaced by neutral pseudonyms, comments and docstrings are removed, and string literals keep their shape but lose domain words. Public library and framework names are kept so that the model can recognise sources and sinks.",
    L4: "At level L4 CodeKavach sends the sanitised slice plus the callers and callees needed for context, with the same sanitisation as L3 on every line. This discloses more of the repository in exchange for better model recall.",
  };
  return {
    tone: level === "L4" ? "warning" : "info",
    title: `Sanitised payloads are sent to ${provider?.name ?? "the selected provider"}`,
    body: `${base[level as Exclude<PrivacyLevel, "L0">]} What is sent is recorded in the hash-chained ledger and can be read afterwards in the Privacy Centre.`,
    remains:
      level === "L1"
        ? "Still visible to the provider: the kinds of weakness suspected and the technology stack."
        : "Still visible to the provider: the structure of each slice, the technology stack through public library names, and the kind of weakness suspected.",
  };
}

export function EgressPreview({
  level,
  provider,
  send,
}: {
  level: PrivacyLevel;
  provider: ProviderInfo | undefined;
  send: boolean;
}) {
  const [open, setOpen] = useState(false);
  const s = egressSummary(level, provider, send);
  const Icon = s.tone === "success" ? (level === "L0" ? CloudOff : ShieldCheck) : Send;
  return (
    <Callout tone={s.tone} title={s.title} icon={<Icon className="h-5 w-5" aria-hidden />}>
      <p>{s.body}</p>
      {s.remains && <p className="mt-1.5">{s.remains}</p>}
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-fg hover:underline"
      >
        {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />} Technical detail
      </button>
      {open && (
        <ul className="mt-2 list-disc space-y-1 pl-5 text-xs">
          {LEVEL_INFO[level].detail.map((d) => (
            <li key={d}>{d}</li>
          ))}
          <li>Privacy steps fail closed: if any redaction step fails for a candidate, that payload is blocked, not sent.</li>
          {provider && !provider.local && level !== "L0" && (
            <li>
              Provider {provider.name} ({provider.kind}), model chosen below; trust tier: hosted.
            </li>
          )}
        </ul>
      )}
    </Callout>
  );
}
