import type { PrivacyLevel, ProviderInfo } from "@/api/types";

/** Plain-language summary of what leaves at a level, for a provider. */
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
  const base: Record<Exclude<PrivacyLevel, "L0">, string> = {
    L4: "At level L4 CodeKavach sends no code. For each candidate it sends abstract data-flow facts and questions: the weakness class, the kinds of source and sink, and the shape of the flow between them.",
    L3: "At level L3 CodeKavach sends a minimal slice of the code around each candidate finding. Before sending, detected secrets and personal data are replaced by typed placeholders, internal names are replaced by neutral pseudonyms, comments and docstrings are removed, and string literals keep their shape but lose domain words. Public library and framework names are kept so that the model can recognise sources and sinks.",
    L2: "At level L2 CodeKavach sends the relevant files in full, with secrets and personal data replaced by typed placeholders and identifiers, literals and comments pseudonymised. This discloses more of the repository than L3 in exchange for more context.",
    L1: "At level L1 CodeKavach sends source code with only secrets and personal data replaced by typed placeholders. Identifiers, literals and comments are sent as written, so use this level only with a model you trust with your code.",
  };
  const what = base[level as Exclude<PrivacyLevel, "L0">];
  if (!send) {
    return {
      tone: "success",
      title: "Payloads are prepared but not sent",
      body: `${what} With no-send, these payloads are built and recorded in the ledger so you can inspect them, but no request is made to ${provider?.name ?? "the provider"}. Use this to review exactly what would be disclosed before allowing egress.`,
    };
  }
  if (provider?.local) {
    return {
      tone: "success",
      title: `Sent only to a local model (${provider.name})`,
      body: `${what} ${provider.kind === "mock" || provider.id === "mock" ? "The Mock provider answers on this machine, so nothing is transmitted: the ledger records what would have been sent." : "These payloads go to a model running on this machine or network; nothing is sent to a third party. The ledger still records every local call so the review remains auditable."}`,
    };
  }
  const tone: "info" | "warning" = level === "L1" || level === "L2" ? "warning" : "info";
  return {
    tone,
    title: `Sanitised payloads are sent to ${provider?.name ?? "the selected provider"}`,
    body: `${what} What is sent is recorded in the hash-chained ledger and can be read afterwards in the Privacy Centre.`,
    remains:
      level === "L4"
        ? "Still visible to the provider: the kinds of weakness suspected and the technology stack."
        : level === "L1"
          ? "Still visible to the provider: your source code apart from the redacted values, including internal names and comments."
          : "Still visible to the provider: the structure of the code sent, the technology stack through public library names, and the kind of weakness suspected.",
  };
}
