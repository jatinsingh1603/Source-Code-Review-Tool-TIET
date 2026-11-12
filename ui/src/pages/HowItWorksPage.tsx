import { Link } from "react-router-dom";
import { ButtonLink, Content, Icon } from "@/components/ui";

function Stand({ n, title, sub }: { n: string; title: string; sub: string }) {
  return (
    <div className="stand" style={{ flex: 1 }}>
      <span className="sn">{n}</span>
      <span className="st-t">{title}</span>
      <span className="xs muted">{sub}</span>
    </div>
  );
}

/** How it works (SCREENS.md §02): the local / boundary / remote diagram. */
export default function HowItWorksPage() {
  return (
    <Content>
      <div className="ph">
        <div>
          <div className="crumb">
            <span>CodeKavach</span>
            <span>/</span>
            <span>How it works</span>
          </div>
          <h1>How CodeKavach works</h1>
          <p className="muted" style={{ marginTop: 4, maxWidth: 760 }}>
            Heavy analysis stays on your machine. Only a minimal, sanitised slice crosses the boundary, every outbound byte is
            written to the egress ledger, and verdicts are mapped back using a vault that never leaves.
          </p>
        </div>
        <ButtonLink variant="primary" to="/demo" icon={<Icon name="play" />}>
          Run KavachBank demo
        </ButtonLink>
      </div>

      <section className="card" style={{ padding: 24, overflowX: "auto" }}>
        <div
          role="img"
          aria-label="Stages 1 to 3 and 7 to 9 run on your machine. Stage 4, the privacy layer, sanitises what leaves; stage 5, the model, receives only that slice; stage 6 maps verdicts back locally."
          style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 170px 230px", gap: 0, minWidth: 920 }}
        >
          <div
            style={{
              gridRow: "1 / span 3",
              border: "1px solid var(--border-strong)",
              borderRadius: "14px 0 0 14px",
              padding: 18,
              background: "var(--surface-2)",
              display: "flex",
              flexDirection: "column",
              gap: 14,
              minWidth: 520,
            }}
          >
            <div className="row between">
              <span className="sec-h">Your machine · local</span>
              <span className="xs faint">code, vault and ledger never leave</span>
            </div>
            <div className="row" style={{ gap: 8, flexWrap: "nowrap" }}>
              <Stand n="01" title="Ingest & parse" sub="ASTs, symbols, call graph" />
              <Icon name="flow-right" className="faint" />
              <Stand n="02" title="Deterministic analysis" sub="SAST, secrets, SCA, IaC, taint" />
              <Icon name="flow-right" className="faint" />
              <Stand n="03" title="Candidate findings" sub="source-to-sink paths, hits" />
            </div>
            <div className="hr" />
            <div className="row" style={{ gap: 8, flexWrap: "nowrap" }}>
              <Stand n="09" title="Issue sync" sub="GitHub issues, Kanban" />
              <Icon name="flow-left" className="faint" />
              <Stand n="08" title="Audit report" sub="PDF, DOCX, SARIF, JSON" />
              <Icon name="flow-left" className="faint" />
              <Stand n="07" title="Risk rating" sub="CWE, OWASP, CVSS 4.0" />
            </div>
            <div className="row" style={{ gap: 10 }}>
              <span className="chip">
                <Icon name="lock" />
                Vault · pseudonym map
              </span>
              <span className="chip">
                <Icon name="lines" />
                Egress ledger · hash-chained
              </span>
            </div>
          </div>
          <div
            style={{
              gridRow: "1 / span 3",
              background: "var(--priv-bg)",
              borderTop: "1px solid var(--priv)",
              borderBottom: "1px solid var(--priv)",
              padding: "18px 12px",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              textAlign: "center",
            }}
          >
            <span className="sec-h">Boundary</span>
            <div>
              <div className="sn mono xs" style={{ color: "var(--priv)" }}>
                04 · OUTBOUND
              </div>
              <div style={{ fontWeight: 650 }}>Privacy layer</div>
              <div className="xs muted">redact → slice → pseudonymise → leak check → ledger</div>
            </div>
            <div className="xs" style={{ color: "var(--priv)", fontWeight: 600, letterSpacing: "0.06em" }}>
              THE ARMOUR
            </div>
            <div>
              <div className="sn mono xs" style={{ color: "var(--priv)" }}>
                06 · INBOUND
              </div>
              <div style={{ fontWeight: 650 }}>De-pseudonymise</div>
              <div className="xs muted">verdicts mapped back from the local vault</div>
            </div>
          </div>
          <div
            style={{
              gridRow: "1 / span 3",
              border: "1px dashed var(--border-strong)",
              borderRadius: "0 8px 8px 0",
              padding: 18,
              display: "flex",
              flexDirection: "column",
              gap: 12,
              background: "var(--surface)",
            }}
          >
            <span className="sec-h" style={{ color: "var(--high)" }}>
              Remote · or self-hosted
            </span>
            <div className="stand">
              <span className="sn">05</span>
              <span className="st-t">LLM reasoning</span>
              <span className="xs muted">
                Claude, OpenAI, Gemini, Grok, Bedrock, Azure, or Qwen, DeepSeek, Llama via Ollama / vLLM
              </span>
            </div>
            <div className="xs muted">Receives only the sanitised slice. Returns a verdict, rationale and exploit scenario in pseudonyms.</div>
            <div className="note xs" style={{ background: "transparent" }}>
              At <b>L0</b> this column is empty: a local model or deterministic engines only.
            </div>
          </div>
        </div>
      </section>

      <section className="g g-3">
        <div className="card stack">
          <h3>What crosses the boundary</h3>
          <p className="sub">
            At the default L3: the minimal vulnerability-relevant slice, with secrets and PII redacted and identifiers, strings and
            comments pseudonymised. No whole files.
          </p>
          <Link className="btn sm" to="/privacy/inspect" style={{ alignSelf: "flex-start" }}>
            Open Privacy Inspect
          </Link>
        </div>
        <div className="card stack">
          <h3>How it is measured</h3>
          <p className="sub">
            Every payload is hashed, checked against the listed-term set and appended to a hash-chained ledger. The chain can be
            verified offline at any time.
          </p>
          <Link className="btn sm" to="/privacy/ledger" style={{ alignSelf: "flex-start" }}>
            Open Egress Ledger
          </Link>
        </div>
        <div className="note">
          <b>What this does not cover.</b>
          <ul>
            <li>Control flow, literal shapes and public API names stay visible at L2 and L3.</li>
            <li>The leak check is verbatim only; paraphrase or encoding is out of scope.</li>
            <li>CodeKavach measures disclosure. It does not claim zero disclosure.</li>
          </ul>
        </div>
      </section>
    </Content>
  );
}
