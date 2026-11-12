import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useSelectedScan } from "@/app/useSelectedScan";
import { useSession } from "@/app/session";
import { useFindings, usePolicy, useSavePolicy } from "@/api/queries";
import type { PrivacyLevel } from "@/api/types";
import { locationOf } from "@/lib/domain";
import { LEVEL_NAME } from "@/lib/display";
import { globToRegExp, matches, policyDoc, rulesToToml, type PathRule } from "@/lib/policy";
import { Button, Content, Empty, ErrorBanner, Guard, Skeleton, StatusDot, useToast } from "@/components/ui";

type Action = "never-send" | PrivacyLevel;
const ACTIONS: Action[] = ["never-send", "L4", "L3", "L2", "L1"];

const TEMPLATES: { name: string; desc: string; rules: PathRule[] }[] = [
  {
    name: "Bank strict",
    desc: "config, keys and fixtures never-send · payments and interest logic L4",
    rules: [
      { pattern: "config/**", never_send: true },
      { pattern: "**/*.pem", never_send: true },
      { pattern: "tests/fixtures/**", never_send: true },
      { pattern: "**/secrets/**", never_send: true },
      { pattern: "**/payments/**", level: "L4" },
      { pattern: "**/interest/**", level: "L4" },
    ],
  },
  {
    name: "Healthcare",
    desc: "PII paths never-send · everything else L3",
    rules: [
      { pattern: "**/patients/**", never_send: true },
      { pattern: "**/pii/**", never_send: true },
      { pattern: "**/secrets/**", never_send: true },
    ],
  },
  { name: "Minimal", desc: "No extra rules · the scan level applies", rules: [] },
];

const key = (r: PathRule) => `${r.pattern}|${r.never_send ? "never-send" : r.level ?? ""}`;

/** Privacy policy (SCREENS.md §13): path rules, live TOML preview and validation. */
export default function PolicyPage() {
  const q = usePolicy();
  const save = useSavePolicy();
  const toast = useToast();
  const { can } = useSession();
  const { scanId, project } = useSelectedScan();
  const findings = useFindings(scanId).data;
  const doc = useMemo(() => policyDoc(q.data), [q.data]);
  const [rules, setRules] = useState<PathRule[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  useEffect(() => {
    setRules(doc.path.map((r) => ({ pattern: r.pattern, never_send: !!r.never_send, level: r.level ?? null })));
  }, [doc]);

  const original = doc.path.map(key);
  const current = rules.map(key);
  const changes =
    current.filter((k, i) => k !== original[i]).length + Math.max(0, original.length - current.length);
  const advanced = (doc.language?.length ?? 0) > 0;
  const editable = can("settings:write") && !advanced;
  const toml = advanced ? q.data?.toml ?? "" : rulesToToml(doc, rules.filter((r) => r.pattern.trim()));
  const files = useMemo(() => [...new Set((findings ?? []).map((f) => locationOf(f)?.path).filter((x): x is string => !!x))], [findings]);

  const errors: string[] = [];
  rules.forEach((r, i) => {
    if (!r.pattern.trim()) errors.push(`Rule ${i + 1} has no path glob`);
    try {
      globToRegExp(r.pattern);
    } catch {
      errors.push(`Rule ${i + 1}: the glob does not parse`);
    }
  });
  const overlaps: string[] = [];
  for (let i = 0; i < rules.length; i++)
    for (let j = i + 1; j < rules.length; j++) {
      const n = files.filter((f) => matches(rules[i]!.pattern, f) && matches(rules[j]!.pattern, f)).length;
      if (n) overlaps.push(`Rule ${i + 1} overlaps rule ${j + 1} on ${n} file${n === 1 ? "" : "s"} · stricter wins`);
    }

  const setRule = (i: number, r: Partial<PathRule>) => setRules((rs) => rs.map((x, k) => (k === i ? { ...x, ...r } : x)));
  const tomlLines = toml.replace(/\n$/, "").split("\n");
  // Lines of the selected rule's [[path]] block in the preview.
  const selRange = (() => {
    if (sel === null) return null;
    let count = -1;
    let start = -1;
    for (let i = 0; i < tomlLines.length; i++) {
      if (tomlLines[i] === "[[path]]") {
        count += 1;
        if (count === sel) start = i;
        else if (start >= 0) return [start, i - 2];
      }
    }
    return start >= 0 ? [start, tomlLines.length - 1] : null;
  })();

  const doSave = () =>
    save.mutate(toml, {
      onSuccess: () => toast.success("Policy saved", "It applies to the next scan."),
      onError: (e) => toast.error("Policy not saved", e.message),
    });

  return (
    <Content>
      <div className="ph">
        <div>
          <div className="crumb">
            <Link to="/privacy">Privacy</Link>
            <span>/</span>
            <span>Policy</span>
          </div>
          <h1>Privacy policy</h1>
          <p className="sub" style={{ marginTop: 4 }}>
            Decide which level each part of the codebase is reviewed at. The strictest matching rule wins.
          </p>
        </div>
        <div className="row">
          {changes > 0 && <span className="sub">Unsaved changes · {changes}</span>}
          <Button disabled={!changes} onClick={() => setRules(doc.path.map((r) => ({ ...r })))}>
            Discard
          </Button>
          <Button variant="primary" disabled={!editable || !changes || errors.length > 0} loading={save.isPending} onClick={doSave}>
            Save policy
          </Button>
        </div>
      </div>
      {q.isError && <ErrorBanner what="The policy could not be loaded." error={q.error} onRetry={() => void q.refetch()} />}
      {!can("settings:write") && <div className="banner info sm">Only administrators can change the policy. You can read it here.</div>}

      <section className="g g-side">
        <div className="stack s16">
          <div className="card">
            <div className="card-h">
              <h2>Rules</h2>
              <Button
                size="sm"
                disabled={!editable}
                onClick={() => {
                  setRules((rs) => [...rs, { pattern: "", never_send: false, level: "L4" }]);
                  setSel(rules.length);
                }}
              >
                + Add rule
              </Button>
            </div>
            {q.isLoading ? (
              <Skeleton rows={2} />
            ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Order</th>
                      <th>Path glob</th>
                      <th>Language</th>
                      <th>Rule ID</th>
                      <th>Action</th>
                      <th className="num">Matches</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {rules.map((r, i) => (
                      <tr key={i} className={sel === i ? "sel" : undefined} onFocus={() => setSel(i)} onClick={() => setSel(i)}>
                        <td className="mono faint">{i + 1}</td>
                        <td>
                          <input
                            className="inp mono sm"
                            aria-label={`Path glob ${i + 1}`}
                            value={r.pattern}
                            disabled={!editable}
                            onChange={(e) => setRule(i, { pattern: e.target.value })}
                          />
                        </td>
                        <td className="sm">any</td>
                        <td className="mono xs">path.{i + 1}</td>
                        <td>
                          <select
                            className="inp sm"
                            aria-label={`Action ${i + 1}`}
                            style={{ width: 140 }}
                            disabled={!editable}
                            value={r.never_send ? "never-send" : r.level ?? "L3"}
                            onChange={(e) => {
                              const v = e.target.value as Action;
                              setRule(i, v === "never-send" ? { never_send: true, level: null } : { never_send: false, level: v });
                            }}
                          >
                            {ACTIONS.map((a) => (
                              <option key={a} value={a}>
                                {a === "never-send" ? a : `${a} ${LEVEL_NAME[a]}`}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td className="num mono">{findings ? files.filter((f) => matches(r.pattern, f)).length : "—"}</td>
                        <td>
                          {editable && (
                            <button className="btn sm ghost" type="button" onClick={() => setRules((rs) => rs.filter((_, k) => k !== i))}>
                              Remove
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                    <tr>
                      <td className="mono faint">{rules.length + 1}</td>
                      <td className="mono sm" style={{ paddingLeft: 22 }}>
                        **
                      </td>
                      <td className="sm">any</td>
                      <td className="mono xs">default</td>
                      <td className="sm muted">scan level</td>
                      <td className="num mono">{findings ? files.filter((f) => !rules.some((r) => matches(r.pattern, f))).length : "—"}</td>
                      <td />
                    </tr>
                  </tbody>
                </table>
              </div>
            )}
            {advanced && (
              <p className="xs faint" style={{ marginTop: 8 }}>
                This policy also has language rules; edit kavach-policy.toml on the server to change it.
              </p>
            )}
          </div>

          <section className="g g-2">
            <div className="card stack">
              <h2>Floor level</h2>
              <p className="sub">Scans and users cannot choose a level that discloses more than this.</p>
              <div className="seg" aria-label="Floor level">
                {(["L1", "L2", "L3"] as PrivacyLevel[]).map((l) => (
                  <button key={l} type="button" disabled className={doc.floor === l ? "on" : undefined}>
                    {l}
                  </button>
                ))}
              </div>
              <p className="xs faint">
                {doc.floor
                  ? `Current floor ${doc.floor}.`
                  : "No organisation floor in this policy. Each provider's trust tier sets its own minimum level (see Providers)."}
              </p>
            </div>
            <div className="card stack">
              <h2>Templates</h2>
              <div>
                {TEMPLATES.map((t) => {
                  const applied = t.rules.map(key).join() === current.join();
                  return (
                    <div className="listrow" key={t.name}>
                      <div>
                        <b className="sm">{t.name}</b>
                        <div className="xs faint">{t.desc}</div>
                      </div>
                      {applied ? (
                        <span className="chip on">Applied</span>
                      ) : (
                        <Button size="sm" disabled={!editable} onClick={() => setRules(t.rules.map((r) => ({ ...r })))}>
                          Apply
                        </Button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </section>
        </div>

        <div className="stack s16">
          <div>
            <div className="code-h">
              <span className="mono">kavach-policy.toml</span>
              <StatusDot tone={errors.length ? "bad" : "ok"} className="xs">
                {errors.length ? "Invalid" : `Valid · version ${doc.policy_version ?? 1}`}
              </StatusDot>
            </div>
            <div className="code" style={{ fontSize: 12, lineHeight: "20px" }}>
              {tomlLines.map((l, i) => (
                <div key={i} className={selRange && i >= selRange[0]! && i <= selRange[1]! ? "ln hl" : "ln"}>
                  <span className="n">{i + 1}</span>
                  {l.startsWith("#") ? (
                    <span className="tc">{l}</span>
                  ) : l.startsWith("[[") ? (
                    <span className="tk">{l}</span>
                  ) : l.includes(" = ") ? (
                    <>
                      {l.split(" = ")[0]} = <span className={/^"/.test(l.split(" = ")[1] ?? "") ? "ts" : "tn"}>{l.split(" = ").slice(1).join(" = ")}</span>
                    </>
                  ) : (
                    l
                  )}
                </div>
              ))}
            </div>
          </div>
          <div className="card stack">
            <h2>Validation</h2>
            {errors.length ? (
              errors.map((e) => (
                <Guard key={e} result={<span className="note-w">Fix</span>}>
                  {e}
                </Guard>
              ))
            ) : (
              <Guard result="pass">Schema and glob syntax</Guard>
            )}
            {overlaps.map((o) => (
              <Guard key={o} result={<span className="note-w">Note</span>}>
                {o}
              </Guard>
            ))}
            {findings ? (
              <Guard result="pass">
                Dry run on {project?.name ?? "the project"} · {files.length} files with findings resolved
              </Guard>
            ) : scanId ? (
              <Skeleton />
            ) : (
              <Empty title="No scan to dry-run against">Run a scan to see how many files each rule matches.</Empty>
            )}
            <p className="xs faint">The server validates the policy again when you save.</p>
          </div>
        </div>
      </section>
    </Content>
  );
}
