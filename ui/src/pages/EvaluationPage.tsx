import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { endpoints } from "@/api/endpoints";
import { asEvaluation, Frontier, type EvaluationData } from "@/components/Frontier";
import { sampleEvaluation } from "@/lib/sampleEval";
import { Button, Content, Empty, PageHeader, Skeleton, useToast } from "@/components/ui";

interface EvalJob {
  id: string;
  status: string;
  steps?: { kind: string; status: string; error?: string }[];
}

const pct = (v: number | null | undefined) => (v === null || v === undefined ? "n/a" : `${(v * 100).toFixed(v < 0.1 && v > 0 ? 1 : 0)}%`);

/** Evaluation (SCREENS.md §17): detection by arm, the frontier and attacker experiments. */
export default function EvaluationPage() {
  const toast = useToast();
  const qc = useQueryClient();
  const [starting, setStarting] = useState(false);
  // The latest run comes back as `job` on GET /evaluation; poll while it runs.
  const q = useQuery({
    queryKey: ["optional", "evaluation"],
    queryFn: endpoints.evaluation,
    retry: false,
    staleTime: 60_000,
    refetchInterval: (query) => ((query.state.data as { job?: EvalJob } | null)?.job?.status === "running" ? 2000 : false),
  });
  const job = (q.data as { job?: EvalJob | null } | null)?.job ?? null;
  const running = starting || job?.status === "running";
  const seen = useRef<string | null>(null);
  useEffect(() => {
    if (!job) return;
    if (job.status === "running") {
      seen.current = job.id;
    } else if (seen.current === job.id) {
      seen.current = null;
      if (job.status === "completed") toast.success("Evaluation finished", "Detection and leakage results updated from this server's run.");
      else toast.error("Evaluation failed", job.steps?.find((st) => st.status === "failed")?.kind ?? "see the server log");
    }
  }, [job, toast]);
  const run = async () => {
    setStarting(true);
    try {
      const started = await endpoints.evaluationRun();
      seen.current = started.id;
      toast.info("Evaluation started", "Detection, then leakage, on the KavachBank sample with the Mock provider. About a minute.");
      await qc.invalidateQueries({ queryKey: ["optional", "evaluation"] });
    } catch (e) {
      toast.error("Could not start the evaluation", e instanceof Error ? e.message : String(e));
    } finally {
      setStarting(false);
    }
  };
  const server = asEvaluation(q.data);
  const data: EvaluationData = useMemo(() => server ?? sampleEvaluation(), [server]);
  const bench = data.benchmarks ?? [];
  const isDefault = (arm: string) => /L3/.test(arm) && !/mock/i.test(arm);
  const arms = bench.filter((b) => b.dataset === bench[0]?.dataset);
  const base = arms.find((a) => /sast only/i.test(a.arm));
  const levels = ["L2", "L3", "L4"];
  const f1s = (data.frontier ?? []).map((p) => p.f1.toFixed(2));
  const flatF1 = f1s.length > 1 && new Set(f1s).size === 1;

  return (
    <Content>
      <PageHeader
        crumbs={[{ label: "Organisation" }, { label: "Evaluation" }]}
        title="Evaluation"
        sub="How detection quality changes with privacy level, and what an attacker can recover from the payloads."
        actions={
          <>
            {data.sample !== false && <span className="chip">Sample results · replace with your runs</span>}
            <Button
              onClick={run}
              disabled={running}
              title="Runs the detection and leakage evaluation of the KavachBank sample on this server with the Mock provider (nothing leaves the machine)."
            >
              {running ? "Running benchmark…" : "Run benchmark"}
            </Button>
          </>
        }
      />
      {q.isLoading ? (
        <div className="card">
          <Skeleton rows={3} />
        </div>
      ) : (
        <>
          <section className="stack">
            <div className="row between">
              <h2 style={{ fontSize: 14, fontWeight: 600 }}>Benchmark results</h2>
              <span className="xs faint">Precision, recall, F1 · 95% bootstrap confidence intervals</span>
            </div>
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Dataset</th>
                    <th>Arm</th>
                    <th className="num">Precision</th>
                    <th className="num">Recall</th>
                    <th className="num">F1</th>
                    <th style={{ width: 220 }}>F1 with CI</th>
                  </tr>
                </thead>
                <tbody>
                  {bench.map((b, i) => {
                    const sel = isDefault(b.arm);
                    const [lo, hi] = b.f1_ci ?? [b.f1, b.f1];
                    return (
                      <tr key={i} className={sel ? "sel" : undefined}>
                        <td className="sm">{b.dataset}</td>
                        <td className="sm">{sel ? <b>{b.arm}</b> : b.arm}</td>
                        <td className="num mono">{b.precision.toFixed(2)}</td>
                        <td className="num mono">{b.recall.toFixed(2)}</td>
                        <td className="num mono">{sel ? <b>{b.f1.toFixed(2)}</b> : b.f1.toFixed(2)}</td>
                        <td>
                          <div
                            className={`ci-bar${sel ? " acc" : ""}`}
                            style={{ ["--lo" as string]: `${lo * 100}%`, ["--hi" as string]: `${hi * 100}%`, ["--pt" as string]: `calc(${b.f1 * 100}% - 1px)` }}
                            title={`F1 ${b.f1.toFixed(2)}, 95% CI ${lo.toFixed(2)} to ${hi.toFixed(2)}`}
                          >
                            <i className="ci" />
                            <i className="pt" />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {bench.length === 0 && <Empty title="No benchmark results yet">Run the detection evaluation to fill this table.</Empty>}
            </div>
          </section>

          <section className="g g-2">
            <div className="card">
              <div className="card-h">
                <div>
                  <h2>Arms comparison</h2>
                  <p className="sub">F1 on {arms[0]?.dataset.split(" · ")[0] ?? "the dataset"} by arm</p>
                </div>
              </div>
              <div className="stack" style={{ gap: 12 }}>
                {arms.map((a) => {
                  const sel = isDefault(a.arm);
                  const label = /sast only/i.test(a.arm) ? "SAST only" : a.arm.replace("SAST + LLM", "+ LLM");
                  return (
                    <div className="hbar" key={a.arm}>
                      <span className="hb-l">{sel ? <b>{label}</b> : label}</span>
                      <div className="hb-t">
                        <i className={/sast only/i.test(a.arm) ? "base" : sel ? "acc" : undefined} style={{ width: `${a.f1 * 100}%` }} />
                      </div>
                      <span className="hb-v">{sel ? <b>{a.f1.toFixed(2)}</b> : a.f1.toFixed(2)}</span>
                    </div>
                  );
                })}
              </div>
              {base && arms.find((a) => isDefault(a.arm)) && (
                <p className="xs faint" style={{ marginTop: 14 }}>
                  The model review at L3 changes F1 from {base.f1.toFixed(2)} to {arms.find((a) => isDefault(a.arm))!.f1.toFixed(2)} while sending no
                  whole files.
                </p>
              )}
            </div>
            <div className="card">
              <div className="card-h">
                <div>
                  <h2>Privacy-utility frontier</h2>
                  <p className="sub">F1 against identifier recovery rate</p>
                </div>
              </div>
              {data.frontier?.length ? <Frontier points={data.frontier} /> : <Empty title="No frontier yet">Run the leakage evaluation.</Empty>}
              {flatF1 && (
                <p className="xs faint" style={{ marginTop: 10 }}>
                  Every arm has the same F1 here because the leakage runs use the Mock provider, which does not change verdicts. Only the recovery axis differs
                  between levels.
                </p>
              )}
            </div>
          </section>

          <section className="stack">
            <div className="row between">
              <h2 style={{ fontSize: 14, fontWeight: 600 }}>Attacker experiments</h2>
              <span className="xs faint">Simulated adversary holding every payload from one scan</span>
            </div>
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Experiment</th>
                    <th>What the attacker tries</th>
                    {levels.map((l) => (
                      <th key={l} className="num">
                        {l}
                      </th>
                    ))}
                    <th>Reading</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.attacks ?? []).map((a) => (
                    <tr key={a.experiment}>
                      <td>
                        <b className="sm">{a.experiment}</b>
                      </td>
                      <td className="wrap sm muted">{a.description}</td>
                      {levels.map((l) => (
                        <td key={l} className="num mono">
                          {pct(a.by_level?.[l])}
                        </td>
                      ))}
                      <td className="wrap sm muted">{a.reading}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="xs faint">
              These rates measure disclosure; they are not a guarantee. Re-run per codebase, as results depend on naming style and code structure.
              {data.note ? ` ${data.note}` : ""}
            </p>
          </section>
        </>
      )}
    </Content>
  );
}
