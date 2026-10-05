# Demo 1 agenda: proof of the privacy layer

Owning epic: E42 (issue E42-08). Demo date in `docs/PLAN.md` section 5: 2026-10-05.

**Objective.** Show, with evidence from the egress ledger, what would leave the machine when CodeKavach reviews a Python and JavaScript code base, and that nothing sensitive is in it.

**Scope.** Demo 1 proves the privacy layer on Python and JavaScript only. It is not a demonstration of detection breadth.

**Readiness.** The live commands of segments 1 to 6 are provided by the demo slice, epic E13 (issues #222, #223 and #224), and by its M1 dependencies. On the day this agenda was written those issues were open, so the commands marked "E13" cannot be run yet. The command spellings below are taken from `docs/PLAN.md` section 5 and from the E13 issues; reconcile them with the runbook `docs/demo/DEMO1.md` (written by E13-03) before the demo.

## Running order

About 27 minutes. Every command is run from the repository root on the bundled sample only, not on real client code.

| # | Minutes | Segment | Command | What the supervisor should see | Exit criterion |
|---|---------|---------|---------|--------------------------------|----------------|
| 0 | 0 to 2 | Opening | none | The objective above, the scope, and the sentence on the mock provider (see segment 4). | |
| 1 | 2 to 5 | The sample application | Open `fixtures/kavachbank/` and its ground-truth manifest (E13) | Planted vulnerabilities, planted secrets and recognisable business logic: an interest and fee engine. Every planted value is synthetic and listed in the manifest. | 2 |
| 2 | 5 to 9 | Scan without a paid key | `codekavach providers list --check-secrets`, then `codekavach scan fixtures/kavachbank` (E13) | No provider key is configured. The scan completes on the laptop with no paid API key and prints a severity summary. | 1 |
| 3 | 9 to 14 | What was prepared for the LLM | `codekavach privacy inspect` (E13) | Side by side: the original code and the exact payload prepared for the LLM. Secrets are replaced by typed placeholders; identifiers, strings and comments are pseudonymised; only slices are present. | 3 |
| 4 | 14 to 18 | The leak check | `uv run pytest tests/integration/test_demo_zero_leak.py` (E13), then `codekavach privacy ledger verify` | The automated check passes: no planted secret and no listed business-domain term occurs verbatim anywhere in the egress ledger, and the ledger's hash chain verifies. Say it as it is: with a mock or replay provider the ledger shows what *would* have left. | 4 |
| 5 | 18 to 21 | Findings in the real code | The findings table of the scan from segment 2 | Findings come back mapped to the real files, lines and names, although the LLM saw pseudonyms only. | 5 |
| 6 | 21 to 25 | Reports | `codekavach report fixtures/kavachbank --format html,pdf` (E13) | An HTML and a PDF report with executive summary, risk matrix, findings with snippet evidence, impact and remediation. | 6 |
| 7 | 25 to 27 | Close | none | What is not shown yet (below), then questions. | |

The one-command path `codekavach demo` (E13-03) runs segments 2 to 6 in one go; use it for the rehearsal and keep the step-by-step path for the session, because each step is one exit criterion.

## Exit criteria covered

The six Demo 1 exit criteria of `docs/PLAN.md` section 5, and where each is shown:

1. `codekavach scan fixtures/kavachbank` completes on a laptop with no paid API key: segment 2.
2. The sample contains planted vulnerabilities, planted secrets and recognisable business logic (an interest and fee engine): segment 1.
3. `codekavach privacy inspect` shows the original code and the exact payload side by side: segment 3.
4. An automated check proves that no planted secret and no listed business-domain term occurs verbatim in the egress ledger: segment 4.
5. Findings are mapped to the real files, lines and names: segment 5.
6. An HTML and a PDF report are produced: segment 6.

## Pre-demo checklist

- [ ] No paid key is needed and none is set: the provider key variables are unset in the shell, and `codekavach providers list --check-secrets` shows the mock provider as the default.
- [ ] The laptop is offline for the egress-ledger proof (network switched off before segment 2), so the audience sees that the scan and the leak check need no connection.
- [ ] The sample repository is present: `fixtures/kavachbank/` with its ground-truth manifest.
- [ ] The reports directory is clean and the sample has no state directory left from a rehearsal.
- [ ] `codekavach doctor` reports no failed check.
- [ ] The whole running order was rehearsed once on this laptop, with the timings above.
- [ ] The fallback artefacts of the next section are saved locally, because the laptop is offline.
- [ ] Terminal font and browser zoom are readable from the back of the room.

## Fallback plan

The demo degrades in steps; say which step is being used.

1. **A live command fails.** Run the same step with the replay provider and the recorded cassettes in `fixtures/kavachbank/cassettes/` (E13-03). The ledger statement of segment 4 is the same: it shows what would have left.
2. **The scan itself does not run.** Show the recorded artefacts of the last rehearsal or of the CI demo job (E13-03): the HTML report, the saved inspect page and the output of the ledger verification.
3. **The PDF cannot be rendered** because system libraries are missing on the laptop. Show the HTML report and state that the PDF is produced from the same document; show the PDF saved at rehearsal.
4. **Time runs out.** Segments 3 and 4 are the centrepiece; shorten segments 1 and 6 first.

## What we are not showing yet

- Detection depth: engine adapters, native rules and taint analysis are milestone M2 Detection engine; review by real LLM providers is M3 LLM reasoning.
- Reporting polish: risk rating, compliance mapping and the full set of report formats are M5 Audit reporting.

## Related

- Sprint rhythm and who prepares the demo: [`docs/process/sprint-cadence.md`](../process/sprint-cadence.md).
- Privacy invariants shown live (I2, I4, I6): `docs/ARCHITECTURE.md` section 6.3.
