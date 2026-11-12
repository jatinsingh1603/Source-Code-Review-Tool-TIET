# Taint engine: precision and recall on KavachBank

Measured by `tests/integration/taint/test_precision_recall.py` (E17-03). The whole of
`fixtures/kavachbank/services` is analysed as one project: summaries bottom-up over the call graph,
then every function with them, using the shipped default catalogues and the default settings
(`taint.max_depth = 5`, `taint.recursion_iterations = 3`, `taint.unknown_callee = propagate`).
A candidate matches a planted weakness when the CWE is equal and the primary location is within one
line of the planted line in the same file. Raw numbers:
`docs/research/results/taint-precision-recall-kavachbank.json` (regenerate with
`CODEKAVACH_RECORD_TAINT=1 uv run pytest tests/integration/taint/test_precision_recall.py`).

Scope: the six planted classes that are a source reaching a sink (SQL injection, command injection,
path traversal, SSRF, insecure deserialisation, reflected XSS). Weak cryptography, missing
authorisation and IDOR are rule or semantic findings and are not scored here.

## Result

| Measure | Value |
|---|---|
| Planted weaknesses in scope | 6 |
| Found | 4 (recall 0.67) |
| Certain candidates in the scored classes | 5, of which 4 match a planted weakness (precision 0.80) |
| Uncertain candidates | 1 |
| Negative controls in scope | 6, with 1 certain hit |

Found: SQL injection (KB-VULN-001), path traversal (003), SSRF (004, which needs the cross-file
summary: the route handler is in one file and the request is in another), reflected XSS (010).

## Misses and the false positive, explained

* KB-VULN-002 (command injection in `reports.py`) and KB-VULN-005 (`pickle.loads` in
  `serialisation.py`): in the sample, the vulnerable function is a plain helper taking its data as
  a parameter and nothing in the project calls it from a handler. Without a caller or a framework
  entry point the parameter has no source, so the engine reports no flow. This is the intended
  behaviour of an entry-point-seeded analysis and is the recall cost of it; a library-mode
  setting that seeds every public parameter is a possible follow-up and would trade precision.
* The one control hit is KB-SAFE-010 (`renderGreetingSafely`, `escapeHtml(req.query.name)`): the
  engine does not know that the application's own `escapeHtml` neutralises HTML. Project-defined
  sanitisers are not modelled; the summary of `escapeHtml` is a pass-through, which is the
  conservative reading.

The test asserts floors (recall and precision of at least 0.5) so that a regression is visible; it
does not assert the values above, which are the record.

## Limits of this measurement

One small synthetic application with one planted instance per class: the figures are a smoke
measurement, not an estimate of production performance. The public benchmark subsets (OWASP
Benchmark and similar) are not run here; they are fetched at test time under the licence rule of
the issue and are not part of this result.
