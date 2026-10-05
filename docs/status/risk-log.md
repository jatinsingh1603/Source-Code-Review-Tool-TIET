# Risk log

Owning epic: E42 (issue E42-07). How this log is kept: [`docs/process/risk-review.md`](../process/risk-review.md).

The full text and the mitigation of each risk are in `docs/PLAN.md` section 8; the Risk column here is the label of that row. The log is append-only: a review adds a row for a risk whose assessment changed, and the current state of a risk is its last row.

Scale for Likelihood and Impact: Low, Medium, High. Trend: `up`, `flat`, `down`, `closed`.

| Id | Risk | Likelihood | Impact | Trend | Owner | Last reviewed | Next action |
|----|------|------------|--------|-------|-------|---------------|-------------|
| R-01 | Pseudonymisation reduces LLM accuracy too far | Medium | High | flat | To be named (E42-09) | 2026-10-05 | Measure accuracy per privacy level once the M1 slice runs |
| R-02 | Residual leakage through structure or literals | Medium | High | flat | To be named (E42-09) | 2026-10-05 | Land the egress guard leak checks (E12) |
| R-03 | Scope is very wide for three months | High | Medium | flat | To be named (E42-09) | 2026-10-05 | Finish M0, then the thin end-to-end slice (E13) |
| R-04 | No paid LLM keys during development | High | Medium | flat | To be named (E42-09) | 2026-10-05 | Build the mock and replay providers in M1 |
| R-05 | Third-party engine licences conflict with MIT or with scanning proprietary code | Medium | High | flat | To be named (E42-09) | 2026-10-05 | Keep the licence verdict per engine in `docs/research/INSIGHTS.md` current |
| R-06 | Prompt injection from reviewed code | Medium | High | flat | To be named (E42-09) | 2026-10-05 | Land the regression suite (E24) |
| R-07 | New GitHub account rate or abuse limits | Medium | Medium | flat | To be named (E42-09) | 2026-10-05 | Keep commits small and regular; pace issue creation |
| R-08 | Benchmark contamination in LLM evaluation | Medium | Medium | flat | To be named (E42-09) | 2026-10-05 | Choose post-cutoff CVE sets for the evaluation (M7) |

## Reviews

- 2026-10-05, Sprint 3: log seeded with the baseline likelihood and impact of `docs/PLAN.md` section 8 (R-01 to R-08). This is the baseline, not a review; the first review is due at the end of Sprint 3.
