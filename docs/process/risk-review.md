# Risk review

Owning epic: E42 (issue E42-07).

The risk register is in `docs/PLAN.md` section 8: it holds the full text of each risk and its mitigation. A register helps only if it is revisited, so each sprint ends with a short review whose outcome is recorded in [`docs/status/risk-log.md`](../status/risk-log.md).

## When and who

- **When:** at the end of each sprint (Sunday), together with the status note; see the weekly rhythm in [`sprint-cadence.md`](sprint-cadence.md).
- **Who:** the status-note author runs it. Each risk has an owner in the log, who brings the assessment for that risk. Until E42-09 names people, the status-note author does both.
- **How long:** about fifteen minutes. It is a check of eight or so lines, not a workshop.

## Fields reassessed for each risk

| Field | Values | Question to answer |
|-------|--------|--------------------|
| Likelihood | Low, Medium, High | How likely is it now, given what the last sprint showed? |
| Impact | Low, Medium, High | How bad would it be now for the next milestone or for v1.0? |
| Trend | `up`, `flat`, `down`, `closed` | Compared with the previous row of this risk: worse, the same, better, or no longer a risk. |
| Owner | A name | Who watches this risk and carries its next action. |
| Next action | One line | The next concrete step, preferably an issue number. |

## Steps

1. Open `docs/status/risk-log.md` and `docs/PLAN.md` section 8 side by side.
2. For each open risk, in Id order, answer the five questions above. The current state of a risk is its last row in the log.
3. If any field of a risk changed, **append** a new row with the same Id, the new values and today's date in Last reviewed. Earlier rows stay as they are: the log is the history.
4. If nothing changed for a risk, append nothing for it.
5. Add one line to the "Reviews" list at the end of the log: the date, the sprint and the Ids that changed (or "no change").
6. Copy the top three open risks into the `## Risks and blockers` section of the sprint's status note (see "Top three" below).
7. If a mitigation itself has to change, that is a change to `docs/PLAN.md` or an ADR and gets its own issue; the review only records the need as the Next action.

## New and closed risks

- **New risk:** append a row with the next free Id. The seeded risks are R-01 to R-08, so the first new one is R-09; Ids are not reused. Give it a short label, and add the full description and mitigation to `docs/PLAN.md` section 8 in the same commit.
- **Closed risk:** append a row with Trend `closed` and the closing date in Last reviewed. A closed risk is no longer reassessed and is left out of the top three. If it comes back, append a row with a Trend other than `closed`.

## Top three

The status note names the three open risks with the highest score.

- Score = likelihood times impact, with Low = 1, Medium = 2, High = 3. The score ranges from 1 to 9.
- Only the last row of each risk counts, and risks whose last row has Trend `closed` are left out.
- Order by score, highest first. Equal scores are ordered by Id, lowest first.

With the seeded values, R-01 to R-06 score 6 and R-07 and R-08 score 4, so the top three are R-01, R-02 and R-03.

## Wording

The leakage and prompt-injection risks (R-02, R-06) are the threats the privacy layer defends against; keep their wording in step with the threat model of `docs/ARCHITECTURE.md` section 6.4.
