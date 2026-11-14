"""The deterministic executive summary, key findings and strategic recommendations.

Owning epic: E30 (E30-03). Written for a board reader: business consequences first, numbers
second, no code.
"""

from collections import Counter
from collections.abc import Sequence

from codekavach.report.model.finding_view import FindingView
from codekavach.report.narrative.base import AggregatedFacts, NarrativeBlock, RoadmapItem

_NUMBER_WORDS = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine")
_POSTURE_TEXT = {
    "Critical": "critical: at least one weakness can be exploited to compromise the application "
    "or its data, and immediate action is required",
    "High": "high: several weaknesses could be exploited with little effort and expose "
    "customer data or core functions",
    "Moderate": "moderate: the weaknesses found need specific conditions to exploit but should "
    "be fixed in the normal release cycle",
    "Low": "low: only minor weaknesses were found",
    "Minimal": "minimal: no exploitable weakness was found by the techniques applied",
}


def _n(count: int) -> str:
    return _NUMBER_WORDS[count] if 0 <= count < len(_NUMBER_WORDS) else str(count)


def _plural(count: int, word: str) -> str:
    return f"{_n(count)} {word}{'' if count == 1 else 's'}"


def _first_sentence(text: str) -> str:
    sentence = text.strip().split(". ")[0].rstrip(".")
    return sentence + "."


def executive_summary(
    facts: AggregatedFacts,
    views: Sequence[FindingView],
    roadmap: Sequence[RoadmapItem],
    *,
    client: str,
    project: str,
    period: str,
    provider: str | None,
    model: str | None,
) -> tuple[NarrativeBlock, ...]:
    """The executive summary blocks: overview, posture, key findings, recommendations."""
    counts = ", ".join(
        f"{count} {name}" for name, count in facts.by_severity if count and name != "info"
    )
    info = facts.count("info")
    languages = ", ".join(facts.languages) or "the languages in scope"
    opening = (
        f"{client} commissioned a secure source code review of {project}."
        if client != project
        else f"This report presents the secure source code review of {project}."
    )
    overview = (
        f"{opening[0].upper()}{opening[1:]} The review was performed {period} with "
        "CodeKavach, combining deterministic rule and taint analysis "
        f"with model-assisted triage under a privacy-preserving egress policy. "
        f"{facts.files_analysed} files and {facts.lines_analysed:,} lines of {languages} code "
        "were analysed."
    )
    if facts.total:
        found = (
            f"The review identified {_plural(facts.total, 'finding')}"
            + (f" ({counts}" + (f", {info} informational)" if info else ")") if counts else "")
            + "."
        )
        if facts.closed:
            found += (
                f" {_n(facts.total - facts.closed).capitalize()} remain open; "
                f"{_n(facts.closed)} {'was' if facts.closed == 1 else 'were'} closed by the "
                "reviewers (fixed, false positive or accepted risk)."
            )
    else:
        found = "The review identified no findings."
    stance = f"The overall security posture is rated {_POSTURE_TEXT[facts.posture]}."
    model_text = ""
    if facts.reviewed_by_model and provider:
        model_text = (
            f" {facts.reviewed_by_model} findings were independently assessed by the language "
            f"model {model or ''} ({provider}); it judged {facts.confirmed_by_model} of them "
            "exploitable. Model assessments are advisory and no finding was dismissed by a model."
        )
    taint = ""
    if facts.taint_confirmed:
        taint = (
            f" {facts.taint_confirmed} findings are supported by a complete source-to-sink "
            "data-flow trace."
        )
    blocks = [
        NarrativeBlock(
            id="overview",
            heading="Overview",
            paragraphs=(overview, f"{found} {stance}{taint}{model_text}"),
            facts_used=("total", "by_severity", "files_analysed", "lines_analysed", "posture"),
        )
    ]
    significant = [view for view in views if view.severity in {"critical", "high"}][:5] or list(
        views[:3]
    )
    if significant:
        blocks.append(
            NarrativeBlock(
                id="key_findings",
                heading="Most significant findings",
                bullets=tuple(
                    f"{view.report_id} ({view.severity.title()}): {view.title.rstrip('.')}. "
                    f"{_first_sentence(view.impact)}"
                    for view in significant
                ),
                facts_used=("views",),
            )
        )
    if facts.top_cwes:
        top = facts.top_cwes[:3]
        theme = "; ".join(f"{name} ({count})" for name, count in top)
        owasp = (
            f" By OWASP Top 10 category the largest group is {facts.top_owasp[0][0]} "
            f"({facts.top_owasp[0][1]} findings)."
            if facts.top_owasp
            else ""
        )
        blocks.append(
            NarrativeBlock(
                id="concentration",
                heading="Where the weaknesses concentrate",
                paragraphs=(
                    f"The most frequent weakness classes are {theme}.{owasp} Recurring classes "
                    "indicate a missing shared control rather than isolated mistakes, so the "
                    "recommendations below address the control as well as each instance.",
                ),
                facts_used=("top_cwes", "top_owasp"),
            )
        )
    recs: list[str] = []
    seen: Counter[str] = Counter()
    for item in roadmap:
        if seen[item.lane] >= 2:
            continue
        seen[item.lane] += 1
        ids = ", ".join(item.report_ids[:4]) + (" and others" if len(item.report_ids) > 4 else "")
        recs.append(f"{item.lane} ({item.window}): {item.action} [{ids}]")
    recs.append(
        "Embed the deterministic rules in CI so that the weakness classes found here are blocked "
        "at pull-request time, and schedule a retest once the fixes are deployed."
    )
    blocks.append(
        NarrativeBlock(
            id="recommendations",
            heading="Strategic recommendations",
            bullets=tuple(recs),
            facts_used=("roadmap",),
        )
    )
    return tuple(blocks)
