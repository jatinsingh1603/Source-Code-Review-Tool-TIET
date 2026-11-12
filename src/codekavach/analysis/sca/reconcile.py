"""Cross-matcher reconciliation (E19-02).

Matchers name the same vulnerability differently (the native mirror says ``GHSA-...``, Trivy says
``CVE-...``), so two rows are the same finding when they affect the same component version and
their identifier sets (the id plus its aliases) intersect. The merged row keeps the native
matcher's data where it exists, lists every matcher that agreed in ``sources`` and unions the
aliases, fixed versions and CWEs. Agreement raises confidence one step (see
``agreement_bonus``); a finding only one matcher saw keeps its own confidence, which is the
recall gain of running a second matcher.
"""

from collections.abc import Iterable
from dataclasses import replace

from codekavach.analysis.sca.advisories import AdvisoryMatch

NATIVE = "codekavach-native"


def _ids(match: AdvisoryMatch) -> set[str]:
    return {match.advisory_id, *match.aliases}


def _merge(base: AdvisoryMatch, other: AdvisoryMatch) -> AdvisoryMatch:
    aliases = tuple(dict.fromkeys((*base.aliases, other.advisory_id, *other.aliases)))
    aliases = tuple(a for a in aliases if a != base.advisory_id)
    return replace(
        base,
        aliases=aliases,
        cwe=tuple(dict.fromkeys((*base.cwe, *other.cwe))),
        fixed=tuple(dict.fromkeys((*base.fixed, *other.fixed))),
        references=tuple(dict.fromkeys((*base.references, *other.references)))[:6],
        cvss_vector=base.cvss_vector or other.cvss_vector,
        cvss4_vector=base.cvss4_vector or other.cvss4_vector,
        symbols=tuple(dict.fromkeys((*base.symbols, *other.symbols))),
        sources=tuple(dict.fromkeys((*base.sources, *other.sources))),
    )


def reconcile(
    native: Iterable[AdvisoryMatch], *others: Iterable[AdvisoryMatch]
) -> list[AdvisoryMatch]:
    """One row per ``(package identifier, resolved version, advisory)`` with its provenance."""
    merged: list[AdvisoryMatch] = []
    for row in [*native, *(r for group in others for r in group)]:
        for position, existing in enumerate(merged):
            if (
                existing.dependency.purl == row.dependency.purl
                and existing.dependency.resolved_from == row.dependency.resolved_from
                and _ids(existing) & _ids(row)
            ):
                merged[position] = _merge(existing, row)
                break
        else:
            merged.append(row)
    return sorted(merged, key=lambda m: (m.dependency.purl, m.advisory_id))


def agreement_bonus(match: AdvisoryMatch) -> bool:
    """True when more than one matcher agreed on ``match``."""
    return len(match.sources) > 1
