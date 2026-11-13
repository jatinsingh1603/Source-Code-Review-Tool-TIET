"""Turn the knowledge base into a finding's OWASP, ASVS, CAPEC, compliance and reference fields.

Owning epic: E29. ``StandardsAnnotator.annotations`` returns, for a tuple of CWEs, the
``owasp``, ``taxonomy`` (ASVS, CAPEC, CWE Top 25), ``compliance`` and ``references`` values and
the default remediation text. Every row records whether the mapping is official (the source
document maps it) or derived (our interpretation), so reports can say which is which.
"""

from dataclasses import dataclass
from typing import Final

from codekavach.core.log import get_logger
from codekavach.core.models.taxonomy import Reference, TaxonomyRef, format_cwe
from codekavach.risk.taxonomy.loader import KnowledgeBase

_log = get_logger(__name__)

MAX_CAPEC: Final = 6
_OWASP_SCHEME: Final = "owasp-top10"


@dataclass(frozen=True, slots=True)
class Annotations:
    """Taxonomy fields for one finding."""

    owasp: tuple[TaxonomyRef, ...]
    taxonomy: tuple[TaxonomyRef, ...]
    compliance: tuple[TaxonomyRef, ...]
    references: tuple[Reference, ...]
    remediation: str


EMPTY: Final = Annotations((), (), (), (), "")


class StandardsAnnotator:
    """Maps CWEs to standards and compliance clauses from the knowledge base."""

    id = "standards"

    def __init__(self, knowledge_base: KnowledgeBase) -> None:
        self.kb = knowledge_base
        self._cache: dict[tuple[int, ...], Annotations] = {}

    def annotations(self, cwes: tuple[int, ...]) -> Annotations:
        """The annotations of ``cwes`` (memoised per CWE tuple)."""
        if cwes not in self._cache:
            self._cache[cwes] = self._build(cwes)
        return self._cache[cwes]

    def _build(self, cwes: tuple[int, ...]) -> Annotations:
        kb = self.kb
        owasp: list[TaxonomyRef] = []
        taxonomy: list[TaxonomyRef] = []
        references: list[Reference] = []
        seen: set[tuple[str, str]] = set()

        def add(target: list[TaxonomyRef], ref: TaxonomyRef) -> None:
            if (ref.scheme, ref.id) not in seen:
                seen.add((ref.scheme, ref.id))
                target.append(ref)

        for cwe in cwes:
            entry = kb.entry(cwe)
            if entry is None:
                continue
            references.append(
                Reference(title=f"{format_cwe(cwe)}: {entry.name}"[:300], url=entry.url)
            )
            if entry.owasp is not None:
                category = kb.owasp[entry.owasp]
                add(
                    owasp,
                    TaxonomyRef(
                        scheme=_OWASP_SCHEME,
                        id=f"{entry.owasp}:{kb.owasp_version}",
                        title=category.title,
                        version=kb.owasp_version,
                        basis=entry.owasp_basis,
                        url=category.url,
                    ),
                )
            if entry.top25 is not None:
                add(
                    taxonomy,
                    TaxonomyRef(
                        scheme="cwe-top25",
                        id=f"#{entry.top25}",
                        title=f"{format_cwe(cwe)} ranked {entry.top25} in the 2024 CWE Top 25",
                        version="2024",
                        basis="official",
                    ),
                )
            for requirement in entry.asvs:
                add(
                    taxonomy,
                    TaxonomyRef(
                        scheme="owasp-asvs", id=requirement, version="4.0.3", basis="derived"
                    ),
                )
            for capec in entry.capec[:MAX_CAPEC]:
                add(
                    taxonomy,
                    TaxonomyRef(
                        scheme="capec",
                        id=f"CAPEC-{capec}",
                        basis="official",
                        url=f"https://capec.mitre.org/data/definitions/{capec}.html",
                    ),
                )
        family = kb.family_for(cwes)
        compliance = tuple(
            TaxonomyRef(
                scheme=control.framework,
                id=control.id[:64],
                title=control.title[:300],
                version=kb.frameworks[control.framework].version,
                basis=control.basis,
            )
            for control in kb.controls_for(family)
        )
        entry = kb.primary(cwes)
        # A weakness with its own remediation is one the family's advice does not fit (a
        # pull_request_target workflow in the "integrity" family is not mass assignment), so the
        # family's cheat sheets would mislead as much as its advice did.
        if not (entry and entry.remediation):
            references.extend(family.references)
        if owasp and owasp[0].url:
            references.append(
                Reference(title=f"OWASP Top 10 2021 {owasp[0].title}", url=owasp[0].url)
            )
        remediation = (
            entry.remediation if entry and entry.remediation else ""
        ) or family.remediation
        return Annotations(
            owasp=tuple(owasp),
            taxonomy=tuple(taxonomy),
            compliance=compliance,
            references=tuple(references),
            remediation=remediation.strip(),
        )
