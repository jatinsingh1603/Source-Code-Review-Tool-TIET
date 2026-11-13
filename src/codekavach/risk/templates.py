"""Propose CVSS v4.0 and v3.1 Base vectors for a finding from its weakness family and context.

Owning epic: E29. Each weakness family in ``data/cwe/families.yaml`` carries a default vector for a
typical, network-reachable instance. ``base_vectors_for`` adjusts it with deterministic evidence
only and records a rationale per changed metric:

- untrusted data enters locally (command line, environment, files): AV becomes Local;
- the code sits behind an authentication guard: PR becomes Low (unless already High);
- a taint path ends at the sink through an inadequate sanitiser: no change (still exploitable);
- the finding is in test code: AT becomes Present (attack requires conditions not in production).

An engine-supplied vector (a SARIF property) always wins over the template. Dependency and
misconfiguration findings whose engine rates each instance (a privileged container is critical, a
root user medium; an advisory carries its own severity) take their vector from ``SEVERITY_LADDER``
so that the CVSS score agrees with that per-instance severity. A CISA KEV listing sets the Threat
metric E to Attacked.
"""

from typing import Final

from codekavach.core.log import get_logger
from codekavach.core.models.enums import CandidateKind, Severity
from codekavach.risk.context import RatingContext
from codekavach.risk.cvss.v4 import Cvss4Vector
from codekavach.risk.cvss.v4 import try_parse as parse4
from codekavach.risk.cvss.v31 import Cvss31Vector
from codekavach.risk.cvss.v31 import try_parse as parse31
from codekavach.risk.taxonomy.loader import Family

_log = get_logger(__name__)

GENERIC_CVSS4: Final = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"
GENERIC_CVSS31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
# Kinds whose engine rates each instance; a hotspot is a place to review, so its rule's own
# severity applies rather than the worst case of its weakness family.
LADDER_KINDS: Final = frozenset(
    {CandidateKind.DEPENDENCY, CandidateKind.MISCONFIGURATION, CandidateKind.HOTSPOT}
)
# Representative Base vectors whose v4.0 and v3.1 scores fall in each qualitative band (derived).
SEVERITY_LADDER: Final[dict[Severity, tuple[str, str]]] = {
    Severity.CRITICAL: (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    Severity.HIGH: (
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    ),
    Severity.MEDIUM: (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    ),
    Severity.LOW: (
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L",
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
    ),
    Severity.INFO: (
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N",
    ),
}


def base_vectors_for(
    context: RatingContext, family: Family | None
) -> tuple[Cvss4Vector, Cvss31Vector, tuple[tuple[str, str], ...], tuple[str, ...]]:
    """The v4.0 and v3.1 vectors, a per-metric rationale and the adjustments applied."""
    rationale: list[tuple[str, str]] = []
    adjustments: list[str] = []
    engine4 = parse4(context.cvss4_vector)
    engine31 = parse31(context.cvss31_vector)
    base4 = Cvss4Vector.parse(family.cvss4 if family else GENERIC_CVSS4)
    base31 = Cvss31Vector.parse(family.cvss31 if family else GENERIC_CVSS31)
    label = family.key if family else "generic"
    ladder = context.engine_severity if engine4 is None and context.kind in LADDER_KINDS else None
    if engine4 is not None:
        rationale.append(("vector", "CVSS v4.0 vector supplied by the reporting engine"))
        adjustments.append("engine_vector")
        v4 = engine4
    elif ladder is not None:
        ladder4, ladder31 = SEVERITY_LADDER[ladder]
        rationale.append(
            (
                "vector",
                f"representative {ladder.value} vector matching the engine's rating of this "
                f"{context.kind.value} instance",
            )
        )
        adjustments.append("severity_ladder")
        v4 = Cvss4Vector.parse(ladder4)
        base31 = Cvss31Vector.parse(ladder31)
    else:
        rationale.append(("vector", f"default Base vector of the {label} weakness family"))
        v4 = base4
    v31 = engine31 if engine31 is not None else base31
    if context.kev and v4.get("E") == "X":
        v4 = v4.with_metrics(E="A")
        rationale.append(("E", "a referenced CVE is listed in the CISA KEV catalogue"))
        adjustments.append("kev")
    if engine4 is None and ladder is None:
        v4, v31 = _adjust(
            context,
            v4,
            v31,
            adjust31=engine31 is None,
            rationale=rationale,
            adjustments=adjustments,
        )
    return v4, v31, tuple(rationale), tuple(adjustments)


def _adjust(
    context: RatingContext,
    v4: Cvss4Vector,
    v31: Cvss31Vector,
    *,
    adjust31: bool,
    rationale: list[tuple[str, str]],
    adjustments: list[str],
) -> tuple[Cvss4Vector, Cvss31Vector]:
    """Apply the evidence-based metric changes to a template vector."""
    changes4: dict[str, str] = {}
    changes31: dict[str, str] = {}
    if context.entry_point == "local" and v4.get("AV") == "N":
        changes4["AV"] = "L"
        changes31["AV"] = "L"
        rationale.append(("AV", "untrusted data enters from a local source, not the network"))
        adjustments.append("local_entry_point")
    elif context.entry_point == "network":
        rationale.append(("AV", "untrusted data reaches the code from a network request"))
    if context.authentication_required and v4.get("PR") == "N":
        changes4["PR"] = "L"
        changes31["PR"] = "L"
        rationale.append(("PR", "the handler sits behind an authentication guard"))
        adjustments.append("authentication_required")
    if context.is_test_code and v4.get("AT") == "N":
        changes4["AT"] = "P"
        changes31["AC"] = "H"
        rationale.append(("AT", "test code: exploitation needs conditions absent in production"))
        adjustments.append("test_code")
    if context.sanitiser_inadequate:
        rationale.append(("AC", "a sanitiser exists on the path but does not cover the sink"))
    if changes4:
        v4 = v4.with_metrics(**changes4)
    if changes31 and adjust31:
        v31 = Cvss31Vector.from_metrics({**v31.as_dict, **changes31})
    return v4, v31
