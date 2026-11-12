"""The deterministic facts a rating reads about one candidate.

Owning epic: E29. ``RatingContext.for_candidate`` derives, from the candidate and the original
source text only (never from a model answer), where untrusted data enters (network, local, none),
whether the code path sits behind an authentication check, whether the finding is in test code,
and the asset criticality. The heuristics are deliberately conservative: when a fact cannot be
established it stays ``None``/``"unknown"`` and the CVSS template keeps its default metric.
"""

import re
from collections.abc import Callable
from typing import ClassVar, Final, Literal

from pydantic import Field

from codekavach.core.log import get_logger
from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.enums import CandidateKind, Confidence, Severity, TaintRole
from codekavach.core.models.taxonomy import CweId

_log = get_logger(__name__)

EntryPoint = Literal["network", "adjacent", "local", "physical", "none", "unknown"]
Criticality = Literal["low", "medium", "high", "critical"]

_NETWORK_SOURCE: Final = re.compile(
    r"request\.|req\.(body|query|params|headers|cookies)|\$_(get|post|request|cookie|server)|"
    r"getparameter|getheader|getquerystring|@requestparam|@pathvariable|@requestbody|"
    r"flask|django|fastapi|starlette|express|http\.request|r\.formvalue|r\.url\.query|"
    r"\bquery_params\b|\bform\b|websocket|graphql|event\[|lambda_handler",
    re.IGNORECASE,
)
_LOCAL_SOURCE: Final = re.compile(
    r"sys\.argv|argparse|\binput\(|os\.environ|getenv|process\.env|process\.argv|stdin|"
    r"open\(|read_text|readfile|scanner\(system\.in|os\.args|click\.|typer\.",
    re.IGNORECASE,
)
_WEB_FILE: Final = re.compile(
    r"@(app|bp|blueprint|router|api)\.(route|get|post|put|delete|patch)|app\.(get|post|put|use)\(|"
    r"@(get|post|put|delete|request)mapping|@restcontroller|http\.handlefunc|urlpatterns|"
    r"from flask|from fastapi|from django|require\(['\"]express['\"]\)",
    re.IGNORECASE,
)
_AUTH_GUARD: Final = re.compile(
    r"login_required|jwt_required|requires_auth|auth_required|permission_required|"
    r"@authenticated|@auth\b|@secured|@preauthorize|@rolesallowed|isauthenticated|"
    r"depends\(\s*get_current_(active_)?user|passport\.authenticate|ensureauth|"
    r"current_user\.is_authenticated|@token_required|verify_token",
    re.IGNORECASE,
)
_TEST_PATH: Final = re.compile(
    r"(^|/)(tests?|spec|__tests__|testdata)(/|$)|(^|/)test_[^/]*$|_test\."
)
_VENDORED: Final = re.compile(r"(^|/)(vendor|third_party|node_modules|site-packages)(/|$)")
_GUARD_WINDOW: Final = 25


class RatingContext(KavachModel):
    """Facts about one candidate that the rating rules read; local client context only."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    cwe: tuple[CweId, ...] = ()
    kind: CandidateKind = CandidateKind.VULNERABILITY
    entry_point: EntryPoint = "unknown"
    authentication_required: bool | None = None
    user_interaction: bool | None = None
    taint_source: str | None = None
    has_taint_path: bool = False
    sanitiser_inadequate: bool = False
    is_test_code: bool = False
    is_vendored: bool = False
    asset_criticality: Criticality = "medium"
    engine_severity: Severity | None = None
    engine_confidence: Confidence | None = None
    cvss4_vector: str | None = None
    cvss31_vector: str | None = None
    kev: bool = False
    epss: float | None = Field(default=None, ge=0.0, le=1.0)

    @classmethod
    def for_candidate(
        cls,
        candidate: Candidate,
        *,
        read_line: Callable[[str, int], str | None] | None = None,
        file_text: Callable[[str], str | None] | None = None,
        asset_criticality: Criticality = "medium",
    ) -> "RatingContext":
        """Derive the context of ``candidate``; ``read_line``/``file_text`` read original code."""
        properties = dict(candidate.properties)
        primary = candidate.locations[0]
        path = primary.path
        source_text: list[str] = []
        sanitiser_inadequate = False
        path_obj = candidate.taint_path
        if path_obj is not None:
            for step in path_obj.steps:
                if step.role is TaintRole.SOURCE:
                    source_text.append(step.note or "")
                    if read_line is not None:
                        source_text.append(
                            read_line(step.location.path, step.location.start_line) or ""
                        )
                if step.note and "sanitiser.inadequate" in step.note:
                    sanitiser_inadequate = True
        if "taint.source" in properties:
            source_text.append(properties["taint.source"])
        joined = " ".join(source_text)
        entry: EntryPoint = "unknown"
        if joined.strip():
            if _NETWORK_SOURCE.search(joined):
                entry = "network"
            elif _LOCAL_SOURCE.search(joined):
                entry = "local"
        text = file_text(path) if file_text is not None else None
        if entry == "unknown" and text is not None and _WEB_FILE.search(text):
            entry = "network"
        auth: bool | None = None
        if text is not None:
            lines = text.splitlines()
            start = max(0, primary.start_line - _GUARD_WINDOW)
            window = "\n".join(lines[start : primary.start_line])
            auth = bool(_AUTH_GUARD.search(window)) if window else None
        return cls(
            cwe=candidate.cwe,
            kind=candidate.kind,
            entry_point=entry,
            authentication_required=auth,
            taint_source=(properties.get("taint.source") or None),
            has_taint_path=path_obj is not None,
            sanitiser_inadequate=sanitiser_inadequate,
            is_test_code=bool(_TEST_PATH.search(path)),
            is_vendored=bool(_VENDORED.search(path)),
            asset_criticality=asset_criticality,
            engine_severity=candidate.engine_severity,
            engine_confidence=candidate.engine_confidence,
            cvss4_vector=properties.get("cvss4_vector") or properties.get("cvss_v4_vector"),
            cvss31_vector=properties.get("cvss31_vector") or properties.get("cvss_v3_vector"),
            kev=bool(properties.get("sca.kev")),
            epss=_probability(properties.get("sca.epss")),
        )


def _probability(value: str | None) -> float | None:
    try:
        number = float(value) if value else None
    except ValueError:
        return None
    return number if number is not None and 0.0 <= number <= 1.0 else None
