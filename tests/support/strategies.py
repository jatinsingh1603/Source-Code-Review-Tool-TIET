"""Shared hypothesis strategies: text shapes (E01-07) and every core model (E02-26).

Model strategies build through the real constructors and class methods, so each example is
valid by construction; none uses ``assume`` or a rejecting ``filter`` on model objects. Sizes
are drawn before content so that shrinking gives small, readable examples. Ids are drawn rather
than taken from the ULID factory, so that derandomized runs are reproducible. Secret-looking
values come only from ``tests.support.synthetic``.
"""

import functools
import keyword
import random
import string
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from codekavach.core.models.candidate import Candidate
from codekavach.core.models.egress import EgressRecord, TokenCounts
from codekavach.core.models.enums import (
    CandidateKind,
    Confidence,
    ContextKind,
    DetectionOrigin,
    EgressOutcome,
    FindingStatus,
    Language,
    PlaceholderKind,
    PrivacyLevel,
    ScanStatus,
    SegmentRole,
    Severity,
    SliceStrategy,
    StageStatus,
)
from codekavach.core.models.evidence import Evidence
from codekavach.core.models.finding import (
    EngineRef,
    Finding,
    Impact,
    Likelihood,
    LLMReviewRef,
    Provenance,
)
from codekavach.core.models.fingerprint import FingerprintParts, fingerprint_batch, snippet_hash
from codekavach.core.models.ids import (
    CandidateId,
    FindingId,
    PayloadId,
    ProjectId,
    ScanId,
    SliceId,
)
from codekavach.core.models.lifecycle import (
    ALLOWED_TRANSITIONS,
    PERMITTED_ACTORS,
    REASON_REQUIRED,
    StatusChange,
    apply_transition,
)
from codekavach.core.models.location import CodeRegion, Location
from codekavach.core.models.payload import LineMapEntry, SanitisedPayload, format_placeholder
from codekavach.core.models.scan import DEFAULT_STAGES, Project, Scan, StageResult
from codekavach.core.models.slice import CodeSlice, SliceSegment
from codekavach.core.models.summary import EgressTotals, ScanSummary
from codekavach.core.models.taint import TaintPath
from codekavach.core.models.taxonomy import Reference, TaxonomyRef
from codekavach.core.models.text import RawCode, SanitisedText, split_lines
from codekavach.core.models.verdict import ContextRequest, LLMVerdict
from tests.support.synthetic import SECRET_SHAPES, build_secret

# ECMAScript reserved words: never valid identifiers in JavaScript.
_JS_RESERVED = frozenset(
    {
        "await", "break", "case", "catch", "class", "const", "continue", "debugger",
        "default", "delete", "do", "else", "enum", "export", "extends", "false", "finally",
        "for", "function", "if", "implements", "import", "in", "instanceof", "interface",
        "let", "new", "null", "package", "private", "protected", "public", "return", "static",
        "super", "switch", "this", "throw", "true", "try", "typeof", "var", "void", "while",
        "with", "yield",
    }
)  # fmt: skip
_NON_ASCII_LETTERS = "éñßøçλπждü"
_LOWER = string.ascii_lowercase + _NON_ASCII_LETTERS
_WORD = st.text(alphabet=_LOWER, min_size=1, max_size=8)


def _join(words: list[str], style: str) -> str:
    if style == "snake":
        return "_".join(words)
    return words[0] + "".join(w[:1].upper() + w[1:] for w in words[1:])


def _is_valid(name: str) -> bool:
    return (
        name.isidentifier()
        and not keyword.iskeyword(name)
        and name not in _JS_RESERVED
        and name.isprintable()
    )


def identifiers(min_size: int = 1, max_size: int = 40) -> SearchStrategy[str]:
    """Valid Python and JavaScript identifiers, never a keyword.

    Covers snake_case, camelCase, leading underscores, digit suffixes and non-ASCII letters.
    """

    @st.composite
    def build(draw: st.DrawFn) -> str:
        words = draw(st.lists(_WORD, min_size=1, max_size=4))
        name = _join(words, draw(st.sampled_from(["snake", "camel"])))
        name = "_" * draw(st.integers(0, 2)) + name
        if draw(st.booleans()):
            name += str(draw(st.integers(0, 99)))
        name = name[:max_size]
        if len(name) < min_size:
            name += "x" * (min_size - len(name))
        return name

    return build().filter(_is_valid)


def fake_secrets() -> SearchStrategy[tuple[str, str]]:
    """Pairs of (kind, value) whose value matches the kind's detector pattern."""

    @st.composite
    def build(draw: st.DrawFn) -> tuple[str, str]:
        kind = draw(st.sampled_from(sorted(SECRET_SHAPES)))
        body = draw(st.from_regex(SECRET_SHAPES[kind].body_pattern, fullmatch=True))
        return kind, build_secret(kind, body)

    return build()


def nested_json(leaves: SearchStrategy[object]) -> SearchStrategy[object]:
    """Dicts, lists and tuples nested up to depth 4, always holding at least one leaf."""

    def containers(children: SearchStrategy[object]) -> SearchStrategy[object]:
        items = st.lists(children, min_size=1, max_size=4)
        return st.one_of(
            items,
            items.map(tuple),
            st.dictionaries(st.text(max_size=8), children, min_size=1, max_size=4),
        )

    level: SearchStrategy[object] = leaves
    for _ in range(3):
        level = st.one_of(leaves, containers(level))
    return containers(level)


# --- building blocks -------------------------------------------------------------------------
#
# Hypothesis spends roughly a tenth of a millisecond per draw, so bulky text is assembled from
# fixed vocabularies, and long texts from a seeded ``random.Random`` whose seed is one draw:
# the seed shrinks to 0 and the sizes shrink first, which keeps failing examples small.

FORM_FEED = chr(0x0C)
LINE_SEPARATOR = chr(0x2028)
LONG_LINE_LENGTH = 5000
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_SENTENCES = (
    "",
    "Reviewed by the security team.",
    "The owner parameter comes from the request.",
    "Use a parameterised query.",
    "Input reaches the sink without validation (see line 12).",
    "Accepted until the next release; tracked in the risk register.",
    "var_4 flows into fn_2 through string concatenation.",
    "No exploitable path found.",
)
_PLAIN = st.sampled_from(_SENTENCES)
_TITLES = st.sampled_from(
    ("SQL injection in find_by_owner", "Hard-coded secret", "Path traversal", "Weak hash")
)
_KEYWORDS = tuple(sorted(keyword.kwlist))
_PSEUDONYM_KINDS = ("fn", "var", "param", "cls", "field", "tbl", "col", "mod")
_PUNCTUATION = ("(", ")", "[", "]", "{", "}", ":", "=", ".", ",", "+", "-", "*", '"', "'", "==")
_SUBTYPES = ("aws_access_key", "github_token", "email", "domain", "ip_address", "client_name")
# Identifier-like words of four or more characters, some non-ASCII (NFC), for I6 tests.
_WORDS = (
    "account", "owner", "cursor", "execute", "fetch_all", "request", "user_name", "balance",
    "transfer", "customer_id", "loadConfig", "parseInput", "session", "render", "query",
    "handler", "données", "größe", "счёт", "खाता", "naïve_value", "résumé", "Ωmega",
)  # fmt: skip
_INDENTS = ("", "    ", "        ", "\t", "\t\t", "  \t")
_PATH_SEGMENTS = (
    "src", "lib", "app", "bank", "tests", "a", "x_1", "accounts.py", "__init__.py", "main.go",
    "Service.java", "config.yaml", "utils-v2", "Read Me.md", "données", "खाता", "naïve file.txt",
    "v1.2", "web app", "Ünïcode", "日本語",
)  # fmt: skip
_CVSS_VECTORS = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:N/VI:L/VA:H/SC:L/SI:L/SA:L",
)
_REPOSITORY_URLS = (
    "https://example.test/org/repo.git",
    "http://git.example.test/team/app",
    "ssh://git@example.test/org/repo.git",
    "git@example.test:org/repo.git",
)


_OPTIONAL_SEQ = st.none() | st.integers(0, 1000)
_OPTIONAL_BOOL = st.none() | st.booleans()
_OPTIONAL_COUNT = st.none() | st.integers(0, 10_000)
_OPTIONAL_COMMIT = st.none() | st.from_regex(r"[0-9a-f]{7,40}", fullmatch=True)
_OWASP = st.lists(
    st.builds(
        TaxonomyRef,
        scheme=st.just("owasp-top10"),
        id=st.sampled_from(["A01", "A03", "A07"]),
        version=st.just("2021"),
    ),
    max_size=2,
).map(tuple)
_REFERENCES = st.lists(
    st.builds(
        Reference,
        title=st.sampled_from(["CWE entry", "Vendor advisory"]),
        url=st.none() | st.just("https://example.test/advisory"),
    ),
    max_size=2,
).map(tuple)


@functools.cache
def _members(enum: type[Enum]) -> SearchStrategy[Any]:
    """Cached ``sampled_from`` over an enum's members (strategy construction is costly)."""
    return st.sampled_from(list(enum))


@functools.cache
def _pick(options: tuple[Any, ...]) -> SearchStrategy[Any]:
    return st.sampled_from(options)


@functools.cache
def _maybe(strategy: SearchStrategy[Any]) -> SearchStrategy[Any]:
    return st.none() | strategy


def _rng(draw: st.DrawFn) -> random.Random:
    return random.Random(draw(st.integers(0, 2**32 - 1)))  # noqa: S311 - test data, not crypto


@functools.cache
def _ulid() -> SearchStrategy[str]:
    return st.integers(0, 2**128 - 1).map(
        lambda value: "".join(_CROCKFORD[(value >> (5 * (25 - i))) & 31] for i in range(26))
    )


@functools.cache
def _typed_id(prefix: str) -> SearchStrategy[str]:
    return _ulid().map(lambda ulid: prefix + ulid)


@functools.cache
def _times() -> SearchStrategy[datetime]:
    return st.datetimes(
        min_value=datetime(2024, 1, 1),  # noqa: DTZ001 - naive bounds; tz is applied below
        max_value=datetime(2034, 12, 31),  # noqa: DTZ001
        timezones=st.just(UTC),
    )


@functools.cache
def _hex64() -> SearchStrategy[str]:
    return st.binary(min_size=32, max_size=32).map(bytes.hex)


@functools.cache
def _cwes(max_size: int = 3) -> SearchStrategy[tuple[int, ...]]:
    return st.lists(st.integers(1, 1400), max_size=max_size, unique=True).map(tuple)


@functools.cache
def _symbols() -> SearchStrategy[str]:
    return st.lists(st.sampled_from(_WORDS), min_size=1, max_size=3).map(".".join)


@functools.cache
def repo_paths() -> SearchStrategy[str]:
    """Normalised repository paths: one to six segments, non-ASCII letters, inner spaces.

    Never a ``.`` or ``..`` segment, a control character, a leading slash, a backslash or a
    drive-like first segment, so every example is a fixed point of ``normalise_repo_path``.
    """
    segment = st.sampled_from(_PATH_SEGMENTS)
    return st.lists(segment, min_size=1, max_size=6).map("/".join)


@functools.cache
def regions(max_line: int = 500) -> SearchStrategy[CodeRegion]:
    """Line regions, optionally with columns."""

    @st.composite
    def build(draw: st.DrawFn) -> CodeRegion:
        length = draw(st.integers(0, 30))
        start = draw(st.integers(1, max(1, max_line - length)))
        end = start + length
        if not draw(st.booleans()):
            return CodeRegion(start_line=start, end_line=end)
        start_col = draw(st.integers(1, 80))
        end_col = draw(st.integers(start_col if length == 0 else 1, 120))
        return CodeRegion(start_line=start, end_line=end, start_col=start_col, end_col=end_col)

    return build()


@functools.cache
def locations(paths: SearchStrategy[str] | None = None) -> SearchStrategy[Location]:
    """Locations in a drawn (or given) path, with an optional qualified symbol."""

    @st.composite
    def build(draw: st.DrawFn) -> Location:
        path = draw(paths if paths is not None else repo_paths())
        region = draw(regions())
        symbol = draw(_maybe(_symbols()))
        return Location.from_region(path, region, symbol=symbol)

    return build()


def _draw_taint(draw: st.DrawFn, sink: Location | None) -> TaintPath:
    via_count = draw(st.integers(0, 3))
    source = draw(locations())
    via = [draw(locations()) for _ in range(via_count)]
    return TaintPath.from_locations(source, sink or draw(locations()), via)


def taint_paths(sink: Location | None = None) -> SearchStrategy[TaintPath]:
    """Source, zero to three propagators and a sink (the given one, if any)."""

    @st.composite
    def build(draw: st.DrawFn) -> TaintPath:
        return _draw_taint(draw, sink)

    return build()


# --- text ---------------------------------------------------------------------------------------


def _code_line(rng: random.Random) -> str:
    """One line of up to 200 characters; one in ten holds a form feed or U+2028."""
    tokens = [
        rng.choice(_WORDS) if rng.random() < 0.6 else rng.choice(_PUNCTUATION)
        for _ in range(rng.randint(0, 10))
    ]
    line = rng.choice(_INDENTS) + " ".join(tokens)
    if tokens and rng.randint(0, 9) == 0:
        cut = rng.randint(0, len(line))
        line = line[:cut] + rng.choice((FORM_FEED, LINE_SEPARATOR)) + line[cut:]
    return line[:200]


def _code_lines(draw: st.DrawFn, count: int) -> list[str]:
    """``count`` lines drawn from a small pool of generated lines and blank lines."""
    rng = _rng(draw)
    pool = [_code_line(rng) for _ in range(rng.randint(1, 6))] + [""]
    return [rng.choice(pool) for _ in range(count)]


@functools.cache
def raw_code_texts() -> SearchStrategy[str]:
    """Client-code-like text: 1 to 120 lines, tabs, blank lines, CRLF, no final newline.

    Occasionally a form feed or U+2028 sits inside a line (not a line break under ADR D13),
    and occasionally one line is 5,000 characters long, to exercise truncation. Lines hold
    identifier-like words of four or more characters for later I6 completeness tests.
    """

    @st.composite
    def build(draw: st.DrawFn) -> str:
        count = draw(st.integers(1, 120))
        lines = _code_lines(draw, count)
        if draw(st.integers(0, 19)) == 0:
            word = draw(st.sampled_from(_WORDS))
            index = draw(st.integers(0, count - 1))
            lines[index] = ((word + " ") * LONG_LINE_LENGTH)[:LONG_LINE_LENGTH].rstrip()
        ending = "\r\n" if draw(st.integers(0, 4)) == 0 else "\n"
        text = ending.join(lines)
        if draw(st.integers(0, 3)) != 0 or not text:
            text += ending  # a lone blank line needs its terminator to count as a line
        return text

    return build()


@functools.cache
def safe_payload_texts() -> SearchStrategy[str]:
    """Sanitised text: pseudonyms (``fn_1``), keywords, punctuation and whole placeholders.

    Never contains ``<`` or ``>`` outside a well-formed placeholder, so no partial placeholder
    can appear.
    """

    def token(rng: random.Random) -> str:
        roll = rng.random()
        if roll < 0.45:
            return f"{rng.choice(_PSEUDONYM_KINDS)}_{rng.randint(1, 99)}"
        if roll < 0.65:
            return rng.choice(_KEYWORDS)
        if roll < 0.95:
            return rng.choice(_PUNCTUATION)
        kind = rng.choice(sorted(PlaceholderKind))
        return format_placeholder(kind, rng.choice(_SUBTYPES), rng.randint(1, 9))

    @st.composite
    def build(draw: st.DrawFn) -> str:
        count = draw(st.integers(1, 30))
        rng = _rng(draw)
        lines = [
            rng.choice(("", "    ", "        "))
            + " ".join(token(rng) for _ in range(rng.randint(0, 8)))
            for _ in range(count)
        ]
        return "\n".join(lines) + "\n"

    return build()


# --- candidates, slices, payloads, verdicts -------------------------------------------------


def _fingerprint(location: Location, rule_id: str, engine: str, snippet: list[str]) -> str:
    parts = FingerprintParts(
        engine=engine,
        rule_id=rule_id,
        path=location.path,
        symbol=location.symbol,
        snippet_hash=snippet_hash(snippet),
        start_line=location.start_line,
    )
    return fingerprint_batch([parts])[0]


_RULE_IDS = st.from_regex(r"[a-z][a-z0-9._-]{0,40}", fullmatch=True)
_ENGINES = st.sampled_from(["codekavach-rules", "semgrep", "bandit", "gitleaks", "osv-scanner"])


@functools.cache
def candidates() -> SearchStrategy[Candidate]:
    """Candidates with one to three locations and an optional taint path to the first."""

    @st.composite
    def build(draw: st.DrawFn) -> Candidate:
        count = draw(st.integers(1, 3))
        found = [draw(locations()) for _ in range(count)]
        rule_id, engine = draw(_RULE_IDS), draw(_ENGINES)
        taint = _draw_taint(draw, found[0]) if draw(st.booleans()) else None
        snippet = _code_lines(draw, draw(st.integers(1, 3)))
        return Candidate.create(
            id=CandidateId(draw(_typed_id("cand_"))),
            rule_id=rule_id,
            engine=engine,
            cwe=draw(_cwes()),
            locations=tuple(found),
            taint_path=taint,
            engine_severity=draw(_maybe(_members(Severity))),
            fingerprint=_fingerprint(found[0], rule_id, engine, snippet),
            kind=draw(_members(CandidateKind)),
            language=draw(_members(Language)),
            message=draw(_PLAIN),
        )

    return build()


@functools.cache
def code_slices() -> SearchStrategy[CodeSlice]:
    """Slices whose segments are ascending and non-overlapping per file, one primary."""

    @st.composite
    def build(draw: st.DrawFn) -> CodeSlice:
        file_count = draw(st.integers(1, 3))
        paths = draw(st.lists(repo_paths(), min_size=file_count, max_size=file_count, unique=True))
        layout: list[tuple[str, int, int]] = []
        for path in paths:
            line = 0
            for _ in range(draw(st.integers(1, 3))):
                start = line + draw(st.integers(1, 20))
                end = start + draw(st.integers(0, 15))
                layout.append((path, start, end))
                line = end
        primary = draw(st.integers(0, len(layout) - 1))
        segments = []
        for index, (path, start, end) in enumerate(layout):
            lines = _code_lines(draw, end - start + 1)
            role = SegmentRole.PRIMARY if index == primary else SegmentRole.CONTEXT
            segments.append(
                SliceSegment(
                    path=path,
                    region=CodeRegion(start_line=start, end_line=end),
                    text=RawCode("".join(line + "\n" for line in lines)),
                    role=role,
                )
            )
        return CodeSlice(
            id=SliceId(draw(_typed_id("slice_"))),
            candidate_id=CandidateId(draw(_typed_id("cand_"))),
            language=draw(_members(Language)),
            strategy=draw(_members(SliceStrategy)),
            segments=tuple(segments),
            token_estimate=draw(st.integers(0, 50_000)),
            truncated=draw(st.booleans()),
        )

    return build()


@functools.cache
def sanitised_payloads() -> SearchStrategy[SanitisedPayload]:
    """Payloads built with ``SanitisedPayload.build``; L4 payloads carry no line map."""

    @st.composite
    def build(draw: st.DrawFn) -> SanitisedPayload:
        text = draw(safe_payload_texts())
        level = draw(_members(PrivacyLevel))
        total = len(split_lines(text))
        line_map: list[LineMapEntry] = []
        if level is not PrivacyLevel.L4:
            line = 0
            for index in range(draw(st.integers(0, 3))):
                if line >= total:
                    break
                start = line + 1
                end = draw(st.integers(start, total))
                line_map.append(
                    LineMapEntry(
                        payload_start_line=start,
                        payload_end_line=end,
                        segment_index=index,
                        file_start_line=draw(st.integers(1, 5000)),
                    )
                )
                line = end
        slice_id: str | None = draw(_typed_id("slice_"))
        if level is PrivacyLevel.L4 and draw(st.booleans()):
            slice_id = None
        payload = SanitisedPayload.build(
            candidate_id=CandidateId(draw(_typed_id("cand_"))),
            slice_id=SliceId(slice_id) if slice_id else None,
            text=SanitisedText(text),
            level=level,
            pseudonym_count=draw(st.integers(0, 500)),
            line_map=tuple(line_map),
        )
        return payload.evolve(id=PayloadId(draw(_typed_id("pay_"))))

    return build()


@functools.cache
def _untrusted(min_size: int = 0) -> SearchStrategy[str]:
    """Model output text; some examples carry the whitespace the model cleaner strips."""
    text = st.sampled_from([sentence for sentence in _SENTENCES if len(sentence) >= min_size])
    return text | text.map(lambda sentence: f"  {sentence}" + chr(9))


@functools.cache
def verdicts() -> SearchStrategy[LLMVerdict]:
    """Verdicts in pseudonym space; ``is_vulnerable=None`` always comes with context requests."""

    @st.composite
    def build(draw: st.DrawFn) -> LLMVerdict:
        decided = draw(_pick((True, False, None)))
        requests = [
            ContextRequest(
                kind=draw(_members(ContextKind)),
                symbol=draw(st.sampled_from(_WORDS)),
                reason=draw(_untrusted()),
            )
            for _ in range(draw(st.integers(1 if decided is None else 0, 3)))
        ]
        return LLMVerdict(
            is_vulnerable=decided,
            confidence=draw(_members(Confidence)),
            cwe=draw(_cwes(5)),
            reasoning=draw(_untrusted()),
            impact=draw(_untrusted()),
            remediation=draw(_untrusted()),
            needs_context=tuple(requests),
            cited_lines=tuple(draw(st.lists(st.integers(1, 400), max_size=20, unique=True))),
        )

    return build()


# --- evidence, status history, findings -----------------------------------------------------


def _located_evidence(draw: st.DrawFn, path: str) -> tuple[Location, Evidence]:
    source = draw(raw_code_texts())
    total = len(split_lines(source))
    start = draw(st.integers(1, total))
    end = draw(st.integers(start, min(total, start + 10)))
    columns: tuple[int, int] | tuple[None, None] = (None, None)
    if draw(st.booleans()):
        first = draw(st.integers(1, 80))
        columns = (first, draw(st.integers(first if start == end else 1, 90)))
    location = Location(
        path=path,
        start_line=start,
        end_line=end,
        start_col=columns[0],
        end_col=columns[1],
        symbol=draw(_maybe(_symbols())),
    )
    evidence = Evidence.from_source(
        RawCode(source),
        location,
        language=draw(_members(Language)),
        context_lines=draw(st.integers(0, 3)),
        max_lines=draw(st.integers(4, 40)),
    )
    return location, evidence


@functools.cache
def evidences() -> SearchStrategy[Evidence]:
    """Evidence cut from generated source by ``Evidence.from_source``."""

    @st.composite
    def build(draw: st.DrawFn) -> Evidence:
        return _located_evidence(draw, draw(repo_paths()))[1]

    return build()


def _draw_history(
    draw: st.DrawFn, start: datetime
) -> tuple[FindingStatus, tuple[StatusChange, ...]]:
    steps = draw(st.integers(0, 6))
    status = FindingStatus.OPEN
    history: tuple[StatusChange, ...] = ()
    moment = start
    for _ in range(steps):
        target = draw(_pick(tuple(sorted(ALLOWED_TRANSITIONS[status]))))
        actor_kind = draw(_pick(tuple(sorted(PERMITTED_ACTORS[target]))))
        moment += timedelta(minutes=draw(st.integers(0, 10_000)))
        reason = draw(_PLAIN)
        if target in REASON_REQUIRED and not reason.strip():
            reason = "reviewed by the security team"
        expires_at = None
        if target is FindingStatus.ACCEPTED_RISK and draw(st.booleans()):
            expires_at = moment + timedelta(days=draw(st.integers(1, 365)))
        change = StatusChange(
            from_status=status,
            to_status=target,
            at=moment,
            actor_kind=actor_kind,
            actor=draw(_pick(("alice", "ci-policy", "codekavach", "reviewer-2"))),
            reason=reason,
            expires_at=expires_at,
        )
        status, history = apply_transition(status, history, change)
    return status, history


def status_histories() -> SearchStrategy[tuple[FindingStatus, tuple[StatusChange, ...]]]:
    """``(status, history)`` pairs from legal transitions applied with ``apply_transition``."""

    @st.composite
    def build(draw: st.DrawFn) -> tuple[FindingStatus, tuple[StatusChange, ...]]:
        return _draw_history(draw, draw(_times()))

    return build()


def _provenance(draw: st.DrawFn, candidate_ids: list[CandidateId]) -> Provenance:
    origin = draw(_members(DetectionOrigin))
    engines = [
        EngineRef(engine=draw(_ENGINES), rule_id=draw(_RULE_IDS))
        for _ in range(draw(st.integers(1 if origin is DetectionOrigin.DETERMINISTIC else 0, 2)))
    ]
    reviews = [
        LLMReviewRef(
            provider="mock",
            model="mock-1",
            task="triage",
            level=draw(_members(PrivacyLevel)),
            ledger_seq=draw(_OPTIONAL_SEQ),
            is_vulnerable=draw(_OPTIONAL_BOOL),
            confidence=draw(_members(Confidence)),
            reasoning=draw(_PLAIN),
        )
        for _ in range(draw(st.integers(0, 2)))
    ]
    return Provenance(
        origin=origin,
        scan_id=ScanId(draw(_typed_id("scan_"))),
        candidate_ids=tuple(candidate_ids),
        engines=tuple(engines),
        llm_reviews=tuple(reviews),
        codekavach_version="0.1.0.dev0",
    )


@functools.cache
def findings() -> SearchStrategy[Finding]:
    """Findings with evidence from ``Evidence.from_source`` and a legal status history."""

    @st.composite
    def build(draw: st.DrawFn) -> Finding:
        path = draw(repo_paths())
        location, evidence = _located_evidence(draw, path)
        others = draw(st.lists(locations(), max_size=2))
        created_at = draw(_times())
        status, history = _draw_history(draw, created_at)
        scored = draw(st.booleans())
        candidate_ids = [
            CandidateId(draw(_typed_id("cand_"))) for _ in range(draw(st.integers(1, 2)))
        ]
        engine, rule_id = draw(_ENGINES), draw(_RULE_IDS)
        snippet = [line.text.expose() for line in evidence.lines]
        return Finding(
            id=FindingId(draw(_typed_id("find_"))),
            title=draw(_TITLES),
            severity=draw(_members(Severity)),
            cvss4_vector=draw(st.sampled_from(_CVSS_VECTORS)) if scored else None,
            cvss4_score=draw(st.integers(0, 100)) / 10 if scored else None,
            cwe=draw(_cwes()),
            owasp=draw(_OWASP),
            locations=(location, *others),
            evidence=(evidence,),
            impact=Impact(level=draw(st.integers(1, 5)), narrative=draw(_PLAIN)),
            likelihood=Likelihood(level=draw(st.integers(1, 5)), rationale=draw(_PLAIN)),
            remediation=draw(_PLAIN),
            references=draw(_REFERENCES),
            status=status,
            status_history=history,
            provenance=_provenance(draw, candidate_ids),
            fingerprint=_fingerprint(location, rule_id, engine, snippet),
            confidence=draw(_members(Confidence)),
            description=draw(_PLAIN),
            taint_path=_draw_taint(draw, location) if draw(st.booleans()) else None,
            kind=draw(_members(CandidateKind)),
            language=evidence.language,
            created_at=created_at,
        )

    return build()


# --- ledger, summaries, projects, scans -----------------------------------------------------


@functools.cache
def egress_chains(max_size: int = 20) -> SearchStrategy[list[EgressRecord]]:
    """Sealed ledger chains mixing sent, blocked, completed and failed entries.

    Completed and failed entries refer to an earlier sent entry; timestamps never decrease.
    """

    @st.composite
    def build(draw: st.DrawFn) -> list[EgressRecord]:
        size = draw(st.integers(1, max_size))
        scan_id = ScanId(draw(_typed_id("scan_")))
        candidate_id = CandidateId(draw(_typed_id("cand_")))
        moment = draw(_times())
        rng = _rng(draw)
        chain: list[EgressRecord] = []
        sent: list[int] = []
        for seq in range(1, size + 1):
            choices = [EgressOutcome.SENT, EgressOutcome.BLOCKED]
            if sent:
                choices += [EgressOutcome.COMPLETED, EgressOutcome.FAILED]
            outcome = rng.choice(choices)
            moment += timedelta(milliseconds=rng.randint(0, 60_000))
            completion = rng.randint(0, 4000) if outcome is EgressOutcome.COMPLETED else None
            chain.append(
                EgressRecord.seal(
                    prev=chain[-1] if chain else None,
                    timestamp=moment,
                    scan_id=scan_id,
                    candidate_id=rng.choice((None, candidate_id)),
                    provider=rng.choice(("mock", "ollama", "anthropic")),
                    model=rng.choice(("mock-1", "llama3", "claude")),
                    task=rng.choice((None, "triage", "explain", "fix")),
                    level=rng.choice(list(PrivacyLevel)),
                    payload_hash=rng.randbytes(32).hex(),
                    request_hash=rng.choice((None, rng.randbytes(32).hex())),
                    token_counts=TokenCounts(
                        prompt=rng.randint(0, 20_000),
                        completion=completion,
                        estimated=rng.random() < 0.5,
                    ),
                    outcome=outcome,
                    block_code=(
                        rng.choice(("i6_leak", "policy_level", "budget_exceeded"))
                        if outcome is EgressOutcome.BLOCKED
                        else None
                    ),
                    ref_seq=(
                        rng.choice(sent)
                        if outcome in (EgressOutcome.COMPLETED, EgressOutcome.FAILED)
                        else None
                    ),
                )
            )
            if outcome is EgressOutcome.SENT:
                sent.append(seq)
        return chain

    return build()


@functools.cache
def egress_totals() -> SearchStrategy[EgressTotals]:
    """Totals computed by ``EgressTotals.from_records`` over a generated chain."""
    return egress_chains(max_size=8).map(EgressTotals.from_records)


@functools.cache
def summaries() -> SearchStrategy[ScanSummary]:
    """Summaries computed by ``ScanSummary.from_findings``."""

    @st.composite
    def build(draw: st.DrawFn) -> ScanSummary:
        found = draw(st.lists(findings(), max_size=3))
        total = draw(st.integers(len(found), 500))
        return ScanSummary.from_findings(
            found,
            files_scanned=draw(st.integers(0, 10_000)),
            lines_scanned=draw(st.integers(0, 2_000_000)),
            candidates_total=total,
            candidates_reviewed_by_llm=draw(st.integers(0, total)),
            egress=draw(egress_totals()),
            duration_seconds=draw(st.floats(0, 86_400, allow_nan=False, allow_infinity=False)),
        )

    return build()


@functools.cache
def projects() -> SearchStrategy[Project]:
    """Projects with an optional repository URL of every accepted form."""
    return st.builds(
        Project,
        id=_typed_id("proj_").map(ProjectId),
        name=st.text(alphabet=string.ascii_letters + string.digits + " -_", min_size=1, max_size=60)
        .map(str.strip)
        .map(lambda name: name or "project"),
        root=st.none() | st.just("/home/user/src/project"),
        repository_url=st.none() | st.sampled_from(_REPOSITORY_URLS),
        default_privacy_level=_members(PrivacyLevel),
        created_at=_times(),
    )


def _stages(draw: st.DrawFn, started_at: datetime) -> tuple[StageResult, ...]:
    names = draw(st.lists(st.sampled_from(DEFAULT_STAGES), max_size=5, unique=True))
    stages = []
    for name in names:
        status = draw(_members(StageStatus))
        begin = started_at + timedelta(seconds=draw(st.integers(0, 60)))
        stages.append(
            StageResult(
                name=name,
                status=status,
                started_at=begin,
                finished_at=begin + timedelta(seconds=draw(st.integers(0, 600))),
                error_code="stage_error" if status is StageStatus.FAILED else None,
                items_in=draw(_OPTIONAL_COUNT),
                items_out=draw(_OPTIONAL_COUNT),
            )
        )
    return tuple(stages)


@functools.cache
def scans() -> SearchStrategy[Scan]:
    """Scans in every status; ended scans have ``finished_at``, completed ones a summary."""

    @st.composite
    def build(draw: st.DrawFn) -> Scan:
        status = draw(_members(ScanStatus))
        started_at = draw(_times())
        ended = status not in (ScanStatus.PENDING, ScanStatus.RUNNING)
        completed = status in (ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS)
        finished_at = started_at + timedelta(seconds=draw(st.integers(0, 7200))) if ended else None
        summary = draw(summaries()) if completed or (ended and draw(st.booleans())) else None
        return Scan(
            id=ScanId(draw(_typed_id("scan_"))),
            project_id=ProjectId(draw(_typed_id("proj_"))),
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            codekavach_version="0.1.0.dev0",
            config_hash=draw(_hex64()),
            git_commit=draw(_OPTIONAL_COMMIT),
            git_branch=draw(_maybe(_pick(("main", "feature/login", "release-1.2")))),
            git_dirty=draw(_OPTIONAL_BOOL),
            languages=tuple(draw(st.lists(_members(Language), max_size=4))),
            privacy_level=draw(_members(PrivacyLevel)),
            provider=draw(_maybe(_pick(("mock", "ollama")))),
            model=draw(_maybe(_pick(("mock-1", "llama3")))),
            stages=_stages(draw, started_at),
            summary=summary,
        )

    return build()


__all__ = [
    "FORM_FEED",
    "LINE_SEPARATOR",
    "candidates",
    "code_slices",
    "egress_chains",
    "egress_totals",
    "evidences",
    "fake_secrets",
    "findings",
    "identifiers",
    "locations",
    "nested_json",
    "projects",
    "raw_code_texts",
    "regions",
    "repo_paths",
    "safe_payload_texts",
    "sanitised_payloads",
    "scans",
    "status_histories",
    "summaries",
    "taint_paths",
    "verdicts",
]
