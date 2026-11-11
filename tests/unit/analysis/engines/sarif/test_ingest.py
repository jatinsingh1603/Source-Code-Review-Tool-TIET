"""The SARIF entry point: worked example, hostile input, limits and the golden file (E14-02)."""

import io
import json
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.analysis.engines.base import EngineRun
from codekavach.analysis.engines.sarif.errors import SarifError, SarifFormatError, SarifSizeError
from codekavach.analysis.engines.sarif.ingest import (
    IngestOptions,
    ingest_engine_run,
    ingest_sarif,
    validate_log,
)
from codekavach.analysis.engines.sarif.tables import CweFallback
from codekavach.core.models import Candidate
from codekavach.core.models.enums import CandidateKind, Confidence, Language, Severity
from codekavach.core.models.fingerprint import FingerprintParts, fingerprint_batch, snippet_hash
from tests.support.engines import make_spec
from tests.support.golden import assert_matches_golden
from tests.support.sarif import (
    code_flow,
    location,
    log,
    numbered_source,
    region,
    result,
    run,
    step,
    write_tree,
)

GOLDEN = Path(__file__).parent / "golden"
JAVA = "src/main/java/Accounts.java"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return write_tree(
        tmp_path / "view",
        {
            JAVA: numbered_source(100, 80),
            "app/util.py": numbered_source(30, 40),
            "app.py": numbered_source(50, 40),
            "web/page.js": "// header\nconst a = 1;\nconst s = '\U0001f600' + x;\n",
            "package.json": "{}\n",
        },
    )


def ingest(root: Path, data: bytes, **kwargs: Any) -> list[Candidate]:
    return ingest_sarif(data, engine_id="fake", root=root, engine_version=None, **kwargs)


# --- the worked example ------------------------------------------------------------------------


def worked_example(root: Path) -> list[Candidate]:
    java_result = result(
        "java/sql-injection",
        uri=JAVA,
        level="error",
        message="Query built from user input",
    )
    java_result["locations"] = [location(JAVA, base_id="%SRCROOT%", at=region(88, 9, 88, 62))]
    java_result["codeFlows"] = [
        code_flow(step(JAVA, 80, "user input read"), step(JAVA, 88, "query executed"))
    ]
    rule = {"id": "java/sql-injection", "properties": {"tags": ["external/cwe/cwe-089"]}}
    data = log(run([java_result], rules=[rule], name="engine", version="2.0.1"))
    return ingest_sarif(data, engine_id="fake", root=root, engine_version="2.0.1")


def test_the_worked_example(root: Path) -> None:
    (found,) = worked_example(root)
    assert found.engine == "fake"
    assert found.rule_id == "java/sql-injection"
    assert found.cwe == (89,)
    assert found.engine_severity is Severity.HIGH
    (loc,) = found.locations
    assert (loc.path, loc.start_line, loc.end_line, loc.start_col, loc.end_col, loc.symbol) == (
        JAVA,
        88,
        88,
        9,
        62,
        None,
    )
    line_88 = numbered_source(100, 80).split("\n")[87]
    expected = fingerprint_batch(
        [
            FingerprintParts(
                engine="fake",
                rule_id="java/sql-injection",
                path=JAVA,
                symbol=None,
                snippet_hash=snippet_hash([line_88]),
                start_line=88,
            )
        ]
    )
    assert found.fingerprint == expected[0]
    assert found.fingerprint.startswith("ckfp1:")
    props = dict(found.properties)
    assert props["cwe.source"] == "tags"
    assert props["engine.run"] == "engine@2.0.1"
    assert found.taint_path is not None
    assert len(found.taint_path) == 2
    assert found.language is Language.JAVA
    assert found.engine_version == "2.0.1"
    assert found.kind is CandidateKind.VULNERABILITY
    assert found.message == "Query built from user input"


def test_the_fingerprint_follows_the_code_not_the_line_number(root: Path, tmp_path: Path) -> None:
    (before,) = worked_example(root)
    moved = write_tree(tmp_path / "moved", {JAVA: "# added\n" * 3 + numbered_source(100, 80)})
    other = result("java/sql-injection", uri=JAVA, level="error")
    other["locations"] = [location(JAVA, at=region(91, 9, 91, 62))]
    (after,) = ingest(moved, log(run([other])))
    assert before.fingerprint == after.fingerprint


def test_identical_results_get_distinct_fingerprints(root: Path) -> None:
    same = [result("r", uri="app.py", line=5), result("r", uri="app.py", line=5)]
    first, second = ingest(root, log(run(same)))
    assert first.fingerprint != second.fingerprint


# --- paths -------------------------------------------------------------------------------------


def test_every_uri_spelling_gives_the_same_candidate_path(root: Path) -> None:
    absolute = root.resolve().as_posix().lstrip("/")
    spellings = [
        "app/util.py",
        "file:///" + absolute + "/app/util.py",
        "app" + chr(92) + "util.py",
        "app/ut%69l.py",
    ]
    data = log(run([result("r", uri=u, line=3) for u in spellings]))
    assert {c.locations[0].path for c in ingest(root, data)} == {"app/util.py"}


def test_a_traversal_uri_gives_no_candidate_and_is_logged(
    root: Path, log_output: io.StringIO
) -> None:
    data = log(run([result("r", uri="../../etc/passwd"), result("ok", uri="app.py", line=2)]))
    found = ingest(root, data)
    assert [c.rule_id for c in found] == ["ok"]
    logged = log_output.getvalue()
    assert "sarif_results_skipped" in logged
    assert "path_rejected" in logged
    assert "passwd" not in logged


def test_a_result_for_a_missing_file_or_line_is_skipped(root: Path) -> None:
    data = log(
        run(
            [
                result("a", uri="nowhere.py"),
                result("b", uri="app.py", line=9999),
                result("c", uri="app.py", line=2),
            ]
        )
    )
    assert [c.rule_id for c in ingest(root, data)] == ["c"]


def test_a_symlink_that_leaves_the_root_is_not_followed(root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    try:
        (root / "link.py").symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    assert ingest(root, log(run([result("r", uri="link.py")]))) == []


# --- fields ------------------------------------------------------------------------------------


def test_snippets_are_never_copied(root: Path) -> None:
    item = result("r", uri="app.py", line=2)
    item["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": "SNIPPET-MARK"}
    item["locations"][0]["physicalLocation"]["contextRegion"] = {
        "snippet": {"text": "CONTEXT-MARK"}
    }
    (found,) = ingest(root, log(run([item])))
    dumped = found.model_dump_json()
    assert "SNIPPET-MARK" not in dumped
    assert "CONTEXT-MARK" not in dumped


def test_the_message_is_cut_at_a_word_boundary(root: Path) -> None:
    long = "alpha beta " * 400
    (found,) = ingest(root, log(run([result("r", uri="app.py", message=long)])))
    assert len(found.message) <= 2000
    assert found.message.endswith("…")
    assert not found.message[:-1].endswith("alph")


def test_the_message_is_data_not_markup(root: Path) -> None:
    text = "<script>alert(1)</script>\x00\x1b[31m"
    (found,) = ingest(root, log(run([result("r", uri="app.py", message=text)])))
    assert "\x00" not in found.message
    assert "\x1b" not in found.message
    assert "<script>" in found.message  # kept as text; renderers escape it


def test_a_rule_id_with_whitespace_is_made_safe(root: Path) -> None:
    (found,) = ingest(root, log(run([result("a rule\twith\nspace", uri="app.py")])))
    assert found.rule_id == "a_rule_with_space"


def test_partial_fingerprints_are_kept_as_properties_and_our_key_is_ignored(root: Path) -> None:
    item = result(
        "r",
        uri="app.py",
        partialFingerprints={
            "primaryLocationLineHash": "abc:1",
            "codekavachFingerprint/v1": "ckfp1:" + "0" * 32,
        },
    )
    (found,) = ingest(root, log(run([item])))
    props = dict(found.properties)
    assert props["sarif.partial_fingerprint.primarylocationlinehash"] == "abc:1"
    assert not any("codekavach" in key for key in props)
    assert found.fingerprint != "ckfp1:" + "0" * 32


def test_suppressed_results_are_kept_and_marked(root: Path) -> None:
    plain = result("r", uri="app.py", suppressions=[{"kind": "inSource"}])
    explained = result(
        "s", uri="app.py", suppressions=[{"kind": "external", "justification": "x " * 400}]
    )
    first, second = ingest(root, log(run([plain, explained])))
    assert dict(first.properties)["sarif.suppressed"] == "true"
    assert 0 < len(dict(second.properties)["sarif.suppressed"]) <= 500


def test_at_most_32_properties_of_500_characters(root: Path) -> None:
    prints = {f"k{n}": "v" * 900 for n in range(60)}
    (found,) = ingest(root, log(run([result("r", uri="app.py", partialFingerprints=prints)])))
    assert len(found.properties) == 32
    assert all(len(value) <= 500 for _, value in found.properties)
    assert found.properties[0][0] == "engine.run"


def test_the_kind_comes_from_the_spec_unless_the_rule_tags_say_otherwise(root: Path) -> None:
    rules: list[dict[str, Any]] = [{"id": "r", "properties": {"tags": ["dependency"]}}, {"id": "s"}]
    data = log(run([result("r", uri="package.json"), result("s", uri="package.json")], rules=rules))
    options = IngestOptions(default_kind=CandidateKind.MISCONFIGURATION)
    tagged, plain = ingest(root, data, options=options)
    assert tagged.kind is CandidateKind.DEPENDENCY
    assert plain.kind is CandidateKind.MISCONFIGURATION


def test_a_secret_candidate_does_not_carry_the_engine_message(root: Path) -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret - vendor-documented example key
    rules = [
        {
            "id": "aws-key",
            "shortDescription": {"text": "AWS access key"},
            "properties": {"tags": ["secret"]},
        }
    ]
    item = result(
        "aws-key",
        uri="app.py",
        message=f"found {secret}",
        partialFingerprints={"h": secret},
        properties={"match": secret},
    )
    (found,) = ingest(root, log(run([item], rules=rules)))
    assert found.kind is CandidateKind.SECRET
    assert found.message == "AWS access key"
    assert secret not in found.model_dump_json()


def test_confidence_and_cwe_fallback_are_applied(root: Path) -> None:
    rules = [{"id": "EX2.a", "properties": {"precision": "high"}}]
    data = log(run([result("EX2.a", uri="app.py")], rules=rules))
    options = IngestOptions(cwe_fallback=CweFallback({"fake": {"EX2.": (78,)}}))
    (found,) = ingest(root, data, options=options)
    assert found.cwe == (78,)
    assert found.engine_confidence is Confidence.HIGH
    assert dict(found.properties)["cwe.source"] == "fallback"


def test_a_pillar_only_rule_is_marked_unmapped(root: Path) -> None:
    rules = [{"id": "r", "properties": {"cwe": 284}}]
    (found,) = ingest(root, log(run([result("r", uri="app.py")], rules=rules)))
    assert found.cwe == ()
    props = dict(found.properties)
    assert props["cwe.unmapped"] == "pillar"
    assert "cwe.source" not in props


def test_a_flow_whose_sink_is_not_a_location_is_discarded(
    root: Path, log_output: io.StringIO
) -> None:
    item = result("r", uri="app.py", line=2)
    item["codeFlows"] = [code_flow(step("app.py", 3), step("app/util.py", 4))]
    (found,) = ingest(root, log(run([item])))
    assert found.taint_path is None
    assert "codeflow_discarded" in log_output.getvalue()


def test_a_sink_first_engine_gets_its_flow_reversed(root: Path) -> None:
    item = result("r", uri="app.py", line=9)
    item["codeFlows"] = [code_flow(step("app.py", 9), step("app.py", 5), step("app.py", 2))]
    options = IngestOptions(code_flow_order="sink_first")
    (found,) = ingest(root, log(run([item])), options=options)
    assert found.taint_path is not None
    assert found.taint_path.source.location.start_line == 2
    assert found.taint_path.sink.location.start_line == 9


def test_skipped_kinds_and_unknown_rules(root: Path) -> None:
    items = [
        result("a", uri="app.py", kind="pass"),
        result("b", uri="app.py", kind="notApplicable"),
        result("c", uri="app.py", kind="fail"),
        {"message": {"text": "no rule"}, "locations": [location("app.py", at=region(1))]},
    ]
    assert [c.rule_id for c in ingest(root, log(run(items)))] == ["c"]


def test_rules_are_found_by_index_reference_and_extension(root: Path) -> None:
    item = {
        "ruleIndex": 0,
        "rule": {"toolComponent": {"name": "ext"}},
        "message": {"text": "x"},
        "locations": [location("app.py", at=region(1))],
    }
    body = run([item])
    body["tool"]["extensions"] = [
        {"name": "ext", "rules": [{"id": "from-extension", "properties": {"cwe": 79}}]}
    ]
    (found,) = ingest(root, log(body))
    assert found.rule_id == "from-extension"
    assert found.cwe == (79,)


def test_engine_version_prefers_the_probe_then_the_log(root: Path) -> None:
    data = log(run([result("r", uri="app.py")], version="9.9.9"))
    (from_log,) = ingest(root, data)
    (from_probe,) = ingest_sarif(data, engine_id="fake", root=root, engine_version="1.0.0")
    assert (from_log.engine_version, from_probe.engine_version) == ("9.9.9", "1.0.0")


# --- malformed and oversize logs ---------------------------------------------------------------


def test_validate_log_reports_structure_problems() -> None:
    assert validate_log(log(run([result()]))) == []
    assert "missing runs" in validate_log(b'{"version": "2.1.0"}')
    assert "missing version" in validate_log(b'{"runs": []}')
    assert validate_log(b"not json") == ["the output is not valid JSON"]
    assert validate_log(b"[]") == ["the log is not a JSON object"]
    dangling = result(ruleIndex=3)
    assert any("ruleIndex 3" in p for p in validate_log(log(run([dangling], rules=[{"id": "a"}]))))
    assert validate_log(b'{"version": "2.1.0", "runs": [{"results": []}]}') == [
        "runs[0] has no tool.driver"
    ]


@pytest.mark.parametrize(
    "data",
    [
        b"not json",
        b'{"version": "2.1.0"}',
        b'{"runs": [{"tool": {"driver": {}}}]}',
        b"[]",
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"rules": []}}, "results": [{"ruleIndex": 2}]}],
            }
        ).encode(),
        json.dumps(
            {"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": [{"level": ["x"]}]}]}
        ).encode(),
    ],
)
def test_a_malformed_log_raises_instead_of_returning_nothing(root: Path, data: bytes) -> None:
    with pytest.raises(SarifFormatError):
        ingest(root, data)


def test_an_empty_but_valid_log_is_an_empty_list(root: Path) -> None:
    assert ingest(root, log(run([]))) == []
    assert ingest(root, log()) == []


def test_error_text_never_quotes_the_log(root: Path) -> None:
    secret_text = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret - vendor-documented example key
    bad = json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {}}, "results": [{"level": [secret_text]}]}],
        }
    )
    with pytest.raises(SarifFormatError) as info:
        ingest(root, bad.encode())
    assert secret_text not in str(info.value)


def test_a_log_over_the_limit_is_refused_unparsed(root: Path) -> None:
    with pytest.raises(SarifSizeError):
        ingest(root, log(run([result()])), options=IngestOptions(max_bytes=10))


def test_ingest_engine_run_uses_the_spec(root: Path, tmp_path: Path) -> None:
    output = tmp_path / "out.sarif"
    item = result("r", uri="app.py", line=9)
    item["codeFlows"] = [code_flow(step("app.py", 9), step("app.py", 2))]
    output.write_bytes(log(run([item])))
    spec = make_spec("fake", code_flow_order="sink_first", default_kind=CandidateKind.HOTSPOT)
    engine_run = EngineRun(
        engine="fake",
        version="3.1.4",
        exit_code=0,
        duration_seconds=0.1,
        status="ok",
        output_path=output,
    )
    (found,) = ingest_engine_run(spec, engine_run, root)
    assert found.kind is CandidateKind.HOTSPOT
    assert found.engine_version == "3.1.4"
    assert found.taint_path is not None
    assert found.taint_path.source.location.start_line == 2
    with pytest.raises(SarifSizeError):
        ingest_engine_run(spec, engine_run, root, max_bytes=5)
    with pytest.raises(SarifFormatError):
        ingest_engine_run(spec, EngineRun("fake", "1", 0, 0.0, "ok"), root)


# --- the golden sample -------------------------------------------------------------------------


def canonical(candidates: list[Candidate]) -> str:
    rows = [{**c.model_dump(mode="json"), "id": f"cand-{n}"} for n, c in enumerate(candidates)]
    return json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def test_golden_sample_with_two_runs_and_three_results(root: Path) -> None:
    found = ingest(root, (GOLDEN / "sample.sarif").read_bytes())
    assert len(found) == 3
    assert_matches_golden(canonical(found), GOLDEN / "candidates_sample.json")


def test_golden_sample_has_the_documented_properties(root: Path) -> None:
    java, util, page = ingest(root, (GOLDEN / "sample.sarif").read_bytes())
    assert java.taint_path is not None
    assert "NEVER-COPIED" not in java.model_dump_json()
    assert util.cwe == (328,)
    assert util.engine_severity is Severity.MEDIUM  # security-severity 5.3 beats level note
    assert dict(util.properties)["sarif.suppressed"] == "accepted risk"
    assert page.cwe == (79,)
    assert (page.locations[0].start_col, page.locations[0].end_col) == (12, 13)
    assert page.engine_version == "3.4.5"


# --- the property: hostile input never escapes -------------------------------------------------


@pytest.fixture(scope="module")
def property_root() -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as directory:
        yield write_tree(
            Path(directory) / "view", {"a.py": numbered_source(20, 30), "d/b.py": "x\n"}
        )


uris = st.one_of(
    st.sampled_from(
        ["a.py", "d/b.py", "../a.py", "d/../../a.py", "/a.py", "file:///a.py", "d\\b.py"]
    ),
    st.text(alphabet=st.characters(exclude_categories=["Cs"]), max_size=24),
)
numbers = st.one_of(st.none(), st.integers(min_value=-5, max_value=400))


@settings(max_examples=60, deadline=None)
@given(
    uri=uris,
    start=numbers,
    end=numbers,
    start_col=numbers,
    end_col=numbers,
    level=st.one_of(st.none(), st.sampled_from(["error", "warning", "note", "none", "bogus"])),
    rule_id=st.text(alphabet=st.characters(exclude_categories=["Cs"]), min_size=1, max_size=20),
)
def test_ingest_yields_valid_rooted_candidates_or_a_typed_error(  # noqa: PLR0917
    property_root: Path,
    uri: str,
    start: int | None,
    end: int | None,
    start_col: int | None,
    end_col: int | None,
    level: str | None,
    rule_id: str,
) -> None:
    item: dict[str, Any] = {
        "ruleId": rule_id,
        "message": {"text": "m"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": start,
                        "endLine": end,
                        "startColumn": start_col,
                        "endColumn": end_col,
                    },
                }
            }
        ],
    }
    if level is not None:
        item["level"] = level
    try:
        found = ingest_sarif(
            log(run([item])), engine_id="fake", root=property_root, engine_version=None
        )
    except SarifError:
        return
    resolved_root = property_root.resolve()
    for candidate in found:
        Candidate.model_validate(candidate.model_dump())
        for loc in candidate.locations:
            assert not loc.path.startswith("/")
            assert ".." not in loc.path.split("/")
            assert (property_root / loc.path).resolve().is_relative_to(resolved_root)
            assert (property_root / loc.path).is_file()
