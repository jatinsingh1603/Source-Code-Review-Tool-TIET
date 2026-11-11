"""Loader safety, packs, settings gating and bundles (E16-01)."""

import gzip
from pathlib import Path

import pytest

from codekavach.analysis.rules.bundle import (
    MAX_BUNDLE_BYTES,
    bundle_bytes,
    read_bundle,
    write_bundle,
)
from codekavach.analysis.rules.errors import (
    RuleEncodingError,
    RuleFileTooLargeError,
    RuleLoadError,
    RulePackError,
    RulePathError,
    RuleShapeError,
    RuleYamlError,
)
from codekavach.analysis.rules.loader import (
    MAX_RULE_BYTES,
    load_pack,
    load_packs,
    load_rule_file,
    parse_yaml,
    scan_pack,
)
from codekavach.analysis.rules.validate import RuleCode
from codekavach.config import Settings
from tests.support.rule_files import rule_text, write_pack

NL = chr(10)


def write(tmp_path: Path, text: str | bytes, name: str = "rule.yaml") -> Path:
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8") if isinstance(text, str) else text)
    return path


def test_a_file_of_ten_megabytes_is_refused_without_being_parsed(tmp_path: Path) -> None:
    path = write(tmp_path, b"a: 1\n" + b"#" * (10 * 1024 * 1024))
    with pytest.raises(RuleFileTooLargeError):
        load_rule_file(path)


def test_the_limit_is_exactly_one_mebibyte(tmp_path: Path) -> None:
    padding = "#" * (MAX_RULE_BYTES - len(rule_text()) - 1) + "\n"
    ok = write(tmp_path, rule_text() + padding)
    assert ok.stat().st_size <= MAX_RULE_BYTES
    assert load_rule_file(ok).id
    with pytest.raises(RuleFileTooLargeError):
        load_rule_file(write(tmp_path, rule_text() + padding + "##", "big.yaml"))


@pytest.mark.parametrize(
    "text",
    [
        "a: &x [1, 2]\nb: *x\n",
        "a: &x 1\n",
        "a: *y\n",
        "a: !!python/object/apply:os.system [x]\n",
        "a: !custom 1\n",
    ],
)
def test_aliases_anchors_and_tags_are_refused(tmp_path: Path, text: str) -> None:
    with pytest.raises(RuleYamlError):
        parse_yaml(text, tmp_path / "x.yaml")


def test_a_python_object_tag_constructs_nothing(tmp_path: Path) -> None:
    marker = tmp_path / "created"
    inner = f"!!python/object/apply:pathlib.Path [{marker.as_posix()}]"
    text = f"a: !!python/object/apply:pathlib.Path.touch [{inner}]\n"
    with pytest.raises(RuleYamlError):
        parse_yaml(text, "x.yaml")
    assert not marker.exists()


def test_a_star_or_ampersand_inside_a_pattern_is_not_an_alias() -> None:
    data = parse_yaml('pattern: "f(*args, **kwargs) & x != y"\n', "x.yaml")
    assert data == {"pattern": "f(*args, **kwargs) & x != y"}


def test_non_utf8_bytes_are_refused(tmp_path: Path) -> None:
    with pytest.raises(RuleEncodingError):
        load_rule_file(write(tmp_path, b"id: caf\xe9\n"))


def test_malformed_yaml_and_a_non_mapping_are_typed_errors(tmp_path: Path) -> None:
    with pytest.raises(RuleYamlError):
        load_rule_file(write(tmp_path, "a: [unclosed\n"))
    with pytest.raises(RuleShapeError):
        load_rule_file(write(tmp_path, "- a\n- b\n", "list.yaml"))


def test_a_shape_error_names_fields_not_values(tmp_path: Path) -> None:
    with pytest.raises(RuleShapeError) as caught:
        load_rule_file(write(tmp_path, rule_text(severity="TOPSECRETVALUE")))
    assert "severity" in str(caught.value)
    assert "TOPSECRETVALUE" not in str(caught.value)


def test_a_regular_expression_that_does_not_compile_fails_at_load(tmp_path: Path) -> None:
    text = rule_text(match={"any": [{"pattern_regex": "(unclosed"}]})
    with pytest.raises(RuleShapeError):
        load_rule_file(write(tmp_path, text))


@pytest.mark.parametrize(
    "text",
    [
        "[" * 5000 + "]" * 5000,
        "- " * 5000 + "x",
        "".join(" " * i + "a:" + NL for i in range(300)) + " " * 300 + "b: 1" + NL,
        "{a: " * 200 + "1" + "}" * 200,
    ],
    ids=["flow", "compact-sequence", "indentation", "flow-mapping"],
)
def test_deep_nesting_is_a_typed_error_and_never_a_crash(text: str) -> None:
    with pytest.raises(RuleYamlError):
        parse_yaml(text, "x.yaml")


def test_ordinary_nesting_is_accepted_on_the_fast_path_and_the_scanning_path() -> None:
    assert parse_yaml("a: {b: [1, [2, [3]]]}" + NL, "x.yaml") == {"a": {"b": [1, [2, [3]]]}}
    wide = "items:" + NL + "".join(f"  - {n}" + NL for n in range(300))
    assert len(parse_yaml(wide, "x.yaml")["items"]) == 300


def test_a_symlink_is_refused(tmp_path: Path) -> None:
    target = write(tmp_path, rule_text(), "real.yaml")
    link = tmp_path / "link.yaml"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")
    with pytest.raises(RulePathError):
        load_rule_file(link)


def test_a_directory_is_not_a_rule_file(tmp_path: Path) -> None:
    with pytest.raises(RulePathError):
        load_rule_file(tmp_path)


# --- packs ------------------------------------------------------------------------------------


def test_a_pack_loads_with_a_checksum_and_its_rules_sorted(tmp_path: Path) -> None:
    pack_dir = write_pack(
        tmp_path,
        rules={
            "b/two.yaml": rule_text(id="python.b.two"),
            "a/one.yaml": rule_text(id="python.a.one"),
        },
    )
    pack = load_pack(pack_dir)
    assert [rule.id for rule in pack.rules] == ["python.a.one", "python.b.two"]
    assert pack.version == "1.0.0" and len(pack.checksum) == 64


def test_the_checksum_is_the_same_for_crlf_files_and_any_file_order(tmp_path: Path) -> None:
    one, two = rule_text(id="python.a.one"), rule_text(id="python.b.two")
    lf = load_pack(write_pack(tmp_path / "lf", rules={"x.yaml": one, "y.yaml": two}))
    crlf = load_pack(
        write_pack(
            tmp_path / "crlf",
            rules={"z.yaml": one.replace("\n", "\r\n"), "a.yaml": two.replace("\n", "\r\n")},
        )
    )
    assert lf.checksum == crlf.checksum


def test_a_planted_invalid_rule_is_reported_with_its_path_and_code(tmp_path: Path) -> None:
    pack_dir = write_pack(
        tmp_path,
        rules={
            "good.yaml": rule_text(),
            "bad/nocwe.yaml": rule_text(id="python.x.nocwe", metadata={"licence": "MIT"}),
        },
    )
    scan = scan_pack(pack_dir)
    assert [(item.code, item.path) for item in scan.issues] == [
        (RuleCode.MISSING_CWE, "mit/packs/default/bad/nocwe.yaml")
    ]
    with pytest.raises(RulePackError):
        load_pack(pack_dir)


def test_an_unreadable_file_in_a_pack_is_an_issue_not_a_crash(tmp_path: Path) -> None:
    pack_dir = write_pack(tmp_path, rules={"ok.yaml": rule_text(), "broken.yaml": "a: [\n"})
    codes = {item.code for item in scan_pack(pack_dir).issues}
    assert codes == {RuleCode.FILE_UNUSABLE}


def test_a_pack_in_the_wrong_licence_directory_is_reported(tmp_path: Path) -> None:
    pack_dir = write_pack(tmp_path, licence="lgpl-2.1")
    codes = {item.code for item in scan_pack(pack_dir).issues}
    assert RuleCode.LICENCE_MISMATCH in codes


def test_catalogue_entries_resolve_taint_references(tmp_path: Path) -> None:
    catalogue = (
        "language: python\nframework: flask\nentries:\n"
        "  - {id: python.flask.args, kind: source, pattern: request.args}\n"
        "  - {id: python.db.execute, kind: sink, pattern: $C.execute($Q)}\n"
    )
    taint = {"sources": ["python.flask.args"], "sinks": ["python.db.execute"]}
    ok = write_pack(
        tmp_path / "ok",
        rules={"t.yaml": rule_text(match={}, taint=taint)},
        catalogues={"python/flask.yaml": catalogue},
    )
    assert scan_pack(ok).issues == []
    bad = {"sources": ["python.flask.nope"]}
    broken = write_pack(
        tmp_path / "bad",
        rules={"t.yaml": rule_text(match={}, taint=bad)},
        catalogues={"python/flask.yaml": catalogue},
    )
    assert [item.code for item in scan_pack(broken).issues] == [RuleCode.UNKNOWN_CATALOGUE]


# --- settings, confinement, bundles ---------------------------------------------------------


def settings_with(**engines: object) -> Settings:
    return Settings.model_validate({"engines": engines})


def test_with_native_rules_off_nothing_is_loaded(tmp_path: Path) -> None:
    write_pack(tmp_path)
    found = load_packs(settings_with(native={"rules": False}), rules_root=tmp_path)
    assert found == []


def test_named_packs_come_from_the_rules_root(tmp_path: Path) -> None:
    write_pack(tmp_path)
    assert [
        p.id for p in load_packs(settings_with(rule_packs=["default"]), rules_root=tmp_path)
    ] == ["default"]


def test_a_missing_named_pack_is_skipped_with_a_warning(tmp_path: Path) -> None:
    assert load_packs(settings_with(rule_packs=["nope"]), rules_root=tmp_path) == []


def test_extra_rule_paths_are_loaded_and_confined(tmp_path: Path) -> None:
    inside = tmp_path / "project" / "extra"
    write_pack(inside, pack="mine")
    settings = settings_with(rule_packs=[], rule_paths=[str(inside / "mit")])
    got = load_packs(settings, allowed_roots=[tmp_path / "project"])
    assert [p.id for p in got] == ["mine"]
    outside = tmp_path / "elsewhere"
    write_pack(outside, pack="evil")
    escaping = settings_with(rule_packs=[], rule_paths=[str(outside / "mit")])
    with pytest.raises(RulePathError):
        load_packs(escaping, allowed_roots=[tmp_path / "project"])


def test_a_path_that_is_neither_a_pack_nor_a_licence_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    with pytest.raises(RulePathError):
        load_packs(settings_with(rule_packs=[], rule_paths=[str(tmp_path / "empty")]))


def test_two_packs_with_one_id_are_refused(tmp_path: Path) -> None:
    write_pack(tmp_path / "a")
    write_pack(tmp_path / "b")
    settings = settings_with(
        rule_packs=[], rule_paths=[str(tmp_path / "a" / "mit"), str(tmp_path / "b" / "mit")]
    )
    with pytest.raises(RuleLoadError):
        load_packs(settings)


def test_a_bundle_is_byte_identical_across_runs_and_loads_offline(tmp_path: Path) -> None:
    pack = load_pack(write_pack(tmp_path / "src"))
    first, second = tmp_path / "one.ckrules", tmp_path / "two.ckrules"
    write_bundle([pack], first, codekavach_version="1.2.3")
    write_bundle([pack], second, codekavach_version="1.2.3")
    assert first.read_bytes() == second.read_bytes()
    loaded = load_packs(settings_with(rule_packs=[], rule_paths=[str(first)]))
    assert loaded == [pack]


def test_a_tampered_bundle_is_refused(tmp_path: Path) -> None:
    pack = load_pack(write_pack(tmp_path / "src"))
    raw = gzip.decompress(bundle_bytes([pack], codekavach_version="1")).replace(
        b"cursor-execute-concat", b"cursor-execute-xxxxxx"
    )
    path = tmp_path / "t.ckrules"
    path.write_bytes(gzip.compress(raw))
    with pytest.raises(RuleShapeError):
        read_bundle(path)


def test_a_bundle_that_expands_beyond_the_limit_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "bomb.ckrules"
    path.write_bytes(gzip.compress(b"0" * (MAX_BUNDLE_BYTES + 10), compresslevel=1))
    with pytest.raises(RuleFileTooLargeError):
        read_bundle(path)


def test_garbage_is_not_a_bundle(tmp_path: Path) -> None:
    path = tmp_path / "x.ckrules"
    path.write_bytes(b"not gzip")
    with pytest.raises(RuleYamlError):
        read_bundle(path)
    path.write_bytes(gzip.compress(b"[]"))
    with pytest.raises(RuleShapeError):
        read_bundle(path)


def test_the_seed_pack_of_the_repository_is_valid() -> None:
    root = Path(__file__).resolve().parents[4] / "rules" / "mit" / "packs" / "default"
    assert scan_pack(root).issues == []
    assert (root / "pack.yaml").is_file()
