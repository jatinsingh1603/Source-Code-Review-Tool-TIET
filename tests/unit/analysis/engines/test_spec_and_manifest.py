"""EngineSpec validation, engine ids, and the pinned-version manifest (E14-01)."""

import pytest

from codekavach.analysis.engines.base import (
    ENGINE_ID_PATTERN,
    SLUG_PATTERN,
    DistributionMode,
    EngineInvocation,
)
from codekavach.analysis.engines.manifest import (
    MANIFEST_PATH,
    ManifestError,
    effective_policy,
    licence_inventory,
    load_manifest,
    parse_manifest,
    pin_for,
    version_tuple,
)
from codekavach.analysis.engines.registry import iter_adapters
from codekavach.core.models import Language
from tests.support.engines import make_spec

ROW = """
[engines.sample]
pinned_version = "1.2.3"
min_version = "1.2.0"
spdx_licence = "MIT"
distribution = "client_installed"
hosted_allowed = false
scans_proprietary_code = true
install = "pipx install sample"
telemetry_env = { SAMPLE_NO_TELEMETRY = "1" }
"""
DIGEST = "a" * 64


@pytest.mark.parametrize(
    "engine_id", ["opengrep", "eslint-security", "spotbugs-fsb", "a", "x" * 32]
)
def test_valid_ids_satisfy_both_patterns(engine_id: str) -> None:
    assert ENGINE_ID_PATTERN.match(engine_id)
    assert SLUG_PATTERN.match(engine_id)
    assert make_spec(engine_id).id == engine_id


@pytest.mark.parametrize("engine_id", ["Opengrep", "eslint.security", "x" * 33, "", "1abc", "a_b"])
def test_invalid_ids_are_rejected(engine_id: str) -> None:
    with pytest.raises(ValueError, match="engine id"):
        make_spec(engine_id)


def test_every_registered_spec_id_satisfies_both_patterns() -> None:
    for adapter in iter_adapters():
        assert ENGINE_ID_PATTERN.match(adapter.spec.id)
        assert SLUG_PATTERN.match(adapter.spec.id)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"name": "  "}, "name"),
        ({"languages": frozenset()}, "language"),
        ({"languages": frozenset({Language.UNKNOWN})}, "known Language"),
        ({"languages": frozenset({"cobol"})}, "known Language"),
        ({"spdx_licence": ""}, "SPDX"),
        ({"spdx_licence": "not a licence!"}, "SPDX"),
        ({"weight": 0}, "weight"),
        ({"weight": 17}, "weight"),
        ({"config_filenames": ("dir/.rc",)}, "config_filenames"),
        ({"expect_exit_codes": frozenset()}, "expect_exit_codes"),
    ],
)
def test_a_bad_spec_is_rejected(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        make_spec(**overrides)


def test_a_compound_spdx_expression_is_accepted() -> None:
    assert make_spec(spdx_licence="LGPL-3.0-or-later OR MIT").spdx_licence


@pytest.mark.parametrize(
    "argv",
    [(), ("",), ("tool", "")],
)
def test_an_invocation_needs_a_real_argument_vector(argv: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="argv"):
        EngineInvocation(argv=argv)


def test_an_invocation_refuses_nul_and_ambiguous_output() -> None:
    with pytest.raises(ValueError, match="NUL"):
        EngineInvocation(argv=("tool", "a\x00b"))
    with pytest.raises(ValueError, match="alternatives"):
        EngineInvocation(argv=("tool",), output_file="o.json", stdout_is_output=True)


def test_a_manifest_row_is_parsed_with_its_telemetry_opt_out() -> None:
    entry = parse_manifest(ROW)["sample"]
    assert entry.pinned_version == "1.2.3"
    assert entry.distribution is DistributionMode.CLIENT_INSTALLED
    assert entry.hosted_allowed is False
    assert dict(entry.telemetry_env) == {"SAMPLE_NO_TELEMETRY": "1"}


@pytest.mark.parametrize(
    "key",
    [
        "pinned_version",
        "min_version",
        "spdx_licence",
        "distribution",
        "hosted_allowed",
        "scans_proprietary_code",
        "install",
    ],
)
def test_every_required_key_is_required(key: str) -> None:
    text = "\n".join(line for line in ROW.splitlines() if not line.startswith(key))
    with pytest.raises(ManifestError, match=key):
        parse_manifest(text)


@pytest.mark.parametrize(
    ("addition", "message"),
    [
        ('colour = "red"', "colour"),
        ('image = "repo/tool:latest"', "image"),
        ("weight = 0", "weight"),
        ("timeout_seconds = 1", "timeout_seconds"),
        ("no_documented_opt_out = true", "contradicts"),
    ],
)
def test_a_bad_manifest_value_names_the_key(addition: str, message: str) -> None:
    with pytest.raises(ManifestError, match=message):
        parse_manifest(ROW + addition + "\n")


def test_an_image_pinned_by_digest_is_accepted() -> None:
    entry = parse_manifest(ROW + f'image = "registry.example/tool@sha256:{DIGEST}"\n')["sample"]
    assert entry.image is not None


def test_an_engine_must_list_an_opt_out_or_say_it_has_none() -> None:
    bare = ROW.replace('telemetry_env = { SAMPLE_NO_TELEMETRY = "1" }', "")
    with pytest.raises(ManifestError, match="opt-out"):
        parse_manifest(bare)
    entry = parse_manifest(bare + "no_documented_opt_out = true\n")["sample"]
    assert entry.no_documented_opt_out


def test_a_malformed_manifest_is_an_error() -> None:
    with pytest.raises(ManifestError, match="TOML"):
        parse_manifest("[engines.sample\n")
    with pytest.raises(ManifestError, match="top-level"):
        parse_manifest("extra = 1\n")


def test_the_bundled_manifest_loads_and_every_row_has_a_valid_id() -> None:
    manifest = load_manifest()
    assert MANIFEST_PATH.is_file()
    assert all(ENGINE_ID_PATTERN.match(engine_id) for engine_id in manifest)


def test_the_manifest_row_wins_over_the_spec() -> None:
    manifest = parse_manifest(ROW)
    spec = make_spec("sample", hosted_allowed=True, scans_proprietary_code=False)
    policy = effective_policy(spec, manifest)
    assert policy.hosted_allowed is False
    assert policy.scans_proprietary_code is True
    assert policy.pinned_version == "1.2.3"
    assert pin_for("sample", manifest) is manifest["sample"]
    assert pin_for("other", manifest) is None


def test_the_licence_inventory_has_one_sorted_row_per_engine() -> None:
    manifest = parse_manifest(ROW)
    rows = licence_inventory([make_spec("sample"), make_spec("alpha")], manifest)
    assert [row.engine for row in rows] == ["alpha", "sample"]
    assert rows[0].version == "unpinned"
    assert rows[1].version == "1.2.3"
    assert rows[1].spdx_licence == "MIT"
    assert rows[1].distribution is DistributionMode.CLIENT_INSTALLED


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1.2.3", (1, 2, 3)),
        ("v2.0", (2, 0)),
        ("1.2.3-rc1", (1, 2, 3)),
        ("1.10", (1, 10)),
        ("x", ()),
    ],
)
def test_version_tuple(text: str, expected: tuple[int, ...]) -> None:
    assert version_tuple(text) == expected
