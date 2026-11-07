"""The KavachBank manifest loader: schema, references and failure modes (E13-01)."""

import shutil
from pathlib import Path

import pytest
import yaml

from tests.support import synthetic
from tests.support.kavachbank import (
    FIXTURE_ROOT,
    MANIFEST_PATH,
    NEGATIVE_CONTROLS_PATH,
    ManifestError,
    load_manifest,
    load_negative_controls,
    resolve_value_ref,
    terms_for,
)


def _document() -> dict[str, object]:
    loaded = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _write(tmp_path: Path, document: object, name: str = "manifest.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def test_the_real_manifest_loads_and_has_every_section() -> None:
    manifest = load_manifest()
    assert manifest.schema_version == 1
    assert manifest.application.name == "KavachBank"
    assert len(manifest.planted_vulnerabilities) == 10
    assert len(manifest.planted_secrets) >= 5
    assert len(manifest.planted_pii) >= 5
    assert len(manifest.business_domain_dictionary) >= 10
    assert all(isinstance(v.cwe, int) for v in manifest.planted_vulnerabilities)
    assert manifest.demo_1_vulnerabilities() == manifest.planted_vulnerabilities


def test_every_vulnerability_class_of_the_issue_is_planted() -> None:
    classes = {v.vuln_class for v in load_manifest().planted_vulnerabilities}
    assert classes == {
        "sql_injection", "command_injection", "path_traversal", "ssrf",
        "insecure_deserialisation", "weak_cryptography", "missing_authorization",
        "insecure_direct_object_reference", "reflected_xss",
    }  # fmt: skip


def test_every_class_has_a_negative_control() -> None:
    manifest, controls = load_manifest(), load_negative_controls()
    assert {c.vuln_class for c in controls} == {
        v.vuln_class for v in manifest.planted_vulnerabilities
    }
    planted = {(v.file, v.line) for v in manifest.planted_vulnerabilities}
    assert not planted & {(c.file, c.line) for c in controls}


@pytest.mark.parametrize(
    ("value_ref", "expected"),
    [
        ("AWS_EXAMPLE_ACCESS_KEY_ID", synthetic.AWS_EXAMPLE_ACCESS_KEY_ID),
        ("EXAMPLE_EMAIL", synthetic.EXAMPLE_EMAIL),
        ("secret:aws_access_key", synthetic.AWS_EXAMPLE_ACCESS_KEY_ID),
        ("secret:razorpay_key_secret", synthetic.synthetic_value("secret", "razorpay_key_secret")),
        ("pii:credit_card:1", synthetic.synthetic_value("pii", "credit_card", 1)),
        ("term:domain", synthetic.synthetic_value("term", "domain")),
    ],
)
def test_a_value_ref_resolves_to_a_synthetic_constant(value_ref: str, expected: str) -> None:
    assert resolve_value_ref(value_ref) == expected


@pytest.mark.parametrize(
    "value_ref",
    [
        "NO_SUCH_CONSTANT",
        "secret:no_such_subtype",
        "pii:email:9",
        "pii:",
        "os.system",
        "SECRET_SHAPES",
        "",
    ],
)
def test_a_value_ref_that_names_nothing_is_refused(value_ref: str) -> None:
    with pytest.raises(ManifestError, match="value_ref"):
        resolve_value_ref(value_ref)


def test_a_malformed_manifest_is_refused(tmp_path: Path) -> None:
    for broken in ("- just\n- a list\n", ":\n  - [", ""):
        path = tmp_path / "broken.yaml"
        path.write_text(broken, encoding="utf-8")
        with pytest.raises(ManifestError):
            load_manifest(path)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("planted_secrets"),
        lambda d: d.update(schema_version=2),
        lambda d: d.update(surprise=1),
        lambda d: d["planted_vulnerabilities"][0].update(cwe="89"),
        lambda d: d["planted_vulnerabilities"][0].update(line=0),
        lambda d: d["planted_vulnerabilities"][0].update(demo_1="yes"),
        lambda d: d["planted_vulnerabilities"][0].update(id="VULN-1"),
        lambda d: d["planted_vulnerabilities"][0].pop("class"),
        lambda d: d["planted_secrets"][0].pop("value_ref"),
    ],
    ids=["missing-section", "schema-version", "extra-key", "cwe-text", "line-zero", "flag-text",
         "bad-id", "no-class", "no-value-ref"],
)  # fmt: skip
def test_a_manifest_that_breaks_the_schema_is_refused(tmp_path: Path, mutate) -> None:  # type: ignore[no-untyped-def]
    document = _document()
    mutate(document)
    with pytest.raises(ManifestError, match="schema"):
        load_manifest(_write(tmp_path, document))


def test_a_duplicate_id_is_refused(tmp_path: Path) -> None:
    document = _document()
    document["planted_vulnerabilities"][1]["id"] = document["planted_vulnerabilities"][0]["id"]  # type: ignore[index]
    with pytest.raises(ManifestError, match="unique"):
        load_manifest(_write(tmp_path, document))


def test_a_reference_to_a_missing_line_is_refused(tmp_path: Path) -> None:
    document = _document()
    document["planted_vulnerabilities"][0]["line"] = 99_999  # type: ignore[index]
    with pytest.raises(ManifestError, match="no line 99999"):
        load_manifest(_write(tmp_path, document))


def test_a_reference_to_a_missing_file_or_outside_the_fixture_is_refused(tmp_path: Path) -> None:
    for name in ("services/api/nope.py", "../../pyproject.toml", "/etc/passwd"):
        document = _document()
        document["planted_vulnerabilities"][0]["file"] = name  # type: ignore[index]
        with pytest.raises(ManifestError, match="not a file of the fixture"):
            load_manifest(_write(tmp_path, document))


def test_a_value_that_is_not_on_its_line_is_refused(tmp_path: Path) -> None:
    document = _document()
    document["planted_secrets"][0]["line"] = 1  # type: ignore[index]
    with pytest.raises(ManifestError, match="does not hold its value"):
        load_manifest(_write(tmp_path, document))


def test_an_unresolvable_value_ref_in_the_manifest_is_refused(tmp_path: Path) -> None:
    document = _document()
    document["planted_pii"][0]["value_ref"] = "pii:nonexistent"  # type: ignore[index]
    with pytest.raises(ManifestError, match="value_ref"):
        load_manifest(_write(tmp_path, document))


def test_negative_controls_are_validated_too(tmp_path: Path) -> None:
    document = yaml.safe_load(NEGATIVE_CONTROLS_PATH.read_text(encoding="utf-8"))
    document["negative_controls"][0]["line"] = 99_999
    with pytest.raises(ManifestError, match="no line"):
        load_negative_controls(_write(tmp_path, document, "controls.yaml"))
    for broken in ({"schema_version": 1}, {"schema_version": 2, "negative_controls": []}):
        with pytest.raises(ManifestError):
            load_negative_controls(_write(tmp_path, broken, "controls.yaml"))


def test_the_terms_hold_every_line_of_each_secret_then_the_dictionary() -> None:
    manifest = load_manifest()
    terms = terms_for(manifest)
    assert synthetic.AWS_EXAMPLE_ACCESS_KEY_ID in terms
    pem = resolve_value_ref("secret:private_key_block").split("\n")
    assert all(line in terms for line in pem)
    assert terms[-len(manifest.business_domain_dictionary) :] == list(
        manifest.business_domain_dictionary
    )
    assert len(terms) == len(set(terms))


def test_the_loader_reads_a_copy_of_the_fixture_from_another_root(tmp_path: Path) -> None:
    copy = tmp_path / "kavachbank"
    shutil.copytree(FIXTURE_ROOT, copy)
    assert (
        load_manifest(copy / "ground-truth" / "manifest.yaml", root=copy).application.name
        == "KavachBank"
    )
