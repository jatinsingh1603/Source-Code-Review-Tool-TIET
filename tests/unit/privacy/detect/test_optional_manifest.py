"""The licence manifest of the optional engines, models and datasets (E08-04)."""

import tomllib
from pathlib import Path

import pytest

from codekavach.privacy.detect.optional import (
    DISTRIBUTION_MODES,
    engine_manifest,
    parse_manifest,
)
from codekavach.privacy.detect.pii.ner import DEFAULT_MODEL
from codekavach.privacy.detect.secrets.adapters import DetectSecretsEngine, GitleaksEngine

PYPROJECT = Path(__file__).resolve().parents[4] / "pyproject.toml"


def test_every_optional_engine_and_model_has_an_entry_with_the_three_fields() -> None:
    entries = {entry.id: entry for entry in engine_manifest()}
    for needed in (GitleaksEngine.id.replace("_", "-"), DetectSecretsEngine.id.replace("_", "-")):
        assert needed in entries, needed
    assert {"spacy", DEFAULT_MODEL, "term-baseline"} <= set(entries)
    for entry in entries.values():
        assert entry.spdx and entry.distribution in DISTRIBUTION_MODES
        assert isinstance(entry.hosted, bool)


def test_engines_are_client_installed_and_datasets_are_evaluation_only_and_not_hosted() -> None:
    for entry in engine_manifest():
        if entry.kind in {"engine", "library", "model"}:
            assert entry.distribution == "client-installed", entry.id
        if entry.kind == "dataset":
            assert (entry.distribution, entry.hosted) == ("evaluation-only", False), entry.id


def test_a_bundled_item_has_a_licence_the_project_allows() -> None:
    allowed = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["tool"]["codekavach"][
        "licences"
    ]["allowed"]
    bundled = [entry for entry in engine_manifest() if entry.distribution == "bundled"]
    assert bundled
    assert all(entry.spdx in allowed for entry in bundled)


@pytest.mark.parametrize(
    "text",
    [
        '[[entry]]\nid="a"\nkind="engine"\nspdx="MIT"\nhosted=true\n',  # no distribution
        '[[entry]]\nid="a"\nkind="engine"\nspdx="MIT"\ndistribution="shipped"\nhosted=true\n',
        '[[entry]]\nid="a"\nkind="gadget"\nspdx="MIT"\ndistribution="bundled"\nhosted=true\n',
        '[[entry]]\nid="a"\nkind="data"\nspdx="MIT"\ndistribution="bundled"\nhosted=false\n',
        '[[entry]]\nid="a"\nkind="data"\nspdx="MIT"\ndistribution="bundled"\nhosted="yes"\n',
        '[[entry]]\nid="a"\nkind="data"\nspdx="MIT"\ndistribution="bundled"\nhosted=true\n'
        '[[entry]]\nid="a"\nkind="data"\nspdx="MIT"\ndistribution="bundled"\nhosted=true\n',
    ],
)
def test_a_malformed_manifest_is_refused(text: str) -> None:
    with pytest.raises(ValueError):
        parse_manifest(text)
