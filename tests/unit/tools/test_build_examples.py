"""Generated schema example documents (E02-29)."""

import builtins
import importlib.util
import io
import json
import keyword
import sys
import tokenize
from pathlib import Path
from types import ModuleType

import pytest
from jsonschema import Draft202012Validator

from codekavach.core.models.egress import EgressRecord
from codekavach.core.models.export import EXPORTED_MODELS, snake_name
from codekavach.core.models.verdict import LLMVerdict
from tests.support.factories import SAMPLE_SOURCE

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = REPO_ROOT / "docs" / "schemas"
EXAMPLES = SCHEMAS / "examples"
# Names a sanitised payload may keep: a Python convention and public DB-API (PEP 249) methods,
# the allowlisted public API names of invariant I6.
PUBLIC_NAMES = frozenset({"self", "execute", "fetchall"})


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "build_examples", REPO_ROOT / "tools" / "schemas" / "build_examples.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_examples"] = module
    spec.loader.exec_module(module)
    return module


ex = _load()


def test_one_example_per_model_plus_two() -> None:
    names = set(ex.build_examples())
    expected = {f"{snake_name(model.__name__)}.example.json" for model in EXPORTED_MODELS}
    assert names == expected | {ex.OUTPUT_EXAMPLE, ex.LEDGER_EXAMPLE}


def test_deterministic() -> None:
    assert ex.build_examples() == ex.build_examples()


def test_repository_examples_are_current() -> None:
    assert ex.check_examples(EXAMPLES) == []


def test_check_states(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "examples"
    assert ex.check_examples(out)[0].startswith("missing: ")
    ex.write_examples(out)
    assert ex.check_examples(out) == []
    assert ex.main(["--check", "--out", str(out)]) == 0
    target = out / "location.example.json"
    target.write_text(target.read_text(encoding="utf-8").replace("88", "89"), encoding="utf-8")
    (out / "scan.example.json").unlink()
    (out / "foo.example.json").write_text("{}\n", encoding="utf-8")
    assert sorted(ex.check_examples(out)) == [
        "missing: scan.example.json",
        "stale: location.example.json",
        "unexpected: foo.example.json",
    ]
    before = {path.name: path.read_bytes() for path in out.iterdir()}
    capsys.readouterr()
    assert ex.main(["--check", "--out", str(out)]) == 1
    assert ex.HINT in capsys.readouterr().out
    assert {path.name: path.read_bytes() for path in out.iterdir()} == before  # never rewrites


def test_files_use_lf_and_end_with_a_newline() -> None:
    for path in EXAMPLES.iterdir():
        data = path.read_bytes()
        assert b"\r" not in data, path.name
        assert data.endswith(b"\n"), path.name
        assert b"C:\\" not in data and b"/home/" not in data, path.name


@pytest.mark.parametrize("model", EXPORTED_MODELS, ids=lambda model: model.__name__)
def test_examples_validate(model: type) -> None:
    name = snake_name(model.__name__)
    text = (EXAMPLES / f"{name}.example.json").read_text(encoding="utf-8")
    schema = json.loads((SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(json.loads(text)))
    assert errors == [], errors[0].message if errors else ""
    model.model_validate_json(text)  # type: ignore[attr-defined]


def test_provider_facing_verdict_example() -> None:
    text = (EXAMPLES / ex.OUTPUT_EXAMPLE).read_text(encoding="utf-8")
    document = json.loads(text)
    assert "schema_version" not in document
    schema = json.loads((SCHEMAS / "llm_verdict.output.schema.json").read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(document)) == []
    LLMVerdict.model_validate(document)


def test_ledger_example_verifies_link_by_link() -> None:
    lines = (EXAMPLES / ex.LEDGER_EXAMPLE).read_text(encoding="utf-8").splitlines()
    assert len(lines) == ex.LEDGER_LENGTH
    previous: EgressRecord | None = None
    for line in lines:
        record = EgressRecord.model_validate_json(line)
        record.verify_link(previous)
        previous = record


def source_identifiers() -> set[str]:
    """Identifiers (NAME tokens, not string contents) of SAMPLE_SOURCE, four or more long."""
    names = {
        token.string
        for token in tokenize.generate_tokens(io.StringIO(SAMPLE_SOURCE).readline)
        if token.type == tokenize.NAME
    }
    return {
        name
        for name in names
        if len(name) >= 4 and not keyword.iskeyword(name) and not hasattr(builtins, name)
    }


def test_sanitised_payload_example_holds_no_original_identifier() -> None:
    text = json.loads((EXAMPLES / "sanitised_payload.example.json").read_text("utf-8"))["text"]
    identifiers = source_identifiers()
    assert {"AccountRepo", "find_by_owner", "owner", "conn", "cursor"} <= identifiers
    leaked = sorted(name for name in identifiers - PUBLIC_NAMES if name in text)
    assert leaked == []
