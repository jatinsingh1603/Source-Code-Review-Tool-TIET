"""The generated configuration reference and the error-code catalogue (E03-40)."""

import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, Field

from codekavach.config import docgen
from codekavach.config.env_source import RESERVED_ENV, RESERVED_ENV_MEANINGS, env_var_name
from codekavach.config.errors import ConfigErrorCode
from codekavach.config.introspect import FieldRef, iter_fields
from codekavach.config.keys import DEFAULT_KEY_ENV
from codekavach.config.models.base import (
    SectionModel,
    restricted,
    sensitive,
    union_merge,
    volatile,
)
from codekavach.config.models.root import Settings
from codekavach.config.overrides import FLAG_TO_KEY
from codekavach.config.trust import TIGHTEN_ONLY

DOCS = Path(__file__).resolve().parents[3] / "docs" / "configuration"
REFERENCE = DOCS / "reference.md"
ERROR_CODES = DOCS / "error-codes.md"


def test_committed_reference_is_current() -> None:
    assert docgen.main(["--check", "--output", str(REFERENCE)]) == 0


def test_check_fails_and_names_the_refresh_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stale = tmp_path / "reference.md"
    stale.write_text(REFERENCE.read_text(encoding="utf-8").replace("Directory", "Folder", 1))
    assert docgen.main(["--check", "--output", str(stale)]) == 1
    assert docgen.REFRESH_COMMAND in capsys.readouterr().out
    assert docgen.main(["--check", "--output", str(tmp_path / "missing.md")]) == 1


def test_output_writes_what_render_returns(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "reference.md"
    assert docgen.main(["--output", str(target)]) == 0
    assert target.read_bytes() == docgen.render_reference().encode("utf-8")
    assert b"\r" not in target.read_bytes()


def test_rendering_is_deterministic() -> None:
    assert docgen.render_reference() == docgen.render_reference()


def test_every_leaf_key_appears_exactly_once() -> None:
    # Only the key tables: the tighten-only table lists some keys again.
    text = REFERENCE.read_text(encoding="utf-8").split("## Markers", 1)[0]
    for ref in iter_fields(Settings):
        rows = re.findall(rf"^\| `{re.escape(ref.key)}` \|", text, re.MULTILINE)
        assert len(rows) == 1, ref.key


def test_environment_variable_column() -> None:
    text = REFERENCE.read_text(encoding="utf-8")
    assert f"`{env_var_name('scan.jobs')}`" in text
    prefix = "| `llm.providers.*.base_url`"
    templated = [row for row in text.splitlines() if row.startswith(prefix)]
    assert len(templated) == 1
    assert "CODEKAVACH_LLM__PROVIDERS" not in templated[0]


def test_constants_tables_cover_their_sources() -> None:
    text = REFERENCE.read_text(encoding="utf-8")
    for name in RESERVED_ENV:
        assert f"| `{name}` |" in text, name
    for flag in FLAG_TO_KEY.values():
        assert f"| `{flag.flag}` |" in text, flag.flag
    for kind, names in DEFAULT_KEY_ENV.items():
        assert f"| `{kind}` |" in text
        assert all(f"`{name}`" in text for name in names)
    for key in TIGHTEN_ONLY:
        assert f"| `{key}` |" in text, key


def test_reserved_variables_have_one_line_meanings() -> None:
    assert set(RESERVED_ENV_MEANINGS) == set(RESERVED_ENV)
    assert all(text.strip() and "\n" not in text for text in RESERVED_ENV_MEANINGS.values())


# --- rendering of markers, types and defaults ---------------------------------------------------


class Demo(SectionModel):
    plain: int = 3
    secret: str | None = Field(default=None, json_schema_extra=sensitive())
    both: list[str] = Field(default_factory=list, json_schema_extra={**restricted(), **volatile()})
    merged: list[str] = Field(default_factory=list, json_schema_extra=union_merge())
    long: list[str] = Field(default_factory=lambda: [f"pattern-{n}/**" for n in range(12)])
    pipe: str = "a|b"


def demo_refs() -> dict[str, FieldRef]:
    return {ref.key: ref for ref in iter_fields(Demo)}


def test_marker_combinations() -> None:
    refs = demo_refs()
    assert docgen.markers_text(refs["plain"]) == ""
    assert docgen.markers_text(refs["secret"]) == "sensitive"
    assert docgen.markers_text(refs["both"]) == "restricted, volatile"
    assert docgen.markers_text(refs["merged"]) == "union"


def test_tighten_only_marker_comes_from_the_trust_table() -> None:
    refs = {ref.key: ref for ref in iter_fields(Settings)}
    assert docgen.markers_text(refs["privacy.level"]) == "tighten-only"
    assert "tighten-only" in docgen.markers_text(refs["llm.allow_remote"])


def test_defaults_and_long_defaults() -> None:
    refs = demo_refs()
    assert docgen.default_text(refs["plain"]) == "3"
    assert docgen.default_text(refs["secret"]) == "unset"
    assert docgen.default_text(refs["both"]) == "[]"
    assert docgen.default_text(refs["pipe"]) == '"a|b"'
    assert len(docgen.default_text(refs["long"])) > docgen.LONG_DEFAULT
    lines = docgen._section_table("demo_long", [refs["long"], refs["pipe"]])
    text = "\n".join(lines)
    assert "see note 1" in text
    assert "Defaults too long for the table:" in text
    assert "1. `long`: `[" in text
    assert '`"a\\|b"`' in text  # a pipe inside a cell is escaped


def test_type_names() -> None:
    class Shapes(BaseModel):
        a: list[str]
        b: dict[str, Any]
        c: Path
        d: int | None

    names = {name: docgen.type_name(info.annotation) for name, info in Shapes.model_fields.items()}
    assert names == {"a": "list[str]", "b": "table", "c": "path", "d": "int | unset"}
    refs = {ref.key: ref for ref in iter_fields(Settings)}
    assert docgen.type_name(refs["privacy.level"].annotation) == "L0..L4"
    assert docgen.type_name(refs["privacy.vault.passphrase"].annotation) == (
        "secret reference | unset"
    )


# --- the error-code catalogue ----------------------------------------------------------------


def catalogue_codes() -> list[str]:
    text = ERROR_CODES.read_text(encoding="utf-8")
    return re.findall(r"^### (CK-CFG-\d{3})$", text, re.MULTILINE)


def test_every_error_code_has_an_entry_and_no_other_does() -> None:
    documented = catalogue_codes()
    assert len(documented) == len(set(documented)), "a code is documented twice"
    assert set(documented) == {code.value for code in ConfigErrorCode}


def test_entries_have_meaning_cause_and_fix() -> None:
    text = ERROR_CODES.read_text(encoding="utf-8")
    entries = re.split(r"^### CK-CFG-\d{3}$", text, flags=re.MULTILINE)[1:]
    assert len(entries) == len(ConfigErrorCode)
    for entry in entries:
        for label in ("**Meaning.**", "**Typical cause.**", "**Fix.**"):
            assert label in entry, entry[:80]


def test_catalogue_is_in_code_order() -> None:
    codes = catalogue_codes()
    assert codes == sorted(codes)


def test_index_links_both_pages() -> None:
    text = (DOCS / "README.md").read_text(encoding="utf-8")
    assert "(reference.md)" in text
    assert "(error-codes.md)" in text
