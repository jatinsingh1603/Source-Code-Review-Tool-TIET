import pytest
from pydantic import ValidationError

from codekavach.core.models import CweId, KavachModel, format_cwe, parse_cwe


@pytest.mark.parametrize("value", [89, "89", "CWE-89", "cwe_89", "CWE 89", "cwe-89", " CWE-89 "])
def test_parse_cwe_accepts(value: int | str) -> None:
    assert parse_cwe(value) == 89


@pytest.mark.parametrize("value", ["CWE-", "0", "-5", "SQLi", True, 0, 100000, "CWE--89", ""])
def test_parse_cwe_rejects(value: int | str) -> None:
    with pytest.raises(ValueError):
        parse_cwe(value)


def test_format_cwe() -> None:
    assert format_cwe(89) == "CWE-89"


class WithCwe(KavachModel):
    cwe: CweId


def test_cwe_field_accepts_string_form_and_dumps_int() -> None:
    model = WithCwe.model_validate({"cwe": "CWE-79"})
    assert model.cwe == 79
    assert model.model_dump_json() == '{"cwe":79}'


def test_cwe_field_rejects_invalid() -> None:
    with pytest.raises(ValidationError):
        WithCwe.model_validate({"cwe": "SQLi"})
