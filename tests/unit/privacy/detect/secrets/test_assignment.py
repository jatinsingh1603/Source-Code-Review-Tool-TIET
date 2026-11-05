"""``secret.assignment``: credential-named identifiers assigned a string literal."""

from dataclasses import replace

import pytest

from codekavach.core.models import Confidence, Language, RawCode
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.parser import parse
from codekavach.privacy.detect.secrets.assignment import (
    AssignmentDetector,
    credential_names,
    is_credential_name,
)

VALUE = "hunter2hunter2"  # pragma: allowlist secret


def run(text: str, path: str, language: Language) -> list[tuple[str, str]]:
    """``(confidence, value)`` of the line-based pass."""
    data = text.encode()
    spans = AssignmentDetector().detect(RawCode(text), path=path, language=language)
    return [(s.confidence.value, data[s.start_byte : s.end_byte].decode()) for s in spans]


# The six forms of the issue: Python, JavaScript, YAML, INI, .env (and JSON for good measure).
# {v} is the value; the templates hold no credential-looking literal.
FORMS = {
    "python": ("password = {q}{v}{q}\n", "src/db.py", Language.PYTHON),
    "javascript": ("const password = {s}{v}{s};\n", "src/db.js", Language.JAVASCRIPT),
    "yaml": ("db:\n  password: {v}\n", "deploy/db.yaml", Language.YAML),
    "ini": ("[db]\npassword = {v}\n", "config/db.ini", Language.UNKNOWN),
    "env": ("DB_PASSWORD={v}\n", ".env", Language.UNKNOWN),
    "json": ("{{{q}password{q}: {q}{v}{q}}}\n", "config/db.json", Language.JSON),
}


@pytest.mark.parametrize("form", sorted(FORMS))
def test_hunter2_is_found_in_every_file_form(form: str) -> None:
    template, path, language = FORMS[form]
    text = template.format(q='"', s="'", v=VALUE)
    assert run(text, path, language) == [("medium", VALUE)]


@pytest.mark.parametrize(
    "name",
    [
        "password", "passwd", "pwd", "secret", "token", "apiKey", "api_key", "API_KEY",
        "access_key", "accessKey", "private_key", "credential", "credentials_file_secret",
        "authToken", "auth", "session_key", "signing_key", "DB_PASSWORD", "client_secret",
        "oauthToken", "api-key",
    ],
)  # fmt: skip
def test_names_that_hold_a_credential(name: str) -> None:
    assert is_credential_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "passwordHint", "password_prompt", "max_tokens", "tokens", "author", "authority",
        "token_count_label", "secretName", "api_key_url", "username", "key", "count",
        "tokenExpiry", "password_length", "auth_endpoint", "monkey_business",
    ],
)  # fmt: skip
def test_names_that_do_not_hold_a_credential(name: str) -> None:
    assert not is_credential_name(name)


def test_the_helper_lists_the_accepted_names() -> None:
    assert credential_names(["api_key", "passwordHint", "token"]) == ["api_key", "token"]


def test_api_key_fires_and_passwordHint_does_not() -> None:
    text = 'api_key = "abcdefghijklmnop"\npasswordHint = "your first pet name"\n'
    assert run(text, "src/a.py", Language.PYTHON) == [("medium", "abcdefghijklmnop")]


@pytest.mark.parametrize(
    ("value", "confidence"),
    [
        ("abcdefghijkl", Confidence.MEDIUM),  # exactly 12 characters
        ("abcdefghijk", Confidence.LOW),  # 11
        ("changeme", Confidence.LOW),  # short, and a placeholder
        ("your-api-key-here", Confidence.LOW),  # long, but a placeholder
        ("changeme123!", Confidence.MEDIUM),  # the denylist matches the whole literal only
    ],
)
def test_confidence_is_low_unless_twelve_characters_and_not_a_placeholder(
    value: str, confidence: Confidence
) -> None:
    ((found, shown),) = run(f'password = "{value}"\n', "a.py", Language.PYTHON)
    assert (found, shown) == (confidence.value, value)


def test_values_shorter_than_four_characters_are_not_reported() -> None:
    assert run('password = "abc"\n', "a.py", Language.PYTHON) == []


@pytest.mark.parametrize(
    "text",
    [
        'password = "${DB_PASSWORD}"\n',
        'password: "{{ vault_password }}"\n',
        "password: ${DB_PASSWORD}\n",
        "password: $DB_PASSWORD\n",
        "password = %(password)s\n",
        'password = os.environ["DB_PASSWORD"]\n',
        "password: null\n",
        "password: true\n",
        'if password == "abcdefgh":\n',
        'password != "abcdefgh"\n',
        'password = ""\n',
    ],
)
def test_references_expressions_and_comparisons_are_not_literals(text: str) -> None:
    assert run(text, "deploy/app.yaml", Language.YAML) == []


def test_a_bare_value_in_code_is_not_a_string_literal() -> None:
    assert run("password = hunter2hunter2\n", "src/a.py", Language.PYTHON) == []


def test_a_bare_value_in_a_config_file_is_reported_up_to_the_end_of_the_line() -> None:
    assert run("password = hunter2hunter2   \r\n", "config/db.cfg", Language.UNKNOWN) == [
        ("medium", VALUE)
    ]


def test_a_dotted_property_name_uses_its_last_word() -> None:
    assert run(
        "spring.datasource.password=hunter2hunter2\n", "app.properties", Language.UNKNOWN
    ) == [("medium", VALUE)]
    assert (
        run("spring.datasource.url=jdbc-thing-here-long\n", "app.properties", Language.UNKNOWN)
        == []
    )


def test_offsets_are_utf8_bytes() -> None:
    text = 'café = "日本"\npassword = "hunter2hunter2"  # \U0001f600\n'  # pragma: allowlist secret
    assert run(text, "a.py", Language.PYTHON) == [("medium", VALUE)]


# --- the tree-based pass -------------------------------------------------------------------


def parsed(text: str, path: str, language: Language) -> ParsedFile:
    return parse(path, language, text)


def tree_values(text: str, path: str, language: Language) -> list[tuple[str, str]]:
    data = text.encode()
    file = parsed(text, path, language)
    return [
        (s.confidence.value, data[s.start_byte : s.end_byte].decode())
        for s in AssignmentDetector().detect_parsed(file)
    ]


@pytest.mark.parametrize(
    ("text", "path", "language"),
    [
        ("password = {q}{v}{q}\n", "a.py", Language.PYTHON),
        ("self.password = {q}{v}{q}\n", "a.py", Language.PYTHON),
        ("config = {{{q}password{q}: {q}{v}{q}}}\n", "a.py", Language.PYTHON),
        ("connect(password={q}{v}{q})\n", "a.py", Language.PYTHON),
        ("const password = {q}{v}{q};\n", "a.js", Language.JAVASCRIPT),
        ("const o = {{ password: {q}{v}{q} }};\n", "a.js", Language.JAVASCRIPT),
        ("const password: string = {q}{v}{q};\n", "a.ts", Language.TYPESCRIPT),
    ],
)
def test_the_tree_pass_finds_the_literal_in_each_grammar(
    text: str, path: str, language: Language
) -> None:
    assert tree_values(text.format(q="'", v=VALUE), path, language) == [("medium", VALUE)]


@pytest.mark.parametrize(
    ("text", "path", "language"),
    [
        ("passwordHint = {q}your first pet name{q}\n", "a.py", Language.PYTHON),
        ("label = {q}{v}{q}\n", "a.py", Language.PYTHON),
        ("print({q}{v}{q})\n", "a.py", Language.PYTHON),
        ("const label = {q}{v}{q};\n", "a.js", Language.JAVASCRIPT),
    ],
)
def test_the_tree_pass_ignores_literals_that_are_not_assigned_to_a_credential(
    text: str, path: str, language: Language
) -> None:
    assert tree_values(text.format(q='"', v=VALUE), path, language) == []


def test_the_tree_pass_handles_multibyte_text_and_a_triple_quoted_literal() -> None:
    text = '# café\npassword = """hunter2hunter2"""\n'
    assert tree_values(text, "a.py", Language.PYTHON) == [("medium", VALUE)]


def test_without_a_tree_the_tree_pass_falls_back_to_the_line_pass() -> None:
    file = parsed('password = "hunter2hunter2"\n', "a.py", Language.PYTHON)
    spans = AssignmentDetector().detect_parsed(replace(file, tree=None))
    assert len(spans) == 1
