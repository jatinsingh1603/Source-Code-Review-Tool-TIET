"""Unit tests for the literal shapers (E09-03): one case per kind and rule, plus the regressions."""

import re

import pytest

from codekavach.core.models import Location, PrivacyLevel
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.parsing.models import LiteralKind, LiteralSpan
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator
from codekavach.privacy.pseudonymise.literals import (
    ShapeDisplay,
    ShapeProvenance,
    shape,
    shape_content,
)

SALT = ScanSalt(bytes(range(32)))
PLACEHOLDER = "<SECRET:api_key:1>"


class Allow:
    def __init__(self, *words: str) -> None:
        self.words = frozenset(words)

    def is_public(self, word: str) -> bool:
        return word in self.words


def run(content: str, kind: str, allowlist: Allow | None = None) -> tuple[str, ShapeProvenance]:
    return shape_content(
        content,
        kind,
        generator=PseudonymGenerator(SALT),
        allowlist=allowlist or Allow(),
    )


def shaped(content: str, kind: str, allowlist: Allow | None = None) -> str:
    return run(content, kind, allowlist)[0]


def skeleton(text: str) -> str:
    """The shape of a shaped SQL text with every pseudonym number erased."""
    return re.sub(r"(col|tbl)_\d+", "X", text)


# ---- sql ---------------------------------------------------------------------------------------


def test_worked_example_keeps_the_sql_skeleton() -> None:
    text = shaped(
        "SELECT balance, festival_bonus FROM premium_accounts WHERE customer_id = '%s'", "sql"
    )
    assert skeleton(text) == "SELECT X, X FROM X WHERE X = '%s'"
    assert re.fullmatch(r"SELECT col_\d+, col_\d+ FROM tbl_\d+ WHERE col_\d+ = '%s'", text)


def test_sql_worked_example_has_no_domain_word() -> None:
    text = shaped(
        "SELECT balance, festival_bonus FROM premium_accounts WHERE customer_id = '%s'", "sql"
    )
    for word in ("balance", "festival", "bonus", "premium", "accounts", "customer"):
        assert word not in text


@pytest.mark.parametrize("marker", ["?", "%s", "%d", ":name", "$1"])
def test_sql_parameter_markers_are_kept(marker: str) -> None:
    # The string is SQL text for a shaper to read, never executed: S608 does not apply.
    assert marker in shaped("SELECT x FROM t WHERE id = " + marker, "sql")  # noqa: S608


def test_sql_keeps_comparison_constant_only_when_security_relevant() -> None:
    kept = shaped("SELECT a FROM t WHERE port_number = 5432", "sql")
    coarsened = shaped("SELECT a FROM t WHERE balance > 250000", "sql")
    assert "5432" in kept
    assert "250000" not in coarsened
    assert "100000" in coarsened


def test_sql_string_content_is_filled_but_format_markers_kept() -> None:
    text = shaped("SELECT a FROM t WHERE status = 'premium member %s'", "sql")
    assert "%s" in text
    assert "premium" not in text


def test_sql_keyword_is_never_replaced() -> None:
    text = shaped("SELECT COUNT(*) FROM orders", "sql")
    assert "COUNT" in text and "SELECT" in text and "FROM" in text


def test_a_word_spelled_like_a_pseudonym_is_still_replaced() -> None:
    """An original identifier that looks like a pseudonym must not reach the provider (I6)."""
    text = shaped("SELECT fn_7777 FROM var_8888", "sql")
    assert "fn_7777" not in text and "var_8888" not in text
    assert "SELECT" in text and "FROM" in text


def test_sql_display_prefixes_are_supplied_by_the_caller() -> None:
    text, _ = shape_content(
        "SELECT balance FROM accounts",
        "sql",
        generator=PseudonymGenerator(SALT),
        allowlist=Allow(),
        display=ShapeDisplay(column_prefix="fld", table_prefix="rel"),
    )
    assert re.fullmatch(r"SELECT fld_\d+ FROM rel_\d+", text)


# ---- url ---------------------------------------------------------------------------------------


def test_url_keeps_scheme_port_and_segment_count_and_loses_host_and_values() -> None:
    text = shaped("https://billing.example.test:8443/v2/customers/x/invoices?token=abc", "url")
    assert text.startswith("https://mod_")
    assert ":8443/" in text
    assert text.count("/") == 6
    assert "billing" not in text and "abc" not in text
    assert text.endswith("?var_1=x") or "=x" in text


def test_url_keeps_allowlisted_query_names() -> None:
    text = shaped("https://a.example.test/x?format=json&token=abc", "url", Allow("format"))
    assert "format=x" in text
    assert "token" not in text and "abc" not in text


@pytest.mark.parametrize("marker", ["{id}", ":id", "*"])
def test_url_template_marker_is_kept(marker: str) -> None:
    assert marker in shaped(f"https://a.example.test/items/{marker}", "url")


def test_url_that_does_not_parse_is_filled_not_kept() -> None:
    text = shaped("mailto:someone@example.test", "url")
    assert "someone" not in text and "example" not in text


# ---- path --------------------------------------------------------------------------------------


def test_path_keeps_separator_style_prefix_count_and_extension() -> None:
    text = shaped("..\\..\\reports\\quarterly.pdf", "path")
    assert text.startswith("..\\..\\")
    assert text.count("\\") == 3
    assert text.endswith(".pdf")
    assert "reports" not in text and "quarterly" not in text


def test_path_keeps_drive_prefix_and_leading_slash() -> None:
    text = shaped("C:/data/customer_exports/q3.csv", "path")
    assert text.startswith("C:/")
    assert text.endswith(".csv")
    assert text.count("/") == 3


def test_path_keeps_a_segment_that_is_on_the_allowlist() -> None:
    text = shaped("/usr/bin/tool", "path", Allow("usr"))
    assert text.startswith("/usr/")


# ---- format ------------------------------------------------------------------------------------


def test_format_keeps_specifiers_exactly_and_in_order() -> None:
    text = shaped("Hi %s, you owe %5.2f and %-8d more", "format")
    assert re.findall(r"%[-+ #0-9.]*[a-zA-Z]", text) == ["%s", "%5.2f", "%-8d"]


def test_format_replaces_internal_placeholder_name_and_keeps_format_spec() -> None:
    text = shaped("Dear {customer_name}, balance {0:>10.2f}", "format")
    assert "{customer_name}" not in text
    assert "{0:>10.2f}" in text


def test_format_keeps_public_named_placeholder() -> None:
    text = shaped("hello %(date)s", "format", Allow("date"))
    assert "%(date)s" in text


def test_format_keeps_escaped_braces() -> None:
    assert "{{" in shaped("literal {{braces}} here", "format")


# ---- regex -------------------------------------------------------------------------------------


def test_regex_keeps_metacharacters_quantifiers_and_classes() -> None:
    text = shaped(r"^[0-9]{3}-(\d+)$", "regex")
    assert text == r"^[0-9]{3}-(\d+)$"


def test_regex_replaces_long_alphabetic_runs_outside_classes() -> None:
    text = shaped(r"customer\d+", "regex")
    assert "customer" not in text
    re.compile(text)  # raises when the shaped pattern is invalid


def test_regex_named_group_is_shaped_and_still_compiles() -> None:
    text = shaped(r"(?P<account_id>\d+)", "regex")
    assert "account_id" not in text
    re.compile(text)  # raises when the shaped pattern is invalid


def test_regex_that_breaks_when_shaped_falls_back_to_a_filler() -> None:
    # Two distinct group names that become the same filler once shaped: a duplicate group name.
    content, provenance = run(r"(?P<abcd>x)(?P<efgh>y)", "regex")
    re.compile(content)  # raises when the shaped pattern is invalid
    assert "abcd" not in content and "efgh" not in content
    assert provenance.fallbacks == 1


def test_regex_that_does_not_compile_is_replaced_not_sent() -> None:
    content, provenance = run(r"[unclosed", "regex")
    assert content == "x" * len(r"[unclosed")
    assert provenance.fallbacks == 1


# ---- natural -----------------------------------------------------------------------------------


def test_natural_shorter_than_four_characters_is_kept_verbatim() -> None:
    assert shaped("ok", "natural") == "ok"
    assert shaped("abc", "natural") == "abc"


def test_natural_long_string_becomes_a_same_length_filler() -> None:
    text = shaped("Payment failed", "natural")
    assert text == "xxxxxxx xxxxxx"


def test_natural_keeps_allowlisted_words() -> None:
    assert shaped("Use the Requests library", "natural", Allow("Requests")) == (
        "xxx xxx Requests xxxxxxx"
    )


# ---- placeholders ------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["sql", "url", "path", "format", "regex", "natural"])
def test_placeholder_passes_through_every_shaper_byte_for_byte(kind: str) -> None:
    content = {
        "sql": "SELECT a FROM t WHERE k = '" + PLACEHOLDER + "'",  # noqa: S608
        "url": f"https://h.example.test/{PLACEHOLDER}/x",
        "path": f"/srv/{PLACEHOLDER}/file.txt",
        "format": f"Use {PLACEHOLDER} for %s",
        "regex": f"{PLACEHOLDER}[0-9]+",
        "natural": f"The {PLACEHOLDER} value",
    }[kind]
    assert PLACEHOLDER in shaped(content, kind)


# ---- levels, kinds and provenance --------------------------------------------------------------


def test_unknown_kind_is_refused() -> None:
    with pytest.raises(PseudonymError):
        run("anything", "not_a_kind")


def _span(text: str, kind: LiteralKind) -> LiteralSpan:
    location = Location(path="a.py", start_line=1, end_line=1, start_col=1, end_col=len(text) + 1)
    return LiteralSpan(location=location, kind=kind, raw_text=text)


def test_shape_refuses_level_l0_because_nothing_is_sent() -> None:
    with pytest.raises(PseudonymError):
        shape(
            _span("hello world", "natural"),
            generator=PseudonymGenerator(SALT),
            allowlist=Allow(),
            level=PrivacyLevel.L0,
        )


def test_shape_dispatches_on_span_kind() -> None:
    text = shape(
        _span("Payment failed", "natural"),
        generator=PseudonymGenerator(SALT),
        allowlist=Allow(),
        level=PrivacyLevel.L2,
    )
    assert text == "xxxxxxx xxxxxx"


def test_provenance_counts_kept_and_replaced_tokens() -> None:
    _, provenance = run("SELECT balance FROM accounts", "sql")
    assert provenance.tokens_replaced == 2
    assert provenance.tokens_kept == 2
