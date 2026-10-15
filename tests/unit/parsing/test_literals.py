"""``classify_literal``: pure string-content classification (E07-02)."""

import pytest

from codekavach.parsing.literals import LiteralContext, classify_literal

CASES = [
    # sql
    pytest.param(
        "SELECT * FROM premium_accounts WHERE id = '%s'", None, "sql", id="sql-select-beats-format"
    ),
    pytest.param("insert into users (name) values (?)", None, "sql", id="sql-insert"),
    pytest.param("UPDATE accounts SET balance = balance - 1", None, "sql", id="sql-update"),
    pytest.param("DELETE FROM sessions WHERE expired = true", None, "sql", id="sql-delete"),
    pytest.param("WITH recent AS (SELECT 1) SELECT * FROM recent", None, "sql", id="sql-with-cte"),
    pytest.param("CREATE TABLE t (id int)", None, "sql", id="sql-create"),
    pytest.param("ALTER TABLE t ADD COLUMN x int", None, "sql", id="sql-alter"),
    pytest.param("DROP TABLE t", None, "sql", id="sql-drop"),
    pytest.param("select name from users join orders on 1=1", None, "sql", id="sql-select-join"),
    pytest.param(
        "pick rows from the table where id matches", None, "sql", id="sql-from-where-lowercase"
    ),
    # url
    pytest.param("https://example.com/path", None, "url", id="url-https"),
    pytest.param("http://example.com", None, "url", id="url-http"),
    pytest.param("ftp://files.example.com/a", None, "url", id="url-ftp-scheme"),
    pytest.param("//cdn.example.com/lib.js", None, "url", id="url-protocol-relative"),
    pytest.param("mailto:ops@example.com", None, "url", id="url-mailto"),
    pytest.param("jdbc:postgresql://localhost/db", None, "url", id="url-jdbc"),
    # path
    pytest.param("/etc/passwd", None, "path", id="path-absolute-unix"),
    pytest.param("C:\\Windows\\System32", None, "path", id="path-windows-drive"),
    pytest.param("./relative/file.txt", None, "path", id="path-dot-relative"),
    pytest.param("../up/one.txt", None, "path", id="path-parent-relative"),
    pytest.param("~/config/app.toml", None, "path", id="path-home-relative"),
    pytest.param("a/b/c", None, "path", id="path-plain-separators"),
    pytest.param("a\\b\\c", None, "path", id="path-backslash-separators"),
    # format
    pytest.param("hello %s, you have %d items", None, "format", id="format-printf-s-d"),
    pytest.param("balance for %(name)s is %(amount)d", None, "format", id="format-named-printf"),
    pytest.param("Hello, {name}!", None, "format", id="format-brace-name"),
    pytest.param("Item {0} of {1}", None, "format", id="format-brace-index"),
    pytest.param("count: {}", None, "format", id="format-brace-empty"),
    pytest.param("total: ${total}", None, "format", id="format-shell-style"),
    # regex (context-driven; the text alone carries no signal)
    pytest.param(
        "^[a-z]+$", LiteralContext(callee_text="re.compile"), "regex", id="regex-re-compile"
    ),
    pytest.param(
        "[0-9]{3}-[0-9]{4}", LiteralContext(callee_text="re.match"), "regex", id="regex-re-match"
    ),
    pytest.param("abc", LiteralContext(is_regex_literal=True), "regex", id="regex-js-literal-flag"),
    pytest.param("[A-Z]", LiteralContext(callee_text="new RegExp"), "regex", id="regex-new-regexp"),
    # natural
    pytest.param("hello world", None, "natural", id="natural-plain-sentence"),
    pytest.param(
        "premium tier gets the festival bonus", None, "natural", id="natural-comment-like-text"
    ),
    pytest.param("", None, "natural", id="natural-empty-string"),
    # ordering: sql beats everything else even when other signals are present
    pytest.param(
        "SELECT * FROM t WHERE id = %s",
        None,
        "sql",
        id="ordering-sql-beats-format-with-percent-s",
    ),
    pytest.param(
        "select name from accounts where id = '{0}'",
        None,
        "sql",
        id="ordering-sql-beats-format-with-brace",
    ),
    pytest.param(
        "https://example.com/{id}",
        None,
        "url",
        id="ordering-url-beats-path-and-format",
    ),
    pytest.param(
        "/api/v1/{resource}",
        None,
        "path",
        id="ordering-path-beats-format",
    ),
    # joined_text: the concatenated whole is classified, not each fragment
    pytest.param(
        "ECT * FR",
        LiteralContext(joined_text="SELECT * FROM accounts WHERE id = '%s'"),
        "sql",
        id="joined-text-sql-fragment-alone-would-not-match",
    ),
    pytest.param(
        "hello",
        LiteralContext(joined_text="hello world"),
        "natural",
        id="joined-text-natural",
    ),
]


@pytest.mark.parametrize(("text", "context", "expected"), CASES)
def test_classify_literal(text: str, context: LiteralContext | None, expected: str) -> None:
    assert classify_literal(text, context) == expected


def test_a_fragment_alone_would_not_classify_as_sql() -> None:
    """Confirms the joined-text case above is actually testing something."""
    assert classify_literal("ECT * FR") == "natural"
