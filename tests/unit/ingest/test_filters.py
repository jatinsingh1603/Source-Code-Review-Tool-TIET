"""Gitignore-semantics exclusion: ``IgnoreSet`` (E06-01).

The pattern table below is this issue's required "at least 20 pattern/path cases including
negation, anchoring, directory-only and ``**``" test, plus the nested-``.gitignore``
re-inclusion case and ``.codekavachignore``.
"""

import pytest

from codekavach.config.models.ingest import IngestSettings
from codekavach.ingest.filters import IgnoreSet
from tests.support.synthetic import make_tree

# (gitignore content, path, is_dir, expected ignored)
PATTERN_CASES = [
    pytest.param("*.log", "a.log", False, True, id="unanchored-extension"),
    pytest.param("*.log", "sub/a.log", False, True, id="unanchored-extension-nested"),
    pytest.param("*.log\n!keep.log", "keep.log", False, False, id="negation-re-includes"),
    pytest.param(
        "*.log\n!keep.log", "other.log", False, True, id="negation-does-not-affect-others"
    ),
    pytest.param("/root.txt", "root.txt", False, True, id="anchored-at-root"),
    pytest.param("/root.txt", "sub/root.txt", False, False, id="anchored-does-not-match-nested"),
    pytest.param("build/", "build", True, True, id="directory-only-matches-dir"),
    pytest.param("build/", "build", False, False, id="directory-only-does-not-match-file"),
    pytest.param("**/logs", "logs", True, True, id="leading-double-star-matches-root"),
    pytest.param("**/logs", "a/b/logs", True, True, id="leading-double-star-matches-nested"),
    pytest.param(
        "logs/**", "logs/a/b.txt", False, True, id="trailing-double-star-matches-contents"
    ),
    pytest.param("a/**/b", "a/b", False, True, id="middle-double-star-zero-segments"),
    pytest.param("a/**/b", "a/x/y/b", False, True, id="middle-double-star-many-segments"),
    pytest.param("*.py[co]", "module.pyc", False, True, id="character-class-c"),
    pytest.param("*.py[co]", "module.pyo", False, True, id="character-class-o"),
    pytest.param("*.py[co]", "module.py", False, False, id="character-class-no-match"),
    pytest.param("doc?.txt", "doc1.txt", False, True, id="question-mark-wildcard"),
    pytest.param("doc?.txt", "doc12.txt", False, False, id="question-mark-is-exactly-one"),
    pytest.param("temp", "temp", False, True, id="plain-name-matches-file"),
    pytest.param("temp", "a/temp", False, True, id="plain-name-matches-nested-file"),
    pytest.param("# comment\n*.log", "notes.md", False, False, id="comment-line-ignored"),
    pytest.param("", "anything.txt", False, False, id="empty-gitignore-matches-nothing"),
]


@pytest.mark.parametrize(("gitignore", "path", "is_dir", "expected"), PATTERN_CASES)
def test_gitignore_pattern_table(gitignore: str, path: str, is_dir: bool, expected: bool) -> None:
    root = make_tree({".gitignore": gitignore})
    settings = IngestSettings(excludes=[])
    ignore_set = IgnoreSet.from_root(root, settings)
    assert ignore_set.matches(path, is_dir=is_dir) is expected


def test_nested_gitignore_reincludes_a_file_its_parent_excludes() -> None:
    root = make_tree({".gitignore": "*.txt\n", "keep/.gitignore": "!important.txt\n"})
    settings = IngestSettings(excludes=[])
    ignore_set = IgnoreSet.from_root(root, settings)
    assert ignore_set.matches("a.txt", is_dir=False) is True
    assert ignore_set.matches("keep/other.txt", is_dir=False) is True
    assert ignore_set.matches("keep/important.txt", is_dir=False) is False


def test_nested_gitignore_pattern_does_not_leak_outside_its_directory() -> None:
    root = make_tree({"sub/.gitignore": "secret.txt\n"})
    settings = IngestSettings(excludes=[])
    ignore_set = IgnoreSet.from_root(root, settings)
    assert ignore_set.matches("secret.txt", is_dir=False) is False
    assert ignore_set.matches("sub/secret.txt", is_dir=False) is True


def test_codekavachignore_applies_even_when_gitignore_is_disrespected() -> None:
    root = make_tree({".gitignore": "*.txt\n", ".codekavachignore": "excluded_always.py\n"})
    settings = IngestSettings(excludes=[], respect_gitignore=False)
    ignore_set = IgnoreSet.from_root(root, settings)
    assert ignore_set.matches("a.txt", is_dir=False) is False  # gitignore not respected
    assert ignore_set.matches("excluded_always.py", is_dir=False) is True


def test_excludes_setting_is_always_applied() -> None:
    root = make_tree({})
    settings = IngestSettings(excludes=["**/*.min.js"])
    ignore_set = IgnoreSet.from_root(root, settings)
    assert ignore_set.matches("a.min.js", is_dir=False) is True
    assert ignore_set.matches("deep/nested/a.min.js", is_dir=False) is True
    assert ignore_set.matches("a.js", is_dir=False) is False
