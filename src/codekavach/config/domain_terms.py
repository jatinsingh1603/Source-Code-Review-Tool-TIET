r"""Domain-term files: parsing and fail-closed reading of ``privacy.domain_terms_file`` (E03-21).

Owning epic: E03.

A terms file is UTF-8 text with one term per line. Lines come from ``split_lines`` (only ``\n``
and ``\r\n`` end a line), never from ``str.splitlines``, so a form feed or U+2028 stays inside a
term and line numbers agree with every other tool. White space around a term is stripped; empty
lines and lines starting with ``#`` are ignored; a byte-order mark is dropped; duplicates are
removed in first-seen order; case is preserved.

Every failure stops the run: a terms file that cannot be honoured would let the client's
vocabulary through the egress guard (I4). Messages carry line numbers, never term text (CWE-532).
"""

from pathlib import Path

from codekavach.config.constants import MAX_CONFIG_BYTES
from codekavach.config.errors import ConfigError, ConfigErrorCode
from codekavach.config.toml_source import read_bounded_text
from codekavach.core.models.text import split_lines

MAX_TERMS = 10_000
MIN_TERM_LENGTH = 2
MAX_TERM_LENGTH = 128
TERMS_FILE_KEY = "privacy.domain_terms_file"


def _invalid(message: str, line: int, source: str | None) -> ConfigError:
    return ConfigError.single(
        ConfigErrorCode.CK_CFG_003, message, key=TERMS_FILE_KEY, source=source, line=line
    )


def parse_terms(text: str, *, source: str | None = None) -> list[str]:
    """The terms of a terms file, de-duplicated in first-seen order.

    Raises:
        ConfigError: CK-CFG-003 with the line number when a term is shorter than two or longer
            than 128 characters, or the file has more than 10000 terms.
    """
    terms: dict[str, None] = {}
    count = 0
    for number, line in enumerate(split_lines(text.removeprefix("﻿")), start=1):
        term = line.strip()
        if not term or term.startswith("#"):
            continue
        if not MIN_TERM_LENGTH <= len(term) <= MAX_TERM_LENGTH:
            raise _invalid(
                f"domain term must have {MIN_TERM_LENGTH} to {MAX_TERM_LENGTH} characters "
                f"(got {len(term)})",
                number,
                source,
            )
        count += 1
        if count > MAX_TERMS:
            raise _invalid(f"domain terms file has more than {MAX_TERMS} terms", number, source)
        terms.setdefault(term, None)
    return list(terms)


def read_terms_file(
    path: Path, *, max_bytes: int = MAX_CONFIG_BYTES, confine_to: Path | None
) -> list[str]:
    """Read and parse one terms file, bounded and, for project configuration, confined.

    Raises:
        ConfigError: CK-CFG-005 when the file is missing, not a regular file, too large, not
            UTF-8 or escapes ``confine_to``; CK-CFG-003 as for ``parse_terms``.
    """
    text, _ = read_bounded_text(path, max_bytes=max_bytes, confine_to=confine_to)
    return parse_terms(text, source=str(path))
