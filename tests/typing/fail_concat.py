"""Wrappers do not support string concatenation."""

from codekavach.core.models.text import RawCode

raw = RawCode("a = 1")
joined = raw + "x"  # E: operator
