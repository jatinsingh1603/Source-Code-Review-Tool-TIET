"""Fenced code blocks of a Markdown page, with the HTML comment directly above each (E03-41).

Documentation tests use the comment as a marker: ``<!-- project-file -->`` says a ``toml`` block is
a project file to load, ``<!-- expect: CK-CFG-041 -->`` names the code a ``toml-invalid`` block must
fail with. Only a fence with an info string (``toml``, ``console``, ...) is a block.
"""

import re
from dataclasses import dataclass

FENCE = re.compile(r"^```(?P<language>[A-Za-z0-9_-]*)\s*$")
MARKER = re.compile(r"^<!--\s*(?P<text>.+?)\s*-->$")


@dataclass(frozen=True)
class Block:
    """One fenced code block of a documentation page."""

    page: str
    line: int
    language: str
    text: str
    marker: str | None

    @property
    def id(self) -> str:
        return f"{self.page}:{self.line}"


def extract_blocks(text: str, page: str = "page.md") -> list[Block]:
    """Fenced blocks of ``text``, each with the HTML comment directly above it (if any)."""
    blocks: list[Block] = []
    lines = text.splitlines()
    index = 0
    previous = ""
    while index < len(lines):
        match = FENCE.match(lines[index])
        if match is None or not match["language"]:
            if lines[index].strip():
                previous = lines[index].strip()
            index += 1
            continue
        start = index
        body: list[str] = []
        index += 1
        while index < len(lines) and lines[index].rstrip() != "```":
            body.append(lines[index])
            index += 1
        comment = MARKER.match(previous)
        marker = comment["text"] if comment is not None else None
        blocks.append(Block(page, start + 1, match["language"], "\n".join(body) + "\n", marker))
        previous = ""
        index += 1
    return blocks
