"""Resolve ``(task, version)`` to a prompt template and its hash.

Owning epic: E13. MVP; extended by E23, which adds the prompt library and its evaluation.

Templates are plain Markdown files under ``prompts/<task>/<version>.md`` shipped inside the
package. The hash is SHA-256 of the file's bytes, so a provenance record that names ``triage``,
``v1`` and the hash identifies exactly the wording that was used; editing a published version
changes the hash and is caught by the test that pins it.
"""

import re
from dataclasses import dataclass
from importlib import resources
from typing import Final

from codekavach.core.models.canonical import sha256_hex

_NAME: Final = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_VERSION: Final = re.compile(r"^v[0-9]{1,3}$")


class PromptNotFoundError(LookupError):
    """No template exists for the requested task and version."""


@dataclass(frozen=True, slots=True)
class PromptTemplate:
    """A template text and the hash that identifies it."""

    task: str
    version: str
    text: str
    sha256: str


def load_prompt(task: str, version: str) -> PromptTemplate:
    """The template for ``task`` at ``version``.

    Raises:
        PromptNotFoundError: the names are malformed or the file does not exist. The message names
            the task and version only.
    """
    if not _NAME.fullmatch(task) or not _VERSION.fullmatch(version):
        raise PromptNotFoundError("malformed prompt name or version")
    resource = resources.files("codekavach.llm.prompts").joinpath(task, f"{version}.md")
    try:
        data = resource.read_bytes()
    except (FileNotFoundError, NotADirectoryError):
        raise PromptNotFoundError(f"no prompt {task}/{version}") from None
    text = data.decode("utf-8")
    return PromptTemplate(task=task, version=version, text=text, sha256=sha256_hex(text))
