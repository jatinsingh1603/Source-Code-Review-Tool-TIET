"""Repository-relative paths in one normalised POSIX form.

Owning epic: E02. Backslashes are always separators, absolute, drive-relative and parent
traversal paths are rejected (never resolved), and names are NFC-normalised. Paths are client
data, so error messages never contain the path.
"""

import re
import unicodedata
from typing import Annotated

from pydantic import AfterValidator

MAX_PATH_LENGTH = 1024
_DRIVE = re.compile(r"^[A-Za-z]:")


def _has_control_character(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)


def normalise_repo_path(value: str) -> str:
    """Return ``value`` as a normalised repository-relative POSIX path.

    Raises:
        ValueError: the path is empty, absolute, drive-relative, contains ``..``, a control
            character or a trailing separator, or is longer than 1024 code points.
    """
    if value == "":
        raise ValueError("repository path must be a non-empty string")
    if _has_control_character(value):
        raise ValueError("repository path contains a control character")
    text = unicodedata.normalize("NFC", value).replace("\\", "/")
    if text.startswith("/"):
        raise ValueError("repository path must be relative, not absolute")
    if _DRIVE.match(text):
        raise ValueError("repository path must not start with a drive letter")
    if text.endswith("/"):
        raise ValueError("repository path must name a file, not end with a separator")
    segments = [segment for segment in text.split("/") if segment not in ("", ".")]
    if ".." in segments:
        raise ValueError("repository path must not contain parent traversal")
    if not segments:
        raise ValueError("repository path must name a file")
    result = "/".join(segments)
    if _DRIVE.match(result):  # "./C:" loses its prefix and would become drive-relative
        raise ValueError("repository path must not start with a drive letter")
    if len(result) > MAX_PATH_LENGTH:
        raise ValueError("repository path is longer than 1024 characters")
    return result


RepoPath = Annotated[str, AfterValidator(normalise_repo_path)]
