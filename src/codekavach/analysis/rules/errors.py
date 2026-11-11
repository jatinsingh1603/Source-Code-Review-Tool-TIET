"""Typed errors of the rule loader (E16-01).

Owning epic: E16. A rule file may come from the repository being scanned, so no message carries
file content: only the path, the kind of problem and the names of the offending fields.
"""

from pathlib import Path


class RuleLoadError(Exception):
    """A rule, catalogue, pack or bundle could not be loaded."""

    code = "load"

    def __init__(self, path: Path | str, reason: str) -> None:
        self.path = str(path)
        self.reason = reason
        super().__init__(f"{self.path}: {reason}")


class RuleFileTooLargeError(RuleLoadError):
    """A file is larger than the limit."""

    code = "too_large"


class RuleEncodingError(RuleLoadError):
    """A file is not valid UTF-8."""

    code = "encoding"


class RuleYamlError(RuleLoadError):
    """The YAML is malformed or uses a construct the loader refuses (alias, anchor, tag)."""

    code = "yaml"


class RuleShapeError(RuleLoadError):
    """The YAML parsed but its fields do not fit the model."""

    code = "shape"


class RulePathError(RuleLoadError):
    """A path is a symlink, not a regular file, or resolves outside the allowed roots."""

    code = "path"


class RulePackError(RuleLoadError):
    """A pack has validation issues; ``issues`` lists them."""

    code = "pack"

    def __init__(self, path: Path | str, issues: tuple[object, ...]) -> None:
        self.issues = issues
        super().__init__(path, f"{len(issues)} problem(s)")
