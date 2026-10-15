"""``SourceFile`` and ``FileInventory``, the output of repository discovery (E06-01).

Owning epic: E06.

Both carry client data (a path and derived facts about client code), so ``DATA_CLASSIFICATION``
is ``RAW``: neither may reach ``codekavach.llm`` directly (I2), and their ``repr`` is not
redacted the way ``RawCode`` is, so logging one whole is still a reviewer's mistake to avoid, not
something this module can prevent by itself. Deliberately no text field: a scan holding every
file's content in memory at once is the resource-exhaustion risk E06-01's performance budget
exists to avoid, so content is read again, once, by whichever later stage needs it.
"""

from typing import ClassVar

from codekavach.core.models import DataClassification, KavachModel, Language, RepoPath


class SourceFile(KavachModel):
    """One file discovery accepted, with the facts later stages need and no content."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    path: RepoPath
    sha256: str
    size_bytes: int
    language: Language
    line_count: int
    encoding: str
    is_generated: bool = False
    is_minified: bool = False
    is_vendored: bool = False


class FileInventory(KavachModel):
    """Aggregate facts about one discovery run, for the report and the manifest."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    total_files: int
    total_lines: int
    total_bytes: int
    languages: tuple[tuple[Language, int], ...]
    git_commit: str | None = None
    git_branch: str | None = None
    git_dirty: bool | None = None
