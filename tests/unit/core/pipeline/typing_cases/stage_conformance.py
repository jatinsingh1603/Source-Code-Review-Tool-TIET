"""A conforming class is assignable to ``Stage`` under ``mypy --strict``."""

from typing import Any

from codekavach.core.pipeline.stage import Stage


class CountFiles:
    name = "count-files"
    requires = frozenset({"files"})
    provides = frozenset({"stats.file_count"})

    def run(self, ctx: Any) -> None:
        del ctx


stage: Stage = CountFiles()
