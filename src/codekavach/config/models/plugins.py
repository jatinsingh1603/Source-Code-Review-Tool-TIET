"""The ``[plugins]`` section: which installed plugins may load (applied by E04-11).

Owning epic: E03.

Both keys are restricted: an untrusted project configuration inside a scanned repository must not
enable or disable plugins (E03-25).
"""

import re

from pydantic import Field, field_validator

from codekavach.config.models.base import INVALID, SectionModel, StrList, restricted

_DISTRIBUTION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_DISABLE = re.compile(
    r"^(stage|language|engine|detector|provider|renderer):[a-z0-9][a-z0-9_.-]{0,63}$"
)
_NEVER_DISABLE = frozenset({"stage:privacy-prepare", "stage:restore"})


def normalise_distribution(name: str) -> str:
    """PEP 503 normalisation of a distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


class PluginsSettings(SectionModel):
    """Plugin allow-list and disable-list."""

    allow_distributions: StrList = Field(
        default_factory=list,
        description=(
            "Distributions whose plugins may load; empty allows all, and codekavach itself is "
            "always allowed."
        ),
        json_schema_extra=restricted(),
    )
    disable: StrList = Field(
        default_factory=list,
        description="Plugins to disable, written as kind:name, for example engine:semgrep.",
        json_schema_extra=restricted(),
    )

    @field_validator("allow_distributions")
    @classmethod
    def _check_distributions(cls, value: list[str]) -> list[str]:
        for name in value:
            if not _DISTRIBUTION.match(name):
                raise ValueError(f"{INVALID} plugins.allow_distributions has an invalid name")
        return value

    @field_validator("disable")
    @classmethod
    def _check_disable(cls, value: list[str]) -> list[str]:
        for entry in value:
            if entry in _NEVER_DISABLE:
                raise ValueError(
                    f"{INVALID} plugins.disable cannot remove the privacy or restore stage; "
                    "set llm.enabled = false instead"
                )
            if not _DISABLE.match(entry):
                raise ValueError(f"{INVALID} plugins.disable entries must be written kind:name")
        return value
