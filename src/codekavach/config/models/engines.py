"""The ``[engines]`` section: which analysers run, with which executables and limits.

Owning epic: E03.

External engines are separate processes (ARCHITECTURE section 2), and a malicious or
compromised engine is in the threat model (section 6.4). The keys that decide what gets
executed (``executable``, ``args``, ``env_passthrough``) are therefore restricted, so an untrusted
project file cannot set them (E03-25; CWE-426, CWE-78). ``env_passthrough`` defaults to empty so
that provider keys in the environment stay invisible to third-party engines.

Precedence inside the section, implemented by E14: ``options.<id>.enabled`` beats the
``enabled`` and ``disabled`` lists, and ``disabled`` beats ``enabled``. Any syntactically valid
engine id is accepted here; E14 reports unknown ones.
"""

import re
from pathlib import Path
from typing import Annotated, Self

from pydantic import AfterValidator, BeforeValidator, Field, field_validator, model_validator

from codekavach.config.models.base import (
    INVALID,
    SectionModel,
    StrList,
    bounds,
    in_range,
    restricted,
    split_csv,
    volatile,
)

MIN_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 86_400
MAX_ARGS = 64
MAX_ARG_LENGTH = 1024
BOTH_ENABLED_AND_DISABLED = "[CK-CFG-035]"
_ENGINE_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _check_engine_id(value: str) -> str:
    if not _ENGINE_ID.match(value):
        raise ValueError(f"{INVALID} engine ids match ^[a-z][a-z0-9-]{{0,31}}$")
    return value


EngineId = Annotated[str, AfterValidator(_check_engine_id)]
EngineIdList = Annotated[list[EngineId], BeforeValidator(split_csv)]
TimeoutSeconds = Annotated[
    int, in_range(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS, "engines timeout_seconds")
]


class NativeEngines(SectionModel):
    """Built-in analysers (ARCHITECTURE ``analysis/``); all on by default."""

    rules: bool = Field(default=True, description="Native pattern rules.")
    taint: bool = Field(default=True, description="Native taint analysis.")
    secrets: bool = Field(default=True, description="Native secret detection.")
    sca: bool = Field(default=True, description="Native software composition analysis.")
    iac: bool = Field(default=True, description="Native infrastructure-as-code checks.")


class EngineOptions(SectionModel):
    """Per-engine overrides."""

    enabled: bool | None = Field(
        default=None, description="Force the engine on or off; beats the section lists."
    )
    executable: Path | None = Field(
        default=None,
        description="Path of the engine executable instead of the one found on PATH.",
        json_schema_extra=restricted(),
    )
    args: list[str] = Field(
        default_factory=list,
        description="Extra command-line arguments passed to the engine.",
        json_schema_extra={**restricted(), "maxItems": MAX_ARGS},
    )
    env_passthrough: StrList = Field(
        default_factory=list,
        description="Names of environment variables the sandboxed engine may see.",
        json_schema_extra=restricted(),
    )
    timeout_seconds: TimeoutSeconds | None = Field(
        default=None,
        description="Time limit for this engine in seconds.",
        json_schema_extra={**volatile(), **bounds(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS)},
    )
    options: dict[str, str | int | float | bool] = Field(
        default_factory=dict, description="Engine-specific options passed to its adapter."
    )

    @field_validator("args")
    @classmethod
    def _check_args(cls, value: list[str]) -> list[str]:
        if len(value) > MAX_ARGS:
            raise ValueError(f"{INVALID} engines options args hold at most {MAX_ARGS} items")
        for item in value:
            if len(item) > MAX_ARG_LENGTH or "\x00" in item:
                raise ValueError(
                    f"{INVALID} engines options args are at most {MAX_ARG_LENGTH} characters "
                    "without NUL"
                )
        return value

    @field_validator("env_passthrough")
    @classmethod
    def _check_env_names(cls, value: list[str]) -> list[str]:
        for name in value:
            if not _ENV_NAME.match(name):
                raise ValueError(
                    f"{INVALID} engines options env_passthrough entries match "
                    "^[A-Za-z_][A-Za-z0-9_]{0,127}$"
                )
        return value


class EnginesSettings(SectionModel):
    """Which external engines and native analysers run, and how."""

    enabled: EngineIdList = Field(
        default_factory=list,
        description=(
            "External engine ids to run; empty means every installed engine applicable to the "
            "detected languages."
        ),
    )
    disabled: EngineIdList = Field(
        default_factory=list, description="External engine ids that are not run."
    )
    timeout_seconds: TimeoutSeconds = Field(
        default=600,
        description="Time limit per engine in seconds.",
        json_schema_extra={**volatile(), **bounds(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS)},
    )
    rule_packs: StrList = Field(
        default_factory=lambda: ["default"], description="Native rule packs from rules/."
    )
    rule_paths: list[Path] = Field(
        default_factory=list, description="Extra directories of native YAML rules."
    )
    native: NativeEngines = Field(default_factory=NativeEngines, description="Built-in analysers.")
    options: dict[EngineId, EngineOptions] = Field(
        default_factory=dict, description="Per-engine overrides keyed by engine id."
    )

    @model_validator(mode="after")
    def _check_lists(self) -> Self:
        if set(self.enabled) & set(self.disabled):
            raise ValueError(
                f"{BOTH_ENABLED_AND_DISABLED} an engine id is listed in both engines.enabled "
                "and engines.disabled"
            )
        return self
