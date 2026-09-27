"""The root ``Settings`` model.

Owning epic: E03.
"""

from typing import Any, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from codekavach.config.models.llm import LLMSettings
from codekavach.config.models.log import LoggingSettings
from codekavach.config.models.plugins import PluginsSettings
from codekavach.config.models.privacy import PrivacySettings
from codekavach.config.models.project import ProjectSettings
from codekavach.config.models.scan import ScanSettings


class Settings(BaseSettings):
    """The effective configuration of one CodeKavach invocation.

    ``Settings()`` reads nothing but its arguments: no environment variables, dotenv file or
    secrets directory. The loader (E03-13) is the only component that layers sources (ADR
    decision D9). The environment prefix and delimiter are recorded here only so that the naming
    rule lives on the model; E03-16 implements the environment layer.

    The model is frozen, but lists and dictionaries inside it are still mutable objects;
    consumers must treat them as read-only. The loader hands out one instance per invocation.
    """

    model_config = SettingsConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        env_prefix="CODEKAVACH_",
        env_nested_delimiter="__",
    )

    config_version: Literal[1] = Field(
        default=1, description="Version of the configuration format; only 1 is supported."
    )
    profile: str | None = Field(default=None, description="Name of the profile to apply.")
    project: ProjectSettings = Field(
        default_factory=ProjectSettings, description="Identity of the scanned project."
    )
    scan: ScanSettings = Field(default_factory=ScanSettings, description="What to scan and how.")
    privacy: PrivacySettings = Field(
        default_factory=PrivacySettings, description="What may leave the machine."
    )
    llm: LLMSettings = Field(
        default_factory=LLMSettings, description="Language models and their providers."
    )
    plugins: PluginsSettings = Field(
        default_factory=PluginsSettings, description="Which installed plugins may load."
    )
    logging: LoggingSettings = Field(
        default_factory=LoggingSettings, description="Diagnostic logging on stderr."
    )
    profiles: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Named profile overlays, interpreted by the profile layer.",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Only the constructor arguments; the loader layers every other source."""
        return (init_settings,)
