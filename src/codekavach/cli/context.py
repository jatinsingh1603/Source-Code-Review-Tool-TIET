"""``CliContext``: the global options of one invocation and, lazily, its configuration.

Owning epic: E05.

``get_context`` never touches the disk; only the first access to ``CliContext.loaded`` reads the
configuration, so ``--help``, ``--version`` and ``completion`` work in an untrusted repository
without reading its files. Overrides from flags go through the E03 loader, which enforces the
privacy floors and organisation policy and fails with exit 2 instead of adjusting silently.

``get_context`` also configures logging from the flags (E05-06). The ``[logging]`` settings can
only apply once the configuration has been read, so ``loaded`` configures logging again.
"""

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any, Literal

from typer import _click as click  # Typer >= 0.27 ships its own copy of Click

from codekavach.cli.errors import UsageError
from codekavach.cli.logging_setup import configure_cli_logging
from codekavach.cli.options import globals_of
from codekavach.config import LoadedConfig, Settings, load_settings
from codekavach.config.overrides import (
    CliOverrides,
    combine,
    overrides_from_flags,
    parse_set_options,
)
from codekavach.core.models import PrivacyLevel

CONTEXT_KEY = "codekavach.context"


@dataclass(frozen=True)
class CliContext:
    """Output flags, loader inputs and the lazily loaded configuration."""

    json_mode: bool = False
    quiet: bool = False
    verbosity: int = 0
    debug: bool = False
    log_level: str | None = None
    log_format: Literal["console", "json"] | None = None
    log_file: Path | None = None
    no_input: bool = False
    offline: bool = False
    config_file: Path | None = None
    profile: str | None = None
    use_user_config: bool = True
    trust_project_config: bool = False
    provider: str | None = None
    model: str | None = None
    cli_overrides: CliOverrides = field(default_factory=CliOverrides)
    target_hint: Path | None = None
    argv_origin: Mapping[str, str] = field(default_factory=dict)

    @cached_property
    def loaded(self) -> LoadedConfig:
        """The configuration with the command-line overrides applied (read on first access)."""
        loaded = load_settings(
            target=self.target_hint,
            config_file=self.config_file,
            profile=self.profile,
            cli_overrides=self.cli_overrides,
            use_user_config=self.use_user_config,
            trust_project_config=self.trust_project_config,
        )
        self._check_selection(loaded.settings)
        configure_cli_logging(self, loaded)
        return loaded

    def _check_selection(self, settings: Settings) -> None:
        llm = settings.llm
        chosen = self.provider or (llm.default_provider if llm.default_provider != "auto" else None)
        if self.model is not None and chosen is None:
            raise UsageError(
                "--model needs a concrete provider",
                code="model_needs_provider",
                hint="pass --provider or set llm.default_provider",
            )
        provider = llm.providers.get(chosen) if chosen else None
        if self.offline and provider is not None and provider.is_remote:
            raise UsageError(
                "--offline cannot be combined with a remote provider",
                code="offline_remote_conflict",
                hint="choose a local provider or drop --offline",
            )

    @property
    def settings(self) -> Settings:
        """The effective settings."""
        return self.loaded.settings

    @property
    def privacy_level(self) -> PrivacyLevel:
        """The effective privacy level."""
        return self.settings.privacy.level

    @property
    def provider_id(self) -> str:
        """The configured provider id (``auto`` until provider selection, E22)."""
        return self.settings.llm.default_provider


def _build(values: Mapping[str, Any]) -> CliContext:
    quiet = bool(values.get("quiet", False))
    verbosity = int(values.get("verbose", 0) or 0)
    if quiet and verbosity:
        raise UsageError(
            "--quiet and --verbose contradict each other", code="quiet_verbose_conflict"
        )
    privacy = values.get("privacy_level")
    overrides = combine(
        overrides_from_flags(
            privacy_level=str(privacy).upper() if privacy else None,
            provider=values.get("provider"),
            model=values.get("model"),
            offline=bool(values.get("offline", False)),
        ),
        parse_set_options(list(values.get("set_values", []))),
    )
    return CliContext(
        json_mode=bool(values.get("json_mode", False)),
        quiet=quiet,
        verbosity=verbosity,
        debug=bool(values.get("debug", False)),
        log_level=values.get("log_level"),
        log_format=values.get("log_format"),
        log_file=values.get("log_file"),
        no_input=bool(values.get("no_input", False)),
        offline=bool(values.get("offline", False)),
        config_file=values.get("config"),
        profile=values.get("profile"),
        use_user_config=not values.get("no_user_config", False),
        trust_project_config=bool(values.get("trust_project_config", False)),
        provider=values.get("provider"),
        model=values.get("model"),
        cli_overrides=overrides,
        argv_origin=dict(overrides.key_sources),
    )


def get_context(ctx: click.Context) -> CliContext:
    """The ``CliContext`` of this invocation, built once and cached on the root context."""
    root = ctx.find_root()
    cached = root.meta.get(CONTEXT_KEY)
    if isinstance(cached, CliContext):
        return cached
    context = _build(globals_of(ctx))
    root.meta[CONTEXT_KEY] = context
    configure_cli_logging(context)
    return context


def with_target(ctx: click.Context, path: Path) -> CliContext:
    """Set the directory from which the project configuration is discovered.

    Must be called before ``loaded`` is first read; the new context replaces the cached one.
    """
    current = get_context(ctx)
    if "loaded" in current.__dict__:
        raise RuntimeError("the configuration was already loaded")
    updated = dataclasses.replace(current, target_hint=path)
    ctx.find_root().meta[CONTEXT_KEY] = updated
    return updated


def with_overrides(ctx: click.Context, overrides: CliOverrides) -> CliContext:
    """Add command-specific flag overrides (for example ``scan --jobs``) before loading.

    Raises:
        ConfigError: CK-CFG-061 when a key is set both globally and by the command.
    """
    current = get_context(ctx)
    if "loaded" in current.__dict__:
        raise RuntimeError("the configuration was already loaded")
    merged = combine(current.cli_overrides, overrides)
    updated = dataclasses.replace(
        current, cli_overrides=merged, argv_origin=dict(merged.key_sources)
    )
    ctx.find_root().meta[CONTEXT_KEY] = updated
    return updated
