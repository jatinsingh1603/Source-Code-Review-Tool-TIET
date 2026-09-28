"""Validating a configuration without scanning anything (E03-35).

Owning epic: E03.

``validate_configuration`` runs the whole loader (every layer, plaintext refusal, project trust,
organisation policy, semantic rules) and turns every ``ConfigError`` into a report, so that
``codekavach config validate`` and ``codekavach doctor`` share one implementation. Refusals of
whole layers (plaintext secrets, project trust) stop the loader before values are validated, so
they are reported first and on their own; issues of one validation stage are reported together.
An unexpected exception is a bug and propagates.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codekavach.config.errors import (
    ConfigError,
    ConfigErrorCode,
    ConfigIssue,
    SecretResolutionError,
)
from codekavach.config.keys import effective_key_refs, resolve_provider_key, resolve_secret
from codekavach.config.loader import LoadedConfig, load_settings
from codekavach.config.paths import find_project_config

NO_KEY_KINDS = frozenset({"mock", "replay"})


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """The outcome of validating one configuration."""

    valid: bool
    errors: tuple[ConfigIssue, ...]
    warnings: tuple[ConfigIssue, ...]
    profile: str | None
    project_config: Path | None

    def to_dict(self) -> dict[str, Any]:
        """The JSON form printed by ``config validate --format json``."""
        return {
            "valid": self.valid,
            "errors": [issue.to_dict() for issue in self.errors],
            "warnings": [issue.to_dict() for issue in self.warnings],
            "profile": self.profile,
            "project_config": str(self.project_config) if self.project_config else None,
        }


def _split(issues: tuple[ConfigIssue, ...] | list[ConfigIssue]) -> tuple[list[ConfigIssue], ...]:
    errors = [issue for issue in issues if issue.severity == "error"]
    warnings = [issue for issue in issues if issue.severity != "error"]
    return errors, warnings


def _project_config(loader_kwargs: Mapping[str, Any]) -> Path | None:
    explicit = loader_kwargs.get("config_file")
    if explicit is not None:
        return Path(explicit)
    target = loader_kwargs.get("target") or Path.cwd()
    return find_project_config(Path(target))


def report_from_error(error: ConfigError, **loader_kwargs: Any) -> ValidationReport:
    """The report of a configuration that could not be loaded."""
    errors, warnings = _split(error.issues)
    return ValidationReport(
        valid=False,
        errors=tuple(errors),
        warnings=tuple(warnings),
        profile=loader_kwargs.get("profile"),
        project_config=_project_config(loader_kwargs),
    )


def _secret_issues(loaded: LoadedConfig, env: Mapping[str, str] | None) -> list[ConfigIssue]:
    """Code 012 for the default provider's key and each enabled integration's token."""
    issues: list[ConfigIssue] = []
    root = loaded.project_root
    llm = loaded.settings.llm
    provider = llm.providers.get(llm.default_provider)
    if provider is not None and str(provider.kind) not in NO_KEY_KINDS:
        try:
            resolve_provider_key(llm.default_provider, provider, env=env, project_root=root)
        except SecretResolutionError as error:
            issues.extend(error.issues)
    github = loaded.settings.integrations.github
    if github.enabled:
        refs = effective_key_refs("github", github.token)
        failures: list[ConfigIssue] = []
        for ref in refs:
            try:
                resolve_secret(ref, env=env, project_root=root)
            except SecretResolutionError as error:
                failures.extend(error.issues)
            else:
                failures = []
                break
        if failures:
            issues.append(
                ConfigIssue(
                    code=ConfigErrorCode.CK_CFG_012,
                    severity="error",
                    message=f"integrations.github.token: no reference resolves; tried "
                    f"{', '.join(refs)}",
                    key="integrations.github.token",
                )
            )
    return issues


def validate_configuration(
    *, check_secrets: bool = False, **loader_kwargs: Any
) -> ValidationReport:
    """Load the configuration like a scan would and report every problem found.

    With ``check_secrets`` the key of the effective default provider (unless ``auto``, ``mock``
    or ``replay``) and the token of each enabled integration are resolved; unresolved references
    are code 012 errors. Without it no resolver runs and no keyring is touched.
    """
    try:
        loaded = load_settings(**loader_kwargs)
    except ConfigError as error:
        return report_from_error(error, **loader_kwargs)
    errors, warnings = _split(loaded.warnings)
    if check_secrets:
        errors.extend(_secret_issues(loaded, loader_kwargs.get("env")))
    return ValidationReport(
        valid=not errors,
        errors=tuple(errors),
        warnings=tuple(warnings),
        profile=loaded.profile,
        project_config=loaded.project_config,
    )
