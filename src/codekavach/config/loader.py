"""The settings loader: discover, read, check, merge, validate and record provenance.

Owning epic: E03.

Precedence (ADR decision D2): defaults < user < project < profile < environment < CLI. The
pipeline below is the single place where semi-trusted project configuration meets trusted user
configuration; every later security check hangs off one of its named extension points, and all
layer checks run before merging so that one run reports every refusal together.

1. snapshot the environment and read ``CODEKAVACH_CONFIG`` and ``CODEKAVACH_NO_USER_CONFIG``;
2. derive the project root from the scan target (never from an explicit ``--config``);
3. ``_discover_org_policies`` (E03-28);
4. read the user file (ownership and mode checked first);
5. read the project file: explicit or discovered, confined to the project root when inside it,
   then move deprecated keys of both file layers (E03-22, warning 006);
6. ``_select_profile`` (E03-14); 7. ``_extra_layers`` (E03-16, E03-17);
8. ``_check_layers`` (E03-25, E03-26), on the raw project layer; 9. ``_expand_layer`` (E03-21);
10. deep merge from the defaults; 11. validate; 12. ``_apply_org_policy`` (E03-29, E03-30);
13. compute origins; 14. ``_semantic_checks`` (E03-23), which needs the origins.

Validation errors are converted through ``errors(include_input=False)``; ``str()`` of a Pydantic
error is never used because it may contain the rejected value (CWE-532).
"""

import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from codekavach.config.diagnostics import apply_deprecations, unknown_key_hint
from codekavach.config.domain_terms import TERMS_FILE_KEY, read_terms_file
from codekavach.config.env_source import env_layer
from codekavach.config.errors import (
    DEFAULT_SEVERITY,
    ConfigError,
    ConfigErrorCode,
    ConfigIssue,
    ConfigValidationError,
    PlaintextSecretError,
    ProfileError,
    ProjectTrustError,
)
from codekavach.config.introspect import flatten_leaves, keys_with_marker, loc_to_key
from codekavach.config.merge import deep_merge
from codekavach.config.models.base import split_csv
from codekavach.config.models.root import Settings
from codekavach.config.overrides import CliOverrides, cli_layer
from codekavach.config.paths import (
    check_discovered_project_file,
    check_trusted_file,
    find_project_config,
    project_root_for,
    user_config_file,
)
from codekavach.config.plaintext import find_plaintext_secrets
from codekavach.config.profiles import (
    build_profile_layer,
    check_user_defined,
    select_profile_name,
)
from codekavach.config.provenance import Layer, Origin, compute_origins, origin_in
from codekavach.config.toml_source import locate_key, read_toml
from codekavach.config.trust import check_restricted, is_project_trusted
from codekavach.config.validate import semantic_checks

ProjectTrust = Literal["not-needed", "flag", "env", "store", "external-config"]
CONFIG_ENV = "CODEKAVACH_CONFIG"
NO_USER_CONFIG_ENV = "CODEKAVACH_NO_USER_CONFIG"
_CODE_PREFIX = re.compile(r"^(?:Value error, |Assertion failed, )?\[(CK-CFG-\d{3})\]\s*")
_TRUE = frozenset({"1", "true", "yes", "on"})
TERMS_FILE_KEY_NAME = TERMS_FILE_KEY.rsplit(".", maxsplit=1)[1]


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    """The validated settings of one invocation, with provenance."""

    settings: Settings
    origins: Mapping[str, Origin]
    layers: tuple[Layer, ...]
    project_root: Path
    project_config: Path | None = None
    user_config: Path | None = None
    warnings: tuple[ConfigIssue, ...] = ()
    profile: str | None = None
    profile_origin: Origin | None = None
    project_trust: ProjectTrust = "not-needed"
    org_policies: tuple[Any, ...] = ()
    locked_keys: frozenset[str] = field(default_factory=frozenset)

    def resolve_path(self, path: Path) -> Path:
        """An absolute path unchanged (after ``~`` expansion); a relative one under the root."""
        expanded = path.expanduser()
        return expanded if expanded.is_absolute() else self.project_root / expanded


def union_keys_of(model: type[BaseModel]) -> frozenset[str]:
    """The templated keys whose lists merge by union."""
    return keys_with_marker(model, "union")


def _clean_loc(loc: Sequence[str | int]) -> tuple[str | int, ...]:
    """Drop Pydantic's synthetic location parts such as ``[key]`` or ``function-after[...]``."""
    return tuple(
        part for part in loc if isinstance(part, int) or not any(char in part for char in "[]()")
    )


def convert_validation_error(
    exc: ValidationError, origins_of: Callable[[str], Origin]
) -> tuple[ConfigIssue, ...]:
    """One ``ConfigIssue`` per Pydantic error, with code, dotted key, source and line."""
    issues: list[ConfigIssue] = []
    for error in exc.errors(include_input=False, include_url=False):
        key = loc_to_key(_clean_loc(error["loc"])) or None
        message = str(error["msg"])
        match = _CODE_PREFIX.match(message)
        hint = None
        if error["type"] == "extra_forbidden":
            code, message = ConfigErrorCode.CK_CFG_002, f"unknown key '{key}'"
            hint = unknown_key_hint(key, Settings) if key else None
        elif error["loc"] and error["loc"][0] == "config_version":
            code, message = ConfigErrorCode.CK_CFG_004, "unsupported config_version (expected 1)"
        elif match is not None and match.group(1) in ConfigErrorCode._value2member_map_:
            code, message = ConfigErrorCode(match.group(1)), message[match.end() :]
        else:
            code = ConfigErrorCode.CK_CFG_003
            message = message.removeprefix("Value error, ")
        origin = origins_of(key) if key else Origin(layer="default")
        issues.append(
            ConfigIssue(
                code=code,
                severity=DEFAULT_SEVERITY[code],
                message=message,
                key=key,
                source=origin.source,
                line=origin.line,
                hint=hint,
            )
        )
    return tuple(issues)


def _origin_lookup(layers: Sequence[Layer]) -> Callable[[str], Origin]:
    """Origins for keys of a failed validation: longest written prefix, highest layer first."""
    flats = [flatten_leaves(layer.data) for layer in layers]

    def origins_of(key: str) -> Origin:
        parts = key.split("[", maxsplit=1)[0].split(".")
        for length in range(len(parts), 0, -1):
            candidate = ".".join(parts[:length])
            for layer, flat in zip(reversed(layers), reversed(flats), strict=True):
                if candidate in flat or any(name.startswith(f"{candidate}.") for name in flat):
                    return origin_in(layer, key, candidate)
        return Origin(layer="default")

    return origins_of


# Extension points, called in pipeline order. Each is a no-op until its issue lands.


def _discover_org_policies(*, env: Mapping[str, str], project_root: Path) -> tuple[Any, ...]:
    """Find and verify organisation policies (E03-28)."""
    return ()


def _strip_profile_keys(layer: Layer) -> Layer:
    if "profile" not in layer.data and "profiles" not in layer.data:
        return layer
    data = {key: value for key, value in layer.data.items() if key not in {"profile", "profiles"}}
    return replace(layer, data=data)


def _select_profile(
    layers: list[Layer], *, profile: str | None, env: Mapping[str, str]
) -> tuple[list[Layer], str | None, Origin | None, dict[str, Any]]:
    """Choose a profile and insert its layer after the project layer (E03-14).

    The ``profile`` key and ``profiles`` tables leave the user and project layers; the caller puts
    the selected name and the combined user-defined overlays into the defaults instead, so neither
    takes part in layer precedence. Returns the layers, the name, the origin of the selection and
    the combined ``profiles`` table.
    """
    by_name = {layer.name: layer for layer in layers}
    user_defined: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for name in ("user", "project"):
        layer = by_name.get(name)
        table = layer.data.get("profiles") if layer is not None else None
        if layer is None or table is None:
            continue
        if not isinstance(table, Mapping):
            raise ProfileError.single(
                ConfigErrorCode.CK_CFG_003,
                "profiles must be a table",
                key="profiles",
                source=layer.source,
            )
        for profile_name, overlay in table.items():
            user_defined[profile_name] = overlay
            sources[profile_name] = layer.source
    selected, origin = select_profile_name(
        profile,
        env,
        by_name["project"].data if "project" in by_name else None,
        by_name["user"].data if "user" in by_name else None,
    )
    if origin.layer in {"user", "project"}:
        origin = origin_in(by_name[origin.layer], "profile")
    stripped = [_strip_profile_keys(layer) for layer in layers]
    try:
        check_user_defined(user_defined)
        if selected is None:
            return stripped, None, None, user_defined
        profile_layer = build_profile_layer(
            selected, user_defined, sources=sources, union_keys=union_keys_of(Settings)
        )
    except ProfileError as error:
        raise ProfileError(
            [replace(issue, source=issue.source or origin.source) for issue in error.issues]
        ) from None
    defaults = Settings().model_dump(mode="json")
    try:
        Settings.model_validate(
            deep_merge(defaults, profile_layer.data, union_keys=union_keys_of(Settings))
        )
    except ValidationError as exc:
        at_profile = Origin(layer="profile", source=profile_layer.source)
        raise ProfileError(convert_validation_error(exc, lambda _key: at_profile)) from None
    position = max(
        (index + 1 for index, layer in enumerate(stripped) if layer.name in {"user", "project"}),
        default=0,
    )
    stripped.insert(position, profile_layer)
    return stripped, selected, origin, user_defined


def _extra_layers(
    layers: list[Layer],
    *,
    env: Mapping[str, str],
    cli_overrides: CliOverrides | Mapping[str, Any] | None,
) -> tuple[list[Layer], list[ConfigIssue]]:
    """Append the environment layer (E03-16) and the CLI layer (E03-17), in that order."""
    environment, warnings = env_layer(env)
    if environment is not None:
        layers = [*layers, environment]
    if cli_overrides is not None and (
        cli_overrides.data if isinstance(cli_overrides, CliOverrides) else cli_overrides
    ):
        layers = [*layers, cli_layer(cli_overrides)]
    return layers, warnings


def _confined(layer: Layer, project_source: str | None) -> bool:
    """Project configuration, including profiles it defines, may not leave the repository."""
    if layer.name == "project":
        return True
    return (
        layer.name == "profile"
        and project_source is not None
        and layer.source.startswith(f"{project_source}#")
    )


def _terms_error(error: ConfigError, layer: Layer, path: Path) -> ConfigError:
    source = layer.key_sources.get(TERMS_FILE_KEY, layer.source)
    line = locate_key(layer.text, TERMS_FILE_KEY) if layer.text is not None else None
    return ConfigError(
        [
            replace(
                issue,
                message=f"domain terms file cannot be used: {issue.message}",
                key=TERMS_FILE_KEY,
                source=source,
                line=line,
                hint=f"file named: {path}",
            )
            if issue.code is ConfigErrorCode.CK_CFG_005
            else issue
            for issue in error.issues
        ]
    )


def _expand_layer(layer: Layer, *, project_root: Path, project_source: str | None) -> Layer:
    """Add the terms of ``privacy.domain_terms_file`` to the layer's domain terms (E03-21).

    A relative path is relative to the project root in every layer. The project layer and the
    profiles it defines are confined to the project root; every failure stops the run.

    Raises:
        ConfigError: CK-CFG-005 naming the key, the defining source and line when the file
            cannot be read; CK-CFG-003 with the terms file's line for an invalid term.
    """
    privacy = layer.data.get("privacy")
    if not isinstance(privacy, Mapping) or not isinstance(privacy.get(TERMS_FILE_KEY_NAME), str):
        return layer
    inline_value = privacy.get("domain_terms", [])
    inline = split_csv(inline_value) if isinstance(inline_value, str) else inline_value
    if not isinstance(inline, list):
        return layer  # validation reports the malformed inline value
    path = Path(privacy[TERMS_FILE_KEY_NAME]).expanduser()
    if not path.is_absolute():
        path = project_root / path
    confine_to = project_root.resolve() if _confined(layer, project_source) else None
    try:
        terms = read_terms_file(path, confine_to=confine_to)
    except ConfigError as error:
        raise _terms_error(error, layer, path) from None
    if not terms:
        return layer
    combined = list(dict.fromkeys([*inline, *terms]))
    data = {**layer.data, "privacy": {**privacy, "domain_terms": combined}}
    expanded = {**layer.expanded, "privacy.domain_terms": bool(inline)}
    return replace(layer, data=data, expanded=MappingProxyType(expanded))


def _refuse_plaintext(
    file_layers: Sequence[Layer],
    *,
    env: Mapping[str, str],
    cli_overrides: CliOverrides | Mapping[str, Any] | None,
) -> None:
    """Refuse plaintext secrets in every layer before anything else looks at values (E03-19).

    Runs before profile selection so that every ``[profiles.*]`` table is scanned, selected or
    not, and so that typed validation cannot report a pasted key under another code first. All
    hits of all layers are raised together.

    Raises:
        PlaintextSecretError: CK-CFG-010, one issue per hit.
    """
    scanned = list(file_layers)
    environment, _ = env_layer(env)
    if environment is not None:
        scanned.append(environment)
    if cli_overrides is not None:
        scanned.append(cli_layer(cli_overrides))
    issues = [
        issue
        for layer in scanned
        for issue in find_plaintext_secrets(
            layer.data, source=layer.source, text=layer.text, key_sources=layer.key_sources
        )
    ]
    if issues:
        raise PlaintextSecretError(issues)


def _check_layers(
    layers: Sequence[Layer],
    *,
    raw_project: Layer | None,
    project_root: Path,
    project_trust: ProjectTrust,
    trust_project_config: bool,
    env: Mapping[str, str],
    user_config: Path | None,
) -> tuple[tuple[ConfigIssue, ...], ProjectTrust]:
    """Refuse restricted and loosened keys of the project configuration before merging.

    ``raw_project`` is the project layer as read, with every ``[profiles.*]`` table, so that
    profiles it defines are checked whether or not they are selected. Runs before indirections
    are expanded, so a path key that escapes the project is reported as such (E03-25). E03-26
    adds the loosening checks here. Returns the warnings and the effective project trust.

    Raises:
        ProjectTrustError: CK-CFG-040, one issue per violation.
    """
    if raw_project is None:
        return (), project_trust
    issues = check_restricted(raw_project, project_root=project_root, user_config=user_config)
    if not issues:
        return (), project_trust
    trusted, reason = is_project_trusted(
        flag=trust_project_config, env=env, loaded_external=project_trust == "external-config"
    )
    if not trusted or reason == "untrusted":
        raise ProjectTrustError(issues)
    return (), reason


def _apply_org_policy(
    settings: Settings, merged: Mapping[str, Any], org_policies: tuple[Any, ...]
) -> tuple[Settings, frozenset[str], tuple[ConfigIssue, ...]]:
    """Enforce organisation policy locks and floors (E03-29, E03-30)."""
    return settings, frozenset(), ()


def _semantic_checks(
    settings: Settings, origins: Mapping[str, Origin], *, project_root: Path
) -> tuple[ConfigIssue, ...]:
    """Cross-section checks (E03-23); returns warnings and raises for errors.

    Raises:
        ConfigValidationError: at least one rule failed; carries every issue, warnings included.
    """
    issues = semantic_checks(settings, origins, project_root=project_root)
    if any(issue.severity == "error" for issue in issues):
        raise ConfigValidationError(issues)
    return tuple(issues)


def _read_layer(name: Literal["user", "project"], path: Path, confine_to: Path | None) -> Layer:
    document = read_toml(path, confine_to=confine_to)
    return Layer(
        name=name,
        source=str(path),
        data=document.data,
        text=document.text,
        sha256=document.sha256,
    )


def _project_layer(
    target: Path, config_file: Path | None, project_root: Path
) -> tuple[Layer | None, Path | None, ProjectTrust]:
    if config_file is not None:
        path = config_file.expanduser()
        if not path.is_file():
            raise ConfigError.single(
                ConfigErrorCode.CK_CFG_005,
                "configuration file does not exist or is not a regular file",
                source=str(path),
            )
        root = project_root.resolve()
        if path.resolve().is_relative_to(root):
            return _read_layer("project", path, root), path, "not-needed"
        check_trusted_file(path, what="configuration file")
        return _read_layer("project", path, None), path, "external-config"
    found = find_project_config(target)
    if found is None:
        return None, None, "not-needed"
    check_discovered_project_file(found, target)
    return _read_layer("project", found, project_root.resolve()), found, "not-needed"


def load_settings(
    *,
    target: Path | None = None,
    config_file: Path | None = None,
    profile: str | None = None,
    cli_overrides: CliOverrides | Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
    use_user_config: bool = True,
    trust_project_config: bool = False,
) -> LoadedConfig:
    """Load, merge and validate the configuration of one invocation.

    Raises:
        ConfigError: a file is missing, unsafe or unreadable (CK-CFG-005) or a check fails.
        ConfigSyntaxError: a file is not valid TOML.
        ConfigValidationError: the merged configuration is invalid; lists every problem.
    """
    environment = dict(os.environ if env is None else env)
    if config_file is None and environment.get(CONFIG_ENV, "").strip():
        config_file = Path(environment[CONFIG_ENV].strip())
    if environment.get(NO_USER_CONFIG_ENV, "").strip().lower() in _TRUE:
        use_user_config = False
    target = target if target is not None else Path.cwd()
    project_root = project_root_for(target)
    org_policies = _discover_org_policies(env=environment, project_root=project_root)

    layers: list[Layer] = []
    user_config: Path | None = None
    if use_user_config:
        candidate = user_config_file(environment)
        if candidate.is_file():
            check_trusted_file(candidate, what="user configuration")
            layers.append(_read_layer("user", candidate, None))
            user_config = candidate
    project, project_config, project_trust = _project_layer(target, config_file, project_root)
    if project is not None:
        layers.append(project)

    deprecation_warnings: list[ConfigIssue] = []
    for index, layer in enumerate(layers):
        layers[index], found = apply_deprecations(layer)
        deprecation_warnings.extend(found)
    _refuse_plaintext(layers, env=environment, cli_overrides=cli_overrides)
    raw_project = next((layer for layer in layers if layer.name == "project"), None)
    layers, profile_name, profile_origin, profiles_table = _select_profile(
        layers, profile=profile, env=environment
    )
    layers, env_warnings = _extra_layers(layers, env=environment, cli_overrides=cli_overrides)
    check_warnings, project_trust = _check_layers(
        layers,
        raw_project=raw_project,
        project_root=project_root,
        project_trust=project_trust,
        trust_project_config=trust_project_config,
        env=environment,
        user_config=user_config_file(environment) if use_user_config else None,
    )
    layers = [
        _expand_layer(
            layer,
            project_root=project_root,
            project_source=project.source if project is not None else None,
        )
        for layer in layers
    ]
    warnings = [
        *deprecation_warnings,
        *env_warnings,
        *check_warnings,
    ]

    union_keys = union_keys_of(Settings)
    defaults = Settings().model_dump(mode="json")
    defaults["profile"] = profile_name
    defaults["profiles"] = profiles_table
    merged: dict[str, Any] = defaults
    for layer in layers:
        merged = deep_merge(merged, layer.data, union_keys=union_keys)
    try:
        settings = Settings.model_validate(merged)
    except ValidationError as exc:
        raise ConfigValidationError(convert_validation_error(exc, _origin_lookup(layers))) from None

    settings, locked_keys, policy_warnings = _apply_org_policy(settings, merged, org_policies)
    warnings.extend(policy_warnings)
    origins = compute_origins(
        layers, settings.model_dump(mode="json"), union_keys=union_keys, defaults=defaults
    )
    warnings.extend(_semantic_checks(settings, origins, project_root=project_root))
    return LoadedConfig(
        settings=settings,
        origins=origins,
        layers=tuple(layers),
        project_root=project_root,
        project_config=project_config,
        user_config=user_config,
        warnings=tuple(warnings),
        profile=profile_name,
        profile_origin=profile_origin,
        project_trust=project_trust,
        org_policies=org_policies,
        locked_keys=locked_keys,
    )
