"""Cross-section semantic rules, run after merging and after the organisation policy (E03-23).

Owning epic: E03.

Section models validate themselves; these rules catch configurations that claim one thing and do
another when sections are read together (L0 with a remote provider, the privacy stage skipped
while an LLM is in use, reports written into the vault's directory). Every rule runs, so one
invocation lists every problem. Each issue carries the origin of the key it is about; messages
name keys, levels, stage names and provider ids (a closed, validated pattern), never free text.
"""

from collections.abc import Mapping
from pathlib import Path

from codekavach.config.errors import DEFAULT_SEVERITY, ConfigErrorCode, ConfigIssue
from codekavach.config.models.llm import AUTO, ProviderSettings
from codekavach.config.models.root import Settings
from codekavach.config.provenance import Origin
from codekavach.core.models import PrivacyLevel, TrustTier

# Verbatim copy of ``codekavach.core.pipeline.keys.DEFAULT_STAGE_ORDER`` (E04-03): the config
# package is a leaf and may not import the pipeline; a unit test keeps the two identical.
STAGE_NAMES: tuple[str, ...] = (
    "ingest",
    "parse",
    "analyse",
    "aggregate",
    "privacy-prepare",
    "llm-review",
    "restore",
    "rate",
    "report",
    "sync",
)
UNSKIPPABLE_WITH_LLM: tuple[str, ...] = ("privacy-prepare", "restore")
LLM_STAGE = "llm-review"
PUBLIC_TIER_FLOOR = PrivacyLevel.L3
L0_HINT = "choose a local provider, set llm.enabled = false, or use a level from L1 to L4."


def _origin(origins: Mapping[str, Origin], key: str) -> Origin:
    """The origin of ``key`` or of its nearest recorded parent (lists are leaves)."""
    parts = key.split("[", maxsplit=1)[0].split(".")
    for length in range(len(parts), 0, -1):
        found = origins.get(".".join(parts[:length]))
        if found is not None:
            return found
    return Origin(layer="default")


class _Collector:
    def __init__(self, origins: Mapping[str, Origin]) -> None:
        self.origins = origins
        self.issues: list[ConfigIssue] = []

    def add(
        self, code: ConfigErrorCode, key: str, message: str, *, hint: str | None = None
    ) -> None:
        origin = _origin(self.origins, key)
        self.issues.append(
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


def _default_provider(settings: Settings) -> tuple[str, ProviderSettings] | None:
    name = settings.llm.default_provider
    if name == AUTO:
        return None
    provider = settings.llm.providers.get(name)
    return (name, provider) if provider is not None else None


def _llm_rules(settings: Settings, out: _Collector) -> None:
    chosen = _default_provider(settings)
    if chosen is None:
        return
    name, provider = chosen
    if not provider.enabled:
        out.add(
            ConfigErrorCode.CK_CFG_030,
            "llm.default_provider",
            f"llm.default_provider '{name}' names a disabled provider",
        )
    if not settings.llm.allow_remote and provider.is_remote:
        out.add(
            ConfigErrorCode.CK_CFG_031,
            "llm.allow_remote",
            f"llm.allow_remote is false but llm.default_provider '{name}' is a remote provider",
        )
    if settings.privacy.level is PrivacyLevel.L0 and settings.llm.enabled and provider.is_remote:
        out.add(
            ConfigErrorCode.CK_CFG_032,
            "privacy.level",
            f"privacy.level is L0 (nothing leaves) but llm.default_provider '{name}' is a "
            "remote provider",
            hint=L0_HINT,
        )


def _privacy_rules(settings: Settings, out: _Collector) -> None:
    privacy = settings.privacy
    floor = privacy.min_level
    if not privacy.level.at_least(floor):
        out.add(
            ConfigErrorCode.CK_CFG_037,
            "privacy.level",
            f"privacy.level {privacy.level} is weaker than privacy.min_level {floor}",
        )
    for index, rule in enumerate(privacy.paths):
        if rule.level is not None and not rule.level.at_least(floor):
            out.add(
                ConfigErrorCode.CK_CFG_037,
                f"privacy.paths[{index}].level",
                f"privacy.paths[{index}].level {rule.level} is weaker than privacy.min_level "
                f"{floor}",
            )
    public = privacy.provider_tier_levels.get(TrustTier.PUBLIC)
    if public is not None and not public.at_least(PUBLIC_TIER_FLOOR):
        out.add(
            ConfigErrorCode.CK_CFG_038,
            "privacy.provider_tier_levels.public",
            f"public providers are configured below {PUBLIC_TIER_FLOOR} ({public})",
        )


def _resolve(path: Path, project_root: Path) -> Path:
    expanded = path.expanduser()
    return (expanded if expanded.is_absolute() else project_root / expanded).resolve(strict=False)


def _path_rules(settings: Settings, project_root: Path, out: _Collector) -> None:
    root = project_root.resolve(strict=False)
    state = _resolve(settings.project.state_dir, project_root)
    output = _resolve(settings.reporting.output_dir, project_root)
    if output == root:
        out.add(
            ConfigErrorCode.CK_CFG_070,
            "reporting.output_dir",
            "reporting.output_dir resolves to the project root",
        )
    if output.is_relative_to(state):
        out.add(
            ConfigErrorCode.CK_CFG_070,
            "reporting.output_dir",
            "reporting.output_dir resolves inside project.state_dir, which holds the vault",
        )
    if state == root:
        out.add(
            ConfigErrorCode.CK_CFG_070,
            "project.state_dir",
            "project.state_dir resolves to the project root",
        )


def _stage_rules(settings: Settings, out: _Collector) -> None:
    skipped = settings.scan.skip_stages
    unknown = [name for name in skipped if name not in STAGE_NAMES]
    if unknown:
        out.add(
            ConfigErrorCode.CK_CFG_003,
            "scan.skip_stages",
            f"scan.skip_stages names {len(unknown)} unknown stage(s)",
            hint="valid stage names: " + ", ".join(STAGE_NAMES),
        )
    protected = [name for name in UNSKIPPABLE_WITH_LLM if name in skipped]
    if protected and settings.llm.enabled and LLM_STAGE not in skipped:
        out.add(
            ConfigErrorCode.CK_CFG_003,
            "scan.skip_stages",
            f"scan.skip_stages skips {', '.join(protected)} while the LLM is enabled",
            hint=f"also skip {LLM_STAGE}, or set llm.enabled = false.",
        )


def semantic_checks(
    settings: Settings, origins: Mapping[str, Origin], *, project_root: Path
) -> list[ConfigIssue]:
    """Every cross-section problem of ``settings``: errors and warnings, in rule order."""
    out = _Collector(origins)
    _llm_rules(settings, out)
    _privacy_rules(settings, out)
    _path_rules(settings, project_root, out)
    _stage_rules(settings, out)
    return out.issues
