"""Hypothesis strategies for configuration: sections, whole settings and layers (E03-15).

Every strategy produces valid input by construction; ``settings_dicts()`` always satisfies
``Settings.model_validate``. Text comes from a small vocabulary of lower-case words so that
failing examples are readable. E03-28 adds ``org_policies()`` here.
"""

from typing import Any

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from codekavach.config.models.llm import ProviderKind, TaskName
from codekavach.config.models.reporting import ComplianceFramework, ReportFormat
from codekavach.core.models import Language, PrivacyLevel, Severity, TrustTier

_WORDS = ("alpha", "bank", "core", "data", "engine", "fees", "ledger", "main", "src", "web")
_WORD = st.sampled_from(_WORDS)
SECTIONS = ("project", "scan", "plugins", "privacy", "llm", "reporting", "engines", "integrations")


def privacy_levels() -> SearchStrategy[PrivacyLevel]:
    """Any privacy level."""
    return st.sampled_from(list(PrivacyLevel))


def trust_tiers() -> SearchStrategy[TrustTier]:
    """Any trust tier."""
    return st.sampled_from(list(TrustTier))


def secret_refs() -> SearchStrategy[str]:
    """Valid ``env:``, ``keyring:`` and ``file:`` references."""
    env = _WORD.map(lambda word: f"env:CODEKAVACH_{word.upper()}_KEY")
    keyring = st.tuples(_WORD, _WORD).map(lambda parts: f"keyring:{parts[0]}/{parts[1]}")
    short = _WORD.map(lambda word: f"keyring:{word}")
    file = _WORD.map(lambda word: f"file:/run/secrets/{word}")
    home = _WORD.map(lambda word: f"file:~/{word}.key")
    return st.one_of(env, keyring, short, file, home)


def globs() -> SearchStrategy[str]:
    """Relative, ``/``-separated globs without ``..``."""
    part = st.one_of(_WORD, st.just("**"), _WORD.map(lambda word: f"*.{word[:2]}"))
    return st.lists(part, min_size=1, max_size=4).map("/".join)


@st.composite
def provider_settings(draw: st.DrawFn) -> dict[str, Any]:
    """A valid provider definition; endpoints are loopback or https only."""
    kind = draw(st.sampled_from(list(ProviderKind)))
    data: dict[str, Any] = {"kind": kind.value}
    if kind not in (ProviderKind.MOCK, ProviderKind.REPLAY):
        data["model"] = draw(_WORD) + "-model"
    if kind in (ProviderKind.OPENAI_COMPATIBLE, ProviderKind.AZURE_OPENAI, ProviderKind.LITELLM):
        data["base_url"] = draw(
            st.sampled_from(
                ["http://127.0.0.1:8000/v1", "http://localhost:4000", "https://llm.example.test/v1"]
            )
        )
    if kind is ProviderKind.BEDROCK:
        data["region"] = "eu-west-1"
    if kind is ProviderKind.REPLAY:
        data["cassette_dir"] = "tests/cassettes"
    if kind is ProviderKind.CLI_BRIDGE:
        data["command"] = ["bridge", "--stdio"]
    if draw(st.booleans()) and kind not in (ProviderKind.MOCK, ProviderKind.REPLAY):
        data["api_key"] = draw(secret_refs())
    data["enabled"] = draw(st.booleans())
    return data


def _project() -> SearchStrategy[dict[str, Any]]:
    return st.fixed_dictionaries(
        {},
        optional={
            "name": _WORD,
            "client": _WORD.map(str.title),
            "languages": st.lists(st.sampled_from(list(Language)), max_size=3, unique=True).map(
                lambda values: [value.value for value in values]
            ),
        },
    )


def _scan() -> SearchStrategy[dict[str, Any]]:
    return st.fixed_dictionaries(
        {},
        optional={
            "include": st.lists(globs(), min_size=1, max_size=3),
            "exclude": st.lists(globs(), max_size=3),
            "jobs": st.integers(0, 256),
            "max_file_size_kb": st.integers(1, 102_400),
            "fail_on": st.sampled_from([*(s.value for s in Severity), "none"]),
            "respect_gitignore": st.booleans(),
        },
    )


def _plugins() -> SearchStrategy[dict[str, Any]]:
    return st.fixed_dictionaries(
        {},
        optional={
            "allow_distributions": st.lists(_WORD.map(lambda w: f"codekavach-{w}"), max_size=2),
            "disable": st.lists(_WORD.map(lambda w: f"engine:{w}"), max_size=2, unique=True),
        },
    )


@st.composite
def _privacy(draw: st.DrawFn) -> dict[str, Any]:
    min_level = draw(privacy_levels())
    stricter = [level for level in PrivacyLevel if level.at_least(min_level)]
    data: dict[str, Any] = {
        "min_level": min_level.value,
        "level": draw(st.sampled_from(stricter)).value,
    }
    if draw(st.booleans()):
        data["paths"] = [
            {"pattern": draw(globs()), "level": draw(st.sampled_from(stricter)).value}
            for _ in range(draw(st.integers(0, 3)))
        ]
    if draw(st.booleans()):
        data["domain_terms"] = draw(st.lists(_WORD, max_size=3))
    if draw(st.booleans()):
        data["provider_tier_levels"] = {
            tier.value: draw(privacy_levels()).value for tier in draw(st.sets(trust_tiers()))
        }
    return data


@st.composite
def _llm(draw: st.DrawFn) -> dict[str, Any]:
    ids = draw(st.lists(_WORD, max_size=3, unique=True))
    providers = {provider_id: draw(provider_settings()) for provider_id in ids}
    data: dict[str, Any] = {
        "providers": providers,
        "default_provider": draw(
            st.sampled_from(["auto", *(pid for pid, p in providers.items() if p["enabled"])])
        ),
        "temperature": draw(st.sampled_from([0.0, 0.2, 1.0])),
        "tasks": draw(st.lists(st.sampled_from([t.value for t in TaskName]), unique=True)),
    }
    if draw(st.booleans()):
        data["allow_remote"] = draw(st.booleans())
    return data


def _reporting() -> SearchStrategy[dict[str, Any]]:
    return st.fixed_dictionaries(
        {},
        optional={
            "formats": st.lists(
                st.sampled_from([f.value for f in ReportFormat]), min_size=1, unique=True
            ),
            "snippet_context_lines": st.integers(0, 20),
            "classification": st.sampled_from(["Confidential", "Internal"]),
            "compliance": st.lists(
                st.sampled_from([c.value for c in ComplianceFramework]), unique=True
            ),
        },
    )


@st.composite
def _engines(draw: st.DrawFn) -> dict[str, Any]:
    ids = draw(st.lists(_WORD, max_size=4, unique=True))
    split = draw(st.integers(0, len(ids)))
    return {"enabled": ids[:split], "disabled": ids[split:]}


@st.composite
def _integrations(draw: st.DrawFn) -> dict[str, Any]:
    if not draw(st.booleans()):
        return {}
    return {
        "github": {
            "enabled": True,
            "repository": f"{draw(_WORD)}/{draw(_WORD)}",
            "issue_sync": draw(st.booleans()),
            "dry_run": draw(st.booleans()),
            "token": draw(secret_refs()),
        }
    }


_SECTION_STRATEGIES = {
    "project": _project,
    "scan": _scan,
    "plugins": _plugins,
    "privacy": _privacy,
    "llm": _llm,
    "reporting": _reporting,
    "engines": _engines,
    "integrations": _integrations,
}


def section_dicts(name: str) -> SearchStrategy[dict[str, Any]]:
    """A valid dictionary for one ``[name]`` section."""
    return _SECTION_STRATEGIES[name]()


@st.composite
def settings_dicts(draw: st.DrawFn) -> dict[str, Any]:
    """A valid nested settings dictionary; ``Settings.model_validate(d)`` always succeeds."""
    chosen = draw(st.sets(st.sampled_from(SECTIONS)))
    return {name: draw(section_dicts(name)) for name in sorted(chosen)}


# Sections a project file may set without hitting restricted keys (E03-25).
_PROJECT_LAYER_SECTIONS = ("project", "scan", "reporting")


@st.composite
def layer_sets(draw: st.DrawFn) -> tuple[dict[str, Any], dict[str, Any]]:
    """A user and a project dictionary that each validate when merged over the defaults."""
    user = draw(settings_dicts())
    chosen = draw(st.sets(st.sampled_from(_PROJECT_LAYER_SECTIONS)))
    project = {name: draw(section_dicts(name)) for name in sorted(chosen)}
    return user, project
