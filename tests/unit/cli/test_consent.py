import json
import os
import stat
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.cli import consent as consent_module
from codekavach.cli.consent import (
    CONSENT_FILE,
    ConsentGrant,
    ConsentStore,
    EgressConsent,
    consent_required,
    find_grant,
    new_grant,
)
from codekavach.config import Settings
from codekavach.config.models.llm import ProviderSettings
from codekavach.core.models import PrivacyLevel
from codekavach.core.pipeline.context import ConsentDecision
from tests.support.cli import CliResult
from tests.support.scan_stub import install_stub

Cli = Callable[..., CliResult]
NOW = datetime(2026, 10, 1, 9, 14, 3, tzinfo=UTC)
TRUST = "--trust-project-config"
REMOTE = (
    '[llm]\ndefault_provider = "primary"\n'
    '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n'
)
OTHER_HOST = REMOTE + 'base_url = "https://proxy.example.test/v1"\n'
LOOPBACK = (
    '[llm]\ndefault_provider = "local"\n[llm.providers.local]\nkind = "ollama"\nmodel = "m"\n'
)


REPLAY = (
    '[llm]\ndefault_provider = "rec"\n'
    '[llm.providers.rec]\nkind = "replay"\ncassette_dir = "cassettes"\n'
)


def provider(**values: Any) -> ProviderSettings:
    return ProviderSettings.model_validate({"kind": "anthropic", "model": "m", **values})


LOCAL_HTTP = provider(kind="openai-compatible", base_url="http://127.0.0.1:8000/v1")
REMOTE_HTTP = provider(kind="openai-compatible", base_url="https://llm.example.test/v1")


def settings(level: str = "L3", **llm: Any) -> Settings:
    return Settings.model_validate({"privacy": {"level": level}, "llm": llm})


def grant(level: PrivacyLevel = PrivacyLevel.L3, **changes: Any) -> ConsentGrant:
    values: dict[str, Any] = {
        "provider_id": "primary",
        "kind": "anthropic",
        "host": None,
        "trust_tier": provider().effective_trust_tier.value,
        "level": level,
        "granted_at": NOW,
        "codekavach_version": "0.1.0",
    }
    return ConsentGrant(**{**values, **changes})


def store_with(*grants: ConsentGrant) -> ConsentStore:
    return ConsentStore(Path("consent.json"), grants)


# consent_required


@pytest.mark.parametrize(
    ("candidate", "config", "required"),
    [
        (provider(), settings(), True),
        (provider(), settings("L1"), True),
        (provider(), settings("L4"), True),
        (provider(), settings("L0"), False),
        (provider(), settings(enabled=False), False),
        (provider(), settings(allow_remote=False), False),
        (provider(kind="mock"), settings(), False),
        (provider(kind="replay"), settings(), False),
        (provider(kind="ollama"), settings(), False),
        (provider(trust_tier="local"), settings(), False),
        (LOCAL_HTTP, settings(), False),
        (REMOTE_HTTP, settings(), True),
        (provider(kind="openai"), settings(), True),
    ],
)  # fmt: skip
def test_consent_required(candidate: ProviderSettings, config: Settings, required: bool) -> None:
    assert consent_required(candidate, config) is required
    assert candidate.is_remote or not required


# matching


@pytest.mark.parametrize(
    ("granted", "requested", "covered"),
    [
        ("L3", "L3", True),
        ("L3", "L4", True),
        ("L3", "L2", False),
        ("L3", "L1", False),
        ("L1", "L2", True),
        ("L1", "L4", True),
        ("L4", "L3", False),
        ("L4", "L4", True),
    ],
)
def test_a_grant_covers_its_level_and_stricter_ones(
    granted: str, requested: str, covered: bool
) -> None:
    store = store_with(grant(PrivacyLevel(granted)))
    found = find_grant(store, "primary", provider(), PrivacyLevel(requested))
    assert (found is not None) is covered


def test_a_changed_identity_is_not_covered() -> None:
    store = store_with(grant())
    level = PrivacyLevel.L3
    assert find_grant(store, "primary", provider(), level) is not None
    assert find_grant(store, "secondary", provider(), level) is None
    moved = provider(base_url="https://proxy.example.test/v1")
    assert find_grant(store, "primary", moved, level) is None
    assert find_grant(store, "primary", provider(kind="openai"), level) is None
    assert find_grant(store, "primary", provider(trust_tier="private"), level) is None
    assert find_grant(store_with(), "primary", provider(), level) is None
    hosted = store_with(new_grant("primary", moved, level))
    assert find_grant(hosted, "primary", moved, level) is not None
    assert find_grant(hosted, "primary", provider(), level) is None


def test_decision_passed_to_the_core() -> None:
    assert EgressConsent("not-required").decision() is None
    assert EgressConsent("stored").decision() == ConsentDecision(granted=True, source="user-file")
    assert EgressConsent("flag").decision() == ConsentDecision(granted=True, source="flag")
    assert EgressConsent("env").decision() == ConsentDecision(granted=True, source="env")


# the store


def test_store_round_trip_mode_and_format(tmp_path: Path) -> None:
    env = {"CODEKAVACH_HOME": str(tmp_path / "home")}
    assert ConsentStore.load(env) == ConsentStore(tmp_path / "home" / CONSENT_FILE)
    saved = ConsentStore.load(env).with_grant(grant())
    saved.save()
    path = tmp_path / "home" / CONSENT_FILE
    assert ConsentStore.load(env) == saved
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "version": 1,
        "grants": [
            {
                "provider_id": "primary",
                "kind": "anthropic",
                "host": None,
                "trust_tier": grant().trust_tier,
                "level": "L3",
                "granted_at": "2026-10-01T09:14:03Z",
                "codekavach_version": "0.1.0",
            }
        ],
    }
    assert [entry.name for entry in path.parent.iterdir()] == [CONSENT_FILE]
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    replaced = saved.with_grant(grant(PrivacyLevel.L2))
    assert [item.level for item in replaced.grants] == [PrivacyLevel.L2]
    assert saved.without("primary").grants == ()
    assert saved.without("other").grants == saved.grants
    assert saved.without(None).grants == ()


def test_crash_between_write_and_replace_keeps_the_old_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = {"CODEKAVACH_HOME": str(tmp_path)}
    ConsentStore.load(env).with_grant(grant()).save()
    before = (tmp_path / CONSENT_FILE).read_bytes()

    def crash(self: Path, target: Path) -> Path:
        raise OSError("simulated crash")

    monkeypatch.setattr(Path, "replace", crash)
    with pytest.raises(OSError, match="simulated crash"):
        ConsentStore.load(env).with_grant(grant(PrivacyLevel.L1)).save()
    monkeypatch.undo()
    assert (tmp_path / CONSENT_FILE).read_bytes() == before
    assert [entry.name for entry in tmp_path.iterdir()] == [CONSENT_FILE]
    assert ConsentStore.load(env).grants == (grant(),)


VALID = json.dumps({"version": 1, "grants": [grant().to_json()]}).encode()


@pytest.mark.parametrize(
    "content",
    [
        b"{",
        b"\x00\xff binary",
        b"[]",
        VALID.replace(b'"version": 1', b'"version": 2'),
        VALID.replace(b'"L3"', b'"L9"'),
        VALID.replace(b'"anthropic"', b"17"),
        VALID.replace(b'"2026-10-01T09:14:03Z"', b'"2026-10-01T09:14:03"'),
        b'{"version": 1}',
        b'{"version": 1, "grants": {}}',
        b'{"version": 1, "grants": [{}]}',
    ],
)
def test_an_invalid_store_holds_no_grant(tmp_path: Path, content: bytes) -> None:
    (tmp_path / CONSENT_FILE).write_bytes(content)
    store = ConsentStore.load({"CODEKAVACH_HOME": str(tmp_path)})
    assert store.grants == ()
    assert not store.readable
    assert find_grant(store, "primary", provider(), PrivacyLevel.L4) is None


@given(content=st.one_of(st.binary(max_size=300), st.just(VALID), st.just(VALID[:-5])))
def test_arbitrary_store_contents_never_raise_or_invent_a_grant(content: bytes) -> None:
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, CONSENT_FILE).write_bytes(content)
        store = ConsentStore.load({"CODEKAVACH_HOME": directory})
    found = find_grant(store, "primary", provider(), PrivacyLevel.L3)
    if content == VALID:
        assert found == grant()
    else:
        assert found is None or content.strip().startswith(b"{")
        if found is not None:
            assert json.loads(content)["version"] == 1


# scan


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def remote_scan(cli: Cli, project: Path, *args: str, **kwargs: Any) -> CliResult:
    return cli(["scan", str(project), TRUST, "--fail-on", "none", *args], **kwargs)


def stored(home: Path) -> ConsentStore:
    return ConsentStore.load({"CODEKAVACH_HOME": str(home)})


def test_no_consent_and_no_terminal_refuses_before_the_pipeline(
    cli: Cli, project: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    (project / "codekavach.toml").write_text(REMOTE, encoding="utf-8")
    result = remote_scan(cli, project)
    assert result.exit_code == 3
    assert (
        "error[consent_required]: remote provider 'primary' has not been approved for level L3"
        in result.stderr
    )
    assert "codekavach privacy consent grant --provider primary" in result.stderr
    assert "Remote egress" not in result.stderr  # no question can be asked, so no summary
    assert stub.calls == []
    assert not (isolated_home / CONSENT_FILE).exists()
    machine = remote_scan(cli, project, "--json")
    assert (machine.exit_code, machine.json["exit_code"]) == (3, 3)
    assert stub.calls == []


@pytest.mark.parametrize(
    ("args", "env", "source"),
    [
        (("--accept-egress",), {}, "flag"),
        ((), {"CODEKAVACH_ACCEPT_EGRESS": "1"}, "env"),
    ],
)
def test_explicit_acceptance_runs_and_stores_nothing(  # noqa: PLR0917 - fixtures
    cli: Cli,
    project: Path,
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    args: tuple[str, ...],
    env: dict[str, str],
    source: str,
) -> None:
    stub = install_stub(monkeypatch)
    (project / "codekavach.toml").write_text(REMOTE, encoding="utf-8")
    result = remote_scan(cli, project, *args, env=env)
    assert result.exit_code == 0, result.stderr
    assert stub.calls[0]["consent"] == ConsentDecision(granted=True, source=source)  # type: ignore[arg-type]
    assert f"remote egress to primary accepted via {source}" in result.stderr
    assert not (isolated_home / CONSENT_FILE).exists()
    machine = remote_scan(cli, project, *args, "--json", env=env)
    assert machine.json["data"]["consent"] == {"source": source}


@pytest.mark.parametrize("value", ["true", "yes", "0", "", " 1"])
def test_only_the_exact_value_one_is_accepted(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    stub = install_stub(monkeypatch)
    (project / "codekavach.toml").write_text(REMOTE, encoding="utf-8")
    result = remote_scan(cli, project, env={"CODEKAVACH_ACCEPT_EGRESS": value})
    assert result.exit_code == 3
    assert stub.calls == []


def test_answering_on_a_terminal(
    cli: Cli, project: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    (project / "codekavach.toml").write_text(REMOTE, encoding="utf-8")
    declined = remote_scan(cli, project, tty=True, input="n\n")
    assert declined.exit_code == 3
    assert "Remote egress" in declined.stderr
    assert "Send sanitised payloads to primary (default host) at level L3? [y/N]" in (
        declined.stderr
    )
    assert stub.calls == []
    assert stored(isolated_home).grants == ()
    accepted = remote_scan(cli, project, tty=True, input="y\n")
    assert accepted.exit_code == 0, accepted.stderr
    assert stub.calls[0]["consent"] == ConsentDecision(granted=True, source="user-file")
    grants = stored(isolated_home).grants
    assert [(item.provider_id, item.kind, item.level) for item in grants] == [
        ("primary", "anthropic", PrivacyLevel.L3)
    ]
    if os.name != "nt":
        assert stat.S_IMODE((isolated_home / CONSENT_FILE).stat().st_mode) == 0o600
    again = remote_scan(cli, project, tty=True, input="")
    assert again.exit_code == 0, again.stderr
    assert "Send sanitised payloads" not in again.stderr
    assert "accepted via stored" in again.stderr
    unattended = remote_scan(cli, project)
    assert unattended.exit_code == 0, unattended.stderr


def test_a_stored_grant_covers_stricter_levels_only(
    cli: Cli, project: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    (project / "codekavach.toml").write_text(REMOTE, encoding="utf-8")
    stored(isolated_home).with_grant(grant()).save()
    assert remote_scan(cli, project, "--privacy-level", "L4").exit_code == 0
    assert remote_scan(cli, project).exit_code == 0
    assert len(stub.calls) == 2
    weaker = remote_scan(cli, project, "--set", "privacy.min_level=L1", "--privacy-level", "L2")
    assert weaker.exit_code == 3, weaker.stderr
    assert "has not been approved for level L2" in weaker.stderr
    (project / "codekavach.toml").write_text(OTHER_HOST, encoding="utf-8")
    moved = remote_scan(cli, project)
    assert moved.exit_code == 3
    assert len(stub.calls) == 2


@pytest.mark.parametrize(
    ("config", "args"),
    [
        ("", ()),
        (REPLAY, (TRUST,)),
        (LOOPBACK, (TRUST,)),
        (LOOPBACK, (TRUST, "--privacy-level", "L0")),
        (REMOTE, (TRUST, "--no-llm")),
    ],
)
def test_local_runs_neither_prompt_nor_read_the_store(
    cli: Cli,
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    config: str,
    args: tuple[str, ...],
) -> None:
    stub = install_stub(monkeypatch)

    def forbidden(env: object) -> ConsentStore:
        raise AssertionError("the consent store must not be read")

    monkeypatch.setattr(ConsentStore, "load", staticmethod(forbidden))
    (project / "codekavach.toml").write_text(config, encoding="utf-8")
    result = cli(["scan", str(project), "--fail-on", "none", *args], tty=True, input="")
    assert result.exit_code == 0, result.stderr
    assert "Send sanitised payloads" not in result.stderr
    assert "accepted via" not in result.stderr
    assert stub.calls[0]["consent"] is None


@pytest.mark.parametrize("flags", [("--offline",), ("--privacy-level", "L0")])
def test_offline_or_l0_with_a_remote_provider_is_rejected_by_the_loader(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch, flags: tuple[str, ...]
) -> None:
    """Nothing can be sent in these runs, and the configuration loader refuses the combination."""
    stub = install_stub(monkeypatch)
    (project / "codekavach.toml").write_text(REMOTE, encoding="utf-8")
    result = cli(["scan", str(project), TRUST, *flags], tty=True, input="y\n")
    assert result.exit_code == 2
    assert "Send sanitised payloads" not in result.stderr
    assert stub.calls == []


def test_project_configuration_cannot_grant_consent(
    cli: Cli, project: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    text = REMOTE + "\n[egress]\nacknowledged = true\n"
    (project / "codekavach.toml").write_text(text, encoding="utf-8")
    result = remote_scan(cli, project)
    assert result.exit_code in {2, 3}
    assert stub.calls == []
    text = REMOTE + "\n[privacy]\naccept_egress = true\n"
    (project / "codekavach.toml").write_text(text, encoding="utf-8")
    assert remote_scan(cli, project).exit_code in {2, 3}
    assert stub.calls == []
    assert not (isolated_home / CONSENT_FILE).exists()


# privacy consent


def consent(cli: Cli, project: Path, *args: str, **kwargs: Any) -> CliResult:
    return cli(["privacy", "consent", *args, TRUST], cwd=project, **kwargs)


def test_status_grant_and_revoke(cli: Cli, project: Path, isolated_home: Path) -> None:
    (project / "codekavach.toml").write_text(REMOTE, encoding="utf-8")
    empty = consent(cli, project, "status", "--json")
    assert empty.json["data"] == {"grants": [], "path": str(isolated_home / CONSENT_FILE)}
    assert "no consent has been recorded" in consent(cli, project, "status").stdout

    refused = consent(cli, project, "grant", "--provider", "primary")
    assert refused.exit_code == 2
    assert "not_confirmed" in refused.stderr
    assert stored(isolated_home).grants == ()
    asked = consent(cli, project, "grant", "--provider", "primary", tty=True, input="y\n")
    assert asked.exit_code == 0, asked.stderr
    assert "Send sanitised payloads to primary" in asked.stderr
    assert "consent recorded for primary at L3 and stricter" in asked.stdout
    unattended = consent(
        cli, project, "grant", "--provider", "primary", "--level", "l2", "--yes", "--json"
    )
    assert unattended.exit_code == 0, unattended.stderr
    assert unattended.json["data"]["granted"] is True
    assert unattended.json["data"]["grant"]["level"] == "L2"
    assert [item.level for item in stored(isolated_home).grants] == [PrivacyLevel.L2]

    listed = consent(cli, project, "status", "--json").json["data"]["grants"]
    assert [(item["provider_id"], item["level"]) for item in listed] == [("primary", "L2")]
    human = consent(cli, project, "status").stdout
    assert "primary" in human
    assert "anthropic" in human

    assert consent(cli, project, "grant", "--provider", "nope", "--yes").exit_code == 2
    assert consent(cli, project, "grant", "--provider", "primary", "--level", "L9").exit_code == 2
    local = consent(cli, project, "grant", "--provider", "mock", "--yes", "--json")
    assert local.json["data"]["granted"] is False

    assert consent(cli, project, "revoke").exit_code == 2
    assert consent(cli, project, "revoke", "--provider", "primary", "--all").exit_code == 2
    assert (
        consent(cli, project, "revoke", "--provider", "other", "--json").json["data"]["removed"]
        == 0
    )
    removed = consent(cli, project, "revoke", "--provider", "primary")
    assert "removed 1 grant(s)" in removed.stdout
    consent(cli, project, "grant", "--provider", "primary", "--yes")
    assert consent(cli, project, "revoke", "--all", "--json").json["data"]["removed"] == 1
    document = json.loads((isolated_home / CONSENT_FILE).read_text(encoding="utf-8"))
    assert document == {"version": 1, "grants": []}


def test_status_reports_an_invalid_store(cli: Cli, project: Path, isolated_home: Path) -> None:
    (isolated_home / CONSENT_FILE).write_bytes(b"{")
    result = consent(cli, project, "status")
    assert result.exit_code == 0
    assert "warning[consent_store_invalid]" in result.stderr
    assert "no consent has been recorded" in result.stdout


def test_summary_wording_is_measured() -> None:
    text = consent_module.DISCLOSURE.lower()
    for word in ("never", "guarantee", "impossible", "100%"):
        assert word not in text
