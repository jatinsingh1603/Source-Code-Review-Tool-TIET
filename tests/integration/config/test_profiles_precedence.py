from pathlib import Path

from codekavach.config import load_settings


def test_user_project_profile_precedence_for_fail_on(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text('[scan]\nfail_on = "critical"\n', encoding="utf-8")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    project = repo / "codekavach.toml"
    env = {"CODEKAVACH_HOME": str(home)}

    loaded = load_settings(target=repo, env=env)
    assert loaded.settings.scan.fail_on == "critical"
    assert loaded.origins["scan.fail_on"].layer == "user"

    project.write_text('[scan]\nfail_on = "low"\n', encoding="utf-8")
    loaded = load_settings(target=repo, env=env)
    assert loaded.settings.scan.fail_on == "low"
    assert loaded.origins["scan.fail_on"].layer == "project"
    assert loaded.origins["scan.fail_on"].line == 2

    loaded = load_settings(target=repo, env=env, profile="demo")
    assert loaded.settings.scan.fail_on == "none"
    origin = loaded.origins["scan.fail_on"]
    assert (origin.layer, origin.source) == ("profile", "builtin:demo")
    assert [layer.name for layer in loaded.layers] == ["user", "project", "profile"]
