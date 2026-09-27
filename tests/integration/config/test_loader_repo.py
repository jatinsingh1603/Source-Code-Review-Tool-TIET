from pathlib import Path

from codekavach.config import load_settings
from codekavach.core.models import PrivacyLevel


def test_repository_with_user_and_project_files(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text(
        '[scan]\njobs = 4\n\n[llm]\ndefault_provider = "mock"\n', encoding="utf-8"
    )
    repo = tmp_path / "work" / "bank"
    target = repo / "services" / "payments"
    target.mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / "codekavach.toml").write_text(
        '[project]\nname = "bank"\n\n[privacy]\nlevel = "L4"\n\n'
        '[[privacy.paths]]\npattern = "secrets/**"\nnever_send = true\n',
        encoding="utf-8",
    )
    (tmp_path / "work" / "codekavach.toml").write_text("[scan]\njobs = 99\n", encoding="utf-8")

    loaded = load_settings(target=target, env={"CODEKAVACH_HOME": str(home)})

    assert loaded.project_root == repo.resolve()
    assert loaded.project_config == (repo / "codekavach.toml").resolve()
    assert loaded.user_config == home / "config.toml"
    settings = loaded.settings
    assert settings.scan.jobs == 4  # the file above the repository boundary is ignored
    assert settings.project.name == "bank"
    assert settings.privacy.level is PrivacyLevel.L4
    assert settings.privacy.paths[0].never_send is True
    assert settings.llm.default_provider == "mock"
    assert loaded.origins["privacy.paths"].line == 7
    assert loaded.resolve_path(Path("reports")) == repo.resolve() / "reports"
