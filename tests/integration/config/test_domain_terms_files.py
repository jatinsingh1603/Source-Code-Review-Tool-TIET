from tests.support.config import ConfigSandbox


def test_user_and_project_terms_files_accumulate(config_sandbox: ConfigSandbox) -> None:
    user_terms = config_sandbox.home / "terms.txt"
    user_terms.write_text("# partners\nPartnerCo\n", encoding="utf-8")
    config_sandbox.write_user(
        f'[privacy]\ndomain_terms = ["accrual"]\ndomain_terms_file = "{user_terms.as_posix()}"\n'
    )
    (config_sandbox.root / "terms.txt").write_text("GoldSaver\naccrual\n", encoding="utf-8")
    project = config_sandbox.write_project('[privacy]\ndomain_terms_file = "terms.txt"\n')

    loaded = config_sandbox.load()

    assert loaded.settings.privacy.domain_terms == ["accrual", "PartnerCo", "GoldSaver"]
    origin = loaded.origins["privacy.domain_terms"]
    assert origin.contributors == ("user", "user:file", "project:file")
    assert loaded.origins["privacy.domain_terms_file"].source == str(project)
