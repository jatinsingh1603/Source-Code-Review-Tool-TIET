from tests.support.config import ConfigSandbox


def test_env_wins_over_user_project_and_profile(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user('[scan]\njobs = 2\n[reporting]\nformats = ["csv"]\n')
    config_sandbox.write_project(
        '[scan]\njobs = 3\n[reporting]\nformats = ["json"]\n'
        '[profiles.fast.scan]\njobs = 4\n[profiles.fast.reporting]\nformats = ["sarif"]\n'
    )
    config_sandbox.env["CODEKAVACH_PROFILE"] = "fast"
    loaded = config_sandbox.load()
    assert loaded.settings.scan.jobs == 4
    assert loaded.origins["scan.jobs"].layer == "profile"

    config_sandbox.env["CODEKAVACH_SCAN__JOBS"] = "8"
    config_sandbox.env["CODEKAVACH_REPORTING__FORMATS"] = "html,pdf"
    loaded = config_sandbox.load()
    assert loaded.settings.scan.jobs == 8
    assert [f.value for f in loaded.settings.reporting.formats] == ["html", "pdf"]
    for key, name in (
        ("scan.jobs", "CODEKAVACH_SCAN__JOBS"),
        ("reporting.formats", "CODEKAVACH_REPORTING__FORMATS"),
    ):
        assert loaded.origins[key].layer == "env"
        assert loaded.origins[key].source == name
