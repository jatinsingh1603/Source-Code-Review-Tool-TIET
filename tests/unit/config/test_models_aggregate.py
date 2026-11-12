import pytest
from pydantic import ValidationError

from codekavach.config.models.aggregate import AggregateSettings, SecretsSettings


def test_defaults() -> None:
    assert AggregateSettings().baseline_file == ".codekavach/baseline.json"
    assert AggregateSettings().suppressions_file == ".codekavach/suppressions.yaml"
    assert SecretsSettings().history is False
    assert SecretsSettings().history_max_commits == 200


@pytest.mark.parametrize("value", ["/etc/x", "../x.json", "a/../../x", "C:/x", ""])
def test_files_stay_inside_the_project(value: str) -> None:
    with pytest.raises(ValidationError):
        AggregateSettings(baseline_file=value)
    with pytest.raises(ValidationError):
        AggregateSettings(suppressions_file=value)


def test_history_commit_bounds() -> None:
    assert SecretsSettings(history_max_commits=5000).history_max_commits == 5000
    for bad in (0, 5001):
        with pytest.raises(ValidationError):
            SecretsSettings(history_max_commits=bad)
