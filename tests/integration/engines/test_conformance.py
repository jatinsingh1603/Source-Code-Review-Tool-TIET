"""The adapter conformance kit over every recorded case (E14-02).

Runs without any engine installed: each case is the engine's output recorded once and replayed.
``--engines-live`` re-records the cases whose engine is installed and is refused in CI.
"""

import json
import shutil
from pathlib import Path

import pytest

from codekavach.analysis.engines.adapters.bandit import BanditAdapter
from codekavach.analysis.engines.adapters.eslint_security import EslintSecurityAdapter
from codekavach.analysis.engines.adapters.opengrep import OpengrepAdapter
from codekavach.analysis.engines.base import EngineAdapter
from codekavach.analysis.engines.registry import get_adapter
from codekavach.core.models import Language
from tests.support.engines import (
    FakeAdapter,
    RecordedCase,
    discover_cases,
    record_case,
    run_adapter_contract,
)

CASES = discover_cases()
FAKE = next(case for case in CASES if case.engine_id == "fake")


def adapter_for(case: RecordedCase) -> EngineAdapter:
    known: dict[str, type[EngineAdapter]] = {
        "fake": FakeAdapter,
        "opengrep": OpengrepAdapter,
        "bandit": BanditAdapter,
        "eslint-security": EslintSecurityAdapter,
    }
    if case.engine_id in known:
        return known[case.engine_id]()
    return get_adapter(case.engine_id)


@pytest.fixture
def live(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--engines-live"))


def test_there_is_at_least_one_recorded_case() -> None:
    assert {case.label for case in CASES} >= {
        "fake/basic",
        "bandit/basic",
        "opengrep/basic",
        "eslint-security/basic",
    }


@pytest.mark.parametrize("case", CASES, ids=[case.label for case in CASES])
def test_the_adapter_passes_its_recorded_case(
    case: RecordedCase, live: bool, tmp_path: Path
) -> None:
    adapter = adapter_for(case)
    if live:
        record_case(adapter, case.directory)
    found = run_adapter_contract(adapter, case.directory, case.settings(tmp_path))
    assert found, f"{case.label}: the recorded output produced no candidates"


def copy_of(case: RecordedCase, tmp_path: Path) -> Path:
    target = tmp_path / case.engine_id / case.name
    shutil.copytree(case.directory, target)
    return target


def test_a_golden_file_altered_by_one_character_fails_the_kit(tmp_path: Path) -> None:
    case = FAKE
    target = copy_of(case, tmp_path)
    golden = target / "expected_candidates.json"
    text = golden.read_text(encoding="utf-8")
    assert "fake.rule" in text
    golden.write_text(text.replace("fake.rule", "fake.rulf", 1), encoding="utf-8")
    with pytest.raises(pytest.fail.Exception, match="differs from golden"):
        run_adapter_contract(adapter_for(case), target)


def test_a_planted_secret_in_a_candidate_fails_the_kit(tmp_path: Path) -> None:
    case = FAKE
    target = copy_of(case, tmp_path)
    spec = json.loads((target / "spec.json").read_text(encoding="utf-8"))
    spec["planted_secrets"] = ["fake.rule"]  # a value the adapter's candidates do contain
    (target / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(AssertionError, match="planted secret"):
        run_adapter_contract(adapter_for(case), target)


def test_a_path_missing_from_the_tree_fails_the_kit(tmp_path: Path) -> None:
    case = FAKE
    target = copy_of(case, tmp_path)
    (target / "tree" / "src" / "bank" / "accounts.py").unlink()
    with pytest.raises(AssertionError, match="not in the tree"):
        run_adapter_contract(adapter_for(case), target)


def test_a_shell_metacharacter_in_the_argument_vector_fails_the_kit() -> None:
    case = FAKE
    adapter = FakeAdapter(arguments=("ok", "out.json; rm -rf /"))
    with pytest.raises(AssertionError, match="shell metacharacter"):
        run_adapter_contract(adapter, case.directory)


def test_a_language_the_adapter_does_not_declare_fails_the_kit() -> None:
    adapter = FakeAdapter(languages=frozenset({Language.GO}))
    with pytest.raises(AssertionError, match="languages not declared"):
        run_adapter_contract(adapter, FAKE.directory)


def test_live_recording_is_refused_in_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "true")
    case = FAKE
    with pytest.raises(pytest.UsageError, match="CI"):
        record_case(adapter_for(case), case.directory)
