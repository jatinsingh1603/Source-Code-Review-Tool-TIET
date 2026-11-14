"""Policy loader: each refusal code, the min_level floor, symlinks and the project root."""

import os
from pathlib import Path

import pytest

from codekavach.config import Settings
from codekavach.core.models import PrivacyLevel
from codekavach.privacy.policy.engine import PolicyEngine
from codekavach.privacy.policy.errors import POLICY_ERROR_CODES, PolicyError, PolicyErrorCode
from codekavach.privacy.policy.loader import POLICY_FILE, load_document, load_policy


def strict() -> Settings:
    return Settings.model_validate({"privacy": {"level": "L3", "min_level": "L3"}})


def refused(text: str) -> PolicyError:
    with pytest.raises(PolicyError) as info:
        load_document(text, file=POLICY_FILE)
    return info.value


def test_registry_is_complete() -> None:
    assert [c.value for c in PolicyErrorCode] == [f"CK-POL-{n:03d}" for n in range(1, 10)]
    assert set(POLICY_ERROR_CODES) == set(PolicyErrorCode)


def test_001_oversized_and_not_toml() -> None:
    assert refused("x = '" + "a" * 300_000 + "'").code == "CK-POL-001"
    assert refused("not toml ===").code == "CK-POL-001"


def test_002_unknown_version() -> None:
    error = refused("policy_version = 2\n")
    assert error.code == "CK-POL-002"
    assert error.line == 1


def test_003_unknown_key() -> None:
    assert refused("bogus = 1\n").code == "CK-POL-003"
    assert refused("[[path]]\npattern = 'a'\nlevel = 'L3'\ncolour = 'x'\n").code == "CK-POL-003"


@pytest.mark.parametrize("pattern", ["/abs/**", "../x", "", "x" * 300])
def test_004_bad_pattern(pattern: str) -> None:
    error = refused(f'[[path]]\npattern = "{pattern}"\nlevel = "L4"\n')
    assert error.code == "CK-POL-004"


def test_005_level_and_never_send() -> None:
    error = refused('\n[[path]]\npattern = "x"\nlevel = "L2"\nnever_send = true\n')
    assert error.code == "CK-POL-005"
    assert error.line == 2
    assert POLICY_FILE in str(error)
    assert refused('[[path]]\npattern = "x"\n').code == "CK-POL-005"


def test_006_weaker_than_min_level_is_refused_not_clamped(tmp_path: Path) -> None:
    text = 'policy_version = 1\n\n[[rule]]\nmatch = "CWE-89"\nlevel = "L2"\n'
    (tmp_path / POLICY_FILE).write_text(text, encoding="utf-8")
    with pytest.raises(PolicyError) as info:
        load_policy(strict(), project_root=tmp_path)
    error = info.value
    assert error.code == "CK-POL-006"
    assert error.line == 3
    message = str(error)
    assert POLICY_FILE in message
    assert "L2" in message
    assert "L3" in message
    with pytest.raises(PolicyError):
        PolicyEngine.for_scan(strict(), project_root=tmp_path)


def test_006_does_not_fire_at_or_above_the_floor(tmp_path: Path) -> None:
    text = '[[rule]]\nmatch = "CWE-89"\nlevel = "L4"\n'
    (tmp_path / POLICY_FILE).write_text(text, encoding="utf-8")
    loaded = load_policy(strict(), project_root=tmp_path)
    assert loaded is not None
    assert loaded[0].rule[0].level is PrivacyLevel.L4


def test_007_tag_without_level() -> None:
    error = refused('[[classification]]\ntag = "pci"\npatterns = ["a/**"]\n')
    assert error.code == "CK-POL-007"


def test_008_too_many_rules() -> None:
    text = "".join(f'[[path]]\npattern = "d{i}/**"\nlevel = "L4"\n' for i in range(1001))
    assert refused(text).code == "CK-POL-008"


def test_009_unknown_tier() -> None:
    assert refused('[provider_tiers]\nsemi = "L3"\n').code == "CK-POL-009"


def test_no_file_is_none(tmp_path: Path) -> None:
    assert load_policy(Settings(), project_root=tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need privileges on Windows")
def test_symlinked_policy_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside.toml"
    outside.write_text("policy_version = 1\n", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / POLICY_FILE).symlink_to(outside)
    with pytest.raises(PolicyError) as info:
        load_policy(Settings(), project_root=project)
    assert info.value.code == "CK-POL-001"


def test_messages_name_no_file_contents() -> None:
    error = refused('[[path]]\npattern = "/etc/**"\nlevel = "L4"\n# SECRET_MARKER\n')
    assert "SECRET_MARKER" not in str(error)


def test_001_names_the_line_of_a_toml_syntax_error_but_no_contents() -> None:
    error = refused('policy_version = 1\n[[path]\npattern = "SECRET_MARKER"\n')
    assert error.code == "CK-POL-001"
    assert error.line == 2
    assert "SECRET_MARKER" not in str(error)
    assert "TOMLDecodeError" not in str(error)
    duplicate = refused("policy_version = 1\nSECRET_KEY = 1\nSECRET_KEY = 2\n")
    assert duplicate.line == 3
    assert "SECRET_KEY" not in str(duplicate)
