"""The demo seeding script and the synthetic demo projects stay consistent with each other."""

import importlib.util
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "seed_demo.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("seed_demo", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_scripted_fix_still_applies_to_its_fixture() -> None:
    module = _load_script()
    for fixture, fixes in (
        ("demo-ledgerly", module.LEDGERLY_FIXES),
        ("demo-shopfront", module.SHOPFRONT_FIXES),
    ):
        for relative, old, _new in fixes:
            text = (REPO / "fixtures" / fixture / relative).read_text(encoding="utf-8")
            assert old in text, f"{fixture}/{relative}: the fix no longer matches"


def test_ground_truth_lines_point_at_the_planted_code() -> None:
    for fixture in ("demo-ledgerly", "demo-shopfront"):
        root = REPO / "fixtures" / fixture
        manifest = yaml.safe_load((root / "ground-truth" / "manifest.yaml").read_text("utf-8"))
        entries = [*manifest["planted_vulnerabilities"], *manifest["planted_secrets"]]
        entries += manifest["negative_controls"]
        for entry in entries:
            lines = (root / entry["file"]).read_text(encoding="utf-8").splitlines()
            assert 1 <= entry["line"] <= len(lines), entry
            assert lines[entry["line"] - 1].strip(), entry
