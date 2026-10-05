"""Load ``tools/status_report.py``, which is a stand-alone script and not an importable package."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "status_report.py"
FIXTURES = Path(__file__).parent / "fixtures"
RECORDING = FIXTURES / "projectv2_items.json"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("status_report", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["status_report"] = module
    spec.loader.exec_module(module)
    return module


status_report = _load()
