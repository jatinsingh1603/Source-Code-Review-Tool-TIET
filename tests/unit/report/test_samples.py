"""The committed sample reports (docs/samples) are intact and carry no planted secret (E31).

The samples are generated from a KavachBank scan; they are excluded from the content hooks
because they are byte-exact renderer output, so this test is what checks them: every file
matches the integrity manifest, and no secret value planted in the fixture appears in any text
format or inside the DOCX and XLSX archives.
"""

import re
import zipfile
from pathlib import Path

import pytest
import yaml

from codekavach.report.render.bundle import verify_manifest

ROOT = Path(__file__).parents[3]
SAMPLES = ROOT / "docs" / "samples" / "kavachbank"
FIXTURE = ROOT / "fixtures" / "kavachbank"
QUOTED = re.compile(r"""["']([^"']{8,})["']""")
TEXT_SUFFIXES = {".html", ".json", ".md", ".csv", ".sarif"}

pytestmark = pytest.mark.skipif(not SAMPLES.is_dir(), reason="no committed samples")


def _planted_values() -> list[str]:
    manifest = yaml.safe_load(
        (FIXTURE / "ground-truth" / "manifest.yaml").read_text(encoding="utf-8")
    )
    values: list[str] = []
    for item in manifest["planted_secrets"]:
        lines = (FIXTURE / item["file"]).read_text(encoding="utf-8").splitlines()
        line = lines[item["line"] - 1]
        values.extend(match.group(1) for match in QUOTED.finditer(line))
    return [value for value in values if not value.startswith(("env:", "<"))]


def _contents(path: Path) -> bytes:
    if path.suffix in {".docx", ".xlsx"}:
        with zipfile.ZipFile(path) as archive:
            return b"".join(archive.read(name) for name in archive.namelist())
    return path.read_bytes()


def test_every_sample_matches_the_manifest() -> None:
    assert verify_manifest(SAMPLES) == []


def test_no_planted_secret_appears_in_a_sample() -> None:
    values = _planted_values()
    assert values, "the fixture should plant secrets"
    for path in sorted(SAMPLES.iterdir()):
        if path.suffix not in TEXT_SUFFIXES | {".docx", ".xlsx"}:
            continue
        data = _contents(path)
        for value in values:
            assert value.encode() not in data, f"{path.name} contains a planted secret"
