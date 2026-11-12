"""CVSS v4.0 and v3.1 parsing and scoring against golden vectors."""

import json
from pathlib import Path
from typing import Any

import pytest

from codekavach.core.models.enums import Severity
from codekavach.risk.cvss.v4 import Cvss4Vector, round_half_up
from codekavach.risk.cvss.v31 import Cvss31Vector, roundup
from codekavach.risk.cvss.vector import CvssVectorError

GOLDEN = Path(__file__).parent / "golden"
_SEVERITY = {
    "None": Severity.INFO,
    "Low": Severity.LOW,
    "Medium": Severity.MEDIUM,
    "High": Severity.HIGH,
    "Critical": Severity.CRITICAL,
}


def _rows(name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = json.loads((GOLDEN / name).read_text())["vectors"]
    return rows


@pytest.mark.parametrize("row", _rows("cvss4_vectors.json"), ids=lambda row: row["vector"])
def test_cvss4_golden(row: dict[str, Any]) -> None:
    vector = Cvss4Vector.parse(row["vector"])
    assert vector.score() == row["score"]
    assert vector.severity() is _SEVERITY[row["severity"]]


@pytest.mark.parametrize("row", _rows("cvss31_vectors.json"), ids=lambda row: row["vector"])
def test_cvss31_golden(row: dict[str, Any]) -> None:
    vector = Cvss31Vector.parse(row["vector"])
    assert vector.base_score() == row["score"]
    assert vector.severity() is _SEVERITY[row["severity"]]


def test_round_trip_and_nomenclature() -> None:
    text = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    vector = Cvss4Vector.parse(text)
    assert vector.to_string() == text
    assert vector.nomenclature() == "CVSS-B"
    assert vector.with_metrics(E="U").nomenclature() == "CVSS-BT"
    assert vector.with_metrics(CR="H").nomenclature() == "CVSS-BE"
    assert vector.with_metrics(E="P", MAV="L").nomenclature() == "CVSS-BTE"
    assert vector.with_metrics(U="Amber").to_string().endswith("/U:Amber")


@pytest.mark.parametrize(
    "text",
    [
        "CVSS:3.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/SA:N",
        "CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:A",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/",
    ],
)
def test_cvss4_rejects_bad_vectors(text: str) -> None:
    with pytest.raises(CvssVectorError):
        Cvss4Vector.parse(text)


def test_cvss31_accepts_any_order_and_rejects_bad() -> None:
    vector = Cvss31Vector.parse("CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H")
    assert vector.to_string() == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert vector.base_score() == 9.8
    with pytest.raises(CvssVectorError):
        Cvss31Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")


def test_rounding_helpers() -> None:
    assert roundup(4.02) == 4.1
    assert roundup(4.0) == 4.0
    assert round_half_up(8.6 - 7.15) == 1.5
    assert round_half_up(1.44) == 1.4
