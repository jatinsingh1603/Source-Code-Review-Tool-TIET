"""The finding page states what a weakness allows, not the rate stage's rating line."""

from codekavach.report.model.library import lookup
from codekavach.server.results import _impact


def test_rating_line_is_replaced_by_the_weakness_impact() -> None:
    data = {"impact": {"level": 5, "narrative": "CVSS v4.0 9.3 (CVSS-B); OWASP impact high"}}
    impact = _impact(data, [89])
    assert impact["narrative"] == lookup((89,)).impact
    assert "CVSS-B" not in impact["narrative"]
    assert impact["level"] == 5


def test_a_model_impact_is_kept() -> None:
    data = {"impact": {"level": 4, "narrative": "An attacker reads every account."}}
    assert _impact(data, [89])["narrative"] == "An attacker reads every account."
    assert _impact({}, [89]) == {}
