"""The finding page states what a weakness allows, not the rate stage's rating line."""

from codekavach.report.model.library import lookup
from codekavach.server.results import _impact, _library_text, _offline_review_only


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


def _mock_reviewed(provider: str) -> dict[str, object]:
    return {
        "impact": {"level": 5, "narrative": "Mock impact: an attacker could read or modify data."},
        "remediation": "1. Validate.\n\n```python\nresult = safe_call(x)  # mock example\n```",
        "provenance": {"llm_reviews": [{"provider": provider, "impact": "Mock impact: x"}]},
    }


def test_the_mock_providers_placeholder_text_gives_way_to_the_library() -> None:
    data = _library_text(_mock_reviewed("mock"), [89], None)
    assert _offline_review_only(_mock_reviewed("mock"))
    assert data["impact"]["narrative"] == lookup((89,)).impact
    assert data["impact"]["level"] == 5
    assert "mock" not in data["remediation"].lower()
    assert lookup((89,)).short_term in data["remediation"]


def test_a_real_models_review_is_not_treated_as_offline() -> None:
    assert not _offline_review_only(_mock_reviewed("agentrouter"))
    assert not _offline_review_only({"provenance": {"llm_reviews": []}})
